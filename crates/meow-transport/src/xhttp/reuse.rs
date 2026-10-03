//! Logical XHTTP transport leases (XMUX), distinct from VLESS multiplexing.
use crate::{Result, TransportError};
use rand::Rng as _;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::time::Instant;

/// Inclusive sampled ranges; zero means unlimited unless a positive maximum
/// enables sampling (in which case a sampled zero is meaningful).
#[derive(Clone, Debug, Default)]
pub struct ReuseConfig {
    pub max_concurrency: (usize, usize),
    pub max_connections: (usize, usize),
    pub c_max_reuse_times: (usize, usize),
    pub h_max_request_times: (usize, usize),
    pub h_max_reusable_secs: (usize, usize),
}
impl ReuseConfig {
    pub fn validate(&self) -> Result<()> {
        for (min, max) in [
            self.max_concurrency,
            self.max_connections,
            self.c_max_reuse_times,
            self.h_max_request_times,
            self.h_max_reusable_secs,
        ] {
            if min > max || max > i32::MAX as usize {
                return Err(TransportError::Config(
                    "xhttp: invalid reuse-settings range".into(),
                ));
            }
        }
        Ok(())
    }
}
fn sample(range: (usize, usize)) -> usize {
    rand::rng().random_range(range.0..=range.1)
}
struct Usage {
    active: usize,
    reuses: usize,
    requests: Option<usize>,
    closed: bool,
    last_idle: Instant,
}
struct Entry<T> {
    value: Mutex<Option<Arc<T>>>,
    usage: Mutex<Usage>,
    max_reuses: usize,
    deadline: Option<Instant>,
    maintenance: Mutex<Option<tokio::task::AbortHandle>>,
    changed: Arc<tokio::sync::Notify>,
}
impl<T> Drop for Entry<T> {
    fn drop(&mut self) {
        if let Some(task) = self.maintenance.get_mut().expect("maintenance lock").take() {
            task.abort();
        }
    }
}
impl<T> Entry<T> {
    fn exhausted(&self, u: &Usage) -> bool {
        u.requests == Some(0)
            || (self.max_reuses > 0 && u.reuses >= self.max_reuses)
            || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
    fn cleanup(&self) {
        let mut usage = self.usage.lock().expect("reuse usage");
        if usage.active == 0
            && (self.exhausted(&usage)
                || Instant::now().duration_since(usage.last_idle) >= Duration::from_secs(300))
        {
            usage.closed = true;
            self.value.lock().expect("reuse value").take();
        }
    }
}
/// Dropping the last clone releases one logical tunnel, after both directions
/// and the final upload acknowledgement have stopped using the transport.
pub(super) struct Lease<T> {
    entry: Arc<Entry<T>>,
    pub value: Arc<T>,
}
impl<T> Drop for Lease<T> {
    fn drop(&mut self) {
        {
            let mut u = self.entry.usage.lock().expect("reuse usage");
            u.active -= 1;
            if u.active == 0 {
                u.last_idle = Instant::now();
            }
        }
        self.entry.cleanup();
        self.entry.changed.notify_one();
    }
}
pub(super) struct Pool<T> {
    config: Option<ReuseConfig>,
    concurrency: usize,
    width: usize,
    entries: Mutex<Vec<Arc<Entry<T>>>>,
}
impl<T: Send + Sync + 'static> Pool<T> {
    pub fn new(config: Option<ReuseConfig>) -> Result<Self> {
        if let Some(c) = &config {
            c.validate()?;
        }
        let concurrency = config.as_ref().map_or(0, |c| sample(c.max_concurrency));
        let width = config.as_ref().map_or(0, |c| sample(c.max_connections));
        Ok(Self {
            config,
            concurrency,
            width,
            entries: Mutex::new(Vec::new()),
        })
    }
    pub fn reset(&self) {
        self.entries.lock().expect("reuse pool").clear();
    }
    pub fn acquire(&self, make: impl FnOnce() -> T) -> Arc<Lease<T>> {
        let mut entries = self.entries.lock().expect("reuse pool");
        for e in entries.iter() {
            e.cleanup();
        }
        entries.retain(|e| !e.usage.lock().expect("reuse usage").closed);
        // Fill the preferred width before selecting the least busy entry.
        // The width is not a hard cap: busy entries permit an overflow entry.
        let selected = if self.config.is_some()
            && !(entries.is_empty() || self.width > 0 && entries.len() < self.width)
        {
            entries
                .iter()
                .filter_map(|e| {
                    let u = e.usage.lock().expect("reuse usage");
                    if u.closed
                        || u.requests == Some(0)
                        || (e.max_reuses > 0 && u.reuses >= e.max_reuses)
                        || (self.concurrency > 0 && u.active >= self.concurrency)
                    {
                        None
                    } else {
                        Some((u.active, Arc::clone(e)))
                    }
                })
                .min_by_key(|(active, _)| *active)
                .and_then(|(_, e)| {
                    // Maintenance does not take the pool lock. Reserve the
                    // selected entry while holding its usage lock, so an idle
                    // timer cannot retire it between selection and leasing.
                    let mut u = e.usage.lock().expect("reuse usage");
                    if u.closed {
                        return None;
                    }
                    u.active += 1;
                    u.reuses += 1;
                    if let Some(left) = &mut u.requests {
                        *left = left.saturating_sub(1);
                    }
                    drop(u);
                    Some(e)
                })
        } else {
            None
        };
        let entry = selected.unwrap_or_else(|| {
            let now = Instant::now();
            let cfg = self.config.as_ref();
            let max_reuses = cfg.map_or(0, |c| sample(c.c_max_reuse_times));
            let requests = cfg
                .and_then(|c| (c.h_max_request_times.1 > 0).then(|| sample(c.h_max_request_times)));
            let deadline = cfg.and_then(|c| {
                (c.h_max_reusable_secs.1 > 0)
                    .then(|| now + Duration::from_secs(sample(c.h_max_reusable_secs) as u64))
            });
            let e = Arc::new(Entry {
                value: Mutex::new(Some(Arc::new(make()))),
                usage: Mutex::new(Usage {
                    active: 1,
                    reuses: 0,
                    requests: requests.map(|n| n.saturating_sub(1)),
                    closed: false,
                    last_idle: now,
                }),
                max_reuses,
                deadline,
                maintenance: Mutex::new(None),
                changed: Arc::new(tokio::sync::Notify::new()),
            });
            if self.config.is_some() {
                entries.push(Arc::clone(&e));
                let weak: Weak<Entry<T>> = Arc::downgrade(&e);
                let task = tokio::spawn(async move {
                    loop {
                        let Some(e) = weak.upgrade() else { return; };
                        let notify = Arc::clone(&e.changed);
                        let changed = notify.notified();
                        e.cleanup();
                        let deadline = {
                            let u = e.usage.lock().expect("reuse usage");
                            if u.closed { return; }
                            if u.active == 0 {
                                Some(e.deadline.map_or(u.last_idle + Duration::from_secs(300), |d| d.min(u.last_idle + Duration::from_secs(300))))
                            } else { None }
                        };
                        // No periodic polling while active. The task owns only
                        // a weak entry between waits; idle pool shutdown can
                        // therefore drop the physical transport immediately.
                        drop(e);
                        if let Some(deadline) = deadline {
                            tokio::select! { _ = tokio::time::sleep_until(deadline) => {}, _ = changed => {} }
                        } else {
                            changed.await;
                        }
                    }
                });
                *e.maintenance.lock().expect("maintenance lock") = Some(task.abort_handle());
            }
            e
        });
        entry.changed.notify_one();
        let value = Arc::clone(
            entry
                .value
                .lock()
                .expect("reuse value")
                .as_ref()
                .expect("live entry"),
        );
        Arc::new(Lease { entry, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn width_is_preferred_and_overflows_without_stealing_busy_transports() {
        let pool = Pool::new(Some(ReuseConfig {
            max_connections: (2, 2),
            max_concurrency: (1, 1),
            ..Default::default()
        }))
        .unwrap();
        let a = pool.acquire(|| 1);
        let b = pool.acquire(|| 2);
        let c = pool.acquire(|| 3);
        assert_eq!(*c.value, 3);
        drop(a);
        let d = pool.acquire(|| 4);
        assert_eq!(*d.value, 1);
        pool.reset();
        assert_eq!(*b.value, 2);
        assert_eq!(*c.value, 3);
        assert_eq!(*pool.acquire(|| 5).value, 5);
    }
    #[tokio::test]
    async fn leases_count_logical_requests_and_reacquisitions() {
        let pool = Pool::new(Some(ReuseConfig {
            h_max_request_times: (2, 2),
            c_max_reuse_times: (1, 1),
            ..Default::default()
        }))
        .unwrap();
        let a = pool.acquire(|| 1);
        let b = pool.acquire(|| 2);
        assert!(Arc::ptr_eq(&a.value, &b.value));
        let c = pool.acquire(|| 3);
        assert_eq!(*c.value, 3);
        drop(b);
        assert_eq!(*a.value, 1);
        drop(a);
        let d = pool.acquire(|| 4);
        assert_eq!(*d.value, 3);
    }
    #[tokio::test(start_paused = true)]
    async fn expiration_retires_idle_entries_without_interrupting_active_leases() {
        let pool = Pool::new(Some(ReuseConfig {
            h_max_reusable_secs: (2, 2),
            ..Default::default()
        }))
        .unwrap();
        let a = pool.acquire(|| 1);
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(*a.value, 1);
        drop(a);
        assert_eq!(*pool.acquire(|| 2).value, 2);
    }
    struct Dropped(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn idle_timer_and_pool_drop_release_cached_transports() {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pool = Pool::new(Some(ReuseConfig::default())).unwrap();
        let lease = pool.acquire(|| Dropped(Arc::clone(&count)));
        tokio::task::yield_now().await;
        drop(lease);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(301)).await;
        tokio::task::yield_now().await;
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
        let lease = pool.acquire(|| Dropped(Arc::clone(&count)));
        tokio::task::yield_now().await;
        drop(lease);
        drop(pool);
        assert_eq!(
            count.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "maintenance task must not keep an entry alive"
        );
    }
}
