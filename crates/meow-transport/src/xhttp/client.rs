//! Reusable HTTP/2 endpoints for XHTTP, with independently configured download.
use super::{
    connect_http2,
    reuse::{Pool, ReuseConfig},
    SharedOwner, XhttpConfig,
};
use crate::{Result, Stream, TransportError};
use async_trait::async_trait;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

/// Endpoint dialing belongs to the embedding app so protected/proxy-bound
/// sockets and probe metadata are preserved. Includes any TLS/security wrap.
#[async_trait]
pub trait ConnectionFactory: Send + Sync {
    async fn connect(&self, internal: bool) -> Result<Box<dyn Stream>>;
}

/// An HTTP transport endpoint; upload/download need not share host or TLS.
pub struct XhttpEndpoint {
    config: XhttpConfig,
    factory: Arc<dyn ConnectionFactory>,
    pools: [Pool<Backend>; 2],
    keep_alive: Option<Duration>,
}
impl XhttpEndpoint {
    pub fn new(
        config: XhttpConfig,
        factory: Arc<dyn ConnectionFactory>,
        reuse: Option<ReuseConfig>,
        keep_alive_secs: i64,
    ) -> Result<Self> {
        config.validate()?;
        let period = if keep_alive_secs < 0 {
            None
        } else {
            Some(Duration::from_secs(if keep_alive_secs == 0 {
                45
            } else {
                keep_alive_secs as u64
            }))
        };
        if period.is_some_and(|p| tokio::time::Instant::now().checked_add(p).is_none()) {
            return Err(TransportError::Config(
                "xhttp: keep-alive period exceeds timer range".into(),
            ));
        }
        Ok(Self {
            config,
            factory,
            pools: [Pool::new(reuse.clone())?, Pool::new(reuse)?],
            keep_alive: period,
        })
    }
    pub fn config(&self) -> &XhttpConfig {
        &self.config
    }
    fn lease(&self, internal: bool) -> Arc<super::reuse::Lease<Backend>> {
        self.pools[usize::from(internal)].acquire(|| Backend {
            factory: Arc::clone(&self.factory),
            internal,
            keep_alive: self.keep_alive,
            connection: tokio::sync::Mutex::new(None),
        })
    }
    fn reset(&self) {
        for pool in &self.pools {
            pool.reset();
        }
    }
}

/// XHTTP logical tunnel factory; reuse limits apply per tunnel, not per POST.
pub struct XhttpClient {
    upload: Arc<XhttpEndpoint>,
    download: Option<Arc<XhttpEndpoint>>,
}
impl XhttpClient {
    pub fn new(upload: Arc<XhttpEndpoint>, download: Option<Arc<XhttpEndpoint>>) -> Result<Self> {
        if download.is_some()
            && upload
                .config
                .effective_mode()
                .eq_ignore_ascii_case("stream-one")
            && !(upload.config.mode.is_empty() || upload.config.mode.eq_ignore_ascii_case("auto"))
        {
            return Err(TransportError::Config(
                "xhttp: stream-one cannot use download-settings".into(),
            ));
        }
        Ok(Self { upload, download })
    }
    pub async fn connect(&self, internal: bool) -> Result<Box<dyn Stream>> {
        let upload = self.upload.lease(internal);
        let (sender, physical) = upload.value.sender().await?;
        let mut owners: Vec<SharedOwner> = vec![upload, physical];
        let download = if let Some(endpoint) = &self.download {
            let download = endpoint.lease(internal);
            let (sender, physical) = download.value.sender().await?;
            owners.push(download);
            owners.push(physical);
            Some((endpoint.config.clone(), sender))
        } else {
            None
        };
        connect_http2(self.upload.config.clone(), sender, download, None, owners).await
    }
    /// Reset selection without closing connections serving active tunnels.
    pub fn reset(&self) {
        self.upload.reset();
        if let Some(down) = &self.download {
            down.reset();
        }
    }
}

struct Physical {
    sender: h2::client::SendRequest<bytes::Bytes>,
    alive: Arc<AtomicBool>,
    driver: tokio::task::AbortHandle,
}
impl Drop for Physical {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
struct Backend {
    factory: Arc<dyn ConnectionFactory>,
    internal: bool,
    keep_alive: Option<Duration>,
    connection: tokio::sync::Mutex<Option<Arc<Physical>>>,
}
impl Backend {
    async fn sender(&self) -> Result<(h2::client::SendRequest<bytes::Bytes>, Arc<Physical>)> {
        // Retry only readiness before queuing headers; accepted requests on a
        // draining connection retain their Physical owner until completion.
        for attempt in 0..2 {
            let physical = {
                let mut slot = self.connection.lock().await;
                if slot
                    .as_ref()
                    .is_none_or(|p| !p.alive.load(Ordering::Acquire))
                {
                    let (sender, mut conn) = tokio::time::timeout(Duration::from_secs(10), async {
                        let stream = self.factory.connect(self.internal).await?;
                        crate::h2_common::client_builder()
                            .handshake::<_, bytes::Bytes>(stream)
                            .await
                            .map_err(|e| {
                                crate::h2_common::h2_to_transport(e, TransportError::Xhttp)
                            })
                    })
                    .await
                    .map_err(|_| {
                        TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "xhttp endpoint dial/handshake timed out",
                        ))
                    })??;
                    let alive = Arc::new(AtomicBool::new(true));
                    let task_alive = Arc::clone(&alive);
                    let ping = conn.ping_pong();
                    let period = self.keep_alive;
                    let task = tokio::spawn(async move {
                        let heartbeat = async move {
                            let Some(period) = period else {
                                std::future::pending::<()>().await;
                                return;
                            };
                            let Some(mut ping) = ping else {
                                return;
                            };
                            loop {
                                tokio::time::sleep(period).await;
                                if !matches!(
                                    tokio::time::timeout(
                                        Duration::from_secs(15),
                                        ping.ping(h2::Ping::opaque())
                                    )
                                    .await,
                                    Ok(Ok(_))
                                ) {
                                    return;
                                }
                            }
                        };
                        tokio::select! {_=conn=>{},_=heartbeat=>{}}
                        task_alive.store(false, Ordering::Release);
                    });
                    *slot = Some(Arc::new(Physical {
                        sender,
                        alive,
                        driver: task.abort_handle(),
                    }));
                }
                Arc::clone(slot.as_ref().expect("initialized physical connection"))
            };
            match super::ready(physical.sender.clone()).await {
                Ok(sender) => return Ok((sender, physical)),
                Err(error) => {
                    let mut slot = self.connection.lock().await;
                    if slot
                        .as_ref()
                        .is_some_and(|cached| Arc::ptr_eq(cached, &physical))
                    {
                        slot.take();
                    }
                    if attempt == 1 {
                        return Err(error);
                    }
                }
            }
        }
        unreachable!("bounded readiness retry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct DrainingFactory(AtomicUsize);
    #[async_trait]
    impl ConnectionFactory for DrainingFactory {
        async fn connect(&self, _: bool) -> Result<Box<dyn Stream>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            let (client, server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                let mut first = true;
                while let Some(request) = connection.accept().await {
                    let (request, mut respond) = request.unwrap();
                    if first {
                        // Keep the accepted request alive while announcing
                        // GOAWAY. New logical tunnels must establish a new TCP
                        // transport without aborting this accepted stream.
                        connection.graceful_shutdown();
                        first = false;
                    }
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        let mut response = respond
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        while let Some(data) = body.data().await {
                            let data = data.unwrap();
                            body.flow_control().release_capacity(data.len()).unwrap();
                            response.send_data(data, false).unwrap();
                        }
                        response.send_data(bytes::Bytes::new(), true).unwrap();
                    });
                }
            });
            Ok(Box::new(client))
        }
    }
    #[tokio::test]
    async fn goaway_reconnects_without_interrupting_an_accepted_tunnel() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let factory = Arc::new(DrainingFactory(AtomicUsize::new(0)));
            let endpoint = Arc::new(
                XhttpEndpoint::new(
                    XhttpConfig {
                        mode: "stream-one".into(),
                        ..Default::default()
                    },
                    Arc::clone(&factory) as Arc<dyn ConnectionFactory>,
                    Some(ReuseConfig::default()),
                    -1,
                )
                .unwrap(),
            );
            let client = XhttpClient::new(endpoint, None).unwrap();
            let mut first = client.connect(false).await.unwrap();
            first.write_all(b"open").await.unwrap();
            first.flush().await.unwrap();
            let mut output = [0; 4];
            first.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"open");
            let mut second = client.connect(false).await.unwrap();
            assert_eq!(factory.0.load(Ordering::Relaxed), 2);
            first.write_all(b"live").await.unwrap();
            first.flush().await.unwrap();
            first.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"live");
            second.write_all(b"next").await.unwrap();
            second.flush().await.unwrap();
            second.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"next");
            first.shutdown().await.unwrap();
            second.shutdown().await.unwrap();
        })
        .await
        .expect("draining connection deadline");
    }
}
