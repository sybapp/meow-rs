//! Bounded packet-up upload pump. Only one unacknowledged POST is retained.
use super::{build_packet_request, ready, XhttpConfig};
use crate::{h2_common::RecvState, Stream};
use bytes::Bytes;
use rand::Rng as _;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn connect(
    config: XhttpConfig,
    authority: String,
    session: String,
    sender: h2::client::SendRequest<Bytes>,
    response: h2::client::ResponseFuture,
    driver: tokio::task::JoinHandle<()>,
) -> Box<dyn Stream> {
    let (app, pump) = tokio::io::duplex(BUFFER);
    let (mut read, mut write) = tokio::io::split(pump);
    let error = Arc::new(Mutex::new(None));
    let worker_error = Arc::clone(&error);
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        // This guard is also dropped on cancellation; never detach a socket
        // driver when an application abandons a pending packet upload.
        let _driver = super::AbortOnDrop(Some(driver.abort_handle()));
        let upload = async {
            let result = upload(&config, &authority, &session, sender, &mut read).await;
            let completion = result.as_ref().map(|_| ()).map_err(copy_error);
            let _ = finished_tx.send(completion);
            result
        };
        let download = async {
            let mut response = RecvState::with_timeout(
                response,
                RESPONSE_TIMEOUT,
                crate::h2_common::StatusPolicy::Exact(http::StatusCode::OK),
                "xhttp packet download",
            );
            std::future::poll_fn(|cx| response.poll_ready(cx)).await?;
            let body = response.stream().expect("ready body");
            while let Some(data) = body.data().await {
                let data = data.map_err(crate::h2_common::h2_to_io)?;
                write.write_all(&data).await?;
                body.flow_control()
                    .release_capacity(data.len())
                    .map_err(crate::h2_common::h2_to_io)?;
            }
            write.shutdown().await
        };
        if let Err(e) = tokio::try_join!(upload, download) {
            *worker_error.lock().expect("packet error lock") = Some(e);
        }
    });
    Box::new(PacketStream {
        inner: app,
        error,
        task: Some(task),
        finished: Some(finished_rx),
    })
}

fn copy_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

async fn upload(
    config: &XhttpConfig,
    authority: &str,
    session: &str,
    mut sender: h2::client::SendRequest<Bytes>,
    read: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
) -> io::Result<()> {
    let max =
        rand::rng().random_range(config.sc_max_each_post_bytes.0..=config.sc_max_each_post_bytes.1);
    // Header payloads must remain small enough for ordinary HTTP header limits.
    let max = if matches!(config.uplink_data_placement.as_str(), "header" | "cookie") {
        max.min(8 * 1024)
    } else {
        max
    };
    let mut seq = 0u64;
    let mut scratch = [0u8; CHUNK];
    let mut buffer = Vec::new();
    let mut eof = false;
    loop {
        let n = read.read(&mut scratch[..CHUNK.min(max)]).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&scratch[..n]);
        let delay = rand::rng()
            .random_range(config.sc_min_posts_interval_ms.0..=config.sc_min_posts_interval_ms.1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(delay as u64);
        while buffer.len() < max {
            let capacity = CHUNK.min(max - buffer.len());
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break,
                n = read.read(&mut scratch[..capacity]) => {
                    let n = n?;
                    if n == 0 { eof = true; break; }
                    buffer.reserve_exact(n);
                    buffer.extend_from_slice(&scratch[..n]);
                }
            }
        }
        let (request, payload) = build_packet_request(config, authority, session, seq, &buffer)
            .map_err(io::Error::other)?;
        seq = seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("xhttp sequence exhausted"))?;
        buffer.clear();
        sender = tokio::time::timeout(RESPONSE_TIMEOUT, async {
            let mut sender = ready(sender).await.map_err(io::Error::other)?;
            let response = send_packet(&mut sender, request, payload).await?;
            let response = response.await.map_err(crate::h2_common::h2_to_io)?;
            if response.status() != http::StatusCode::OK {
                return Err(io::Error::other(format!(
                    "xhttp packet upload status {}",
                    response.status()
                )));
            }
            let mut body = response.into_body();
            while let Some(data) = body.data().await {
                let data = data.map_err(crate::h2_common::h2_to_io)?;
                body.flow_control()
                    .release_capacity(data.len())
                    .map_err(crate::h2_common::h2_to_io)?;
            }
            Ok(sender)
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "xhttp packet acknowledgement timed out",
            )
        })??;
        if eof {
            return Ok(());
        }
    }
}

async fn send_packet(
    sender: &mut h2::client::SendRequest<Bytes>,
    request: http::Request<()>,
    payload: Bytes,
) -> io::Result<h2::client::ResponseFuture> {
    let (response, mut stream) = sender
        .send_request(request, payload.is_empty())
        .map_err(crate::h2_common::h2_to_io)?;
    let mut payload = payload;
    while !payload.is_empty() {
        stream.reserve_capacity(payload.len());
        let n = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "xhttp packet upload closed"))?
            .map_err(crate::h2_common::h2_to_io)?
            .min(payload.len());
        if n == 0 {
            continue;
        }
        let data = payload.split_to(n);
        stream
            .send_data(data, payload.is_empty())
            .map_err(crate::h2_common::h2_to_io)?;
    }
    Ok(response)
}

struct PacketStream {
    inner: tokio::io::DuplexStream,
    error: Arc<Mutex<Option<io::Error>>>,
    task: Option<tokio::task::JoinHandle<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<io::Result<()>>>,
}

impl PacketStream {
    fn check(&self) -> io::Result<()> {
        self.error
            .lock()
            .expect("packet error lock")
            .as_ref()
            .map_or(Ok(()), |e| Err(copy_error(e)))
    }
}
impl AsyncRead for PacketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            self.check()?;
        }
        result
    }
}
impl AsyncWrite for PacketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        let Some(completion) = &mut self.finished else {
            return Poll::Ready(Ok(()));
        };
        use std::future::Future as _;
        let result = std::task::ready!(Pin::new(completion).poll(cx));
        self.finished = None;
        Poll::Ready(result.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp packet upload worker closed",
            ))
        }))
    }
}
impl Drop for PacketStream {
    fn drop(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if tokio::time::timeout(Duration::from_secs(1), &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                }
            });
        } else {
            task.abort();
        }
    }
}
