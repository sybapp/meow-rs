//! XHTTP over HTTP/3. The caller supplies a protected/proxied UDP association;
//! this leaf crate owns only QUIC, HTTP framing and bounded stream buffers.
use crate::{
    tls::TlsConfig,
    xhttp::{self, XhttpConfig},
    Result, Stream, TransportError,
};
use async_trait::async_trait;
use rand::seq::IndexedRandom as _;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const BUFFER: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// A connected UDP association. Receive must accept only the selected peer.
/// Implementations keep route selection and platform socket protection outside
/// the transport leaf; both futures must be cancellation safe.
#[async_trait]
pub trait Datagram: Send + Sync {
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize>;
}

/// Prepared HTTP/3 transport. TLS context creation happens once at config load.
pub struct Xhttp3Client {
    config: XhttpConfig,
    sni: String,
    quic: Mutex<quiche::Config>,
}

impl Xhttp3Client {
    pub fn new(config: XhttpConfig, tls: &TlsConfig) -> Result<Self> {
        config.validate()?;
        if config.scheme != "https" {
            return Err(TransportError::Config("XHTTP/3 requires TLS".into()));
        }
        let quic = crate::tls::xhttp3_config(tls)?;
        Ok(Self {
            config,
            sni: tls.sni.clone().expect("validated"),
            quic: Mutex::new(quic),
        })
    }

    /// Open one bounded duplex tunnel on a fresh QUIC connection.
    pub async fn connect(
        &self,
        socket: Arc<dyn Datagram>,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<Box<dyn Stream>> {
        let host = self
            .config
            .hosts
            .choose(&mut rand::rng())
            .expect("validated");
        let authority = xhttp::format_authority(host);
        let split = self.config.mode.eq_ignore_ascii_case("stream-up");
        let session = split.then(|| xhttp::generate_session(&self.config));
        let upload = headers(&xhttp::build_request(
            &self.config,
            &authority,
            http::Method::POST,
            session.as_deref(),
        )?)?;
        let download = if split {
            Some(headers(&xhttp::build_request(
                &self.config,
                &authority,
                http::Method::GET,
                session.as_deref(),
            )?)?)
        } else {
            None
        };
        let scid = rand::random::<[u8; quiche::MAX_CONN_ID_LEN]>();
        let conn = quiche::connect(
            Some(&self.sni),
            &quiche::ConnectionId::from_ref(&scid),
            local,
            peer,
            &mut self.quic.lock().expect("QUIC config lock"),
        )
        .map_err(|e| TransportError::Xhttp(e.to_string()))?;
        let (app, pump) = tokio::io::duplex(BUFFER);
        let error = Arc::new(Mutex::new(None));
        let driver_error = Arc::clone(&error);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if let Err(e) = drive(conn, socket, local, peer, pump, upload, download, ready_tx).await
            {
                *driver_error.lock().expect("driver error lock") = Some(e);
            }
        });
        let mut guard = AbortGuard(Some(task.abort_handle()));
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| TransportError::Xhttp("QUIC handshake timed out".into()))?
            .map_err(|_| {
                TransportError::Io(
                    error
                        .lock()
                        .expect("error lock")
                        .take()
                        .unwrap_or_else(|| io::Error::other("QUIC handshake closed")),
                )
            })?;
        guard.0.take();
        Ok(Box::new(H3Stream {
            inner: app,
            error,
            task: Some(task),
        }))
    }
}

struct AbortGuard(Option<tokio::task::AbortHandle>);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

fn headers(request: &http::Request<()>) -> Result<Vec<quiche::h3::Header>> {
    let uri = request.uri();
    let mut out = vec![
        quiche::h3::Header::new(b":method", request.method().as_str().as_bytes()),
        quiche::h3::Header::new(b":scheme", uri.scheme_str().unwrap_or("https").as_bytes()),
        quiche::h3::Header::new(
            b":authority",
            uri.authority().expect("absolute URI").as_str().as_bytes(),
        ),
        quiche::h3::Header::new(
            b":path",
            uri.path_and_query()
                .expect("request path")
                .as_str()
                .as_bytes(),
        ),
    ];
    for (name, value) in request.headers() {
        if matches!(
            name.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        ) || (name == "te" && value.as_bytes() != b"trailers")
        {
            return Err(TransportError::Config(format!(
                "XHTTP/3 forbids header {name}"
            )));
        }
        out.push(quiche::h3::Header::new(
            name.as_str().as_bytes(),
            value.as_bytes(),
        ));
    }
    Ok(out)
}

fn quic_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("XHTTP/3: {e}"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one connection driver owns its IO and both request streams"
)]
async fn drive(
    mut conn: quiche::Connection,
    socket: Arc<dyn Datagram>,
    local: SocketAddr,
    peer: SocketAddr,
    pump: tokio::io::DuplexStream,
    upload_headers: Vec<quiche::h3::Header>,
    download_headers: Option<Vec<quiche::h3::Header>>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> io::Result<()> {
    let (mut app_read, mut app_write) = tokio::io::split(pump);
    let mut ready = Some(ready);
    let mut keepalive = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut h3 = None;
    let mut upload = 0;
    let mut download = 0;
    let split = download_headers.is_some();
    let mut got_download_headers = false;
    let mut got_upload_headers = false;
    let mut header_deadline = None;
    let mut upload_fin = false;
    let mut app_eof = false;
    let mut download_fin = false;
    let mut down_readable = false;
    let mut up = [0u8; CHUNK];
    let mut up_len = 0;
    let mut up_pos = 0;
    let mut down = [0u8; CHUNK];
    let mut down_len = 0;
    let mut down_pos = 0;
    let mut incoming = [0u8; 1500];
    let mut outgoing = [0u8; 1500];
    loop {
        if conn.is_closed() {
            return Err(quic_io("QUIC connection closed"));
        }
        if conn.is_established() && h3.is_none() {
            let mut cfg = quiche::h3::Config::new().map_err(quic_io)?;
            cfg.set_max_field_section_size(16 * 1024);
            let mut http =
                quiche::h3::Connection::with_transport(&mut conn, &cfg).map_err(quic_io)?;
            if let Some(ref headers) = download_headers {
                download = http
                    .send_request(&mut conn, headers, true)
                    .map_err(quic_io)?;
            }
            upload = http
                .send_request(&mut conn, &upload_headers, false)
                .map_err(quic_io)?;
            if !split {
                download = upload;
            }
            header_deadline = Some(tokio::time::Instant::now() + HEADER_TIMEOUT);
            h3 = Some(http);
            if ready.take().expect("ready once").send(()).is_err() {
                return Ok(());
            }
            // Request HEADERS flush below before waiting for application data.
        }
        if let Some(http) = h3.as_mut() {
            use quiche::h3::NameValue;
            loop {
                match http.poll(&mut conn) {
                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                        // Subsequent headers are trailers, never a replacement
                        // for the initial status (including informational 1xx).
                        let seen = if id == download {
                            &mut got_download_headers
                        } else if split && id == upload {
                            &mut got_upload_headers
                        } else {
                            return Err(quic_io("unexpected HTTP/3 stream"));
                        };
                        if !*seen {
                            let mut status = list.iter().filter(|h| h.name() == b":status");
                            let value = status
                                .next()
                                .ok_or_else(|| quic_io("missing response status"))?
                                .value();
                            if status.next().is_some() {
                                return Err(quic_io("duplicate response status"));
                            }
                            let code = std::str::from_utf8(value)
                                .ok()
                                .and_then(|s| s.parse::<u16>().ok())
                                .ok_or_else(|| quic_io("invalid response status"))?;
                            let valid = if split && id == download {
                                code == 200
                            } else {
                                (200..300).contains(&code)
                            };
                            if !valid {
                                return Err(quic_io(format!("response status {code}")));
                            }
                            *seen = true;
                        }
                    }
                    Ok((id, quiche::h3::Event::Data)) if id == download => down_readable = true,
                    Ok((id, quiche::h3::Event::Data)) if split && id == upload => {
                        // Discard upload acknowledgements without retaining body.
                        let mut scratch = [0u8; CHUNK];
                        loop {
                            match http.recv_body(&mut conn, id, &mut scratch) {
                                Ok(_) => {}
                                Err(quiche::h3::Error::Done) => break,
                                Err(e) => return Err(quic_io(e)),
                            }
                        }
                    }
                    Ok((id, quiche::h3::Event::Finished)) if id == download => download_fin = true,
                    Ok((id, quiche::h3::Event::Finished)) if split && id == upload => {
                        if !got_upload_headers {
                            return Err(quic_io("upload ended without response headers"));
                        }
                    }
                    Ok((_, quiche::h3::Event::Reset(code))) => {
                        return Err(quic_io(format!("stream reset {code}")))
                    }
                    Ok((_, quiche::h3::Event::GoAway)) => return Err(quic_io("server GOAWAY")),
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(quic_io(e)),
                }
            }
            if up_pos < up_len {
                match http.send_body(&mut conn, upload, &up[up_pos..up_len], false) {
                    Ok(n) => up_pos += n,
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => return Err(quic_io(e)),
                }
            }
            if upload_fin && up_pos == up_len {
                match http.send_body(&mut conn, upload, &[], true) {
                    Ok(_) => {
                        upload_fin = false;
                    }
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => return Err(quic_io(e)),
                }
            }
            if down_readable && down_pos == down_len {
                match http.recv_body(&mut conn, download, &mut down) {
                    Ok(n) => {
                        down_pos = 0;
                        down_len = n;
                    }
                    Err(quiche::h3::Error::Done) => down_readable = false,
                    Err(e) => return Err(quic_io(e)),
                }
            }
        }
        if download_fin && down_pos == down_len && !down_readable {
            if !got_download_headers {
                return Err(quic_io("download ended without response headers"));
            }
            app_write.shutdown().await?;
            let _ = conn.close(true, 0x100, b"");
            while let Ok((n, _)) = conn.send(&mut outgoing) {
                let _ = socket.send(&outgoing[..n]).await;
            }
            return Ok(());
        }
        // Flush datagrams before waiting, including retransmissions/ACKs.
        loop {
            match conn.send(&mut outgoing) {
                Ok((n, info)) => {
                    // Honor quiche pacing rather than sending a burst.
                    tokio::time::sleep_until(info.at.into()).await;
                    socket.send(&outgoing[..n]).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(quic_io(e)),
            }
        }
        let timeout = conn.timeout().unwrap_or(Duration::from_secs(30));
        let header_wait = header_deadline
            .filter(|_| !got_download_headers)
            .map_or(Duration::from_secs(86400), |d| {
                d.saturating_duration_since(tokio::time::Instant::now())
            });
        tokio::select! {
            n = socket.recv(&mut incoming) => {
                let n = n?;
                if n > incoming.len() { return Err(quic_io("oversized datagram")); }
                match conn.recv(&mut incoming[..n], quiche::RecvInfo { from: peer, to: local }) {
                    Ok(_) | Err(quiche::Error::Done) | Err(quiche::Error::InvalidPacket) => {},
                    Err(e) => return Err(quic_io(e)),
                }
            }
            n = app_read.read(&mut up), if h3.is_some() && up_pos == up_len && !app_eof => {
                let n = n?; up_pos = 0; up_len = n;
                if n == 0 { upload_fin = true; app_eof = true; }
            }
            n = app_write.write(&down[down_pos..down_len]), if down_pos < down_len => {
                down_pos += n?;
            }
            _ = keepalive.tick(), if h3.is_some() => {
                match conn.send_ack_eliciting() {
                    Ok(()) | Err(quiche::Error::Done) => {},
                    Err(e) => return Err(quic_io(e)),
                }
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
            _ = tokio::time::sleep(header_wait), if !got_download_headers && header_deadline.is_some() => return Err(quic_io("response headers timed out")),
        }
    }
}

struct H3Stream {
    inner: tokio::io::DuplexStream,
    error: Arc<Mutex<Option<io::Error>>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl H3Stream {
    fn check(&self) -> io::Result<()> {
        match self.error.lock().expect("error lock").as_ref() {
            Some(e) => Err(io::Error::new(e.kind(), e.to_string())),
            None => Ok(()),
        }
    }
}
impl AsyncRead for H3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check() {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            if let Err(e) = self.check() {
                return Poll::Ready(Err(e));
            }
        }
        result
    }
}
impl AsyncWrite for H3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl Drop for H3Stream {
    fn drop(&mut self) {
        if let Some(mut task) = self.task.take() {
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
}
