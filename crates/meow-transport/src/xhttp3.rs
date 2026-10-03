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
    verify_name: Option<String>,
    cert_pin: Option<[u8; 32]>,
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
            sni: crate::tls::boring_backend::unbracket_ip_literal(
                tls.sni.as_deref().expect("validated"),
            )
            .into(),
            verify_name: tls
                .verify_name
                .as_deref()
                .map(|s| crate::tls::boring_backend::unbracket_ip_literal(s).into()),
            cert_pin: tls.cert_pin,
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
        let packet = self
            .config
            .effective_mode()
            .eq_ignore_ascii_case("packet-up");
        let split = packet
            || self
                .config
                .effective_mode()
                .eq_ignore_ascii_case("stream-up");
        let session = split.then(|| xhttp::generate_session(&self.config));
        let upload = headers(&xhttp::build_request(
            &self.config,
            &authority,
            self.config
                .uplink_http_method
                .parse()
                .expect("validated method"),
            session.as_deref(),
            true,
        )?)?;
        let download = if split {
            Some(headers(&xhttp::build_request(
                &self.config,
                &authority,
                http::Method::GET,
                session.as_deref(),
                false,
            )?)?)
        } else {
            None
        };
        let scid = rand::random::<[u8; quiche::MAX_CONN_ID_LEN]>();
        // Install SNI and verification independently below: quiche's
        // hostname helper seeds both fields with one name, preventing clean
        // name/IP overrides on BoringSSL.
        let mut conn = quiche::connect(
            None,
            &quiche::ConnectionId::from_ref(&scid),
            local,
            peer,
            &mut self.quic.lock().expect("QUIC config lock"),
        )
        .map_err(|e| TransportError::Xhttp(e.to_string()))?;
        let ssl: &mut boring::ssl::SslRef = conn.as_mut();
        if self.sni.parse::<std::net::IpAddr>().is_err() {
            ssl.set_hostname(&self.sni)
                .map_err(|e| TransportError::Tls(format!("QUIC SNI: {e}")))?;
        }
        if let Some(pin) = self.cert_pin {
            let name = self.verify_name.clone().unwrap_or_else(|| self.sni.clone());
            ssl.set_custom_verify_callback(boring::ssl::SslVerifyMode::PEER, move |ssl| {
                crate::tls::boring_backend::verify_cert_pin(ssl, &pin, &name)
            });
        } else {
            let name = self.verify_name.as_deref().unwrap_or(&self.sni);
            let param = ssl.param_mut();
            param.set_hostflags(boring::x509::verify::X509CheckFlags::NO_PARTIAL_WILDCARDS);
            match name.parse::<std::net::IpAddr>() {
                Ok(ip) => param.set_ip(ip),
                Err(_) => param.set_host(name),
            }
            .map_err(|e| TransportError::Tls(format!("QUIC verify name: {e}")))?;
        }
        let (app, pump) = tokio::io::duplex(BUFFER);
        let error = Arc::new(Mutex::new(None));
        let driver_error = Arc::clone(&error);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let packet_upload = packet.then(|| {
            PacketUpload::new(
                self.config.clone(),
                authority,
                session.expect("packet session"),
            )
        });
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if let Err(e) = drive(
                conn,
                socket,
                local,
                peer,
                pump,
                upload,
                download,
                ready_tx,
                packet_upload,
                finished_tx,
            )
            .await
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
            finished: packet.then_some(finished_rx),
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
    mut packet: Option<PacketUpload>,
    finished: tokio::sync::oneshot::Sender<()>,
) -> io::Result<()> {
    let (mut app_read, mut app_write) = tokio::io::split(pump);
    let mut ready = Some(ready);
    let mut finished = Some(finished);
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
            if packet.is_none() {
                upload = http
                    .send_request(&mut conn, &upload_headers, false)
                    .map_err(quic_io)?;
                if !split {
                    download = upload;
                }
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
                            let valid = if (split && id == download)
                                || (packet.is_some() && id == upload)
                            {
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
                        if let Some(packet) = &mut packet {
                            packet.ack_received = true;
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
            if packet.is_none() && up_pos < up_len {
                match http.send_body(&mut conn, upload, &up[up_pos..up_len], false) {
                    Ok(n) => up_pos += n,
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => return Err(quic_io(e)),
                }
            }
            if packet.is_none() && upload_fin && up_pos == up_len {
                match http.send_body(&mut conn, upload, &[], true) {
                    Ok(_) => {
                        upload_fin = false;
                    }
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
                    // A peer may finish its successful response and cancel
                    // further request input after consuming the final DATA,
                    // before this driver observes the application's EOF. An
                    // empty FIN then targets a stopped/collected stream. Do
                    // not turn the complete response into a read error; a
                    // pending payload write still propagates every failure.
                    Err(quiche::h3::Error::TransportError(quiche::Error::StreamStopped(0x10c))) => {
                        // STOP_SENDING may arrive before the HTTP response
                        // headers; their status/deadline is still enforced.
                        upload_fin = false;
                    }
                    Err(quiche::h3::Error::TransportError(quiche::Error::InvalidStreamState(
                        id,
                    ))) if id == upload
                        && conn.stream_finished(upload)
                        && if split {
                            got_upload_headers
                        } else {
                            got_download_headers
                        } =>
                    {
                        upload_fin = false;
                    }
                    Err(e) => return Err(quic_io(e)),
                }
            }
            if let Some(packet) = &mut packet {
                if !packet.active
                    && !packet.buffer.is_empty()
                    && (app_eof
                        || packet.buffer.len() >= packet.max
                        || packet
                            .deadline
                            .is_some_and(|d| tokio::time::Instant::now() >= d))
                {
                    let (request, body) = xhttp::build_packet_request(
                        &packet.config,
                        &packet.authority,
                        &packet.session,
                        packet.sequence,
                        &packet.buffer,
                    )
                    .map_err(quic_io)?;
                    let request_headers = headers(&request).map_err(quic_io)?;
                    match http.send_request(&mut conn, &request_headers, body.is_empty()) {
                        Ok(id) => {
                            upload = id;
                            got_upload_headers = false;
                            packet.active = true;
                            packet.ack_deadline =
                                Some(tokio::time::Instant::now() + HEADER_TIMEOUT);
                            packet.body = body;
                            packet.fin_sent = packet.body.is_empty();
                            packet.ack_received = false;
                            packet.buffer.clear();
                            packet.deadline = None;
                            packet.sequence = packet
                                .sequence
                                .checked_add(1)
                                .ok_or_else(|| quic_io("packet sequence exhausted"))?;
                        }
                        Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
                            packet.request_blocked = true;
                        }
                        Err(e) => return Err(quic_io(e)),
                    }
                }
                if packet.active && !packet.fin_sent {
                    if !packet.body.is_empty() {
                        match http.send_body(&mut conn, upload, &packet.body, false) {
                            Ok(n) => {
                                let _ = packet.body.split_to(n);
                            }
                            Err(quiche::h3::Error::StreamBlocked)
                            | Err(quiche::h3::Error::Done) => {}
                            Err(e) => return Err(quic_io(e)),
                        }
                    }
                    if packet.body.is_empty() {
                        match http.send_body(&mut conn, upload, &[], true) {
                            Ok(_) => packet.fin_sent = true,
                            Err(quiche::h3::Error::StreamBlocked)
                            | Err(quiche::h3::Error::Done) => {}
                            Err(e) => return Err(quic_io(e)),
                        }
                    }
                }
                if packet.active && packet.fin_sent && packet.ack_received {
                    packet.active = false;
                    packet.ack_deadline = None;
                }
                if app_eof && !packet.active && packet.buffer.is_empty() {
                    if let Some(tx) = finished.take() {
                        let _ = tx.send(());
                    }
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
        if download_fin
            && down_pos == down_len
            && !down_readable
            && packet
                .as_ref()
                .is_none_or(|p| app_eof && !p.active && p.buffer.is_empty())
        {
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
        let flush_wait = packet
            .as_ref()
            .filter(|p| !p.active && !p.request_blocked)
            .and_then(|p| p.deadline)
            .map(|d| d.saturating_duration_since(tokio::time::Instant::now()));
        let ack_wait = packet
            .as_ref()
            .and_then(|p| p.ack_deadline)
            .map(|d| d.saturating_duration_since(tokio::time::Instant::now()));
        let read_limit = packet
            .as_ref()
            .map_or(CHUNK, |p| CHUNK.min(p.max - p.buffer.len()));
        tokio::select! {
            n = socket.recv(&mut incoming) => {
                let n = n?;
                if let Some(packet) = &mut packet { packet.request_blocked = false; }
                if n > incoming.len() { return Err(quic_io("oversized datagram")); }
                match conn.recv(&mut incoming[..n], quiche::RecvInfo { from: peer, to: local }) {
                    Ok(_) | Err(quiche::Error::Done) | Err(quiche::Error::InvalidPacket) => {},
                    Err(e) => return Err(quic_io(e)),
                }
            }
            n = app_read.read(&mut up[..read_limit]), if h3.is_some() && (packet.is_some() || up_pos == up_len) && !app_eof && read_limit > 0 => {
                let n = n?;
                if let Some(packet) = &mut packet {
                    if n == 0 { app_eof = true; }
                    else {
                        if packet.buffer.is_empty() {
                            use rand::Rng as _;
                            let delay = rand::rng().random_range(packet.config.sc_min_posts_interval_ms.0..=packet.config.sc_min_posts_interval_ms.1);
                            packet.deadline = Some(tokio::time::Instant::now() + Duration::from_millis(delay as u64));
                        }
                        packet.buffer.reserve_exact(n);
                        packet.buffer.extend_from_slice(&up[..n]);
                    }
                } else {
                    up_pos = 0; up_len = n;
                    if n == 0 { upload_fin = true; app_eof = true; }
                }
            }
            _ = tokio::time::sleep(flush_wait.unwrap_or(Duration::from_secs(86400))), if flush_wait.is_some() => {},
            _ = tokio::time::sleep(ack_wait.unwrap_or(Duration::from_secs(86400))), if ack_wait.is_some() => return Err(quic_io("packet acknowledgement timed out")),
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

struct PacketUpload {
    config: XhttpConfig,
    authority: String,
    session: String,
    max: usize,
    buffer: Vec<u8>,
    body: bytes::Bytes,
    sequence: u64,
    active: bool,
    fin_sent: bool,
    ack_received: bool,
    request_blocked: bool,
    deadline: Option<tokio::time::Instant>,
    ack_deadline: Option<tokio::time::Instant>,
}
impl PacketUpload {
    fn new(config: XhttpConfig, authority: String, session: String) -> Self {
        use rand::Rng as _;
        let max = rand::rng()
            .random_range(config.sc_max_each_post_bytes.0..=config.sc_max_each_post_bytes.1);
        let max = if matches!(config.uplink_data_placement.as_str(), "header" | "cookie") {
            max.min(8 * 1024)
        } else {
            max
        };
        Self {
            config,
            authority,
            session,
            max,
            buffer: Vec::new(),
            body: bytes::Bytes::new(),
            sequence: 0,
            active: false,
            fin_sent: false,
            ack_received: false,
            request_blocked: false,
            deadline: None,
            ack_deadline: None,
        }
    }
}

struct H3Stream {
    inner: tokio::io::DuplexStream,
    error: Arc<Mutex<Option<io::Error>>>,
    task: Option<tokio::task::JoinHandle<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<()>>,
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
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        let Some(finished) = &mut self.finished else {
            return Poll::Ready(Ok(()));
        };
        use std::future::Future as _;
        let result = std::task::ready!(Pin::new(finished).poll(cx));
        self.finished = None;
        self.check()?;
        Poll::Ready(result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP/3 packet upload worker closed",
            )
        }))
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
