//! XHTTP (SplitHTTP) transport layer (`xhttp` feature).
//!
//! Tunnels bidirectional streams over HTTP/2 using the Xray-core / mihomo
//! `splithttp` (XHTTP) protocol in all three upload modes.
//!
//! upstream: transport/internet/splithttp/dialer.go

use std::time::Duration;

mod browser;
mod client;
pub use client::{ConnectionFactory, XhttpClient, XhttpEndpoint};
mod packet;
mod request;
mod reuse;
pub use reuse::ReuseConfig;

use async_trait::async_trait;
use rand::seq::IndexedRandom as _;
use rand::Rng as _;

use crate::h2_common::{H2Stream, RecvState};
use crate::{Result, Stream, Transport, TransportError};

/// Timeout for acquiring send readiness (`h2.ready()`) during `connect`.
/// Mirrors H2Layer and h2mux's `OPEN_TIMEOUT` (5 s).
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for `x-padding-bytes` — padding becomes a header `String` on
/// every connect, so an unbounded value is
/// a remotely-configurable allocation (a provider/subscription node could
/// request exabytes and abort the process at the first health check or dial).
/// 64 KiB is far beyond any real deployment (Xray ships 100–1000) while still
/// admitting every sane configuration (issue #648).
/// Tokenish measures HPACK encoded bytes and needs at most `ceil(max * 8 / 5)`
/// raw characters; repeat-X needs exactly `max` characters.
///
/// Enforced twice, deliberately: `parse_vless_xhttp_config` rejects at config
/// load (fail-fast, per-node vocabulary) and `validate_config` re-checks at
/// `connect()` (backstop for programmatic `XhttpConfig` construction).
pub const MAX_X_PADDING_BYTES: usize = 64 * 1024;

/// Bound the per-tunnel upload accumulator before allocating it.
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;

/// Same remotely-configurable memory concern as [`MAX_X_PADDING_BYTES`],
/// much smaller blast radius. Enforced at both layers like the padding cap
/// (issue #648). Defined at the crate root because `httpupgrade` shares the
/// bound and the two features compile independently.
pub use crate::MAX_EXTRA_HEADERS;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the XHTTP transport layer.
///
/// upstream: `xhttp-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct XhttpConfig {
    /// The `:path` pseudo-header sent with every request.
    ///
    /// upstream: `xhttp-opts.path`; default `"/"`.
    pub path: String,

    /// Candidate `:authority` values. One is chosen uniformly at random per
    /// connection. The config layer resolves an omitted host from the effective
    /// TLS/REALITY server name and then the dial host.
    ///
    /// upstream: `xhttp-opts.host`.
    pub hosts: Vec<String>,

    /// HTTP scheme used for the `:scheme` pseudo-header and generated Referer.
    /// The config layer sets this to `https` when TLS/REALITY wraps XHTTP and
    /// to `http` for h2c.
    pub scheme: String,

    /// Extra custom HTTP headers sent with the request.
    /// Bounded to [`MAX_EXTRA_HEADERS`] entries — `connect()` rejects more.
    ///
    /// upstream: `xhttp-opts.headers`.
    pub extra_headers: Vec<(String, String)>,

    /// XHTTP mode: `auto`, `stream-one`, `stream-up`, or `packet-up`.
    ///
    /// upstream: `xhttp-opts.mode`.
    pub mode: String,

    /// Set by the TLS caller; auto chooses stream-one with REALITY.
    pub has_reality: bool,

    /// Upload HTTP method, default POST (including packet-up).
    pub uplink_http_method: String,
    /// Packet sequence placement: path, query, header, or cookie.
    pub seq_placement: String,
    /// Empty selects X-Seq for headers or x_seq for query/cookie.
    pub seq_key: String,
    /// Packet payload placement: body/auto, header, or cookie.
    pub uplink_data_placement: String,
    /// Prefix for header/cookie payload chunks.
    pub uplink_data_key: String,
    /// Encoded payload chunk range; (0, 0) selects placement defaults.
    pub uplink_chunk_size: (usize, usize),
    /// Maximum packet body size, selected once per tunnel.
    pub sc_max_each_post_bytes: (usize, usize),
    /// Random delay before flushing a packet, in milliseconds.
    pub sc_min_posts_interval_ms: (usize, usize),

    /// If true, suppress setting the `Content-Type: application/grpc` header.
    /// Default is `false` (the header is set by default per Xray-core spec).
    ///
    /// upstream: `xhttp-opts.no-grpc-header`.
    pub no_grpc_header: bool,

    /// Range for random padding bytes `(min, max)`. Tokenish measures HPACK
    /// encoded bytes; repeat-X measures raw characters. With obfuscation off,
    /// padding is sent in a Referer query that replaces any original query
    /// with `x_padding=<padding>`, matching Xray's `queryInHeader` placement.
    ///
    /// upstream: `xhttp-opts.x-padding-bytes`; default `Some((100, 1000))`.
    /// `max` must not exceed [`MAX_X_PADDING_BYTES`].
    pub x_padding_bytes: Option<(usize, usize)>,

    /// Enable the configurable padding placement and method (mihomo schema).
    pub x_padding_obfs_mode: bool,
    /// `repeat-x` (or empty for the default) and `tokenish` are supported.
    pub x_padding_method: String,
    /// `header`, `queryInHeader`, `query`, `cookie`, or empty (disabled).
    pub x_padding_placement: String,
    /// Header carrying obfuscated padding; required for a header placement.
    pub x_padding_header: String,
    /// Query key for `queryInHeader` obfuscated padding.
    pub x_padding_key: String,
    /// Session placement: `path` (default), `header`, `query`, or `cookie`.
    pub session_placement: String,
    /// Header name for a header session; empty selects upstream's `X-Session`.
    pub session_key: String,
    /// Empty: 32 lowercase hex characters; uuid, predefined/custom ASCII tables.
    pub session_table: String,
    /// Random table ID length, bounded to 128 characters.
    pub session_length: (usize, usize),
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            hosts: vec!["localhost".into()],
            scheme: "https".into(),
            extra_headers: Vec::new(),
            mode: "auto".into(),
            has_reality: false,
            uplink_http_method: "POST".into(),
            seq_placement: "path".into(),
            seq_key: String::new(),
            uplink_data_placement: "body".into(),
            uplink_data_key: String::new(),
            uplink_chunk_size: (0, 0),
            sc_max_each_post_bytes: (1_000_000, 1_000_000),
            sc_min_posts_interval_ms: (30, 30),
            no_grpc_header: false,
            x_padding_bytes: Some((100, 1000)),
            x_padding_obfs_mode: false,
            x_padding_method: String::new(),
            x_padding_placement: String::new(),
            x_padding_header: String::new(),
            x_padding_key: String::new(),
            session_placement: "path".into(),
            session_key: String::new(),
            session_table: String::new(),
            session_length: (16, 32),
        }
    }
}

impl XhttpConfig {
    /// Resolve auto using the same TLS-dependent selection as mihomo.
    pub fn effective_mode(&self) -> &str {
        if self.mode.is_empty() || self.mode.eq_ignore_ascii_case("auto") {
            if self.has_reality {
                "stream-one"
            } else {
                "packet-up"
            }
        } else {
            &self.mode
        }
    }

    /// Validate both parsed YAML and programmatically constructed options.
    pub fn validate(&self) -> Result<()> {
        validate_config(self)
    }
}

// A cancelled connect must not detach a connection driver and pin its socket.
struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

// ─── XhttpLayer ───────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with an XHTTP tunnel.
pub struct XhttpLayer {
    config: XhttpConfig,
}

impl XhttpLayer {
    /// Create an `XhttpLayer` from the given configuration.
    pub fn new(config: XhttpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for XhttpLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        validate_config(&self.config)?;
        let (h2, conn) = crate::h2_common::client_builder()
            .handshake::<_, bytes::Bytes>(inner)
            .await
            .map_err(|e| crate::h2_common::h2_to_transport(e, TransportError::Xhttp))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        connect_http2(self.config.clone(), h2, None, Some(driver), Vec::new()).await
    }
}

pub(super) type SharedOwner = std::sync::Arc<dyn Send + Sync>;
/// Established HTTP connections can be shared across independently leased tunnels.
pub(super) async fn connect_http2(
    mut config: XhttpConfig,
    h2: h2::client::SendRequest<bytes::Bytes>,
    mut download: Option<(XhttpConfig, h2::client::SendRequest<bytes::Bytes>)>,
    driver: Option<tokio::task::JoinHandle<()>>,
    owners: Vec<SharedOwner>,
) -> Result<Box<dyn Stream>> {
    let mut guard = AbortOnDrop(driver.as_ref().map(tokio::task::JoinHandle::abort_handle));
    if download.is_some()
        && (config.mode.is_empty() || config.mode.eq_ignore_ascii_case("auto"))
        && config.has_reality
    {
        config.mode = "stream-up".into();
    }
    if let Some((cfg, _)) = &download {
        validate_config(cfg)?;
        if config.effective_mode().eq_ignore_ascii_case("stream-one") {
            return Err(TransportError::Config(
                "xhttp: stream-one cannot use download-settings".into(),
            ));
        }
    }
    validate_config(&config)?;

    let host = config
        .hosts
        .choose(&mut rand::rng())
        .cloned()
        .unwrap_or_else(|| "localhost".to_string());
    let authority = format_authority(&host);
    let packet = config.effective_mode().eq_ignore_ascii_case("packet-up");
    let split = packet || config.effective_mode().eq_ignore_ascii_case("stream-up");
    let session = split.then(|| generate_session(&config));
    let upload = build_request(
        &config,
        &authority,
        config.uplink_http_method.parse().expect("validated method"),
        session.as_deref(),
        true,
    )?;
    let download_request = if split {
        let (download_config, download_authority) = download.as_ref().map_or_else(
            || (&config, authority.clone()),
            |(cfg, _)| {
                (
                    cfg,
                    format_authority(
                        cfg.hosts
                            .choose(&mut rand::rng())
                            .expect("validated download host"),
                    ),
                )
            },
        );
        Some(build_request(
            download_config,
            &download_authority,
            http::Method::GET,
            session.as_deref(),
            false,
        )?)
    } else {
        None
    };

    let mut h2 = ready(h2).await?;

    // Queue GET first so the server creates the session before POST DATA.
    // Neither response is awaited here: CDN buffering / peers waiting for
    // the first upload byte must not deadlock the VLESS header write.
    let download_response = if let Some(request) = download_request {
        let sender = if let Some((_, sender)) = download.take() {
            ready(sender).await?
        } else {
            h2.clone()
        };
        let mut sender = ready(sender).await?;
        let (response, _) = sender
            .send_request(request, true)
            .map_err(|e| crate::h2_common::h2_to_transport(e, TransportError::Xhttp))?;
        h2 = ready(h2).await?;
        Some(response)
    } else {
        None
    };
    if packet {
        let stream = packet::connect(
            config.clone(),
            authority,
            session.expect("packet session"),
            h2,
            download_response.expect("packet download"),
            driver,
            owners.clone(),
        );
        guard.0 = None;
        return Ok(stream);
    }
    let (upload_response, send_stream) = h2
        .send_request(upload, false)
        .map_err(|e| crate::h2_common::h2_to_transport(e, TransportError::Xhttp))?;
    let stream = if let Some(download_response) = download_response {
        H2Stream::new(
            send_stream,
            RecvState::with_timeout(
                download_response,
                Duration::from_secs(15),
                crate::h2_common::StatusPolicy::Exact(http::StatusCode::OK),
                "xhttp download",
            ),
        )
        .with_auxiliary_recv(RecvState::new(upload_response))
    } else {
        H2Stream::new(
            send_stream,
            RecvState::with_timeout(
                upload_response,
                Duration::from_secs(15),
                crate::h2_common::StatusPolicy::Success,
                "xhttp",
            ),
        )
    };
    guard.0 = None;
    let stream = if let Some(driver) = driver {
        stream.with_conn_driver(driver)
    } else {
        stream
    };
    Ok(Box::new(HeldStream {
        inner: Box::new(stream),
        _owners: owners,
    }))
}

async fn ready(
    h2: h2::client::SendRequest<bytes::Bytes>,
) -> Result<h2::client::SendRequest<bytes::Bytes>> {
    match tokio::time::timeout(OPEN_TIMEOUT, h2.ready()).await {
        Ok(Ok(h2)) => Ok(h2),
        Ok(Err(error)) => Err(crate::h2_common::h2_to_transport(
            error,
            TransportError::Xhttp,
        )),
        Err(_) => Err(TransportError::Xhttp(
            "timed out waiting for send readiness (open)".into(),
        )),
    }
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn random_token(table: &[u8], length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from(table[rng.random_range(0..table.len())]))
        .collect()
}

pub(crate) fn generate_session(config: &XhttpConfig) -> String {
    if config.session_table.is_empty() {
        return random_token(b"0123456789abcdef", 32);
    }
    if config.session_table == "uuid" {
        let mut bytes = rand::random::<[u8; 16]>();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let mut id = String::with_capacity(36);
        use std::fmt::Write as _;
        for (i, byte) in bytes.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                id.push('-');
            }
            let _ = write!(id, "{byte:02x}");
        }
        return id;
    }
    random_token(
        request::session_alphabet(&config.session_table),
        rand::rng().random_range(config.session_length.0..=config.session_length.1),
    )
}

// RFC 7541 Appendix B: HPACK code lengths for the Base62 alphabet. Tokenish
// padding measures encoded bytes rather than raw characters, as in mihomo.
fn base62_huffman_bits(byte: u8) -> usize {
    match byte {
        b'0'..=b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'X' | b'Z' => 8,
        _ => 7,
    }
}

fn generate_padding(method: &str, length: usize) -> String {
    if method != "tokenish" {
        return "X".repeat(length);
    }
    let mut rng = rand::rng();
    // Every character has at least five encoded bits. No unbounded string
    // growth or per-byte allocations, including at the configured cap.
    let mut padding = String::with_capacity((length * 8).div_ceil(5));
    let mut bits: usize = 0;
    while bits.div_ceil(8) < length {
        let byte = BASE62[rng.random_range(0..BASE62.len())];
        bits += base62_huffman_bits(byte);
        padding.push(char::from(byte));
    }
    padding
}

pub(crate) use request::{build_packet_request, build_request};

fn validate_config(config: &XhttpConfig) -> Result<()> {
    validate_path(&config.path)?;
    if config.hosts.is_empty() {
        return Err(TransportError::Config(
            "xhttp: hosts must not be empty".into(),
        ));
    }
    for host in &config.hosts {
        validate_host(host)?;
    }
    // Structural bound before the per-entry scan — an oversized list bails
    // without paying the O(n) byte checks first.
    if config.extra_headers.len() > MAX_EXTRA_HEADERS {
        return Err(TransportError::Config(format!(
            "xhttp: too many extra headers ({}, max {MAX_EXTRA_HEADERS})",
            config.extra_headers.len()
        )));
    }
    for (name, value) in &config.extra_headers {
        validate_header_name(name)?;
        validate_header_value(name, value)?;
    }
    request::validate_options(config)?;
    validate_scheme(&config.scheme)?;
    if let Some((min, max)) = config.x_padding_bytes {
        if min > max {
            return Err(TransportError::Config(format!(
                "xhttp: invalid x_padding_bytes: min ({min}) cannot exceed max ({max})"
            )));
        }
        if max > MAX_X_PADDING_BYTES {
            return Err(TransportError::Config(format!(
                "xhttp: x_padding_bytes max ({max}) exceeds {MAX_X_PADDING_BYTES}"
            )));
        }
    }
    Ok(())
}

fn validate_scheme(scheme: &str) -> Result<()> {
    if matches!(scheme, "http" | "https") {
        Ok(())
    } else {
        Err(TransportError::Config(format!(
            "xhttp: unsupported scheme {scheme:?}; expected 'http' or 'https'"
        )))
    }
}

pub(crate) fn format_authority(host: &str) -> String {
    if host.starts_with('[') || !host.contains(':') {
        host.to_string()
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn validate_path(path: &str) -> Result<()> {
    if path.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "xhttp: path contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(TransportError::Config(
            "xhttp: host contains whitespace or control bytes".into(),
        ));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(is_header_token_byte) {
        return Err(TransportError::Config(format!(
            "xhttp: invalid extra header name {name:?}"
        )));
    }
    Ok(())
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(TransportError::Config(format!(
            "xhttp: invalid value for extra header {name:?}"
        )));
    }
    Ok(())
}

fn is_header_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

struct HeldStream {
    inner: Box<dyn Stream>,
    _owners: Vec<SharedOwner>,
}
impl tokio::io::AsyncRead for HeldStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for HeldStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenish_padding_is_bounded_at_encoded_byte_target() {
        for length in [0, 1, 128, 512, MAX_X_PADDING_BYTES] {
            let padding = generate_padding("tokenish", length);
            assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            let bits: usize = padding.bytes().map(base62_huffman_bits).sum();
            assert_eq!(bits.div_ceil(8), length);
            assert!(padding.len() <= (length * 8).div_ceil(5));
        }
    }

    #[test]
    fn session_ids_are_fresh_and_padding_does_not_replace_session() {
        let config = XhttpConfig {
            mode: "stream-up".into(),
            session_placement: "header".into(),
            session_table: "Base62".into(),
            x_padding_obfs_mode: true,
            x_padding_placement: "header".into(),
            x_padding_header: "X-Session".into(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        let config = XhttpConfig {
            x_padding_header: "X-Padding".into(),
            ..config
        };
        assert!(config.validate().is_ok());
        let ids: std::collections::HashSet<_> =
            (0..64).map(|_| generate_session(&config)).collect();
        assert_eq!(ids.len(), 64);
    }

    #[test]
    fn default_config_valid() {
        let config = XhttpConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn invalid_path() {
        let config = XhttpConfig {
            path: "/bad\npath".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            path: "/has\ncontrol".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn empty_hosts_rejected() {
        let config = XhttpConfig {
            hosts: vec![],
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn invalid_mode() {
        for mode in ["invalid", "stream-two"] {
            let config = XhttpConfig {
                mode: mode.into(),
                ..Default::default()
            };
            assert!(validate_config(&config).is_err(), "mode {mode:?}");
        }

        let config = XhttpConfig {
            mode: "stream-one".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validates_scheme_and_formats_ipv6_authority() {
        let config = XhttpConfig {
            scheme: "ftp".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
        assert_eq!(format_authority("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(format_authority("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(format_authority("example.com"), "example.com");
    }

    #[test]
    fn invalid_padding_range() {
        let config = XhttpConfig {
            x_padding_bytes: Some((500, 100)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            x_padding_bytes: Some((100, 500)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());
    }
    #[test]
    fn padding_and_header_count_bounded() {
        // An over-cap padding range is a remotely-configurable allocation
        // (issue #648) — reject at validation, before `connect` allocates.
        let config = XhttpConfig {
            x_padding_bytes: Some((0, MAX_X_PADDING_BYTES + 1)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            x_padding_bytes: Some((0, MAX_X_PADDING_BYTES)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());

        // Inverted and disable ranges.
        let config = XhttpConfig {
            x_padding_bytes: Some((200, 100)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
        let config = XhttpConfig {
            x_padding_bytes: Some((0, 0)),
            ..Default::default()
        };
        assert!(validate_config(&config).is_ok());

        let config = XhttpConfig {
            extra_headers: (0..=MAX_EXTRA_HEADERS)
                .map(|i| (format!("X-H{i}"), "v".into()))
                .collect(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn invalid_headers() {
        let mut config = XhttpConfig::default();
        config.extra_headers.push(("Bad:Name".into(), "val".into()));
        assert!(validate_config(&config).is_err());

        config.extra_headers.clear();
        config
            .extra_headers
            .push(("Good-Name".into(), "val\r\nbad".into()));
        assert!(validate_config(&config).is_err());

        config.extra_headers.clear();
        config
            .extra_headers
            .push(("Good-Name".into(), "good-value".into()));
        assert!(validate_config(&config).is_ok());
    }
}
