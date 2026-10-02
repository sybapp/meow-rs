//! XHTTP (SplitHTTP) transport layer (`xhttp` feature).
//!
//! Tunnels bidirectional streams over HTTP/2 using the Xray-core / mihomo
//! `splithttp` (XHTTP) protocol in `stream-one` and `stream-up` modes.
//!
//! upstream: transport/internet/splithttp/dialer.go

use std::time::Duration;

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

    /// XHTTP mode: `stream-one` or `stream-up`.
    ///
    /// upstream: `xhttp-opts.mode`.
    pub mode: String,

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
    /// `header`, `queryInHeader`, or empty (no obfuscated padding).
    pub x_padding_placement: String,
    /// Header carrying obfuscated padding; required for a header placement.
    pub x_padding_header: String,
    /// Query key for `queryInHeader` obfuscated padding.
    pub x_padding_key: String,
    /// Session ID placement: `path` (default) or `header`.
    pub session_placement: String,
    /// Header name for a header session; empty selects upstream's `X-Session`.
    pub session_key: String,
    /// Empty selects a 32-character hex ID; `Base62` selects a random token.
    pub session_table: String,
    /// Random Base62 ID length, bounded to 128 characters.
    pub session_length: (usize, usize),
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            hosts: vec!["localhost".into()],
            scheme: "https".into(),
            extra_headers: Vec::new(),
            mode: "stream-one".into(),
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

        let host = self
            .config
            .hosts
            .choose(&mut rand::rng())
            .cloned()
            .unwrap_or_else(|| "localhost".to_string());
        let authority = format_authority(&host);
        let split = self.config.mode.eq_ignore_ascii_case("stream-up");
        let session = split.then(|| generate_session(&self.config));
        let upload = build_request(
            &self.config,
            &authority,
            http::Method::POST,
            session.as_deref(),
        )?;
        let download = if split {
            Some(build_request(
                &self.config,
                &authority,
                http::Method::GET,
                session.as_deref(),
            )?)
        } else {
            None
        };

        // Proxy-sized receive windows — see `h2_common::client_builder`.
        let (mut h2, conn) = crate::h2_common::client_builder()
            .handshake::<_, bytes::Bytes>(inner)
            .await
            .map_err(|e| crate::h2_common::h2_to_transport(e, TransportError::Xhttp))?;

        let driver_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut guard = AbortOnDrop(Some(driver_task.abort_handle()));
        h2 = ready(h2).await?;

        // Queue GET first so the server creates the session before POST DATA.
        // Neither response is awaited here: CDN buffering / peers waiting for
        // the first upload byte must not deadlock the VLESS header write.
        let download_response = if let Some(request) = download {
            let (response, _) = h2
                .send_request(request, true)
                .map_err(|e| crate::h2_common::h2_to_transport(e, TransportError::Xhttp))?;
            h2 = ready(h2).await?;
            Some(response)
        } else {
            None
        };
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
        Ok(Box::new(stream.with_conn_driver(driver_task)))
    }
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
        random_token(b"0123456789abcdef", 32)
    } else {
        random_token(
            BASE62,
            rand::rng().random_range(config.session_length.0..=config.session_length.1),
        )
    }
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

pub(crate) fn build_request(
    config: &XhttpConfig,
    authority: &str,
    method: http::Method,
    session: Option<&str>,
) -> Result<http::Request<()>> {
    let normalized = normalize_path(&config.path);
    let (base, query) = normalized
        .split_once('?')
        .map_or((normalized.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    let mut path = base.to_string();
    if config.session_placement == "path" {
        if let Some(session) = session {
            path.push_str(session);
        }
    }
    if let Some(query) = query {
        path.push('?');
        path.push_str(query);
    }
    let upload = method == http::Method::POST;
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("{}://{authority}{path}", config.scheme))
        .body(())
        .map_err(|e| TransportError::Config(format!("xhttp: invalid request config: {e}")))?;
    let headers = request.headers_mut();
    for (key, value) in &config.extra_headers {
        headers.insert(
            http::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| TransportError::Config(e.to_string()))?,
            http::HeaderValue::from_str(value)
                .map_err(|e| TransportError::Config(e.to_string()))?,
        );
    }
    if upload && !config.no_grpc_header && !headers.contains_key("content-type") {
        headers.insert(
            "content-type",
            http::HeaderValue::from_static("application/grpc"),
        );
    }
    let (placement, key, header, padding_method) = if config.x_padding_obfs_mode {
        (
            config.x_padding_placement.as_str(),
            config.x_padding_key.as_str(),
            config.x_padding_header.as_str(),
            config.x_padding_method.as_str(),
        )
    } else {
        ("queryInHeader", "x_padding", "referer", "repeat-x")
    };
    if !placement.is_empty() && (config.x_padding_obfs_mode || !headers.contains_key("referer")) {
        if let Some((min, max)) = config.x_padding_bytes {
            let length = rand::rng().random_range(min..=max);
            if length > 0 {
                let padding = generate_padding(padding_method, length);
                let value = if placement == "header" {
                    padding
                } else {
                    // Padding is applied before metadata; the Referer uses
                    // the base path and replaces the original query.
                    format!("{}://{authority}{base}?{key}={padding}", config.scheme)
                };
                headers.insert(
                    http::header::HeaderName::from_bytes(header.as_bytes())
                        .map_err(|e| TransportError::Config(e.to_string()))?,
                    http::HeaderValue::from_str(&value)
                        .map_err(|e| TransportError::Config(e.to_string()))?,
                );
            }
        }
    }
    if config.session_placement == "header" {
        if let Some(session) = session {
            let key = if config.session_key.is_empty() {
                "X-Session"
            } else {
                &config.session_key
            };
            headers.insert(
                http::header::HeaderName::from_bytes(key.as_bytes())
                    .map_err(|e| TransportError::Config(e.to_string()))?,
                http::HeaderValue::from_str(session)
                    .map_err(|e| TransportError::Config(e.to_string()))?,
            );
        }
    }
    Ok(request)
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

// Xray normalizes the base path with a trailing slash before matching it,
// including stream-one requests that carry no session ID in the path.
fn normalize_path(path_and_query: &str) -> String {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let mut normalized = path.to_string();
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    if let Some(query) = query {
        normalized.push('?');
        normalized.push_str(query);
    }
    normalized
}

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
    if !config.mode.eq_ignore_ascii_case("stream-one")
        && !config.mode.eq_ignore_ascii_case("stream-up")
    {
        return Err(TransportError::Config(format!(
            "xhttp: unsupported mode {:?}; only 'stream-one' and 'stream-up' are implemented",
            config.mode
        )));
    }
    if !matches!(config.session_placement.as_str(), "path" | "header") {
        return Err(TransportError::Config(
            "xhttp: session-placement must be 'path' or 'header'".into(),
        ));
    }
    if config.session_placement == "header" && !config.session_key.is_empty() {
        validate_header_name(&config.session_key)?;
    }
    if !matches!(config.session_table.as_str(), "" | "Base62") {
        return Err(TransportError::Config(
            "xhttp: session-table must be empty or 'Base62'".into(),
        ));
    }
    let (min, max) = config.session_length;
    if min == 0 || min > max || max > 128 {
        return Err(TransportError::Config(
            "xhttp: session-length must be an ordered range within 1-128".into(),
        ));
    }
    if config.session_table == "Base62" && min < 6 {
        return Err(TransportError::Config(
            "xhttp: Base62 session-length min must be at least 6".into(),
        ));
    }
    if config.x_padding_obfs_mode {
        if !matches!(
            config.x_padding_method.as_str(),
            "" | "repeat-x" | "tokenish"
        ) {
            return Err(TransportError::Config(
                "xhttp: unsupported x-padding-method".into(),
            ));
        }
        if !matches!(
            config.x_padding_placement.as_str(),
            "" | "header" | "queryInHeader"
        ) {
            return Err(TransportError::Config(
                "xhttp: unsupported x-padding-placement".into(),
            ));
        }
        if !config.x_padding_placement.is_empty() {
            validate_header_name(&config.x_padding_header)?;
        }
        if config.x_padding_placement == "queryInHeader"
            && (config.x_padding_key.is_empty()
                || !config.x_padding_key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                }))
        {
            return Err(TransportError::Config(
                "xhttp: x-padding-key must be a non-empty unreserved query key".into(),
            ));
        }
        if config.session_placement == "header" && !config.x_padding_placement.is_empty() {
            let key = if config.session_key.is_empty() {
                "X-Session"
            } else {
                &config.session_key
            };
            if key.eq_ignore_ascii_case(&config.x_padding_header) {
                return Err(TransportError::Config(
                    "xhttp: padding and session headers must differ".into(),
                ));
            }
        }
    }
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
    if !path.starts_with('/') {
        return Err(TransportError::Config(
            "xhttp: path must start with '/'".into(),
        ));
    }
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
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
        assert!(config.validate().is_err());
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
            path: "no_slash".into(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());

        let config = XhttpConfig {
            path: "/has space".into(),
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
        for mode in ["packet-up", "auto", ""] {
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
