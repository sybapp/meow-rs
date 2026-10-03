//! Shared XHTTP wire metadata for HTTP/2 and HTTP/3.
use super::{
    generate_padding, is_header_token_byte, validate_header_name, XhttpConfig, MAX_PACKET_BYTES,
};
use crate::{Result, TransportError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng as _;

pub(super) fn session_alphabet(table: &str) -> &[u8] {
    match table {
        "ALPHABET" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => super::BASE62,
        "HEX" => b"0123456789ABCDEF",
        "alphabet" => b"abcdefghijklmnopqrstuvwxyz",
        "base36" => b"0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => b"0123456789abcdef",
        "number" => b"0123456789",
        _ => table.as_bytes(),
    }
}

fn placement<'a>(value: &'a str, fallback: &'static str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn metadata_key<'a>(
    configured: &'a str,
    placement: &str,
    header: &'a str,
    other: &'a str,
) -> &'a str {
    if !configured.is_empty() {
        configured
    } else if placement == "header" {
        header
    } else {
        other
    }
}

pub(super) fn validate_options(config: &XhttpConfig) -> Result<()> {
    let error = |message: &str| TransportError::Config(format!("xhttp: {message}"));
    if !matches!(
        config.effective_mode().to_ascii_lowercase().as_str(),
        "stream-one" | "stream-up" | "packet-up"
    ) {
        return Err(error("unsupported mode"));
    }
    http::Method::from_bytes(config.uplink_http_method.as_bytes())
        .map_err(|_| error("invalid uplink-http-method"))?;
    for (label, value, key) in [
        ("session", &config.session_placement, &config.session_key),
        ("seq", &config.seq_placement, &config.seq_key),
    ] {
        let value = placement(value, "path");
        if !matches!(value, "path" | "query" | "header" | "cookie") {
            return Err(error(&format!("invalid {label}-placement")));
        }
        if !key.is_empty() && matches!(value, "header" | "cookie") {
            validate_header_name(key)?;
        }
    }
    let (min, max) = config.session_length;
    if min == 0 || min > max || max > 128 {
        return Err(error(
            "session-length must be an ordered range within 1-128",
        ));
    }
    if !matches!(config.session_table.as_str(), "" | "uuid") {
        let table = session_alphabet(&config.session_table);
        if !table.is_ascii() {
            return Err(error("session-table must contain only ASCII characters"));
        }
        // Saturation avoids arbitrary precision allocations and overflow. Only
        // the comparison with 2^31 matters, including variable-length tables.
        let mut room = 0u64;
        let mut term = 1u64;
        for length in 1..=max {
            term = term.saturating_mul(table.len() as u64);
            if length >= min {
                room = room.saturating_add(term);
            }
            if room >= (2u64 << 30) {
                break;
            }
        }
        if room < (2u64 << 30) {
            return Err(error("session-table or session-length is too small"));
        }
        if placement(&config.session_placement, "path") == "cookie"
            && !table.iter().copied().all(cookie_value_byte)
        {
            return Err(error("session-table contains bytes invalid in a cookie"));
        }
        if config.session_placement == "header" && table.iter().any(|b| *b < b' ' || *b == 0x7f) {
            return Err(error("session-table contains bytes invalid in a header"));
        }
    }
    if config.x_padding_obfs_mode {
        if !matches!(
            config.x_padding_method.as_str(),
            "" | "repeat-x" | "tokenish"
        ) {
            return Err(error("unsupported x-padding-method"));
        }
        let p = config.x_padding_placement.as_str();
        if !matches!(p, "" | "header" | "queryInHeader" | "query" | "cookie") {
            return Err(error("unsupported x-padding-placement"));
        }
        if matches!(p, "header" | "queryInHeader") {
            validate_header_name(&config.x_padding_header)?;
        }
        if p == "cookie" {
            validate_header_name(&config.x_padding_key)?;
        }
        if matches!(p, "query" | "queryInHeader") && config.x_padding_key.is_empty() {
            return Err(error("x-padding-key must not be empty"));
        }
    }
    let (min, max) = config.sc_max_each_post_bytes;
    if min == 0 || min > max || max > MAX_PACKET_BYTES {
        return Err(error(
            "sc-max-each-post-bytes must be an ordered positive range within 1 MiB",
        ));
    }
    let (min, max) = config.sc_min_posts_interval_ms;
    if min == 0 || min > max {
        return Err(error(
            "sc-min-posts-interval-ms must be an ordered positive range",
        ));
    }
    if tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(max as u64))
        .is_none()
    {
        return Err(error("sc-min-posts-interval-ms exceeds the timer range"));
    }
    let (min, max) = config.uplink_chunk_size;
    if min > max {
        return Err(error("invalid uplink-chunk-size range"));
    }
    let data = placement(&config.uplink_data_placement, "body");
    if !matches!(data, "body" | "auto" | "header" | "cookie") {
        return Err(error("invalid uplink-data-placement"));
    }
    if matches!(data, "header" | "cookie") {
        // An empty prefix is accepted upstream (-0 / _0).
        if !config.uplink_data_key.bytes().all(is_header_token_byte) {
            return Err(error("invalid uplink-data-key"));
        }
        if !config.effective_mode().eq_ignore_ascii_case("packet-up") {
            return Err(error("header/cookie uplink data requires packet-up"));
        }
    }
    Ok(())
}

fn cookie_value_byte(byte: u8) -> bool {
    (b' '..=b'~').contains(&byte) && !matches!(byte, b'"' | b';' | b'\\')
}

struct RequestParts {
    path: String,
    query: Vec<(String, String)>,
    headers: http::HeaderMap,
}

impl RequestParts {
    fn header(&mut self, name: &str, value: &str) -> Result<()> {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| TransportError::Config(e.to_string()))?;
        let value = http::HeaderValue::from_str(value)
            .map_err(|e| TransportError::Config(e.to_string()))?;
        self.headers.insert(name, value);
        Ok(())
    }

    fn query(&mut self, name: &str, value: &str) {
        self.query.retain(|(key, _)| key != name);
        self.query.push((name.to_string(), value.to_string()));
    }

    fn cookie(&mut self, name: &str, value: &str) -> Result<()> {
        // Cookie values with space/comma must be quoted, as net/http does.
        let quoted = value.bytes().any(|b| matches!(b, b' ' | b','));
        let mut cookie = self
            .headers
            .get("cookie")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        if !cookie.is_empty() {
            cookie.push_str("; ");
        }
        cookie.push_str(name);
        cookie.push('=');
        if quoted {
            cookie.push('"');
        }
        cookie.push_str(value);
        if quoted {
            cookie.push('"');
        }
        self.header("cookie", &cookie)
    }

    fn metadata(&mut self, p: &str, key: &str, value: &str) -> Result<()> {
        match p {
            "path" => {
                if !self.path.ends_with('/') {
                    self.path.push('/');
                }
                self.path.push_str(&escape_path(value));
                Ok(())
            }
            "query" => {
                self.query(key, value);
                Ok(())
            }
            "cookie" => self.cookie(key, value),
            "header" => self.header(key, value),
            _ => unreachable!("validated placement"),
        }
    }
}

fn escape_path(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/:@$&+,;=".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

pub(crate) fn build_request(
    config: &XhttpConfig,
    authority: &str,
    method: http::Method,
    session: Option<&str>,
    streaming_upload: bool,
) -> Result<http::Request<()>> {
    build(
        config,
        authority,
        method,
        session,
        None,
        None,
        streaming_upload,
    )
}

pub(crate) fn build_packet_request(
    config: &XhttpConfig,
    authority: &str,
    session: &str,
    seq: u64,
    payload: &[u8],
) -> Result<(http::Request<()>, bytes::Bytes)> {
    let method = config.uplink_http_method.parse().expect("validated method");
    let request = build(
        config,
        authority,
        method,
        Some(session),
        Some(&seq.to_string()),
        Some(payload),
        false,
    )?;
    let body = if matches!(
        placement(&config.uplink_data_placement, "body"),
        "body" | "auto"
    ) {
        bytes::Bytes::copy_from_slice(payload)
    } else {
        bytes::Bytes::new()
    };
    Ok((request, body))
}

#[allow(
    clippy::too_many_arguments,
    reason = "shared wire builder has explicit upload roles"
)]
fn build(
    config: &XhttpConfig,
    authority: &str,
    method: http::Method,
    session: Option<&str>,
    seq: Option<&str>,
    payload: Option<&[u8]>,
    streaming_upload: bool,
) -> Result<http::Request<()>> {
    let base = config.path.as_str();
    let mut path = if base.starts_with('/') {
        base.to_string()
    } else {
        format!("/{base}")
    };
    let sp = placement(&config.session_placement, "path");
    let qp = placement(&config.seq_placement, "path");
    if (sp == "path" || qp == "path") && !path.ends_with('/') {
        path.push('/');
    }
    let mut parts = RequestParts {
        path: escape_path(&path),
        query: Vec::new(),
        headers: http::HeaderMap::new(),
    };
    for (name, value) in &config.extra_headers {
        parts.header(name, value)?;
    }
    super::browser::apply(&mut parts.headers);
    if let Some(data) = payload {
        let p = placement(&config.uplink_data_placement, "body");
        if matches!(p, "header" | "cookie") {
            let encoded = URL_SAFE_NO_PAD.encode(data);
            let (min, max) = if config.uplink_chunk_size.1 == 0 {
                if p == "cookie" {
                    (2048, 3072)
                } else {
                    (3072, 4096)
                }
            } else {
                (
                    config.uplink_chunk_size.0.max(64),
                    config.uplink_chunk_size.1.max(64),
                )
            };
            let mut remaining = encoded.as_str();
            let mut i = 0;
            while !remaining.is_empty() {
                let size = rand::rng().random_range(min..=max).min(remaining.len());
                let (chunk, rest) = remaining.split_at(size);
                if p == "header" {
                    parts.header(&format!("{}-{i}", config.uplink_data_key), chunk)?;
                } else {
                    parts.cookie(&format!("{}_{i}", config.uplink_data_key), chunk)?;
                }
                remaining = rest;
                i += 1;
            }
        } else {
            parts.header("content-length", &data.len().to_string())?;
        }
    }
    let (p, key, header, padding_method) = if config.x_padding_obfs_mode {
        (
            config.x_padding_placement.as_str(),
            config.x_padding_key.as_str(),
            config.x_padding_header.as_str(),
            config.x_padding_method.as_str(),
        )
    } else {
        ("queryInHeader", "x_padding", "referer", "repeat-x")
    };
    if let Some((min, max)) = config.x_padding_bytes {
        let padding = generate_padding(padding_method, rand::rng().random_range(min..=max));
        if !padding.is_empty() {
            match p {
                "header" => parts.header(header, &padding)?,
                "queryInHeader" => parts.header(
                    header,
                    &format!(
                        "{}://{authority}{}?{key}={padding}",
                        config.scheme, parts.path
                    ),
                )?,
                "query" => parts.query(key, &padding),
                "cookie" => parts.cookie(key, &padding)?,
                _ => {}
            }
        }
    }
    if let Some(session) = session {
        parts.metadata(
            sp,
            metadata_key(&config.session_key, sp, "X-Session", "x_session"),
            session,
        )?;
    }
    if let Some(seq) = seq {
        parts.metadata(qp, metadata_key(&config.seq_key, qp, "X-Seq", "x_seq"), seq)?;
    }
    if streaming_upload && !config.no_grpc_header {
        parts.header("content-type", "application/grpc")?;
    }
    parts.query.sort_by(|a, b| a.0.cmp(&b.0));
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&parts.query)
        .finish();
    if !query.is_empty() {
        parts.path.push('?');
        parts.path.push_str(&query);
    }
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("{}://{authority}{}", config.scheme, parts.path))
        .body(())
        .map_err(|e| TransportError::Config(format!("xhttp: invalid request: {e}")))?;
    *request.headers_mut() = parts.headers;
    Ok(request)
}
