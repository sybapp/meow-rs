//! Endpoint inheritance and XMUX configuration, resolved above the leaf transport.
use super::{parse_vless_reality_opts, required_port};
use meow_proxy::{dialer::TcpDialer, TransportChain, XhttpDialerFactory};
use meow_transport::{
    tls::{ClientCert, EchOpts, TlsConfig, TlsLayer},
    xhttp::{ReuseConfig, XhttpConfig, XhttpEndpoint},
};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc};

type Config = HashMap<String, Value>;

fn range(value: Option<&Value>, key: &str) -> Result<(usize, usize), String> {
    let text = match value {
        None | Some(Value::Null) => return Ok((0, 0)),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.trim().to_string(),
        _ => {
            return Err(format!(
                "vless: reuse-settings.{key} must be an integer or range string"
            ))
        }
    };
    if text.is_empty() {
        return Ok((0, 0));
    }
    let (min, max) = text.split_once('-').unwrap_or((&text, &text));
    let parse = |s: &str| {
        s.trim()
            .parse::<usize>()
            .map_err(|_| format!("vless: invalid reuse-settings.{key} range"))
    };
    let pair = (parse(min)?, parse(max)?);
    if pair.0 > pair.1 || pair.1 > i32::MAX as usize {
        return Err(format!("vless: invalid reuse-settings.{key} range"));
    }
    Ok(pair)
}
fn reuse(config: &Config) -> Result<(Option<ReuseConfig>, i64), String> {
    let opts = config
        .get("xhttp-opts")
        .and_then(|o| o.get("reuse-settings"));
    let Some(opts) = opts.filter(|o| !o.is_null()) else {
        return Ok((None, 0));
    };
    if !opts.is_mapping() {
        return Err("vless: reuse-settings must be a mapping".into());
    }
    let cfg = ReuseConfig {
        max_concurrency: range(opts.get("max-concurrency"), "max-concurrency")?,
        max_connections: range(opts.get("max-connections"), "max-connections")?,
        c_max_reuse_times: range(opts.get("c-max-reuse-times"), "c-max-reuse-times")?,
        h_max_request_times: range(opts.get("h-max-request-times"), "h-max-request-times")?,
        h_max_reusable_secs: range(opts.get("h-max-reusable-secs"), "h-max-reusable-secs")?,
    };
    let period = match opts.get("h-keep-alive-period") {
        None | Some(Value::Null) => 0,
        Some(Value::String(s)) => s
            .parse::<i64>()
            .map_err(|_| "vless: h-keep-alive-period must be a signed integer")?,
        Some(v) => v
            .as_i64()
            .ok_or("vless: h-keep-alive-period must be a signed integer")?,
    };
    // Go's duration is an int64 nanosecond count; reject overflow rather than
    // accidentally turn a huge positive period into disabled keep-alives.
    if period.checked_mul(1_000_000_000).is_none() {
        return Err("vless: h-keep-alive-period exceeds duration range".into());
    }
    Ok((Some(cfg), period))
}

pub(super) fn reject_xhttp3_connection_options(config: &Config) -> Result<(), String> {
    for key in ["reuse-settings", "download-settings"] {
        if config
            .get("xhttp-opts")
            .and_then(|o| o.get(key))
            .is_some_and(|v| !v.is_null())
        {
            return Err(format!("vless: XHTTP/3 {key} is not implemented"));
        }
    }
    Ok(())
}
pub(super) fn build_xhttp_h2_endpoint(
    config: &Config,
    xhttp: XhttpConfig,
    tls: Option<&TlsConfig>,
    dialer: &Arc<dyn TcpDialer>,
) -> Result<Arc<XhttpEndpoint>, String> {
    let server = config
        .get("server")
        .and_then(Value::as_str)
        .ok_or("vless: missing download server")?;
    let port = required_port(config, "vless XHTTP endpoint")?;
    if server.is_empty() || server.len() > 255 {
        return Err("vless: invalid XHTTP endpoint server".into());
    }
    let mut chain = TransportChain::empty();
    if let Some(tls) = tls {
        chain.push(Box::new(
            TlsLayer::new(tls).map_err(|e| format!("vless: XHTTP endpoint TLS: {e}"))?,
        ));
    }
    let factory = Arc::new(XhttpDialerFactory::new(
        server.into(),
        port,
        Arc::clone(dialer),
        chain,
    ));
    let (reuse, period) = reuse(config)?;
    XhttpEndpoint::new(xhttp, factory, reuse, period)
        .map(Arc::new)
        .map_err(|e| format!("vless: {e}"))
}

/// Null/omitted members inherit; an explicit empty mapping replaces a mapping.
pub(super) fn parse_xhttp_download_settings(config: &Config) -> Result<Option<Config>, String> {
    let opts = config.get("xhttp-opts");
    let Some(download) = opts
        .and_then(|o| o.get("download-settings"))
        .filter(|v| !v.is_null())
    else {
        return Ok(None);
    };
    let mapping = download
        .as_mapping()
        .ok_or("vless: download-settings must be a mapping")?;
    let mut result = config.clone();
    let mut xopts = opts
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    xopts.remove(Value::String("download-settings".into()));
    for (key, value) in mapping {
        if value.is_null() {
            continue;
        }
        let key = key
            .as_str()
            .ok_or("vless: download-settings keys must be strings")?;
        match key {
            "tls" | "skip-cert-verify" if !value.is_bool() => {
                return Err(format!("vless: download-settings.{key} must be a boolean"))
            }
            "server" | "servername" | "client-fingerprint" | "name-cert-verify" | "fingerprint"
            | "certificate" | "private-key" | "path"
                if !value.is_string() =>
            {
                return Err(format!("vless: download-settings.{key} must be a string"))
            }
            "alpn"
                if value
                    .as_sequence()
                    .is_none_or(|v| v.iter().any(|p| !p.is_string())) =>
            {
                return Err("vless: download ALPN must be a string array".into())
            }
            "ech-opts" | "reality-opts" if !value.is_mapping() => {
                return Err(format!("vless: download-settings.{key} must be a mapping"))
            }
            _ => {}
        }
        match key {
            "path" | "host" | "headers" | "reuse-settings" => {
                xopts.insert(Value::String(key.into()), value.clone());
            }
            "server" | "port" | "tls" | "alpn" | "ech-opts" | "reality-opts"
            | "skip-cert-verify" | "name-cert-verify" | "fingerprint" | "certificate"
            | "private-key" | "servername" | "client-fingerprint" => {
                result.insert(key.into(), value.clone());
            }
            "shadow-tls-opts" | "restls-opts" | "jls-opts" => {
                return Err(format!(
                    "vless: download-settings.{key} security is not implemented"
                ))
            }
            _ => return Err(format!("vless: unknown download-settings.{key}")),
        }
    }
    result.insert("xhttp-opts".into(), Value::Mapping(xopts));
    Ok(Some(result))
}

pub(super) fn parse_xhttp_download_tls(
    name: &str,
    config: &Config,
    host: &str,
    sni: &str,
    enabled: bool,
) -> Result<Option<TlsConfig>, String> {
    let reality = parse_vless_reality_opts(name, config)?;
    if let Some(alpn) = config.get("alpn") {
        let values = alpn
            .as_sequence()
            .ok_or("vless: download ALPN must be an array")?;
        if values.iter().any(|v| !v.is_string())
            || values == &[Value::String("h3".into())]
            || values == &[Value::String("http/1.1".into())]
        {
            return Err("vless: download endpoint currently requires HTTP/2 ALPN".into());
        }
    }
    if !enabled {
        if reality.is_some() {
            return Err("vless: download REALITY requires TLS".into());
        }
        if config
            .get("alpn")
            .and_then(Value::as_sequence)
            .is_some_and(|a| a.iter().any(|p| p.as_str() == Some("h3")))
        {
            return Err("vless: download HTTP/3 requires TLS".into());
        }
        return Ok(None);
    }
    let mut tls = TlsConfig::new(if sni.is_empty() { host } else { sni });
    tls.alpn = vec!["h2".into()];
    tls.skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    tls.fingerprint = config
        .get("client-fingerprint")
        .and_then(Value::as_str)
        .map(str::to_string);
    if reality.is_some() && tls.fingerprint.is_none() {
        return Err("vless: download REALITY requires client-fingerprint".into());
    }
    tls.reality = reality;
    apply_vless_tls_identity(config, &mut tls)?;
    if let Some(opts) = config
        .get("ech-opts")
        .filter(|v| v.get("enable").and_then(Value::as_bool) == Some(true))
    {
        use base64::Engine as _;
        let value = opts
            .get("config")
            .and_then(Value::as_str)
            .ok_or("vless: download ECH requires resolved inline config")?;
        tls.ech = Some(EchOpts::Config(
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|e| format!("vless: download ECH base64: {e}"))?,
        ));
    }
    Ok(Some(tls))
}

pub(super) fn apply_vless_tls_identity(config: &Config, tls: &mut TlsConfig) -> Result<(), String> {
    let text = |key: &str| -> Result<&str, String> {
        match config.get(key) {
            None | Some(Value::Null) => Ok(""),
            Some(v) => v
                .as_str()
                .ok_or_else(|| format!("vless: {key} must be a string")),
        }
    };
    let name = text("name-cert-verify")?;
    tls.verify_name = (!name.is_empty()).then(|| name.to_string());
    let pin = text("fingerprint")?;
    if !pin.is_empty() {
        let pin = pin.replace(':', "");
        let pin = pin.trim();
        if pin.len() != 64 || !pin.is_ascii() {
            return Err("vless: fingerprint must be a SHA-256 hex digest; browser profiles use client-fingerprint".into());
        }
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&pin[i * 2..i * 2 + 2], 16)
                .map_err(|_| "vless: invalid certificate fingerprint hex")?;
        }
        tls.cert_pin = Some(bytes);
    }
    let certificate = text("certificate")?;
    let private_key = text("private-key")?;
    if !certificate.is_empty() || !private_key.is_empty() {
        let pem = |value: &str| -> Result<Vec<u8>, String> {
            use std::io::Read as _;
            const LIMIT: usize = 1024 * 1024;
            let bytes = if value.contains("-----BEGIN ") {
                if value.len() > LIMIT {
                    return Err("vless: TLS identity exceeds 1 MiB".into());
                }
                value.as_bytes().to_vec()
            } else {
                let file = std::fs::File::open(value)
                    .map_err(|e| format!("vless: cannot read TLS identity {value:?}: {e}"))?;
                let mut bytes = Vec::new();
                file.take((LIMIT + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|e| format!("vless: cannot read TLS identity: {e}"))?;
                bytes
            };
            if bytes.len() > LIMIT {
                return Err("vless: TLS identity exceeds 1 MiB".into());
            }
            Ok(bytes)
        };
        tls.client_cert = Some(ClientCert {
            cert_pem: pem(certificate)?,
            key_pem: pem(private_key)?,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inheritance_preserves_null_and_replaces_empty_maps() {
        let parent: Config = serde_yaml::from_str("server: old\nport: 443\nreality-opts: {public-key: key}\nxhttp-opts:\n  path: /up\n  headers: {A: B}\n  reuse-settings: {max-connections: 3}\n  download-settings:\n    server: new\n    port: null\n    reality-opts: {}\n    headers: {}\n    reuse-settings: {}\n").unwrap();
        let down = parse_xhttp_download_settings(&parent).unwrap().unwrap();
        assert_eq!(down["server"].as_str(), Some("new"));
        assert_eq!(down["port"].as_u64(), Some(443));
        assert!(down["reality-opts"].as_mapping().unwrap().is_empty());
        let opts = &down["xhttp-opts"];
        assert_eq!(opts["path"].as_str(), Some("/up"));
        assert!(opts["headers"].as_mapping().unwrap().is_empty());
        assert!(reuse(&down).unwrap().0.is_some());
    }
}
