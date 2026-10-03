//! XHTTP's browser request header presets. Versions are sampled once per process.
use http::{HeaderMap, HeaderValue};
use rand::Rng as _;
use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

struct Versions {
    chrome: i64,
    firefox: i64,
    safari: String,
    curl: String,
}
static VERSIONS: OnceLock<Versions> = OnceLock::new();

fn versions() -> &'static Versions {
    VERSIONS.get_or_init(|| {
        let day = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            / 86400;
        let mut rng = rand::rng();
        let chrome =
            144 + (day - 20466 - 35 - (rng.random::<f64>().powi(2) * 105.0).floor() as i64) / 35;
        let firefox =
            128 + (day - 19933 - 25 - (rng.random::<f64>().powi(2) * 50.0).floor() as i64) / 30;
        let curl = format!(
            "8.{}.0",
            (day - 19436 - 60 - (rng.random::<f64>().powi(2) * 165.0).floor() as i64) / 57
        );
        // The release boundary is September 23 plus a sampled 0..74-day lag.
        // Gregorian arithmetic avoids another runtime date/time dependency.
        let delayed = (rng.random::<f64>().powi(3) * 75.0).floor() as i64;
        let mut year = 1970 + day / 365;
        while september23(year) > day {
            year -= 1;
        }
        while september23(year + 1) <= day {
            year += 1;
        }
        if day < september23(year) + delayed {
            year -= 1;
        }
        let age = ((day - september23(year) - delayed) / 15).clamp(0, 24) as usize;
        let minor = [
            0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
        ][age];
        Versions {
            chrome,
            firefox,
            curl,
            safari: format!("{}.{minor}", year - 1999),
        }
    })
}

fn september23(year: i64) -> i64 {
    let days_before = |y: i64| 365 * y + y / 4 - y / 100 + y / 400;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    days_before(year - 1) - days_before(1969) + 265 + i64::from(leap)
}

fn set(headers: &mut HeaderMap, name: &'static str, value: &str) {
    headers.insert(
        name,
        HeaderValue::from_str(value).expect("generated ASCII browser header"),
    );
}
fn default(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if headers.get(name).is_none_or(HeaderValue::is_empty) {
        set(headers, name, value);
    }
}

pub(super) fn apply(headers: &mut HeaderMap) {
    let browser = match headers.get("user-agent") {
        None => "chrome",
        Some(value) => match value.to_str().unwrap_or("") {
            "chrome" => "chrome",
            "edge" => "edge",
            "firefox" => "firefox",
            "safari" => "safari",
            "curl" => "curl",
            "golang" => "golang",
            _ => return,
        },
    };
    let versions = versions();
    if browser == "golang" {
        set(headers, "user-agent", "Go-http-client/1.1");
        return;
    }
    if browser == "curl" {
        set(headers, "user-agent", &format!("curl/{}", versions.curl));
        return;
    }
    match browser {
        "chrome" | "edge" => {
            let suffix = if browser == "edge" {
                format!("Edg/{}.0.0.0", versions.chrome)
            } else {
                String::new()
            };
            set(headers,"user-agent",&format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36{suffix}",versions.chrome));
            set(
                headers,
                "sec-ch-ua",
                &chromium_brands(versions.chrome, browser),
            );
            set(headers, "sec-ch-ua-mobile", "?0");
            set(headers, "sec-ch-ua-platform", "\"Windows\"");
            set(headers, "dnt", "1");
            set(headers, "accept-language", "en-US,en;q=0.9");
        }
        "firefox" => {
            set(headers,"user-agent",&format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{}.0) Gecko/20100101 Firefox/{}.0",versions.firefox,versions.firefox));
            set(headers, "dnt", "1");
            set(headers, "accept-language", "en-US,en;q=0.5");
        }
        "safari" => {
            set(headers,"user-agent",&format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15",versions.safari));
            set(headers, "accept-language", "en-US,en;q=0.9");
        }
        _ => unreachable!(),
    }
    set(headers, "sec-fetch-mode", "cors");
    set(headers, "sec-fetch-dest", "empty");
    set(headers, "sec-fetch-site", "same-origin");
    default(
        headers,
        "priority",
        match browser {
            "firefox" => "u=4",
            "safari" => "u=3, i",
            _ => "u=1, i",
        },
    );
    default(headers, "cache-control", "no-cache");
    default(headers, "pragma", "no-cache");
    default(headers, "accept", "*/*");
}

fn chromium_brands(version: i64, browser: &str) -> String {
    let seed = version.unsigned_abs() as usize;
    let separators = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    let grease = format!(
        "\"Not{}A{}Brand\";v=\"{}\"",
        separators[seed % 11],
        separators[(seed + 1) % 11],
        ["8", "99", "24"][seed % 3]
    );
    let fork = if browser == "edge" {
        "Microsoft Edge"
    } else {
        "Google Chrome"
    };
    let values = [
        grease,
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"{fork}\";v=\"{version}\""),
    ];
    let order = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ][seed % 6];
    let mut shuffled = ["", "", ""];
    for (i, dst) in order.into_iter().enumerate() {
        shuffled[dst] = &values[i];
    }
    shuffled.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_presets_preserve_literal_user_agent_and_fetch_overrides() {
        for literal in ["", "custom/1.0", "Chrome"] {
            let mut headers = HeaderMap::new();
            set(&mut headers, "user-agent", literal);
            apply(&mut headers);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers["user-agent"], literal);
        }
        for browser in ["chrome", "edge", "firefox", "safari", "curl", "golang"] {
            let mut headers = HeaderMap::new();
            set(&mut headers, "user-agent", browser);
            set(&mut headers, "accept", "custom");
            set(&mut headers, "priority", "u=5");
            apply(&mut headers);
            assert_ne!(headers["user-agent"], browser);
            assert_eq!(headers["accept"], "custom");
            assert_eq!(headers["priority"], "u=5");
            if matches!(browser, "curl" | "golang") {
                assert_eq!(headers.len(), 3);
            } else {
                assert_eq!(headers["sec-fetch-mode"], "cors");
            }
        }
        let mut headers = HeaderMap::new();
        apply(&mut headers);
        let sampled = headers["user-agent"].clone();
        apply(&mut headers);
        assert_eq!(headers["user-agent"], sampled);
    }
    #[test]
    fn calendar_anchor_matches_upstream_release_date() {
        assert_eq!(september23(2026), 20719);
        assert_eq!(september23(2024), 19989);
    }
}
