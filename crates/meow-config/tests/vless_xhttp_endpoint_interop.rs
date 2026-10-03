//! Real parser → VLESS adapter → reusable HTTP transport → independent Go peer.
#![cfg(feature = "vless")]
use meow_common::Metadata;
use meow_config::load_config_from_str;
use std::{collections::HashSet, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

async fn exchange(mut conn: Box<dyn meow_common::ProxyConn>) {
    let data = vec![0x5a; 8193];
    let (mut reader, mut writer) = tokio::io::split(&mut conn);
    let send = async {
        writer.write_all(&data).await.unwrap();
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, data);
    };
    tokio::join!(send, receive);
}

async fn configured_endpoints(tls: bool) {
    tokio::time::timeout(Duration::from_secs(25), async {
        let binary = std::env::var("MEOW_XHTTP_PEER_BIN").expect("build the pinned independent mihomo peer; never silently skip interop");
        let mut peer = Command::new(binary)
            .args(["-protocol", if tls { "h2-tls" } else { "h2" }, "-dual", "-capture", "-vless", "-download-path", "/down", "-download-host", "download.org", "-bytes", "8193", "-config", "{\"Host\":\"example.org\",\"Path\":\"/up\",\"Mode\":\"auto\",\"XPaddingBytes\":\"16\",\"SessionPlacement\":\"header\",\"SessionKey\":\"X-Session\"}"])
            .args(if tls { vec!["-require-client-cert"] } else { vec![] })
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut output = BufReader::new(peer.stdout.take().unwrap());
        let mut startup = String::new(); output.read_line(&mut startup).await.unwrap();
        let startup: serde_json::Value = serde_json::from_str(&startup).unwrap();
        let up: std::net::SocketAddr = startup["address"].as_str().unwrap().parse().unwrap();
        let down: std::net::SocketAddr = startup["download-address"].as_str().unwrap().parse().unwrap();
        let yaml = format!("proxies:\n  - name: xhttp\n    type: vless\n    server: {}\n    port: {}\n    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    network: xhttp\n    xhttp-opts:\n      host: example.org\n      path: /up\n      mode: stream-up\n      x-padding-bytes: '16'\n      session-placement: header\n      session-key: X-Session\n      reuse-settings: {{max-connections: 1, h-max-request-times: 10, h-keep-alive-period: -1}}\n      download-settings:\n        server: {}\n        port: {}\n        path: /down\n        host: download.org\n        headers: {{X-Download: separate}}\n", up.ip(), up.port(), down.ip(), down.port());
        let mut document: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        if tls {
            let proxy = &mut document["proxies"][0];
            proxy["tls"] = serde_yaml::Value::Bool(true);
            proxy["servername"] = serde_yaml::Value::String("upload.example".into());
            proxy["fingerprint"] = serde_yaml::Value::String(startup["fingerprint"].as_str().unwrap().into());
            proxy["certificate"] = serde_yaml::Value::String(startup["certificate-pem"].as_str().unwrap().into());
            proxy["private-key"] = serde_yaml::Value::String(startup["private-key-pem"].as_str().unwrap().into());
            proxy["xhttp-opts"]["download-settings"]["servername"] = serde_yaml::Value::String("download.example".into());
            let mut invalid = document.clone();
            invalid["proxies"][0]["fingerprint"] = serde_yaml::Value::String("00".repeat(32));
            let invalid = load_config_from_str(&serde_yaml::to_string(&invalid).unwrap()).await.unwrap();
            assert!(invalid.proxies["xhttp"].dial_tcp(&Metadata { host: "target.example".into(), dst_port: 443, ..Default::default() }).await.is_err(), "wrong certificate pin must fail");
        }
        let config = load_config_from_str(&serde_yaml::to_string(&document).unwrap()).await.unwrap();
        let adapter = config.proxies.get("xhttp").expect("endpoint config loads");
        let metadata = Metadata { host: "target.example".into(), dst_port: 443, ..Default::default() };
        let one = adapter.dial_tcp(&metadata).await.unwrap();
        let two = adapter.dial_tcp(&metadata).await.unwrap();
        exchange(one).await;
        exchange(two).await;
        let probe = adapter.dial_tcp(&Metadata { internal: true, ..metadata }).await.unwrap();
        exchange(probe).await;
        adapter.reset_sessions();
        peer.kill().await.unwrap(); peer.wait().await.unwrap();
        let mut captures = String::new(); output.read_to_string(&mut captures).await.unwrap();
        let rows: Vec<serde_json::Value> = captures.lines().map(|r| serde_json::from_str(r).unwrap()).collect();
        for download in [false, true] {
            let requests: Vec<_> = rows.iter().filter(|r| r["download"] == download).collect();
            assert_eq!(requests.len(), 3);
            let connections: HashSet<_> = requests.iter().map(|r| r["connection"].as_i64().unwrap()).collect();
            assert_eq!(connections.len(), 2, "user tunnels share; probe is separate");
            for request in requests {
                assert_eq!(request["host"], if download { "download.org" } else { "example.org" });
                if tls { assert_eq!(request["sni"], if download { "download.example" } else { "upload.example" }); }
                assert_eq!(request["method"], if download { "GET" } else { "POST" });
                assert!(request["path"].as_str().unwrap().starts_with(if download { "/down" } else { "/up" }));
            }
        }
    }).await.expect("configured VLESS endpoint interop deadline");
}

#[tokio::test]
async fn configured_h2_reuse_download_endpoints_are_used_by_vless() {
    configured_endpoints(false).await;
}
#[tokio::test]
async fn configured_h2_download_tls_sni_pin_and_mutual_tls() {
    configured_endpoints(true).await;
}
