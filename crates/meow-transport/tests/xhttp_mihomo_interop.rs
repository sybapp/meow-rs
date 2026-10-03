//! Independent, pinned mihomo server validates all three XHTTP modes.
//! Build tests/support/mihomo-xhttp-peer and set MEOW_XHTTP_PEER_BIN.
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use meow_transport::{
    tls::TlsConfig,
    xhttp::{XhttpConfig, XhttpLayer},
    xhttp3::{Datagram, Xhttp3Client},
    Transport,
};
use serde_json::json;
use std::{net::SocketAddr, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, UdpSocket},
    process::Command,
};

struct Socket(UdpSocket);
#[async_trait]
impl Datagram for Socket {
    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        let n = self.0.send(data).await?;
        if n != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial datagram",
            ));
        }
        Ok(())
    }
    async fn recv(&self, data: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(data).await
    }
}

async fn round_trip(protocol: &str, config: XhttpConfig, size: usize) {
    tokio::time::timeout(Duration::from_secs(20), async {
        let binary = std::env::var("MEOW_XHTTP_PEER_BIN")
            .expect("build tests/support/mihomo-xhttp-peer and set MEOW_XHTTP_PEER_BIN; independent interop must never silently skip");
        let settings = json!({
            "Host": "example.org", "Path": config.path, "Mode": config.mode,
            "SessionPlacement": config.session_placement, "SessionKey": config.session_key,
            "SeqPlacement": config.seq_placement, "SeqKey": config.seq_key,
            "UplinkHTTPMethod": config.uplink_http_method,
            "UplinkDataPlacement": config.uplink_data_placement, "UplinkDataKey": config.uplink_data_key,
            "ScMaxEachPostBytes": config.sc_max_each_post_bytes.1.to_string(),
            "XPaddingBytes": "16",
            "XPaddingObfsMode": config.x_padding_obfs_mode, "XPaddingPlacement": config.x_padding_placement,
            "XPaddingMethod": config.x_padding_method, "XPaddingHeader": config.x_padding_header, "XPaddingKey": config.x_padding_key,
        });
        let mut peer = Command::new(binary).arg("-protocol").arg(protocol)
            .arg("-config").arg(settings.to_string()).arg("-bytes").arg(size.to_string())
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
        let mut output = BufReader::new(peer.stdout.take().unwrap());
        let mut line = String::new(); output.read_line(&mut line).await.unwrap();
        let info: serde_json::Value = serde_json::from_str(&line).expect("peer startup JSON");
        let addr: SocketAddr = info["address"].as_str().unwrap().parse().unwrap();
        let mut stream = if protocol == "h2" {
            XhttpLayer::new(config.clone()).connect(Box::new(TcpStream::connect(addr).await.unwrap())).await.unwrap()
        } else {
            let mut tls = TlsConfig::new("example.org");
            tls.additional_roots.push(STANDARD.decode(info["certificate"].as_str().unwrap()).unwrap());
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = socket.local_addr().unwrap(); socket.connect(addr).await.unwrap();
            Xhttp3Client::new(config.clone(), &tls).unwrap().connect(Arc::new(Socket(socket)), local, addr).await.unwrap()
        };
        let data: Vec<_> = (0..=255).cycle().take(size).collect();
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let sending = async { write.write_all(&data).await.unwrap(); write.shutdown().await.unwrap(); };
        let receiving = async {
            let mut echoed = Vec::new(); read.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, data, "{protocol}: {config:?}");
        };
        tokio::join!(sending, receiving);
        peer.kill().await.unwrap(); peer.wait().await.unwrap();
    }).await.expect("independent XHTTP exchange deadline");
}

fn config() -> XhttpConfig {
    XhttpConfig {
        hosts: vec!["example.org".into()],
        path: "/interop?original=query".into(),
        x_padding_bytes: Some((16, 16)),
        sc_max_each_post_bytes: (4096, 4096),
        sc_min_posts_interval_ms: (5, 10),
        ..Default::default()
    }
}

#[tokio::test]
async fn mihomo_h2_all_modes_and_auto() {
    for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
        round_trip(
            "h2",
            XhttpConfig {
                mode: mode.into(),
                ..config()
            },
            256 * 1024,
        )
        .await;
    }
}
#[tokio::test]
async fn mihomo_h3_all_modes_and_auto() {
    for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
        round_trip(
            "h3",
            XhttpConfig {
                mode: mode.into(),
                ..config()
            },
            256 * 1024,
        )
        .await;
    }
}
#[tokio::test]
async fn mihomo_packet_metadata_and_payload_placements() {
    for protocol in ["h2", "h3"] {
        for session in ["path", "header", "query", "cookie"] {
            for seq in ["path", "header", "query", "cookie"] {
                for data in ["body", "header", "cookie"] {
                    let cfg = XhttpConfig {
                        mode: "packet-up".into(),
                        session_placement: session.into(),
                        seq_placement: seq.into(),
                        uplink_data_placement: data.into(),
                        uplink_data_key: "X-Data".into(),
                        uplink_chunk_size: (64, 128),
                        ..config()
                    };
                    round_trip(protocol, cfg, 8193).await;
                }
            }
        }
    }
}
#[tokio::test]
async fn mihomo_custom_method_and_session_tables() {
    for protocol in ["h2", "h3"] {
        for table in [
            "uuid", "ALPHABET", "Alphabet", "BASE36", "Base62", "HEX", "alphabet", "base36", "hex",
            "number", "abcde123",
        ] {
            round_trip(
                protocol,
                XhttpConfig {
                    mode: "packet-up".into(),
                    uplink_http_method: "PUT".into(),
                    session_table: table.into(),
                    ..config()
                },
                8193,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn mihomo_padding_placements_and_literal_paths() {
    for protocol in ["h2", "h3"] {
        for placement in ["header", "queryInHeader", "query", "cookie"] {
            for method in ["repeat-x", "tokenish"] {
                round_trip(
                    protocol,
                    XhttpConfig {
                        mode: "packet-up".into(),
                        session_placement: "query".into(),
                        seq_placement: "cookie".into(),
                        x_padding_obfs_mode: true,
                        x_padding_placement: placement.into(),
                        x_padding_method: method.into(),
                        x_padding_header: "X-Padding".into(),
                        x_padding_key: "pad".into(),
                        ..config()
                    },
                    8193,
                )
                .await;
            }
        }
        for path in [
            "",
            "relative",
            "/a space/问?x=1",
            "/literal%2F/#fragment",
            "/notrailing",
        ] {
            round_trip(
                protocol,
                XhttpConfig {
                    mode: "packet-up".into(),
                    path: path.into(),
                    session_placement: "header".into(),
                    seq_placement: "header".into(),
                    ..config()
                },
                8193,
            )
            .await;
        }
        round_trip(
            protocol,
            XhttpConfig {
                mode: "packet-up".into(),
                sc_max_each_post_bytes: (1_048_576, 1_048_576),
                ..config()
            },
            1_048_576,
        )
        .await;
    }
}

struct TcpFactory {
    address: SocketAddr,
    dials: Arc<std::sync::atomic::AtomicUsize>,
    internal: Arc<std::sync::Mutex<Vec<bool>>>,
}
#[async_trait]
impl meow_transport::xhttp::ConnectionFactory for TcpFactory {
    async fn connect(
        &self,
        internal: bool,
    ) -> meow_transport::Result<Box<dyn meow_transport::Stream>> {
        self.dials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.internal.lock().unwrap().push(internal);
        Ok(Box::new(TcpStream::connect(self.address).await?))
    }
}
async fn echo_shared(mut stream: Box<dyn meow_transport::Stream>, size: usize) {
    let data: Vec<_> = (0..=255).cycle().take(size).collect();
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let send = async {
        write.write_all(&data).await.unwrap();
        write.shutdown().await.unwrap();
    };
    let receive = async {
        let mut result = Vec::new();
        read.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, data);
    };
    tokio::join!(send, receive);
}

#[tokio::test]
async fn mihomo_h2_reuse_download_probe_isolation_and_reset() {
    use meow_transport::xhttp::{ReuseConfig, XhttpClient, XhttpEndpoint};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for mode in ["stream-one", "stream-up", "packet-up", "auto"] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let size = 8193;
            let split = mode != "stream-one";
            let mut peer = Command::new(std::env::var("MEOW_XHTTP_PEER_BIN").expect("independent peer required"))
                .args(["-protocol", "h2", "-capture", "-config", "{\"Host\":\"example.org\",\"Path\":\"/up\",\"Mode\":\"auto\",\"SessionPlacement\":\"header\",\"SessionKey\":\"X-Session\",\"XPaddingBytes\":\"16\"}", "-bytes", "8193"])
                .args(if split { vec!["-dual", "-download-path", "/down", "-download-host", "download.org"] } else { vec![] })
                .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
            let mut output = BufReader::new(peer.stdout.take().unwrap());
            let mut startup = String::new(); output.read_line(&mut startup).await.unwrap();
            let info: serde_json::Value = serde_json::from_str(&startup).unwrap();
            let up_count = Arc::new(AtomicUsize::new(0));
            let down_count = Arc::new(AtomicUsize::new(0));
            let up_flags = Arc::new(std::sync::Mutex::new(Vec::new()));
            let down_flags = Arc::new(std::sync::Mutex::new(Vec::new()));
            let config = XhttpConfig { path: "/up".into(), hosts: vec!["example.org".into()], mode: mode.into(), has_reality: mode == "auto", session_placement: "header".into(), session_key: "X-Session".into(), sc_min_posts_interval_ms: (1,1), ..config() };
            let up = Arc::new(XhttpEndpoint::new(config.clone(), Arc::new(TcpFactory { address: info["address"].as_str().unwrap().parse().unwrap(), dials: Arc::clone(&up_count), internal: Arc::clone(&up_flags) }), Some(ReuseConfig::default()), -1).unwrap());
            let down = split.then(|| Arc::new(XhttpEndpoint::new(XhttpConfig { path: "/down".into(), hosts: vec!["download.org".into()], extra_headers: vec![("X-Download".into(), "separate".into())], ..config }, Arc::new(TcpFactory { address: info["download-address"].as_str().unwrap().parse().unwrap(), dials: Arc::clone(&down_count), internal: Arc::clone(&down_flags) }), Some(ReuseConfig::default()), -1).unwrap()));
            let client = XhttpClient::new(up, down).unwrap();
            let first = client.connect(false).await.unwrap();
            let second = client.connect(false).await.unwrap();
            assert_eq!(up_count.load(Ordering::Relaxed), 1, "two tunnels share one physical connection");
            echo_shared(first, size).await;
            let third = client.connect(false).await.unwrap();
            assert_eq!(up_count.load(Ordering::Relaxed), 1, "dropping a tunnel preserves its peer's transport");
            client.reset();
            let fourth = client.connect(false).await.unwrap();
            assert_eq!(up_count.load(Ordering::Relaxed), 2);
            let probe = client.connect(true).await.unwrap();
            assert_eq!(up_count.load(Ordering::Relaxed), 3);
            tokio::join!(echo_shared(second, size), echo_shared(third, size), echo_shared(fourth, size), echo_shared(probe, size));
            assert_eq!(*up_flags.lock().unwrap(), [false, false, true]);
            if split {
                assert_eq!(down_count.load(Ordering::Relaxed), 3);
                assert_eq!(*down_flags.lock().unwrap(), [false, false, true]);
            }
            peer.kill().await.unwrap(); peer.wait().await.unwrap();
            let mut rows = String::new(); output.read_to_string(&mut rows).await.unwrap();
            let rows: Vec<serde_json::Value> = rows.lines().map(|r| serde_json::from_str(r).unwrap()).collect();
            let downloads: Vec<_> = rows.iter().filter(|r| r["download"] == true).collect();
            assert_eq!(downloads.len(), if split { 5 } else { 0 });
            for request in downloads {
                assert_eq!(request["method"], "GET");
                assert!(request["path"].as_str().unwrap().starts_with("/down"));
                assert_eq!(request["host"], "download.org");
                assert_eq!(request["headers"]["X-Download"][0], "separate");
            }
        }).await.unwrap_or_else(|_| panic!("shared H2 {mode} deadline"));
    }
}

#[tokio::test]
async fn mihomo_h3_pins_verify_names_and_mutual_tls() {
    use meow_transport::tls::ClientCert;
    // Expected failures must be tested by using the stream too: a TLS 1.3
    // client may finish its flight before receiving a client-auth rejection.
    for case in [
        "roots",
        "pin",
        "bad-pin",
        "name",
        "bad-name",
        "ip-sni",
        "no-client-cert",
        "truncated-client-chain",
    ] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut peer = Command::new(std::env::var("MEOW_XHTTP_PEER_BIN").expect("independent peer required"))
                .args(["-protocol", "h3", "-require-client-cert", "-bytes", "8193", "-config", "{\"Host\":\"example.org\",\"Path\":\"/tls\",\"Mode\":\"auto\",\"XPaddingBytes\":\"16\"}"])
                .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
            let mut output = BufReader::new(peer.stdout.take().unwrap());
            let mut startup = String::new(); output.read_line(&mut startup).await.unwrap();
            let startup: serde_json::Value = serde_json::from_str(&startup).unwrap();
            let addr: SocketAddr = startup["address"].as_str().unwrap().parse().unwrap();
            let mut tls = TlsConfig::new("example.org");
            tls.additional_roots.push(STANDARD.decode(startup["certificate"].as_str().unwrap()).unwrap());
            tls.client_cert = Some(ClientCert { cert_pem: startup["client-certificate-pem"].as_str().unwrap().as_bytes().to_vec(), key_pem: startup["client-private-key-pem"].as_str().unwrap().as_bytes().to_vec() });
            match case {
                "pin" | "bad-pin" => {
                    tls.sni = Some("different.example".into());
                    tls.additional_roots.clear();
                    tls.skip_cert_verify = true;
                    let pin = startup["fingerprint"].as_str().unwrap();
                    let mut bytes = [0;32];
                    if case == "pin" { for (i, byte) in bytes.iter_mut().enumerate() { *byte = u8::from_str_radix(&pin[i*2..i*2+2],16).unwrap(); } }
                    tls.cert_pin = Some(bytes);
                }
                "name" | "bad-name" | "ip-sni" => {
                    tls.sni = Some(if case == "ip-sni" { "[127.0.0.1]" } else { "different.example" }.into());
                    tls.skip_cert_verify = true;
                    tls.verify_name = Some(if case == "bad-name" { "wrong.example" } else { "example.org" }.into());
                }
                "no-client-cert" => tls.client_cert = None,
                "truncated-client-chain" => {
                    let cert = &mut tls.client_cert.as_mut().unwrap().cert_pem;
                    let first = std::str::from_utf8(cert).unwrap().find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
                    cert.truncate(first);
                },
                _ => {}
            }
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = socket.local_addr().unwrap(); socket.connect(addr).await.unwrap();
            let client = Xhttp3Client::new(XhttpConfig { scheme: "https".into(), hosts: vec!["example.org".into()], path: "/tls".into(), mode: "stream-one".into(), x_padding_bytes: Some((16,16)), ..Default::default() }, &tls).unwrap();
            let exchange = async {
                let mut stream = client.connect(Arc::new(Socket(socket)), local, addr).await.map_err(|e| e.to_string())?;
                let data = vec![0x4a;8193];
                stream.write_all(&data).await.map_err(|e| e.to_string())?;
                stream.shutdown().await.map_err(|e| e.to_string())?;
                let mut result = Vec::new(); stream.read_to_end(&mut result).await.map_err(|e| e.to_string())?;
                if result != data { return Err("missing authenticated echo".into()); }
                Ok::<_, String>(())
            }.await;
            let expected = !["bad-pin", "bad-name", "no-client-cert", "truncated-client-chain"].contains(&case);
            assert_eq!(exchange.is_ok(), expected, "{case}: {exchange:?}");
            peer.kill().await.unwrap(); peer.wait().await.unwrap();
        }).await.unwrap_or_else(|_| panic!("H3 TLS identity {case} deadline"));
    }
}
