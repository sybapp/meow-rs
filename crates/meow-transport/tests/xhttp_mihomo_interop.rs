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

#[cfg(feature = "reality")]
#[tokio::test]
async fn reality_independent_go_tls_flights_and_signature_binding() {
    for (hybrid, curve, chacha) in [
        (false, "", false),
        (true, "", false),
        (false, "", true),
        (true, "", true),
        (false, "p256", false),
        (true, "p256", false),
        (false, "p384", false),
        (true, "p384", false),
        (false, "p521", false),
        (true, "p521", false),
    ] {
        for fragment in [false, true] {
            for bad_signature in [false, true] {
                tokio::time::timeout(Duration::from_secs(20), async {
                    let binary = std::env::var("MEOW_XHTTP_PEER_BIN").expect("independent peer required");
                    let mut command = Command::new(binary);
                    command.args(["-protocol", "reality", "-bytes", "32768", "-curve", curve]);
                    if chacha { command.env("GODEBUG", "cpu.aes=off"); }
                    if fragment { command.arg("-fragment"); }
                    if bad_signature { command.arg("-bad-signature"); }
                    let mut peer = command.stdout(Stdio::piped()).stderr(Stdio::inherit())
                        .kill_on_drop(true).spawn().unwrap();
                    let mut output = BufReader::new(peer.stdout.take().unwrap());
                    let mut line = String::new(); output.read_line(&mut line).await.unwrap();
                    let info: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let mut tls = TlsConfig::new("example.org");
                    tls.fingerprint = Some("chrome".into());
                    tls.reality = Some(meow_transport::tls::RealityConfig {
                        public_key: STANDARD.decode(info["public_key"].as_str().unwrap()).unwrap().try_into().unwrap(),
                        short_id: [1, 2, 3, 4, 5, 6, 7, 8], support_x25519_mlkem768: hybrid,
                    });
                    let tcp = TcpStream::connect(info["address"].as_str().unwrap()).await.unwrap();
                    let connected = meow_transport::tls::TlsLayer::new(&tls).unwrap().connect(Box::new(tcp)).await;
                    if bad_signature {
                        assert!(matches!(connected, Err(meow_transport::TransportError::Tls(message)) if message.contains("CertificateVerify")));
                    } else {
                        let mut stream = connected.unwrap();
                        let (mut read, mut write) = tokio::io::split(&mut stream);
                        let data: Vec<u8> = (0..=255).cycle().take(32768).collect();
                        let send = async { write.write_all(&data).await.unwrap(); write.flush().await.unwrap(); };
                        let receive = async { let mut echoed = vec![0; data.len()]; read.read_exact(&mut echoed).await.unwrap(); assert_eq!(echoed, data); };
                        tokio::join!(send, receive);
                    }
                    peer.kill().await.unwrap(); peer.wait().await.unwrap();
                }).await.expect("independent REALITY handshake and echo deadline");
            }
        }
    }
}

#[cfg(feature = "reality")]
#[tokio::test]
async fn reality_cover_certificate_and_camouflage() {
    for (trust, name) in [
        (true, "example.org"),
        (false, "example.org"),
        (true, "wrong.example.org"),
    ] {
        tokio::time::timeout(Duration::from_secs(10), async {
            let binary = std::env::var("MEOW_XHTTP_PEER_BIN").expect("independent peer required");
            let mut peer = Command::new(binary).args(["-protocol", "reality", "-cover"])
                .stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true).spawn().unwrap();
            let mut output = BufReader::new(peer.stdout.take().unwrap());
            let mut line = String::new(); output.read_line(&mut line).await.unwrap();
            let info: serde_json::Value = serde_json::from_str(&line).unwrap();
            let mut tls = TlsConfig::new(name);
            tls.fingerprint = Some("chrome".into());
            tls.alpn = vec!["h2".into()];
            if trust { tls.additional_roots.push(STANDARD.decode(info["certificate"].as_str().unwrap()).unwrap()); }
            tls.reality = Some(meow_transport::tls::RealityConfig {
                public_key: STANDARD.decode(info["public_key"].as_str().unwrap()).unwrap().try_into().unwrap(),
                short_id: [1,2,3,4,5,6,7,8], support_x25519_mlkem768: false,
            });
            let tcp = TcpStream::connect(info["address"].as_str().unwrap()).await.unwrap();
            let result = meow_transport::tls::TlsLayer::new(&tls).unwrap().connect(Box::new(tcp)).await;
            assert!(matches!(result, Err(meow_transport::TransportError::Tls(ref message)) if message.contains("authentication failed")));
            line.clear();
            if trust && name == "example.org" {
                tokio::time::timeout(Duration::from_secs(2), output.read_line(&mut line)).await.unwrap().unwrap();
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["method"], "GET"); assert_eq!(request["path"], "/"); assert_eq!(request["ua"], "Chrome");
                let padding = request["padding"].as_str().unwrap();
                assert!((30..62).contains(&padding.len())); assert!(padding.bytes().all(|b| b == b'0'));
            } else {
                assert!(tokio::time::timeout(Duration::from_millis(100), output.read_line(&mut line)).await.is_err(), "unverified cover received camouflage");
            }
            peer.kill().await.unwrap(); peer.wait().await.unwrap();
        }).await.expect("cover handshake deadline");
    }
}
