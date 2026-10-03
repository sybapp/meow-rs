//! Independent Go TLS engine validates native REALITY authentication and flights.
//! Build tests/support/reality-peer and set MEOW_REALITY_PEER_BIN.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use meow_transport::{tls::TlsConfig, Transport};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
};

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
                    let binary = std::env::var("MEOW_REALITY_PEER_BIN").expect("independent peer required");
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
            let binary = std::env::var("MEOW_REALITY_PEER_BIN").expect("independent peer required");
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
