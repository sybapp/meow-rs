//! Real loopback QUIC peers (test-only server); no remote nodes or credentials.
use async_trait::async_trait;
use meow_transport::{
    tls::TlsConfig,
    xhttp::XhttpConfig,
    xhttp3::{Datagram, Xhttp3Client},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

struct Socket(UdpSocket);
#[async_trait]
impl Datagram for Socket {
    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        self.0.send(data).await.map(|_| ())
    }
    async fn recv(&self, data: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(data).await
    }
}
#[path = "support/xhttp3_peer.rs"]
mod support;
use support::{peer, Peer};
async fn open(peer: &Peer, split: bool) -> Box<dyn meow_transport::Stream> {
    let mut tls = TlsConfig::new("example.org");
    tls.additional_roots.push(peer.root.clone());
    tls.fingerprint = Some("chrome".into());
    let cfg = XhttpConfig {
        mode: if split { "stream-up" } else { "stream-one" }.into(),
        hosts: vec!["example.org".into()],
        path: "/api/v1/telemetry".into(),
        session_placement: "header".into(),
        session_key: "X-Session-Id".into(),
        session_table: "Base62".into(),
        session_length: (16, 24),
        x_padding_obfs_mode: true,
        x_padding_method: "tokenish".into(),
        x_padding_placement: "header".into(),
        x_padding_header: "X-Cache-Key".into(),
        x_padding_bytes: Some((128, 512)),
        no_grpc_header: true,
        ..Default::default()
    };
    let client = Xhttp3Client::new(cfg, &tls).unwrap();
    let socket = UdpSocket::bind(if peer.addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await
    .unwrap();
    let local = socket.local_addr().unwrap();
    socket.connect(peer.addr).await.unwrap();
    client
        .connect(Arc::new(Socket(socket)), local, peer.addr)
        .await
        .unwrap()
}
async fn echo(bind: &str, split: bool, size: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer = peer(bind, split, 200, 204, true, false).await;
        let stream = open(&peer, split).await;
        let (mut read, mut write) = tokio::io::split(stream);
        let data = vec![0x5a; size];
        let writer = tokio::spawn(async move {
            write.write_all(&data).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut echoed = Vec::new();
        read.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, vec![0x5a; size]);
        writer.await.unwrap();
        let captures = peer.task.await.unwrap();
        assert_eq!(captures.len(), if split { 2 } else { 1 });
        if split {
            let header = |index: usize, key: &[u8]| {
                captures[index]
                    .iter()
                    .find(|(name, _)| name == key)
                    .unwrap()
                    .1
                    .clone()
            };
            let session = header(0, b"x-session-id");
            assert_eq!(session, header(1, b"x-session-id"));
            assert!((16..=24).contains(&session.len()));
            assert!(session.iter().all(u8::is_ascii_alphanumeric));
            assert_ne!(header(0, b"x-cache-key"), header(1, b"x-cache-key"));
            assert_eq!(header(0, b":path"), b"/api/v1/telemetry/");
        }
    })
    .await
    .expect("bounded QUIC echo");
}
#[tokio::test]
async fn stream_up_deferred_headers_and_large_echo() {
    echo("127.0.0.1:0", true, 1024 * 1024).await;
}
#[tokio::test]
async fn stream_one_echo() {
    echo("127.0.0.1:0", false, 128 * 1024).await;
}
#[tokio::test]
async fn ipv6_stream_up_echo() {
    echo("[::1]:0", true, 128 * 1024).await;
}
#[tokio::test]
async fn download_error_status_propagates() {
    let peer = peer("127.0.0.1:0", true, 403, 204, false, false).await;
    let mut stream = open(&peer, true).await;
    let err = tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("403"), "{err}");
    peer.task.abort();
}
#[tokio::test]
async fn upload_error_status_propagates() {
    let peer = peer("127.0.0.1:0", true, 200, 429, false, false).await;
    let mut stream = open(&peer, true).await;
    let err = tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("429"), "{err}");
    peer.task.abort();
}

#[tokio::test]
async fn untrusted_certificate_and_wrong_name_are_rejected() {
    for trust_root in [false, true] {
        let peer = peer("127.0.0.1:0", true, 200, 204, false, false).await;
        let mut tls = TlsConfig::new(if trust_root {
            "wrong.example.org"
        } else {
            "example.org"
        });
        if trust_root {
            tls.additional_roots.push(peer.root.clone());
        }
        let client = Xhttp3Client::new(XhttpConfig::default(), &tls).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        socket.connect(peer.addr).await.unwrap();
        let result = client
            .connect(Arc::new(Socket(socket)), local, peer.addr)
            .await;
        assert!(result.is_err(), "certificate/name check must fail");
        peer.task.abort();
    }
}
struct PendingSocket(std::sync::atomic::AtomicUsize);
#[async_trait]
impl Datagram for PendingSocket {
    async fn send(&self, _: &[u8]) -> std::io::Result<()> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
        std::future::pending().await
    }
}
#[tokio::test]
async fn cancelled_handshake_releases_udp_association() {
    let socket = Arc::new(PendingSocket(std::sync::atomic::AtomicUsize::new(0)));
    let driver_socket = Arc::clone(&socket);
    let mut tls = TlsConfig::new("example.org");
    tls.skip_cert_verify = true;
    let client = Xhttp3Client::new(XhttpConfig::default(), &tls).unwrap();
    let task = tokio::spawn(async move {
        client
            .connect(
                driver_socket,
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while socket.0.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&socket) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled connect must abort the UDP driver");
}
#[tokio::test(start_paused = true)]
async fn timed_out_handshake_releases_udp_association() {
    let socket = Arc::new(PendingSocket(std::sync::atomic::AtomicUsize::new(0)));
    let mut tls = TlsConfig::new("example.org");
    tls.skip_cert_verify = true;
    let client = Xhttp3Client::new(XhttpConfig::default(), &tls).unwrap();
    let result = client
        .connect(
            Arc::clone(&socket) as Arc<dyn Datagram>,
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        )
        .await;
    assert!(result.is_err());
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&socket), 1);
}
#[test]
fn unsupported_tls_options_fail_before_dial() {
    let mut tls = TlsConfig::new("example.org");
    tls.cert_pin = Some([0; 32]);
    assert!(Xhttp3Client::new(XhttpConfig::default(), &tls).is_err());
}

#[tokio::test]
async fn dropped_established_stream_releases_stalled_udp_driver() {
    let peer = peer("127.0.0.1:0", true, 200, 204, false, false).await;
    let mut tls = TlsConfig::new("example.org");
    tls.additional_roots.push(peer.root.clone());
    let client = Xhttp3Client::new(
        XhttpConfig {
            mode: "stream-up".into(),
            ..Default::default()
        },
        &tls,
    )
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    socket.connect(peer.addr).await.unwrap();
    let socket = Arc::new(Socket(socket));
    let stream = client
        .connect(Arc::clone(&socket) as Arc<dyn Datagram>, local, peer.addr)
        .await
        .unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&socket) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drop must release stalled connection within the one-second grace");
    peer.task.abort();
}
