//! Adapter seam between the leaf HTTP/3 transport and meow's protected UDP dialer.
use crate::dialer::{TcpDialer, UdpTarget};
use async_trait::async_trait;
use meow_transport::{
    xhttp3::{Datagram, Xhttp3Client},
    Stream,
};
use std::{io, sync::Arc};

pub(crate) struct Xhttp3Dialer {
    pub client: Xhttp3Client,
    pub dialer: Arc<dyn TcpDialer>,
}
struct Endpoint {
    conn: Arc<dyn meow_common::ProxyPacketConn>,
    target: UdpTarget,
    inbound: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<io::Result<bytes::Bytes>>>,
    read_task: tokio::task::JoinHandle<()>,
}
impl Endpoint {
    fn new(conn: Arc<dyn meow_common::ProxyPacketConn>, target: UdpTarget) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let read_conn = Arc::clone(&conn);
        let read_target = target.clone();
        // ProxyPacketConn may parse a stream with read_exact. Keep that future
        // alive across driver select branches; only the channel recv is cancelled.
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let packet = match read_conn.read_packet(&mut buf).await {
                    Ok((n, src)) if src.ip().is_unspecified() || read_target.src_matches(src) => {
                        if n > buf.len() {
                            continue;
                        }
                        Ok(bytes::Bytes::copy_from_slice(&buf[..n]))
                    }
                    Ok(_) => continue,
                    Err(e) => Err(e.into_io_error("XHTTP/3 UDP receive")),
                };
                let failed = packet.is_err();
                if tx.send(packet).await.is_err() || failed {
                    return;
                }
            }
        });
        Self {
            conn,
            target,
            inbound: tokio::sync::Mutex::new(rx),
            read_task,
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}
#[async_trait]
impl Datagram for Endpoint {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let n = self
            .conn
            .write_packet(packet, &self.target.write_dst())
            .await
            .map_err(|e| e.into_io_error("XHTTP/3 UDP send"))?;
        if n != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial QUIC datagram write",
            ));
        }
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self.inbound.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "QUIC UDP association closed")
        })??;
        if packet.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized QUIC datagram",
            ));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}
#[async_trait]
impl TcpDialer for Xhttp3Dialer {
    async fn dial(&self, host: &str, port: u16, internal: bool) -> io::Result<Box<dyn Stream>> {
        let mut target = UdpTarget::named(host, port);
        let conn = match self.dialer.dial_udp_conn(target.clone(), internal).await {
            Ok(conn) => conn,
            Err(e)
                if e.kind() == io::ErrorKind::Unsupported
                    && matches!(target, UdpTarget::Name { .. }) =>
            {
                let mut result = None;
                let mut last_error = None;
                for addr in meow_common::resolve_host_all(host, port).await? {
                    let candidate = UdpTarget::Addr(addr);
                    match self.dialer.dial_udp_conn(candidate.clone(), internal).await {
                        Ok(conn) => {
                            target = candidate;
                            result = Some(conn);
                            break;
                        }
                        Err(e) => {
                            last_error = meow_common::MeowError::prefer_errno_io(last_error, e);
                        }
                    }
                }
                result.ok_or_else(|| {
                    last_error.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "no UDP endpoint")
                    })
                })?
            }
            Err(e) => return Err(e),
        };
        // quiche addresses are logical on a proxy-bound association; the front
        // can resolve a Name differently. Endpoint handles actual routing.
        let peer = target.write_dst();
        let local = conn
            .local_addr()
            .map_err(|e| e.into_io_error("XHTTP/3 local address"))?;
        let socket = Arc::new(Endpoint::new(conn, target));
        self.client
            .connect(socket, local, peer)
            .await
            .map_err(|e| match e {
                meow_transport::TransportError::Io(e) => e,
                other => io::Error::other(other),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    struct PendingConn {
        reads: AtomicUsize,
        writes: AtomicUsize,
    }
    #[async_trait]
    impl meow_common::ProxyPacketConn for PendingConn {
        async fn read_packet(&self, _: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
        async fn write_packet(&self, data: &[u8], _: &SocketAddr) -> meow_common::Result<usize> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(data.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn receive_cancellation_keeps_packet_parser_alive_and_drop_aborts_it() {
        let conn = Arc::new(PendingConn {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        });
        let endpoint = Endpoint::new(
            Arc::clone(&conn) as Arc<dyn meow_common::ProxyPacketConn>,
            UdpTarget::named("example.org", 443),
        );
        let mut buf = [0; 1500];
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(10), endpoint.recv(&mut buf))
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            conn.reads.load(Ordering::SeqCst),
            1,
            "read_packet must not restart when driver recv is cancelled"
        );
        drop(endpoint);
        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&conn) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    struct UdpOnlyDialer {
        conn: Arc<PendingConn>,
        calls: std::sync::Mutex<Vec<(UdpTarget, bool)>>,
    }
    #[async_trait]
    impl TcpDialer for UdpOnlyDialer {
        async fn dial(&self, _: &str, _: u16, _: bool) -> io::Result<Box<dyn Stream>> {
            panic!("HTTP/3 must dial UDP")
        }
        async fn dial_udp_conn(
            &self,
            target: UdpTarget,
            internal: bool,
        ) -> io::Result<Arc<dyn meow_common::ProxyPacketConn>> {
            self.calls.lock().unwrap().push((target, internal));
            Ok(Arc::clone(&self.conn) as Arc<dyn meow_common::ProxyPacketConn>)
        }
    }
    #[tokio::test]
    async fn h3_preserves_named_proxy_target_and_internal_probe_metadata() {
        let conn = Arc::new(PendingConn {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        });
        let front = Arc::new(UdpOnlyDialer {
            conn: Arc::clone(&conn),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let mut tls = meow_transport::tls::TlsConfig::new("example.org");
        tls.skip_cert_verify = true;
        let client =
            Xhttp3Client::new(meow_transport::xhttp::XhttpConfig::default(), &tls).unwrap();
        let dialer = Xhttp3Dialer {
            client,
            dialer: Arc::clone(&front) as Arc<dyn TcpDialer>,
        };
        let task = tokio::spawn(async move { dialer.dial("remote.example.org", 443, true).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while conn.writes.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            *front.calls.lock().unwrap(),
            vec![(UdpTarget::named("remote.example.org", 443), true)]
        );
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&conn) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
