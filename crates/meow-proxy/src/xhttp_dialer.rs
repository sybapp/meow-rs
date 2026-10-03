//! Protected TCP/security seam for reusable XHTTP endpoints.
use async_trait::async_trait;
use meow_transport::{xhttp::ConnectionFactory, Stream};
use std::sync::Arc;

/// Keeps endpoint sockets inside the application's dialer/protection policy.
pub struct XhttpDialerFactory {
    server: String,
    port: u16,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
    security: crate::TransportChain,
}
impl XhttpDialerFactory {
    pub fn new(
        server: String,
        port: u16,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
        security: crate::TransportChain,
    ) -> Self {
        Self {
            server,
            port,
            dialer,
            security,
        }
    }
}
#[async_trait]
impl ConnectionFactory for XhttpDialerFactory {
    async fn connect(&self, internal: bool) -> meow_transport::Result<Box<dyn Stream>> {
        let raw = self.dialer.dial(&self.server, self.port, internal).await?;
        self.security
            .connect(raw)
            .await
            .map_err(|e| e.into_io_error("XHTTP endpoint security").into())
    }
}
