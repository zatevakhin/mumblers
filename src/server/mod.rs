//! Minimal in-crate Mumble-compatible server scaffolding.
//! Iteration 12: module layout, config, TLS listener stub, framing reuse.

mod config;
mod conn;
mod state;
mod udp;

pub use config::{ChannelConfig, ServerConfig};
pub use state::{ServerState, SessionId};

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;

/// Server builder entry point for tests/examples.
pub struct MumbleServer {
    pub cfg: ServerConfig,
    tls: Arc<TlsServerConfig>,
}

impl MumbleServer {
    pub fn new(cfg: ServerConfig, tls: Arc<TlsServerConfig>) -> Self {
        Self { cfg, tls }
    }

    /// Bind and start accepting connections. For Iteration 12, this only accepts and
    /// immediately closes after TLS handshake wiring exists in conn module.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = format!("{}:{}", self.cfg.bind_host, self.cfg.bind_port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "server listening");
        let tls = self.tls.clone();
        let state = ServerState::new(self.cfg.clone());
        match state
            .ensure_udp_bound(&state.cfg.bind_host, state.cfg.udp_bind_port)
            .await
        {
            Ok(true) => conn::spawn_udp_receiver(state.clone()),
            Ok(false) => {}
            Err(err) => tracing::warn!(error=?err, "server: failed to pre-bind udp socket"),
        }

        loop {
            let (sock, peer) = listener.accept().await?;
            let tls = tls.clone();
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::server::conn::handle_connection(sock, peer, tls.clone(), state.clone())
                        .await
                {
                    tracing::warn!(%peer, error=?e, "connection ended with error");
                }
                // Best-effort cleanup: we don't know session id here; a more
                // advanced impl would tie tasks to sessions. Left for later.
            });
        }
    }
}
