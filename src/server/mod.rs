//! Minimal in-crate Mumble-compatible server scaffolding.

mod config;
mod conn;
mod state;
mod udp;

pub use config::{ChannelConfig, ServerConfig};
pub use state::{ServerState, SessionId};

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;

/// Handle returned by [`MumbleServer::serve`] to trigger graceful shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the server to stop accepting new connections and shut down.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

/// Server builder entry point for tests/examples.
pub struct MumbleServer {
    pub cfg: ServerConfig,
    tls: Arc<TlsServerConfig>,
}

impl MumbleServer {
    pub fn new(cfg: ServerConfig, tls: Arc<TlsServerConfig>) -> Self {
        Self { cfg, tls }
    }

    /// Bind and start accepting connections.
    ///
    /// Returns a [`ShutdownHandle`] that can be used to stop the server
    /// gracefully. When shutdown is signalled, the accept loop exits and
    /// a `UserRemove` is broadcast for each connected user.
    pub async fn serve(self) -> Result<ShutdownHandle, Box<dyn std::error::Error + Send + Sync>> {
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

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = ShutdownHandle {
            tx: shutdown_tx.clone(),
        };

        tokio::spawn(async move {
            Self::accept_loop(listener, tls, state, shutdown_rx).await;
        });

        Ok(handle)
    }

    async fn accept_loop(
        listener: TcpListener,
        tls: Arc<TlsServerConfig>,
        state: ServerState,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((sock, peer)) => {
                            let tls = tls.clone();
                            let state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    crate::server::conn::handle_connection(
                                        sock, peer, tls.clone(), state.clone(),
                                    )
                                    .await
                                {
                                    tracing::warn!(%peer, error=?e, "connection ended with error");
                                }
                            });
                        }
                        Err(err) => {
                            tracing::warn!(error=?err, "server: accept failed");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("server: shutdown signal received");
                        // Broadcast UserRemove for all connected users
                        let users = state.list_users().await;
                        for user in &users {
                            let msg = crate::messages::MumbleMessage::UserRemove(
                                crate::proto::mumble::UserRemove {
                                    session: user.session,
                                    reason: Some("Server shutting down".to_string()),
                                    ..Default::default()
                                },
                            );
                            state.broadcast_except(u32::MAX, msg).await;
                        }
                        break;
                    }
                }
            }
        }
        tracing::info!("server: accept loop stopped");
    }
}
