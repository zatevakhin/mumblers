#![allow(dead_code)]

use mumblers::server::{MumbleServer, ServerConfig};
use mumblers::MumbleEvent;
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::rustls;

/// Generate a self-signed TLS config for localhost.
pub fn make_tls() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap(),
    )
}

/// Start a server with the default config on a random port.
/// Returns `(port, join_handle)`.
pub async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    start_server_with_config(ServerConfig::default()).await
}

/// Start a server with the given config on a random port.
/// Overrides `bind_port` and `udp_bind_port` with the chosen port.
pub async fn start_server_with_config(mut cfg: ServerConfig) -> (u16, tokio::task::JoinHandle<()>) {
    let port = 20000 + (rand::random::<u16>() % 30000);
    cfg.bind_port = port;
    cfg.udp_bind_port = port;
    let tls = make_tls();
    let server = MumbleServer::new(cfg, tls);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (port, handle)
}

/// Initialize tracing (safe to call multiple times).
pub fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .ok();
    });
}

/// Wait for a matching event, returning it if found within the timeout.
pub async fn wait_for_event<F>(
    rx: &mut tokio::sync::broadcast::Receiver<MumbleEvent>,
    limit: Duration,
    mut predicate: F,
) -> Option<MumbleEvent>
where
    F: FnMut(&MumbleEvent) -> bool,
{
    let deadline = Instant::now() + limit;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline - now;
        match timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) => {
                if predicate(&ev) {
                    return Some(ev);
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(_)) => return None,
            Err(_) => return None,
        }
    }
}
