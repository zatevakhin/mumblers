use mumblers::server::{MumbleServer, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio_rustls::rustls;

fn load_dev_tls(cfg: &ServerConfig) -> Arc<rustls::ServerConfig> {
    // Load from config if provided, else build an in-memory self-signed via rcgen in dev.
    if let (Some(cert_path), Some(key_path)) = (&cfg.certificate, &cfg.private_key) {
        let cert_pem = std::fs::read(cert_path).expect("read cert");
        let key_pem = std::fs::read(key_path).expect("read key");
        let mut cert_slice: &[u8] = &cert_pem;
        let certs_iter = rustls_pemfile::certs(&mut cert_slice);
        let certs: Vec<_> = certs_iter.map(|r| r.unwrap()).collect();
        let mut key_slice: &[u8] = &key_pem;
        let keys_iter = rustls_pemfile::pkcs8_private_keys(&mut key_slice);
        let keys: Vec<_> = keys_iter.map(|r| r.unwrap()).collect();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(keys[0].clone_key());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("tls config");
        return Arc::new(config);
    }
    // Dev self-signed path
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
    Arc::new(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Long-lived demo server: bind to defaults (127.0.0.1:64738) unless overridden by env/TOML
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok();
    let mut cfg = ServerConfig::default();
    if cfg.channels.is_empty() {
        cfg.default_channel = "Lobby".to_string();
        cfg.channels = vec![
            mumblers::server::ChannelConfig {
                name: "Lobby".to_string(),
                parent: Some("Root".to_string()),
                description: Some("Default landing channel".to_string()),
                position: Some(1),
                max_users: None,
                noenter: None,
                silent: None,
            },
            mumblers::server::ChannelConfig {
                name: "Games".to_string(),
                parent: Some("Lobby".to_string()),
                description: Some("Drop in to play together".to_string()),
                position: Some(2),
                max_users: None,
                noenter: None,
                silent: None,
            },
            mumblers::server::ChannelConfig {
                name: "AFK".to_string(),
                parent: Some("Root".to_string()),
                description: Some("Read-only parking slot".to_string()),
                position: Some(3),
                max_users: Some(2),
                noenter: Some(true),
                silent: None,
            },
        ];
    }
    let tls = load_dev_tls(&cfg);
    let server = MumbleServer::new(cfg, tls);
    server.serve().await.unwrap();
    Ok(())
}
