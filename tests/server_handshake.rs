use mumblers::{
    server::{MumbleServer, ServerConfig},
    ConnectionConfig, MumbleConnection,
};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_rustls::rustls;

fn make_tls(cfg: &ServerConfig) -> Arc<rustls::ServerConfig> {
    if let (Some(cert), Some(key)) = (&cfg.certificate, &cfg.private_key) {
        let cert_pem = std::fs::read(cert).unwrap();
        let key_pem = std::fs::read(key).unwrap();
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
            .unwrap();
        return Arc::new(config);
    }
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
    Arc::new(config)
}

#[tokio::test]
async fn server_handshake_smoke() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // Start server on a high random port to avoid collisions
    let mut cfg = ServerConfig::default();
    let port = 20000 + (rand::random::<u16>() % 30000);
    cfg.bind_port = port;
    let tls = make_tls(&cfg);
    let server = MumbleServer::new(cfg.clone(), tls);
    tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Give server a moment to bind
    sleep(Duration::from_millis(100)).await;

    // Connect client
    let ccfg = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("test-bot")
        .accept_invalid_certs(true)
        .build();
    let mut client = MumbleConnection::new(ccfg);
    let res = client.connect().await;
    assert!(res.is_ok(), "client failed to connect: {:?}", res.err());

    // Wait a short time to receive ServerSync via internal processing
    sleep(Duration::from_millis(200)).await;

    // Send a ping and expect pong handled by client (ping_received should increase)
    let before = client.state().await.ping_received;
    client.send_ping().await.unwrap();
    sleep(Duration::from_millis(100)).await;
    let after = client.state().await.ping_received;
    assert!(after > before, "expected ping_received to increase");
    let state = client.state().await;
    assert!(
        state.session_id.is_some(),
        "session should be assigned by server"
    );
}
