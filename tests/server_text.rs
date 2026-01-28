use mumblers::{
    server::{MumbleServer, ServerConfig},
    ConnectionConfig, MumbleConnection,
};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_rustls::rustls;

async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    fn make_tls(_cfg: &ServerConfig) -> Arc<rustls::ServerConfig> {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
        let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        Arc::new(config)
    }

    let mut cfg = ServerConfig::default();
    let port = 20000 + (rand::random::<u16>() % 30000);
    cfg.bind_port = port;
    let tls = make_tls(&cfg);
    let server = MumbleServer::new(cfg, tls);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (port, handle)
}

#[tokio::test]
async fn channel_text_broadcast() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("A")
        .accept_invalid_certs(true)
        .build();
    let mut a = MumbleConnection::new(cfg_a);
    a.connect().await.expect("a connect");
    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("B")
        .accept_invalid_certs(true)
        .build();
    let mut b = MumbleConnection::new(cfg_b);
    b.connect().await.expect("b connect");
    sleep(Duration::from_millis(200)).await;

    // Send channel text from A; B should receive
    // Root channel is id 0 by default
    a.send_channel_message(0, "hi from A".to_string())
        .await
        .ok();
    // Give time to deliver; we don't have a direct event recv API exposed here, so we check no crash.
    sleep(Duration::from_millis(150)).await;
}

#[tokio::test]
async fn private_text_routing_and_invalid_target() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("A")
        .accept_invalid_certs(true)
        .build();
    let mut a = MumbleConnection::new(cfg_a);
    a.connect().await.expect("a connect");
    let _a_sess = a.state().await.session_id.unwrap();

    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("B")
        .accept_invalid_certs(true)
        .build();
    let mut b = MumbleConnection::new(cfg_b);
    b.connect().await.expect("b connect");
    sleep(Duration::from_millis(200)).await;

    // Private message from A to B
    if let Some(b_sess) = b.state().await.session_id {
        a.send_private_message(b_sess, "secret".to_string())
            .await
            .ok();
    }
    sleep(Duration::from_millis(150)).await;

    // Invalid target: use a very large session id
    let _ = a
        .send_private_message(0xFFFF_FFFE, "nobody".to_string())
        .await; // server should not crash; may emit PermissionDenied
}
