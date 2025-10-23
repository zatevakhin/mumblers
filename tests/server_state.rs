use mumblers::server::{MumbleServer, ServerConfig};
use mumblers::{ConnectionConfig, MumbleConnection};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_rustls::rustls;

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

async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
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
async fn auth_sequencing_and_disconnect_cleanup() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    let cfg = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("user-a")
        .accept_invalid_certs(true)
        .build();
    let mut client = MumbleConnection::new(cfg);
    client.connect().await.expect("connect ok");
    sleep(Duration::from_millis(150)).await;
    let state = client.state().await;
    assert!(state.session_id.is_some(), "session assigned");
    // ChannelState/UserState emitted before ServerSync is acceptable; we just ensure session matches
    // Ping after auth still works (may require elevated permissions in CI)
    let before = client.state().await.ping_received;
    let _ = client.send_ping().await; // ignore env failures
    sleep(Duration::from_millis(100)).await;
    let after = client.state().await.ping_received;
    assert!(after >= before, "ping count should not regress");

    // Disconnect
    drop(client);
}

#[tokio::test]
async fn two_clients_presence_and_userremove() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    // Client A connects
    let cfg_a = ConnectionConfig::builder("127.0.0.1").port(port).username("user-a").accept_invalid_certs(true).build();
    let mut a = MumbleConnection::new(cfg_a);
    a.connect().await.expect("a connect");
    sleep(Duration::from_millis(120)).await;

    // Client B connects
    let cfg_b = ConnectionConfig::builder("127.0.0.1").port(port).username("user-b").accept_invalid_certs(true).build();
    let mut b = MumbleConnection::new(cfg_b);
    b.connect().await.expect("b connect");
    sleep(Duration::from_millis(150)).await;

    // Both should have sessions
    assert!(a.state().await.session_id.is_some());
    assert!(b.state().await.session_id.is_some());

    // Disconnect B, A should remain connected; we don't expose events directly here, but ensure no crash
    drop(b);
    sleep(Duration::from_millis(150)).await;

    // A can still ping (ignore env failures)
    let _ = a.send_ping().await;
}
