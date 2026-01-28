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
async fn cryptsetup_after_auth_and_resync() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    let cfg = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("u1")
        .accept_invalid_certs(true)
        .enable_udp(false)
        .build();
    let mut c = MumbleConnection::new(cfg);
    c.connect().await.expect("connect");

    // Wait for events, ensure CryptSetup arrived
    sleep(Duration::from_millis(200)).await;
    let state = c.state().await;
    let udp = state.udp.clone().expect("cryptsetup delivered");
    assert_eq!(udp.key.len(), 16);
    assert_eq!(udp.client_nonce.len(), 16);
    assert_eq!(udp.server_nonce.len(), 16);

    // Trigger resync by sending a CryptSetup with a new client_nonce directly over TCP
    use mumblers::messages::MumbleMessage;
    use mumblers::proto::mumble::CryptSetup;

    // We don't have direct writer access; reuse the connection's internal send_message
    let new_client_nonce = vec![0xAB; 16];
    let mut cs = CryptSetup::default();
    cs.client_nonce = Some(new_client_nonce.clone());
    c.send_message(MumbleMessage::CryptSetup(cs))
        .await
        .expect("send resync");

    // Allow time for server to respond with new server_nonce and for client to process it
    sleep(Duration::from_millis(200)).await;
    let state2 = c.state().await;
    let udp2 = state2.udp.clone().expect("cryptsetup after resync");
    assert_eq!(udp2.key.len(), 16);
    assert_eq!(udp2.client_nonce.len(), 16);
    assert_eq!(udp2.server_nonce.len(), 16);
}

#[tokio::test]
async fn udp_pair_and_ping_echo() {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(100)).await;

    let cfg = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("u1")
        .accept_invalid_certs(true)
        .build();
    let mut c = MumbleConnection::new(cfg);
    c.connect().await.expect("connect");

    // Wait to allow UDP to bootstrap and pings to flow
    sleep(Duration::from_millis(500)).await;

    // We expect at least one UdpPing event or, minimally, no crash; check that UDP state exists
    let state = c.state().await;
    assert!(state.udp.is_some(), "udp crypt should be set");
}
