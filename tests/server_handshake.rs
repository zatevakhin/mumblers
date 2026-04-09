mod common;

use common::start_server;
use mumblers::{ConnectionConfig, MumbleConnection};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn server_handshake_smoke() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let (port, _handle) = start_server().await;
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
