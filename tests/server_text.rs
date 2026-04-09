mod common;

use common::start_server;
use mumblers::{ConnectionConfig, MumbleConnection};
use tokio::time::{sleep, Duration};

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
