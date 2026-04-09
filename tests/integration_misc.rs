mod common;

use common::{init_tracing, start_server, start_server_with_config, wait_for_event};
use mumblers::audio::{AudioHeader, VoicePacket};
use mumblers::messages::MumbleMessage;
use mumblers::proto::mumble::ServerSync;
use mumblers::server::{ChannelConfig, ServerConfig};
use mumblers::{ConnectionConfig, MumbleConnection, MumbleEvent};
use tokio::time::{sleep, Duration};

async fn connect_client(
    port: u16,
    name: &str,
    enable_udp: bool,
) -> (
    MumbleConnection,
    u32,
    tokio::sync::broadcast::Receiver<MumbleEvent>,
) {
    let cfg = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username(name)
        .accept_invalid_certs(true)
        .enable_udp(enable_udp)
        .build();
    let mut conn = MumbleConnection::new(cfg);
    let mut events = conn.subscribe_events();
    conn.connect()
        .await
        .unwrap_or_else(|e| panic!("{name} connect: {e}"));
    sleep(Duration::from_millis(300)).await;
    let session = conn
        .state()
        .await
        .session_id
        .unwrap_or_else(|| panic!("{name} session"));
    assert!(
        wait_for_event(&mut events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(ServerSync { session: Some(id), .. }) if *id == session)
        })
        .await
        .is_some(),
        "{name} should receive ServerSync"
    );
    if enable_udp {
        conn.wait_for_udp_ready(Some(Duration::from_secs(5)))
            .await
            .unwrap_or_else(|e| panic!("{name} udp ready: {e}"));
    }
    (conn, session, events)
}

// --- Test: silent channel drops audio ---

#[tokio::test]
async fn silent_channel_drops_audio() {
    init_tracing();

    let mut cfg = ServerConfig::default();
    cfg.default_channel = "Silent".to_string();
    cfg.channels = vec![ChannelConfig {
        name: "Silent".to_string(),
        parent: Some("Root".to_string()),
        description: None,
        position: Some(1),
        max_users: None,
        noenter: None,
        silent: Some(true),
    }];
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    let (alice, _alice_session, _) = connect_client(port, "alice", true).await;
    let (bob, _bob_session, _) = connect_client(port, "bob", true).await;

    let mut bob_rx = bob.subscribe_events();
    while let Ok(_) = bob_rx.try_recv() {}

    // Alice sends audio -- should be dropped by the silent channel
    let packet = VoicePacket {
        header: AudioHeader::Target(0),
        sender_session: None,
        frame_number: 1,
        opus_data: vec![1, 2, 3],
        positional_data: None,
        volume_adjustment: None,
        is_terminator: false,
    };
    for _ in 0..5 {
        alice
            .send_audio(packet.clone())
            .await
            .expect("alice send audio");
        sleep(Duration::from_millis(30)).await;
    }

    let got = wait_for_event(&mut bob_rx, Duration::from_secs(1), |ev| {
        matches!(ev, MumbleEvent::UdpAudio(_))
    })
    .await;
    assert!(
        got.is_none(),
        "bob should NOT receive audio in a silent channel"
    );
}

// --- Test: multiple simultaneous talkers ---

#[tokio::test]
async fn multiple_simultaneous_talkers() {
    init_tracing();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let (alice, alice_session, _) = connect_client(port, "alice", true).await;
    let (bob, bob_session, _) = connect_client(port, "bob", true).await;
    let (carol, _carol_session, _) = connect_client(port, "carol", true).await;

    let mut carol_rx = carol.subscribe_events();
    while let Ok(_) = carol_rx.try_recv() {}

    // Both alice and bob send audio
    for i in 0..5u64 {
        let pkt_a = VoicePacket {
            header: AudioHeader::Target(0),
            sender_session: None,
            frame_number: 100 + i,
            opus_data: vec![0xAA],
            positional_data: None,
            volume_adjustment: None,
            is_terminator: false,
        };
        let pkt_b = VoicePacket {
            header: AudioHeader::Target(0),
            sender_session: None,
            frame_number: 200 + i,
            opus_data: vec![0xBB],
            positional_data: None,
            volume_adjustment: None,
            is_terminator: false,
        };
        alice.send_audio(pkt_a).await.expect("alice send");
        bob.send_audio(pkt_b).await.expect("bob send");
        sleep(Duration::from_millis(30)).await;
    }

    // Carol should receive audio from both senders
    let mut saw_alice = false;
    let mut saw_bob = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if saw_alice && saw_bob {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(500), carol_rx.recv()).await {
            Ok(Ok(MumbleEvent::UdpAudio(pkt))) => {
                if pkt.sender_session == Some(alice_session) {
                    saw_alice = true;
                }
                if pkt.sender_session == Some(bob_session) {
                    saw_bob = true;
                }
            }
            _ => continue,
        }
    }
    assert!(saw_alice, "carol should receive audio from alice");
    assert!(saw_bob, "carol should receive audio from bob");
}

// --- Test: positional audio roundtrip ---

#[tokio::test]
async fn positional_audio_roundtrip() {
    init_tracing();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let (alice, alice_session, _) = connect_client(port, "alice", true).await;
    let (_bob, _bob_session, _) = connect_client(port, "bob", true).await;

    let mut bob_rx = _bob.subscribe_events();
    while let Ok(_) = bob_rx.try_recv() {}

    let positions = [1.0f32, 2.0, 3.0];
    let packet = VoicePacket {
        header: AudioHeader::Target(0),
        sender_session: None,
        frame_number: 42,
        opus_data: vec![10, 20, 30],
        positional_data: Some(positions),
        volume_adjustment: None,
        is_terminator: false,
    };
    for _ in 0..5 {
        alice
            .send_audio(packet.clone())
            .await
            .expect("alice send positional");
        sleep(Duration::from_millis(30)).await;
    }

    let got = wait_for_event(&mut bob_rx, Duration::from_secs(3), |ev| {
        if let MumbleEvent::UdpAudio(pkt) = ev {
            pkt.sender_session == Some(alice_session) && pkt.positional_data.is_some()
        } else {
            false
        }
    })
    .await;
    assert!(got.is_some(), "bob should receive positional audio");
    if let Some(MumbleEvent::UdpAudio(pkt)) = got {
        let pos = pkt.positional_data.expect("positional data");
        assert_eq!(pos, positions, "positional coordinates should be preserved");
    }
}

// --- Test: text message to non-member channel ---

#[tokio::test]
async fn text_message_to_channel_user_is_not_in() {
    init_tracing();

    let mut cfg = ServerConfig::default();
    cfg.default_channel = "Lobby".to_string();
    cfg.channels = vec![
        ChannelConfig {
            name: "Lobby".to_string(),
            parent: Some("Root".to_string()),
            description: None,
            position: Some(1),
            max_users: None,
            noenter: None,
            silent: None,
        },
        ChannelConfig {
            name: "Other".to_string(),
            parent: Some("Root".to_string()),
            description: None,
            position: Some(2),
            max_users: None,
            noenter: None,
            silent: None,
        },
    ];
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    let (alice, _, _) = connect_client(port, "alice", false).await;
    let (bob, bob_session, _) = connect_client(port, "bob", false).await;

    // Move bob to "Other" channel
    let state = bob.state().await;
    let other_id = state
        .channels
        .lock()
        .await
        .find_by_name("Other")
        .map(|ch| ch.channel_id)
        .expect("Other channel should exist");
    bob.move_user_to_channel(bob_session, other_id)
        .await
        .expect("bob move to Other");
    sleep(Duration::from_millis(200)).await;

    let mut alice_rx = alice.subscribe_events();
    while let Ok(_) = alice_rx.try_recv() {}

    // Alice sends text to "Other" channel (she's not in it)
    let text = mumblers::proto::mumble::TextMessage {
        channel_id: vec![other_id],
        message: "hello from outside".to_string(),
        ..Default::default()
    };
    alice
        .send_message(MumbleMessage::TextMessage(text))
        .await
        .expect("alice send text to Other");

    // Server should deny it: alice is not in the target channel
    let denied = wait_for_event(
        &mut alice_rx,
        Duration::from_secs(3),
        |ev| matches!(ev, MumbleEvent::PermissionDenied(pd) if pd.channel_id == Some(other_id)),
    )
    .await;
    assert!(
        denied.is_some(),
        "alice should receive PermissionDenied for cross-channel text"
    );
}

// --- Test: corrupt/malformed protobuf payloads ---

#[tokio::test]
async fn corrupt_payloads_dont_crash_server() {
    init_tracing();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    // Connect alice normally
    let (alice, _alice_session, _) = connect_client(port, "alice", false).await;

    // Send garbage data as a UserState message (type 9)
    // This should not crash the server
    let garbage = mumblers::messages::MessageEnvelope {
        kind: mumblers::messages::TcpMessageKind::UserState,
        payload: vec![0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02],
    };
    let _ = alice.send_message(MumbleMessage::Unknown(garbage)).await;
    sleep(Duration::from_millis(200)).await;

    // Connect bob after the garbage -- server should still be alive
    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("bob")
        .accept_invalid_certs(true)
        .build();
    let mut bob = MumbleConnection::new(cfg_b);
    let mut bob_events = bob.subscribe_events();
    bob.connect()
        .await
        .expect("bob should connect after garbage");
    let bob_session = bob.state().await.session_id.expect("bob session");
    assert!(
        wait_for_event(&mut bob_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(bob_session))
        })
        .await
        .is_some(),
        "bob should receive ServerSync (server survived garbage)"
    );
}

// --- Test: rapid connect/disconnect cycles ---

#[tokio::test]
async fn rapid_connect_disconnect_cycles() {
    init_tracing();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    // Connect and immediately disconnect 10 clients
    for i in 0..10 {
        let cfg = ConnectionConfig::builder("127.0.0.1")
            .port(port)
            .username(&format!("rapid{i}"))
            .accept_invalid_certs(true)
            .build();
        let mut client = MumbleConnection::new(cfg);
        let _ = client.connect().await;
        drop(client);
    }

    sleep(Duration::from_millis(300)).await;

    // Now connect a real client and verify the server is healthy
    let (observer, _obs_session, _obs_events) = connect_client(port, "observer", false).await;

    // The observer should see only itself (all rapid clients disconnected)
    let state = observer.state().await;
    assert_eq!(
        state.users.len(),
        1,
        "only the observer should be connected"
    );
}
