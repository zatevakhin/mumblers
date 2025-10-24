use mumblers::proto::mumble::permission_denied::DenyType as PermissionDenyType;
use mumblers::{
    server::{ChannelConfig, MumbleServer, ServerConfig},
    ConnectionConfig, MumbleConnection, MumbleEvent,
};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration, Instant};
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
            name: "Games".to_string(),
            parent: Some("Lobby".to_string()),
            description: None,
            position: Some(2),
            max_users: None,
            noenter: None,
            silent: None,
        },
        ChannelConfig {
            name: "AFK".to_string(),
            parent: Some("Root".to_string()),
            description: None,
            position: Some(3),
            max_users: Some(1),
            noenter: Some(true),
            silent: None,
        },
    ];
    let port = 20000 + (rand::random::<u16>() % 30000);
    cfg.bind_port = port;
    cfg.udp_bind_port = 40000 + (rand::random::<u16>() % 20000);
    let tls = make_tls(&cfg);
    let server = MumbleServer::new(cfg, tls);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (port, handle)
}

#[tokio::test]
async fn full_stack_text_and_udp() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .accept_invalid_certs(true)
        .enable_udp(true)
        .build();
    let mut a = MumbleConnection::new(cfg_a);
    let mut a_events = a.subscribe_events();

    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("bob")
        .accept_invalid_certs(true)
        .enable_udp(true)
        .build();
    let mut b = MumbleConnection::new(cfg_b);
    let mut b_events = b.subscribe_events();

    a.connect().await.expect("alice connect");
    b.connect().await.expect("bob connect");

    // Allow initial handshake and UDP bootstrap
    sleep(Duration::from_secs(1)).await;

    // Wait until both clients report ServerSync so we know handshake is complete
    let a_session = a.state().await.session_id.expect("alice session");
    let b_session = b.state().await.session_id.expect("bob session");
    assert!(
        wait_for_event(&mut a_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(a_session))
        })
        .await,
        "alice should receive ServerSync"
    );
    assert!(
        wait_for_event(&mut b_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(b_session))
        })
        .await,
        "bob should receive ServerSync"
    );

    // Clear any leftover handshake events before sending messages
    while let Ok(_) = b_events.try_recv() {}
    while let Ok(_) = a_events.try_recv() {}

    let games_channel_id = {
        let state = a.state().await;
        let channels = state.channels.lock().await;
        channels
            .find_by_name("Games")
            .expect("games channel")
            .channel_id
    };
    let afk_channel_id = {
        let state = a.state().await;
        let channels = state.channels.lock().await;
        channels
            .find_by_name("AFK")
            .expect("afk channel")
            .channel_id
    };

    let mut bob_observe_alice_rx = b.subscribe_events();
    while let Ok(_) = bob_observe_alice_rx.try_recv() {}

    // TODO(issue): Flaky – server sometimes drops Alice's self UserState echo during channel move.
    assert!(
        join_channel_and_wait(
            &a,
            "Games",
            games_channel_id,
            a_session,
            Duration::from_secs(5)
        )
        .await,
        "alice should see her own channel update"
    );
    // TODO(issue): Same flake – Bob can miss Alice's move event when the echo is lost.
    assert!(
        wait_for_event(
            &mut bob_observe_alice_rx,
            Duration::from_secs(5),
            |ev| matches!(
                ev,
                MumbleEvent::UserState(user)
                    if user.session == Some(a_session)
                        && user.channel_id == Some(games_channel_id)
            )
        )
        .await,
        "bob should observe alice moving to games"
    );

    let mut alice_observe_bob_rx = a.subscribe_events();
    while let Ok(_) = alice_observe_bob_rx.try_recv() {}

    assert!(
        join_channel_and_wait(
            &b,
            "Games",
            games_channel_id,
            b_session,
            Duration::from_secs(5)
        )
        .await,
        "bob should see his own channel update"
    );
    assert!(
        wait_for_event(
            &mut alice_observe_bob_rx,
            Duration::from_secs(5),
            |ev| matches!(
                ev,
                MumbleEvent::UserState(user)
                    if user.session == Some(b_session)
                        && user.channel_id == Some(games_channel_id)
            )
        )
        .await,
        "alice should observe bob moving to games"
    );

    while let Ok(_) = a_events.try_recv() {}

    a.join_channel_by_name("AFK")
        .await
        .expect("alice attempt afk");
    assert!(
        wait_for_event(&mut a_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::PermissionDenied(pd) if pd.r#type == Some(PermissionDenyType::Permission as i32) && pd.channel_id == Some(afk_channel_id))
        })
        .await,
        "alice should receive PermissionDenied for AFK"
    );
    {
        let state = a.state().await;
        assert_eq!(
            state.user_channels.get(&a_session),
            Some(&games_channel_id),
            "alice should remain in games"
        );
    }

    // Channel text message (retry a few times if the queue is flooded by UDP events)
    let mut channel_ok = false;
    for attempt in 0..5 {
        let mut rx = b.subscribe_events();
        while let Ok(_) = rx.try_recv() {}
        a.send_channel_message_by_name("Games", "hello from alice".to_string())
            .await
            .expect("alice text");
        if wait_for_event(
            &mut rx,
            Duration::from_secs(5),
            |ev| matches!(ev, MumbleEvent::TextMessage(msg) if msg.message == "hello from alice"),
        )
        .await
        {
            channel_ok = true;
            break;
        }
        tracing::warn!(attempt, "channel text not received, retrying");
        sleep(Duration::from_millis(200)).await;
    }
    assert!(channel_ok, "bob should receive channel text");

    // Private message (same approach)
    let mut whisper_ok = false;
    for attempt in 0..5 {
        let mut rx = b.subscribe_events();
        while let Ok(_) = rx.try_recv() {}
        let b_session = b.state().await.session_id.expect("bob session");
        a.send_private_message(b_session, "whisper from alice".to_string())
            .await
            .expect("alice whisper");
        if wait_for_event(
            &mut rx,
            Duration::from_secs(5),
            |ev| matches!(ev, MumbleEvent::TextMessage(msg) if msg.message == "whisper from alice"),
        )
        .await
        {
            whisper_ok = true;
            break;
        }
        tracing::warn!(attempt, "private whisper not received, retrying");
        sleep(Duration::from_millis(200)).await;
    }
    assert!(whisper_ok, "bob should receive text message");

    assert!(
        b.state().await.udp.is_some(),
        "bob should have CryptSetup state"
    );

    // UDP keepalive check (best effort)
    let mut udp_rx = a.subscribe_events();
    while let Ok(_) = udp_rx.try_recv() {}
    if !wait_for_event(&mut udp_rx, Duration::from_secs(5), |ev| {
        matches!(ev, MumbleEvent::UdpPing(_))
    })
    .await
    {
        let state = a.state().await;
        assert!(state.udp.is_some(), "alice UDP state should be initialized");
    }
}

async fn join_channel_and_wait(
    conn: &MumbleConnection,
    channel_name: &str,
    channel_id: u32,
    session: u32,
    timeout: Duration,
) -> bool {
    let mut rx = conn.subscribe_events();
    while let Ok(_) = rx.try_recv() {}
    conn.join_channel_by_name(channel_name)
        .await
        .expect("join channel");
    let observed = wait_for_event(&mut rx, timeout, |ev| {
        matches!(
            ev,
            MumbleEvent::UserState(user)
                if user.session == Some(session) && user.channel_id == Some(channel_id)
        )
    })
    .await;
    if !observed {
        tracing::warn!(session, channel_id, "join_channel_and_wait timed out");
    }
    observed
}

async fn wait_for_event<F>(
    rx: &mut tokio::sync::broadcast::Receiver<MumbleEvent>,
    timeout_dur: Duration,
    mut pred: F,
) -> bool
where
    F: FnMut(&MumbleEvent) -> bool,
{
    let deadline = Instant::now() + timeout_dur;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        match timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) => {
                tracing::info!(?ev, "integration_full: event observed");
                if pred(&ev) {
                    return true;
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(_)) => return false,
            Err(_) => return false,
        }
    }
}
