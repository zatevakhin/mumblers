use mumblers::audio::{AudioHeader, VoicePacket};
use mumblers::proto::mumble::ServerSync;
use mumblers::server::{ChannelConfig, MumbleServer, ServerConfig};
use mumblers::{ConnectionConfig, MumbleConnection, MumbleEvent};
use rcgen::generate_simple_self_signed;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::rustls;

fn init_tracing() {
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
    cfg.channels = vec![ChannelConfig {
        name: "Lobby".to_string(),
        parent: Some("Root".to_string()),
        description: None,
        position: Some(1),
        max_users: None,
        noenter: None,
        silent: None,
    }];
    let port = 20000 + (rand::random::<u16>() % 30000);
    cfg.bind_port = port;
    cfg.udp_bind_port = port;
    let tls = make_tls(&cfg);
    let server = MumbleServer::new(cfg, tls);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (port, handle)
}

async fn wait_for_event<F>(
    rx: &mut tokio::sync::broadcast::Receiver<MumbleEvent>,
    limit: Duration,
    mut predicate: F,
) -> Option<MumbleEvent>
where
    F: FnMut(&MumbleEvent) -> bool,
{
    let deadline = timeout(limit, async {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if predicate(&ev) {
                        return Some(ev);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    })
    .await;
    match deadline {
        Ok(found) => found,
        Err(_) => None,
    }
}

async fn connect_pair() -> (MumbleConnection, MumbleConnection, u32, u32) {
    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .accept_invalid_certs(true)
        .enable_udp(true)
        .build();
    let mut alice = MumbleConnection::new(cfg_a);
    let mut alice_events = alice.subscribe_events();

    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("bob")
        .accept_invalid_certs(true)
        .enable_udp(true)
        .build();
    let mut bob = MumbleConnection::new(cfg_b);
    let mut bob_events = bob.subscribe_events();

    alice.connect().await.expect("alice should connect");
    bob.connect().await.expect("bob should connect");

    // Allow handshake to settle
    sleep(Duration::from_millis(500)).await;

    // Wait for ServerSync on both clients
    let alice_session = alice.state().await.session_id.expect("alice session");
    let bob_session = bob.state().await.session_id.expect("bob session");

    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| matches!(
            ev,
            MumbleEvent::ServerSync(ServerSync {
                session: Some(id),
                ..
            }) if *id == alice_session
        ))
        .await
        .is_some(),
        "alice should receive ServerSync"
    );
    assert!(
        wait_for_event(&mut bob_events, Duration::from_secs(5), |ev| matches!(
            ev,
            MumbleEvent::ServerSync(ServerSync {
                session: Some(id),
                ..
            }) if *id == bob_session
        ))
        .await
        .is_some(),
        "bob should receive ServerSync"
    );

    alice
        .wait_for_udp_ready(Some(Duration::from_secs(5)))
        .await
        .expect("alice udp ready");
    bob.wait_for_udp_ready(Some(Duration::from_secs(5)))
        .await
        .expect("bob udp ready");

    // Drain remaining events
    // Prime UDP pairing for both clients so routing succeeds immediately.
    (alice, bob, alice_session, bob_session)
}

#[tokio::test]
async fn voice_roundtrip() {
    init_tracing();

    let (alice, bob, alice_session, _) = connect_pair().await;

    let mut bob_rx = bob.subscribe_events();
    while let Ok(_) = bob_rx.try_recv() {}

    // Prime Bob's UDP pairing by sending a silent frame.
    let primer = VoicePacket {
        header: AudioHeader::Target(0),
        sender_session: None,
        frame_number: 0,
        opus_data: vec![0],
        positional_data: None,
        volume_adjustment: None,
        is_terminator: false,
    };
    bob.send_audio(primer)
        .await
        .expect("bob sends priming audio");
    sleep(Duration::from_millis(50)).await;
    while let Ok(_) = bob_rx.try_recv() {}

    let packet = VoicePacket {
        header: AudioHeader::Target(0),
        sender_session: None,
        frame_number: 1,
        opus_data: vec![1, 2, 3, 4],
        positional_data: None,
        volume_adjustment: None,
        is_terminator: false,
    };

    alice
        .send_audio(packet.clone())
        .await
        .expect("alice sends audio");

    let audio_ev = wait_for_event(&mut bob_rx, Duration::from_secs(5), |ev| {
        matches!(ev, MumbleEvent::UdpAudio(_))
    })
    .await
    .expect("bob should observe udp audio");

    match audio_ev {
        MumbleEvent::UdpAudio(recv) => {
            assert_eq!(
                recv.sender_session,
                Some(alice_session),
                "audio should identify alice as sender"
            );
            assert_eq!(recv.frame_number, packet.frame_number);
            assert_eq!(recv.header, AudioHeader::Context(0));
            assert_eq!(recv.opus_data, packet.opus_data);
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn voice_out_of_order_delivery() {
    init_tracing();

    let (alice, bob, alice_session, _) = connect_pair().await;

    let mut bob_rx = bob.subscribe_events();
    while let Ok(_) = bob_rx.try_recv() {}

    let primer = VoicePacket {
        header: AudioHeader::Target(0),
        sender_session: None,
        frame_number: 0,
        opus_data: vec![0],
        positional_data: None,
        volume_adjustment: None,
        is_terminator: false,
    };
    bob.send_audio(primer)
        .await
        .expect("bob sends priming audio");
    sleep(Duration::from_millis(50)).await;
    while let Ok(_) = bob_rx.try_recv() {}

    let frames = [(1u64, vec![1u8]), (3u64, vec![3u8]), (2u64, vec![2u8])];

    for (frame, data) in frames.iter().cloned() {
        let packet = VoicePacket {
            header: AudioHeader::Target(0),
            sender_session: None,
            frame_number: frame,
            opus_data: data,
            positional_data: None,
            volume_adjustment: None,
            is_terminator: false,
        };
        alice
            .send_audio(packet)
            .await
            .expect("alice sends audio frame");
        // Small delay to avoid flooding
        sleep(Duration::from_millis(20)).await;
    }

    let mut received_frames = HashSet::new();
    let mut attempts = 0;
    while received_frames.len() < frames.len() && attempts < 10 {
        attempts += 1;
        if let Some(ev) = wait_for_event(&mut bob_rx, Duration::from_secs(2), |ev| {
            matches!(ev, MumbleEvent::UdpAudio(_))
        })
        .await
        {
            if let MumbleEvent::UdpAudio(pkt) = ev {
                assert_eq!(
                    pkt.sender_session,
                    Some(alice_session),
                    "udp audio should come from alice"
                );
                received_frames.insert(pkt.frame_number);
            }
        } else {
            break;
        }
    }

    assert_eq!(
        received_frames.len(),
        frames.len(),
        "bob should eventually observe all voice frames despite reordering"
    );
}
