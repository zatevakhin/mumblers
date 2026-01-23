use mumblers::server::{MumbleServer, ServerConfig};
use mumblers::{ConnectionConfig, MumbleConnection, MumbleEvent};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration, Instant};
use tokio_rustls::rustls;

async fn start_server() -> (u16, tokio::task::JoinHandle<()>) {
    fn make_tls() -> Arc<rustls::ServerConfig> {
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
    cfg.udp_bind_port = port;
    let tls = make_tls();
    let server = MumbleServer::new(cfg, tls);
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (port, handle)
}

#[tokio::test]
async fn client_state_tracks_user_join_and_remove() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    let (port, handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .accept_invalid_certs(true)
        .build();
    let mut alice = MumbleConnection::new(cfg_a);
    let mut alice_events = alice.subscribe_events();
    alice.connect().await.expect("alice connect");
    let alice_session = alice.state().await.session_id.expect("alice session");
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(alice_session))
        })
        .await,
        "alice should receive ServerSync"
    );

    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("bob")
        .accept_invalid_certs(true)
        .build();
    let mut bob = MumbleConnection::new(cfg_b);
    let mut bob_events = bob.subscribe_events();
    bob.connect().await.expect("bob connect");
    let bob_session = bob.state().await.session_id.expect("bob session");
    assert!(
        wait_for_event(&mut bob_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(bob_session))
        })
        .await,
        "bob should receive ServerSync"
    );

    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::UserState(user) if user.session == Some(bob_session))
        })
        .await,
        "alice should observe bob join"
    );

    let state = alice.state().await;
    assert_eq!(
        state.users.get(&bob_session).map(String::as_str),
        Some("bob")
    );
    assert_eq!(state.user_channels.get(&bob_session), Some(&0));

    drop(bob);
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::UserRemove(remove) if remove.session == bob_session)
        })
        .await,
        "alice should observe bob removal"
    );

    let state = alice.state().await;
    assert!(state.users.get(&bob_session).is_none());
    assert!(state.user_channels.get(&bob_session).is_none());

    handle.abort();
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
