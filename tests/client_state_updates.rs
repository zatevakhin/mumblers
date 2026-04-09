mod common;

use common::{start_server, start_server_with_config, wait_for_event};
use mumblers::server::ServerConfig;
use mumblers::{ConnectionConfig, MumbleConnection, MumbleEvent};
use tokio::time::{sleep, Duration};

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
        .await
        .is_some(),
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
        .await
        .is_some(),
        "bob should receive ServerSync"
    );

    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::UserState(user) if user.session == Some(bob_session))
        })
        .await
        .is_some(),
        "alice should observe bob join"
    );

    let state = alice.state().await;
    let bob_info = state.users.get(&bob_session).expect("bob in state");
    assert_eq!(bob_info.name.as_deref(), Some("bob"));
    assert_eq!(bob_info.channel_id, 0);

    drop(bob);
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::UserRemove(remove) if remove.session == bob_session)
        })
        .await
        .is_some(),
        "alice should observe bob removal"
    );

    let state = alice.state().await;
    assert!(state.users.get(&bob_session).is_none());

    handle.abort();
}

#[tokio::test]
async fn self_mute_propagates_to_other_client() {
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
        .build();
    let mut alice = MumbleConnection::new(cfg_a);
    let mut alice_events = alice.subscribe_events();
    alice.connect().await.expect("alice connect");
    let alice_session = alice.state().await.session_id.expect("alice session");
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(alice_session))
        })
        .await
        .is_some(),
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
        .await
        .is_some(),
        "bob should receive ServerSync"
    );
    // Wait for alice to see bob join
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::UserState(user) if user.session == Some(bob_session))
        })
        .await
        .is_some(),
        "alice should observe bob join"
    );

    // Bob self-mutes
    use mumblers::proto::mumble::UserState;
    let self_mute_msg = UserState {
        session: Some(bob_session),
        self_mute: Some(true),
        self_deaf: Some(true),
        ..Default::default()
    };
    bob.send_message(mumblers::messages::MumbleMessage::UserState(self_mute_msg))
        .await
        .expect("bob sends self-mute");

    // Alice should receive a UserState update with self_mute=true
    let got_update = wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
        if let MumbleEvent::UserState(us) = ev {
            us.session == Some(bob_session)
                && us.self_mute == Some(true)
                && us.self_deaf == Some(true)
        } else {
            false
        }
    })
    .await
    .is_some();
    assert!(
        got_update,
        "alice should see bob's self-mute/self-deaf state update"
    );

    // Client state should also reflect the update
    let state = alice.state().await;
    let bob_info = state
        .users
        .get(&bob_session)
        .expect("bob should be in alice's state");
    assert!(
        bob_info.self_mute,
        "bob should be self-muted in alice's state"
    );
    assert!(
        bob_info.self_deaf,
        "bob should be self-deafened in alice's state"
    );
}

#[tokio::test]
async fn server_rejects_when_max_users_reached() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    let mut cfg = ServerConfig::default();
    cfg.max_users = Some(1);
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    // First connection should succeed
    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .accept_invalid_certs(true)
        .build();
    let mut alice = MumbleConnection::new(cfg_a);
    let mut alice_events = alice.subscribe_events();
    alice.connect().await.expect("alice should connect");
    let alice_session = alice.state().await.session_id.expect("alice session");
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(alice_session))
        })
        .await
        .is_some(),
        "alice should receive ServerSync"
    );

    // Second connection should be rejected with ServerFull
    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("bob")
        .accept_invalid_certs(true)
        .build();
    let mut bob = MumbleConnection::new(cfg_b);
    let result = bob.connect().await;
    assert!(
        result.is_err(),
        "bob should fail to connect when server is full"
    );
}

#[tokio::test]
async fn server_rejects_duplicate_username() {
    common::init_tracing();

    let (port, _handle) = start_server().await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("same_name")
        .accept_invalid_certs(true)
        .build();
    let mut alice = MumbleConnection::new(cfg_a);
    let mut alice_events = alice.subscribe_events();
    alice.connect().await.expect("first client should connect");
    let alice_session = alice.state().await.session_id.expect("alice session");
    assert!(
        wait_for_event(&mut alice_events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(alice_session))
        })
        .await
        .is_some(),
        "first client should receive ServerSync"
    );

    // Second client with the same username should be rejected
    let cfg_b = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("same_name")
        .accept_invalid_certs(true)
        .build();
    let mut bob = MumbleConnection::new(cfg_b);
    let result = bob.connect().await;
    assert!(
        result.is_err(),
        "second client with duplicate username should be rejected"
    );
}

#[tokio::test]
async fn server_rejects_empty_username_when_anonymous_disabled() {
    common::init_tracing();

    let mut cfg = ServerConfig::default();
    cfg.allow_anonymous = Some(false);
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("")
        .accept_invalid_certs(true)
        .build();
    let mut client = MumbleConnection::new(cfg_a);
    let result = client.connect().await;
    assert!(
        result.is_err(),
        "empty username should be rejected when allow_anonymous=false"
    );
}

// NOTE: server_accepts_empty_username_when_anonymous_enabled is not tested here
// because the client itself rejects empty usernames before connecting.
// The server's allow_anonymous path assigns "GuestN" names for empty usernames
// that arrive over the wire (e.g. from other Mumble clients).

#[tokio::test]
async fn server_rejects_wrong_password() {
    common::init_tracing();

    let mut cfg = ServerConfig::default();
    cfg.password = Some("secret123".to_string());
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    // Wrong password should be rejected
    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .password("wrongpass")
        .accept_invalid_certs(true)
        .build();
    let mut client = MumbleConnection::new(cfg_a);
    let result = client.connect().await;
    assert!(result.is_err(), "wrong password should be rejected");
}

#[tokio::test]
async fn server_accepts_correct_password() {
    common::init_tracing();

    let mut cfg = ServerConfig::default();
    cfg.password = Some("secret123".to_string());
    let (port, _handle) = start_server_with_config(cfg).await;
    sleep(Duration::from_millis(200)).await;

    let cfg_a = ConnectionConfig::builder("127.0.0.1")
        .port(port)
        .username("alice")
        .password("secret123")
        .accept_invalid_certs(true)
        .build();
    let mut client = MumbleConnection::new(cfg_a);
    let mut events = client.subscribe_events();
    client
        .connect()
        .await
        .expect("correct password should be accepted");
    let session = client.state().await.session_id.expect("session");
    assert!(
        wait_for_event(&mut events, Duration::from_secs(5), |ev| {
            matches!(ev, MumbleEvent::ServerSync(sync) if sync.session == Some(session))
        })
        .await
        .is_some(),
        "should receive ServerSync with correct password"
    );
}
