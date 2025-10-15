use std::sync::Arc;
use std::time::Duration;

use mumblers::connection::MumbleEvent;
use mumblers::messages::{MessageEnvelope, MumbleMessage, TcpMessageKind};
use mumblers::proto::mumble::{ChannelState, ServerSync, TextMessage, UserState, Version};
use mumblers::{ConnectionConfig, MumbleConnection};
use rcgen::generate_simple_self_signed;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::rustls::{self, ServerConfig as TlsServerConfig};
use tokio_rustls::TlsAcceptor;

struct MockMumbleServer {
    addr: String,
    shutdown_tx: broadcast::Sender<bool>,
}

impl MockMumbleServer {
    async fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(
            cert.serialize_der().unwrap(),
        )];

        let mut tls_config = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        tls_config.alpn_protocols = vec![b"mumble".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_rx.recv() => {},
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let stream = acceptor.accept(stream).await.unwrap();
                            let (mut reader, mut writer) = tokio::io::split(stream);

                            // Read version
                            let envelope =
                                mumblers::messages::read_envelope(&mut reader).await.unwrap();
                            let _version =
                                MumbleMessage::try_from(envelope).unwrap();

                            // Read auth
                            let envelope =
                                mumblers::messages::read_envelope(&mut reader).await.unwrap();
                            let _auth =
                                MumbleMessage::try_from(envelope).unwrap();

                            // Write version
                            let version = Version {
                                version_v1: Some(1),
                                ..Default::default()
                            };
                            let envelope = MessageEnvelope::try_from_message(
                                TcpMessageKind::Version,
                                &version,
                            )
                            .unwrap();
                            envelope.write_to(&mut writer).await.unwrap();

                             // Write server sync
                             let server_sync = ServerSync {
                                 session: Some(1),
                                 ..Default::default()
                             };
                             let envelope = MessageEnvelope::try_from_message(
                                 TcpMessageKind::ServerSync,
                                 &server_sync,
                             )
                             .unwrap();
                             envelope.write_to(&mut writer).await.unwrap();

                             // Send simulated channel state
                             let channel_state = ChannelState {
                                 channel_id: Some(0),
                                 name: Some("Root".to_string()),
                                 ..Default::default()
                             };
                             let envelope = MessageEnvelope::try_from_message(
                                 TcpMessageKind::ChannelState,
                                 &channel_state,
                             )
                             .unwrap();
                             envelope.write_to(&mut writer).await.unwrap();

                             // Send simulated user state
                             let user_state = UserState {
                                 session: Some(1),
                                 name: Some("TestUser".to_string()),
                                 channel_id: Some(0),
                                 ..Default::default()
                             };
                             let envelope = MessageEnvelope::try_from_message(
                                 TcpMessageKind::UserState,
                                 &user_state,
                             )
                             .unwrap();
                             envelope.write_to(&mut writer).await.unwrap();

                              // Send simulated text message
                              let text_message = TextMessage {
                                  actor: Some(1),
                                  message: "Hello from simulated server!".to_string(),
                                  ..Default::default()
                              };
                              let envelope = MessageEnvelope::try_from_message(
                                  TcpMessageKind::TextMessage,
                                  &text_message,
                              )
                              .unwrap();
                              envelope.write_to(&mut writer).await.unwrap();

                              // Send simulated channel remove
                              let channel_remove = mumblers::proto::mumble::ChannelRemove {
                                  channel_id: 999, // Non-existent channel
                              };
                              let envelope = MessageEnvelope::try_from_message(
                                  TcpMessageKind::ChannelRemove,
                                  &channel_remove,
                              )
                              .unwrap();
                              envelope.write_to(&mut writer).await.unwrap();

                              // Send simulated user state for move
                              let user_state_move = UserState {
                                  session: Some(1),
                                  channel_id: Some(1), // Move to channel 1
                                  ..Default::default()
                              };
                              let envelope = MessageEnvelope::try_from_message(
                                  TcpMessageKind::UserState,
                                  &user_state_move,
                              )
                              .unwrap();
                              envelope.write_to(&mut writer).await.unwrap();

                              // Send simulated permission denied
                              let permission_denied = mumblers::proto::mumble::PermissionDenied {
                                  permission: Some(1),
                                  channel_id: Some(1),
                                  ..Default::default()
                              };
                              let envelope = MessageEnvelope::try_from_message(
                                  TcpMessageKind::PermissionDenied,
                                  &permission_denied,
                              )
                              .unwrap();
                              envelope.write_to(&mut writer).await.unwrap();
                        });
                    }
                }
            }
        });

        Self { addr, shutdown_tx }
    }

    fn addr(&self) -> &str {
        &self.addr
    }
}

impl Drop for MockMumbleServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[tokio::test]
async fn test_event_stream_version() {
    let server = MockMumbleServer::new().await;
    let host_port: Vec<&str> = server.addr().split(':').collect();
    let host = host_port[0];
    let port = host_port[1].parse().unwrap();

    let mut config = ConnectionConfig::builder(host).port(port).build();
    config.accept_invalid_certs = true;

    let mut connection = MumbleConnection::new(config);
    let mut events = connection.subscribe_events();

    connection.connect().await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();

    if let MumbleEvent::Version(_) = event {
        // expected
    } else {
        panic!("Expected MumbleEvent::Version, got {:?}", event);
    }
}

#[tokio::test]
async fn test_event_stream_channel_user_text() {
    let server = MockMumbleServer::new().await;
    let host_port: Vec<&str> = server.addr().split(':').collect();
    let host = host_port[0];
    let port = host_port[1].parse().unwrap();

    let mut config = ConnectionConfig::builder(host).port(port).build();
    config.accept_invalid_certs = true;

    let mut connection = MumbleConnection::new(config);
    let mut events = connection.subscribe_events();

    connection.connect().await.unwrap();

    // Receive Version event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, MumbleEvent::Version(_)));

    // Receive ServerSync event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, MumbleEvent::ServerSync(_)));

    // Receive ChannelState event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::ChannelState(channel_state) = event {
        assert_eq!(channel_state.channel_id, Some(0));
        assert_eq!(channel_state.name, Some("Root".to_string()));
    } else {
        panic!("Expected MumbleEvent::ChannelState, got {:?}", event);
    }

    // Receive UserState event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::UserState(user_state) = event {
        assert_eq!(user_state.session, Some(1));
        assert_eq!(user_state.name, Some("TestUser".to_string()));
        assert_eq!(user_state.channel_id, Some(0));
    } else {
        panic!("Expected MumbleEvent::UserState, got {:?}", event);
    }

    // Receive TextMessage event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::TextMessage(text_message) = event {
        assert_eq!(text_message.actor, Some(1));
        assert_eq!(
            text_message.message,
            "Hello from simulated server!".to_string()
        );
    } else {
        panic!("Expected MumbleEvent::TextMessage, got {:?}", event);
    }

    // Receive ChannelRemove event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::ChannelRemove(channel_remove) = event {
        assert_eq!(channel_remove.channel_id, 999);
    } else {
        panic!("Expected MumbleEvent::ChannelRemove, got {:?}", event);
    }

    // Receive UserState event for move
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::UserState(user_state) = event {
        assert_eq!(user_state.session, Some(1));
        assert_eq!(user_state.channel_id, Some(1));
    } else {
        panic!("Expected MumbleEvent::UserState, got {:?}", event);
    }

    // Receive PermissionDenied event
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    if let MumbleEvent::PermissionDenied(permission_denied) = event {
        assert_eq!(permission_denied.permission, Some(1));
        assert_eq!(permission_denied.channel_id, Some(1));
    } else {
        panic!("Expected MumbleEvent::PermissionDenied, got {:?}", event);
    }

    // Verify channel manager state
    let state = connection.state().await;
    let channels = state.channels.lock().await;
    assert!(channels.get(0).is_some()); // Root channel
    assert!(channels.get(999).is_none()); // Removed channel

    // Verify user channels
    assert_eq!(state.user_channels.get(&1), Some(&1)); // User moved to channel 1
}
