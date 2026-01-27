use std::sync::Arc;

use mumblers::connection::MumbleEvent;
use mumblers::messages::{MessageEnvelope, MumbleMessage, TcpMessageKind};
use mumblers::proto::mumble::{Ping, ServerSync, TextMessage, Version};
use mumblers::{ConnectionConfig, MumbleConnection};
use rcgen::generate_simple_self_signed;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::rustls::{self, ServerConfig as TlsServerConfig};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn tcp_reader_does_not_desync_on_partial_preamble() {
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
    let addr = listener.local_addr().unwrap();

    let (sent_partial_tx, sent_partial_rx) = oneshot::channel::<()>();
    let (send_rest_tx, send_rest_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(sock).await.unwrap();

        // Client sends Version, Authenticate, CodecVersion.
        for _ in 0..3 {
            let _ = mumblers::messages::read_envelope(&mut tls).await.unwrap();
        }

        // Complete handshake.
        let version = Version {
            version_v1: Some(1),
            ..Default::default()
        };
        let env = MessageEnvelope::try_from_message(TcpMessageKind::Version, &version).unwrap();
        env.write_to(&mut tls).await.unwrap();

        let sync = ServerSync {
            session: Some(1),
            ..Default::default()
        };
        let env = MessageEnvelope::try_from_message(TcpMessageKind::ServerSync, &sync).unwrap();
        env.write_to(&mut tls).await.unwrap();

        // Send a post-handshake message with a deliberately fragmented preamble.
        let msg = TextMessage {
            actor: Some(1),
            message: "hello".to_string(),
            ..Default::default()
        };
        let env = MessageEnvelope::try_from_message(TcpMessageKind::TextMessage, &msg).unwrap();
        let bytes = env.to_bytes();

        // First half: partial preamble.
        tls.write_all(&bytes[..3]).await.unwrap();
        let _ = sent_partial_tx.send(());

        // Wait until client nudges the connection loop (cmd branch).
        let _ = send_rest_rx.await;

        // Second half: remainder of preamble + payload.
        tls.write_all(&bytes[3..]).await.unwrap();

        // Keep connection alive.
        let _ = mumblers::messages::read_envelope(&mut tls).await;
    });

    let cfg = ConnectionConfig::builder("127.0.0.1")
        .port(addr.port())
        .username("u1")
        .accept_invalid_certs(true)
        .enable_udp(false)
        .build();
    let mut connection = MumbleConnection::new(cfg);
    let mut events = connection.subscribe_events();

    connection.connect().await.unwrap();

    // Ensure the server has written the partial preamble.
    let _ = sent_partial_rx.await;

    // Let the connection task start its read.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    // Nudge the connection loop so cmd processing interleaves with reads.
    connection
        .send_message(MumbleMessage::Ping(Ping::default()))
        .await
        .unwrap();

    let _ = send_rest_tx.send(());

    // Drain until we see the TextMessage.
    for _ in 0..8 {
        if let Ok(event) = events.try_recv() {
            if let MumbleEvent::TextMessage(text) = event {
                assert_eq!(text.message, "hello".to_string());
                return;
            }
        }
        tokio::task::yield_now().await;
    }

    // Fall back to an async recv if scheduling lagged.
    let event = events.recv().await.unwrap();
    match event {
        MumbleEvent::TextMessage(text) => assert_eq!(text.message, "hello".to_string()),
        other => panic!("expected TextMessage, got {other:?}"),
    }
}
