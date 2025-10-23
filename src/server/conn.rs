use std::net::SocketAddr;
use std::sync::Arc;
// use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;

use super::state::{ServerState, UserInfo};
use crate::crypto::ocb2::CryptStateOcb2;
use crate::messages::{read_envelope, write_message, MumbleMessage};
use crate::proto::mumble::{
    Authenticate, ChannelState, CodecVersion, CryptSetup, PermissionDenied, Ping, ServerSync,
    TextMessage, UserRemove, UserState, Version,
};
use crate::proto::mumble_udp as udp_proto;
use prost::Message;
use rand::RngCore;

pub async fn handle_connection(
    sock: TcpStream,
    peer: SocketAddr,
    tls_cfg: Arc<TlsServerConfig>,
    _state: ServerState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = TlsAcceptor::from(tls_cfg);
    let mut tls = acceptor.accept(sock).await?;
    tracing::info!(%peer, "tls accepted");
    // Iteration 13: minimal handshake.
    // 1) Send Version (server-first like uMurmur)
    let mut version = Version::default();
    version.version_v1 = Some(0x0105_02df);
    version.release = Some("mumblers".into());
    write_message(&mut tls, &MumbleMessage::Version(version)).await?;

    // 2) Wait for Authenticate
    loop {
        let env = match read_envelope(&mut tls).await {
            Ok(e) => e,
            Err(e) => {
                return Err(Box::new(e));
            }
        };
        match MumbleMessage::try_from(env) {
            Ok(MumbleMessage::Authenticate(auth)) => {
                let session = handle_authenticated(&mut tls, _state.clone(), auth).await?;
                // Send CryptSetup immediately after auth (key + nonces)
                let cs = create_and_store_crypt(session, &_state).await;
                let mut crypt = CryptSetup::default();
                crypt.key = Some(cs.key.to_vec());
                crypt.server_nonce = Some(cs.server_nonce.to_vec());
                crypt.client_nonce = Some(cs.client_nonce.to_vec());
                write_message(&mut tls, &MumbleMessage::CryptSetup(crypt)).await?;
                // After Authenticate, announce CodecVersion (Opus baseline)
                let mut codec = CodecVersion::default();
                codec.opus = Some(true);
                write_message(&mut tls, &MumbleMessage::CodecVersion(codec)).await?;
                // Enter steady-state loop handling messages (e.g., Ping)
                let (mut reader, writer_tx, writer_task) =
                    spawn_writer_task(tls, _state.clone(), session);
                loop {
                    let env = match read_envelope(&mut reader).await {
                        Ok(e) => e,
                        Err(e) => {
                            // Connection closed or error: broadcast UserRemove
                            let mut remove = UserRemove::default();
                            remove.session = session;
                            _state
                                .broadcast_except(session, MumbleMessage::UserRemove(remove))
                                .await;
                            _state.remove_user(session).await;
                            drop(writer_task);
                            return Err(Box::new(e));
                        }
                    };
                    match MumbleMessage::try_from(env) {
                        Ok(MumbleMessage::Ping(p)) => {
                            let mut reply = Ping::default();
                            reply.timestamp = match p.timestamp {
                                Some(0) => None,
                                other => other,
                            };
                            reply.good = Some(0);
                            reply.late = Some(0);
                            reply.lost = Some(0);
                            reply.resync = Some(0);
                            tracing::debug!(session, "server: replying to ping");
                            let _ = writer_tx.send(MumbleMessage::Ping(reply));
                        }
                        Ok(MumbleMessage::CryptSetup(req)) => {
                            // Resync handling: if client_nonce provided, set as new client nonce and respond with new server nonce
                            if let Some(cn) = req.client_nonce.as_ref() {
                                if cn.len() == 16 {
                                    let mut cs = _state
                                        .get_crypt(session)
                                        .await
                                        .unwrap_or(create_and_store_crypt(session, &_state).await);
                                    cs.client_nonce.copy_from_slice(&cn[..16]);
                                    // generate new server nonce
                                    cs.server_nonce = rand_nonce();
                                    _state.set_crypt(session, cs).await;
                                    let mut resp = CryptSetup::default();
                                    resp.server_nonce = Some(cs.server_nonce.to_vec());
                                    let _ = writer_tx.send(MumbleMessage::CryptSetup(resp));
                                }
                            }
                        }
                        Ok(MumbleMessage::TextMessage(mut tm)) => {
                            tracing::info!(session, msg = %tm.message, "server: TextMessage received");
                            // Route: private (target sessions) takes precedence; else channel broadcast (root only)
                            let mut delivered = false;
                            if !tm.session.is_empty() {
                                // Private to sessions
                                for &target in tm.session.iter() {
                                    if target == session {
                                        continue;
                                    }
                                    // send to target if known
                                    let mut out = TextMessage::default();
                                    out.actor = Some(session);
                                    out.message = tm.message.clone();
                                    let _ = _state
                                        .send_to(target, MumbleMessage::TextMessage(out.clone()))
                                        .await;
                                    delivered = true;
                                }
                            } else {
                                // Channel broadcast to root (id 0) for MVP
                                let mut out = TextMessage::default();
                                out.actor = Some(session);
                                out.message = tm.message.clone();
                                tracing::debug!(
                                    session,
                                    "server: broadcasting channel text to root"
                                );
                                _state
                                    .broadcast_except(session, MumbleMessage::TextMessage(out))
                                    .await;
                                delivered = true;
                            }

                            if !delivered {
                                // Invalid target: reply with PermissionDenied(Text)
                                let mut pd = PermissionDenied::default();
                                pd.r#type = Some(1); // Text
                                pd.reason = Some("Invalid text target".to_string());
                                let _ = writer_tx.send(MumbleMessage::PermissionDenied(pd));
                            }
                        }
                        Ok(_) => {
                            // Ignore other messages for now
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(MumbleMessage::Ping(p)) => {
                // Echo back ping with timestamp and zeroed crypt stats (uMurmur includes stats)
                let mut reply = Ping::default();
                reply.timestamp = match p.timestamp {
                    Some(0) => None,
                    other => other,
                };
                reply.good = Some(0);
                reply.late = Some(0);
                reply.lost = Some(0);
                reply.resync = Some(0);
                write_message(&mut tls, &MumbleMessage::Ping(reply)).await?;
            }
            Ok(_) => {
                // Ignore unexpected pre-auth messages for MVP
            }
            Err(_) => {}
        }
    }
    // Unreachable: steady-state loop returns on IO error.
    // Ok(())
}

async fn handle_authenticated(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    state: ServerState,
    auth: Authenticate,
) -> Result<super::state::SessionId, Box<dyn std::error::Error + Send + Sync>> {
    let session = state.alloc_session().await;
    let channel_id = 0u32; // root

    // Emit ChannelState (root)
    let mut chan = ChannelState::default();
    chan.channel_id = Some(channel_id);
    chan.name = Some("Root".into());
    write_message(tls, &MumbleMessage::ChannelState(chan)).await?;

    // Emit UserState (self)
    let mut user = UserState::default();
    user.session = Some(session);
    user.name = auth.username.clone();
    user.channel_id = Some(channel_id);
    write_message(tls, &MumbleMessage::UserState(user)).await?;

    // Emit ServerSync
    let mut sync = ServerSync::default();
    sync.session = Some(session);
    if let Some(text) = state.cfg.welcome_text.clone() {
        sync.welcome_text = Some(text);
    }
    if let Some(bw) = state.cfg.max_bandwidth {
        sync.max_bandwidth = Some(bw as u32);
    }
    write_message(tls, &MumbleMessage::ServerSync(sync)).await?;

    // Track user in state; cleanup on disconnect handled by caller on IO error
    state
        .add_user(UserInfo {
            session,
            name: auth.username.clone(),
            channel_id,
        })
        .await;
    // Presence: send existing users to newcomer
    let existing = state.list_users().await;
    for u in existing.into_iter().filter(|u| u.session != session) {
        let mut ustate = UserState::default();
        ustate.session = Some(u.session);
        ustate.name = u.name.clone();
        ustate.channel_id = Some(u.channel_id);
        write_message(tls, &MumbleMessage::UserState(ustate)).await?;
    }
    // Broadcast newcomer to others
    let mut newcomer = UserState::default();
    newcomer.session = Some(session);
    newcomer.name = auth.username;
    newcomer.channel_id = Some(channel_id);
    state
        .broadcast_except(session, MumbleMessage::UserState(newcomer))
        .await;

    Ok(session)
}

fn spawn_writer_task(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: ServerState,
    session: super::state::SessionId,
) -> (
    tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    tokio::sync::mpsc::UnboundedSender<MumbleMessage>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::split;
    let (reader, mut writer) = split(tls);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MumbleMessage>();
    let reg_state = state.clone();
    let reg_tx = tx.clone();
    tokio::spawn(async move {
        reg_state.register_conn(session, reg_tx).await;
    });
    let task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = write_message(&mut writer, &msg).await;
        }
    });
    (reader, tx, task)
}

fn rand_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

async fn create_and_store_crypt(
    session: super::state::SessionId,
    state: &ServerState,
) -> super::state::UdpCrypt {
    let key = rand_nonce();
    let server_nonce = rand_nonce();
    let client_nonce = rand_nonce();
    let c = super::state::UdpCrypt {
        key,
        server_nonce,
        client_nonce,
    };
    state.set_crypt(session, c).await;
    // Ensure UDP bound (best effort)
    match state
        .ensure_udp_bound(&state.cfg.bind_host, state.cfg.udp_bind_port)
        .await
    {
        Ok(true) => spawn_udp_receiver(state.clone()),
        Ok(false) => {}
        Err(err) => tracing::warn!(error=?err, "failed to bind udp"),
    }
    c
}

fn spawn_udp_receiver(state: ServerState) {
    let udp_handle = state.udp.clone();
    tokio::spawn(async move {
        let mut started = false;
        loop {
            // Wait for socket
            let sock_opt = {
                let guard = udp_handle.lock().await;
                guard.clone()
            };
            if let Some(sock) = sock_opt {
                if !started {
                    tracing::info!("udp receiver started");
                    started = true;
                }
                let mut buf = [0u8; 1500];
                match (&*sock).recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        // Try match against crypt entries
                        let entries = state.crypt_entries().await;
                        for (sess, crypt) in entries {
                            // Attempt decrypt as Udp Ping
                            let mut cs = CryptStateOcb2::new();
                            cs.set_key(&crypt.key, &crypt.client_nonce, &crypt.server_nonce);
                            if let Ok(decrypted) = cs.decrypt(&buf[..n]) {
                                // Try decode as ping
                                if let Ok(p) = udp_proto::Ping::decode(&*decrypted) {
                                    // Pair if needed
                                    if state.get_udp_pair(sess).await.is_none() {
                                        state.set_udp_pair(sess, addr).await;
                                        tracing::info!(session=sess, %addr, "udp paired");
                                    }
                                    tracing::debug!(session=sess, ts=?p.timestamp, "udp ping recv");
                                    // Echo back same timestamp
                                    let mut echo = udp_proto::Ping::default();
                                    echo.timestamp = p.timestamp;
                                    let mut payload = Vec::new();
                                    if prost::Message::encode(&echo, &mut payload).is_ok() {
                                        let mut cs2 = CryptStateOcb2::new();
                                        cs2.set_key(
                                            &crypt.key,
                                            &crypt.client_nonce,
                                            &crypt.server_nonce,
                                        );
                                        if let Ok(enc) = cs2.encrypt(&payload) {
                                            let _ = (&*sock).send_to(&enc, addr).await;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            } else {
                // No socket yet
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });
}
