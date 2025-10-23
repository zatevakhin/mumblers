use std::net::SocketAddr;
use std::sync::Arc;
// use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;

use super::state::{ServerState, UserInfo};
use crate::messages::{read_envelope, write_message, MumbleMessage};
use crate::proto::mumble::{Authenticate, ChannelState, CodecVersion, Ping, ServerSync, TextMessage, PermissionDenied, UserRemove, UserState, Version};

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
                // After Authenticate, announce CodecVersion (Opus baseline)
                let mut codec = CodecVersion::default();
                codec.opus = Some(true);
                write_message(&mut tls, &MumbleMessage::CodecVersion(codec)).await?;
                // Enter steady-state loop handling messages (e.g., Ping)
                let (mut reader, writer_tx, writer_task) = spawn_writer_task(tls, _state.clone(), session);
                loop {
                    let env = match read_envelope(&mut reader).await {
                        Ok(e) => e,
                        Err(e) => {
                            // Connection closed or error: broadcast UserRemove
                            let mut remove = UserRemove::default();
                            remove.session = session;
                            _state.broadcast_except(session, MumbleMessage::UserRemove(remove)).await;
                            _state.remove_user(session).await;
                            drop(writer_task);
                            return Err(Box::new(e));
                        }
                    };
                    match MumbleMessage::try_from(env) {
                        Ok(MumbleMessage::Ping(p)) => {
                            let mut reply = Ping::default();
                            reply.timestamp = match p.timestamp { Some(0) => None, other => other };
                            reply.good = Some(0);
                            reply.late = Some(0);
                            reply.lost = Some(0);
                            reply.resync = Some(0);
                            tracing::debug!(session, "server: replying to ping");
                            let _ = writer_tx.send(MumbleMessage::Ping(reply));
                        }
                        Ok(MumbleMessage::TextMessage(mut tm)) => {
                            tracing::info!(session, msg = %tm.message, "server: TextMessage received");
                            // Route: private (target sessions) takes precedence; else channel broadcast (root only)
                            let mut delivered = false;
                            if !tm.session.is_empty() {
                                // Private to sessions
                                for &target in tm.session.iter() {
                                    if target == session { continue; }
                                    // send to target if known
                                    let mut out = TextMessage::default();
                                    out.actor = Some(session);
                                    out.message = tm.message.clone();
                                    let _ = _state.send_to(target, MumbleMessage::TextMessage(out.clone())).await;
                                    delivered = true;
                                }
                            } else {
                                // Channel broadcast to root (id 0) for MVP
                                let mut out = TextMessage::default();
                                out.actor = Some(session);
                                out.message = tm.message.clone();
                                tracing::debug!(session, "server: broadcasting channel text to root");
                                _state.broadcast_except(session, MumbleMessage::TextMessage(out)).await;
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
                reply.timestamp = match p.timestamp { Some(0) => None, other => other };
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
    if let Some(text) = state.cfg.welcome_text.clone() { sync.welcome_text = Some(text); }
    if let Some(bw) = state.cfg.max_bandwidth { sync.max_bandwidth = Some(bw as u32); }
    write_message(tls, &MumbleMessage::ServerSync(sync)).await?;

    // Track user in state; cleanup on disconnect handled by caller on IO error
    state.add_user(UserInfo { session, name: auth.username.clone(), channel_id }).await;
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
    state.broadcast_except(session, MumbleMessage::UserState(newcomer)).await;

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
    tokio::spawn(async move { reg_state.register_conn(session, reg_tx).await; });
    let task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = write_message(&mut writer, &msg).await;
        }
    });
    (reader, tx, task)
}
