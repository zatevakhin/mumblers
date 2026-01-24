use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;

use super::state::{ChannelError, ChannelInfo, ServerState, UserInfo, VoiceMetrics};
use crate::crypto::ocb2::CryptStateOcb2;
use crate::messages::{read_envelope, write_message, MumbleMessage, PROTOCOL_VERSION};
use crate::proto::mumble::permission_denied::DenyType as PermissionDenyType;
use crate::proto::mumble::reject::RejectType;
use crate::proto::mumble::{
    Authenticate, ChannelState, CodecVersion, CryptSetup, PermissionDenied, Ping, Reject,
    ServerSync, TextMessage, UserRemove, UserState, Version,
};
use crate::proto::mumble_udp as udp_proto;
use prost::Message;
use rand::RngCore;

const CONN_QUEUE_CAPACITY: usize = 256;
const UDP_MSG_TYPE_AUDIO: u8 = 0;
const UDP_MSG_TYPE_PING: u8 = 1;
const UDP_RESYNC_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct HandshakeRejected;

impl std::fmt::Display for HandshakeRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("handshake rejected")
    }
}

impl std::error::Error for HandshakeRejected {}

pub async fn handle_connection(
    sock: TcpStream,
    peer: SocketAddr,
    tls_cfg: Arc<TlsServerConfig>,
    _state: ServerState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = TlsAcceptor::from(tls_cfg);
    let mut tls = acceptor.accept(sock).await?;
    tracing::info!(%peer, "tls accepted");

    let mut version = Version::default();
    version.version_v1 = Some(0x0105_02df);
    version.release = Some("mumblers".into());
    write_message(&mut tls, &MumbleMessage::Version(version)).await?;

    let session = loop {
        let env = read_envelope(&mut tls).await?;
        let parsed = MumbleMessage::try_from(env);
        if let Ok(ref msg) = parsed {
            tracing::debug!(%peer, kind = message_name(msg), "server: handshake message received");
        }
        match parsed {
            Ok(MumbleMessage::Authenticate(auth)) => {
                match handle_authenticated(&mut tls, _state.clone(), auth).await {
                    Ok(session) => break session,
                    Err(err) => match err.downcast::<HandshakeRejected>() {
                        Ok(_) => return Ok(()),
                        Err(e) => return Err(e),
                    },
                }
            }
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
                write_message(&mut tls, &MumbleMessage::Ping(reply)).await?;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(%peer, error=?err, "server: failed to decode handshake message");
                continue;
            }
        }
    };

    let (mut reader, writer_tx, writer_task) =
        spawn_writer_task(tls, _state.clone(), session).await;
    let mut send_failure: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    loop {
        let env = match read_envelope(&mut reader).await {
            Ok(env) => env,
            Err(err) => {
                tracing::warn!(
                    session,
                    error = ?err,
                    "server: read_envelope failed, closing connection"
                );
                let mut remove = UserRemove::default();
                remove.session = session;
                let _ = _state
                    .broadcast_except(session, MumbleMessage::UserRemove(remove))
                    .await;
                _state.remove_user(session).await;
                drop(writer_task);
                return Err(Box::new(err));
            }
        };

        let parsed = MumbleMessage::try_from(env);
        if let Ok(ref msg) = parsed {
            tracing::debug!(
                session,
                kind = message_name(msg),
                "server: received message"
            );
        }
        match parsed {
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
                if let Err(err) = writer_tx.send(MumbleMessage::Ping(reply)).await {
                    tracing::warn!(session, error = ?err, "server: failed to queue ping reply");
                    send_failure = Some(Box::new(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        err.to_string(),
                    )));
                }
            }
            Ok(MumbleMessage::CryptSetup(req)) => {
                let mut cs = _state
                    .get_crypt(session)
                    .await
                    .unwrap_or(create_and_store_crypt(session, &_state).await);

                let mut updated = false;

                if let Some(key) = req.key.as_ref() {
                    if key.len() == 16 {
                        cs.key.copy_from_slice(&key[..16]);
                        updated = true;
                    } else {
                        tracing::debug!(session, "server: ignoring short crypt key");
                    }
                }

                if let Some(server) = req.server_nonce.as_ref() {
                    if server.len() == 16 {
                        cs.server_nonce.copy_from_slice(&server[..16]);
                        updated = true;
                    } else {
                        tracing::debug!(session, "server: ignoring short server nonce");
                    }
                }

                if let Some(client) = req.client_nonce.as_ref() {
                    if client.len() == 16 {
                        cs.client_nonce.copy_from_slice(&client[..16]);
                        updated = true;
                    } else {
                        tracing::debug!(session, "server: ignoring short client nonce");
                    }
                }

                if updated {
                    _state.set_crypt(session, cs).await;
                }

                if req.client_nonce.is_none() {
                    let mut resp = CryptSetup::default();
                    resp.server_nonce = Some(cs.server_nonce.to_vec());
                    if let Err(err) = writer_tx.send(MumbleMessage::CryptSetup(resp)).await {
                        tracing::warn!(
                            session,
                            error = ?err,
                            "server: failed to queue crypt setup reply"
                        );
                        send_failure = Some(Box::new(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            err.to_string(),
                        )));
                    }
                }
            }
            Ok(MumbleMessage::UserState(incoming)) => {
                tracing::debug!(
                    session,
                    target_session = ?incoming.session,
                    target_channel = ?incoming.channel_id,
                    "server: UserState command received"
                );
                let target_session = incoming.session.unwrap_or(session);
                if target_session != session {
                    let mut pd = PermissionDenied::default();
                    pd.r#type = Some(PermissionDenyType::Permission as i32);
                    pd.reason = Some("Cannot modify other users".to_string());
                    pd.session = Some(session);
                    if let Err(err) = writer_tx.send(MumbleMessage::PermissionDenied(pd)).await {
                        tracing::warn!(
                            session,
                            error = ?err,
                            "server: failed to queue permission denied"
                        );
                        send_failure = Some(Box::new(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            err.to_string(),
                        )));
                    }
                    continue;
                }

                if let Some(dest_channel) = incoming.channel_id {
                    match _state.move_user_to_channel(session, dest_channel).await {
                        Ok(info) => {
                            tracing::info!(
                                session,
                                channel = info.channel_id,
                                "server: user moved channel"
                            );
                            let mut update = UserState::default();
                            update.session = Some(info.session);
                            update.actor = Some(session);
                            update.channel_id = Some(info.channel_id);
                            if let Some(name) = info.name.clone() {
                                update.name = Some(name);
                            }
                            let msg = MumbleMessage::UserState(update.clone());
                            let delivered_self = _state.send_to(session, msg.clone()).await;
                            if delivered_self {
                                tracing::info!(
                                    session,
                                    channel = info.channel_id,
                                    "server: self user state delivered"
                                );
                            } else {
                                tracing::warn!(
                                    session,
                                    "server: failed to deliver user state to mover"
                                );
                            }
                            let others = _state.list_users().await;
                            for other in others {
                                if other.session == session {
                                    continue;
                                }
                                let delivered = _state.send_to(other.session, msg.clone()).await;
                                tracing::info!(
                                    session,
                                    target = other.session,
                                    delivered,
                                    "server: broadcast user state"
                                );
                            }
                        }
                        Err(err) => {
                            let mut pd = PermissionDenied::default();
                            pd.session = Some(session);
                            pd.channel_id = Some(dest_channel);
                            let (deny_type, reason) = match err {
                                ChannelError::NoEnter(name) => (
                                    PermissionDenyType::Permission,
                                    format!("Channel '{}' denies entry", name),
                                ),
                                ChannelError::Full(name) => (
                                    PermissionDenyType::ChannelFull,
                                    format!("Channel '{}' is full", name),
                                ),
                                ChannelError::UnknownChannel(_) => (
                                    PermissionDenyType::Permission,
                                    "Unknown channel".to_string(),
                                ),
                                ChannelError::UnknownUser(_) => (
                                    PermissionDenyType::Permission,
                                    "Unknown session".to_string(),
                                ),
                            };
                            pd.r#type = Some(deny_type as i32);
                            pd.reason = Some(reason);
                            if let Err(err) =
                                writer_tx.send(MumbleMessage::PermissionDenied(pd)).await
                            {
                                tracing::warn!(
                                    session,
                                    error = ?err,
                                    "server: failed to queue permission denial"
                                );
                                send_failure = Some(Box::new(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    err.to_string(),
                                )));
                            }
                        }
                    }
                }
            }
            Ok(MumbleMessage::TextMessage(tm)) => {
                tracing::info!(
                    session,
                    msg = %tm.message,
                    chans = ?tm.channel_id,
                    targets = ?tm.session,
                    "server: TextMessage received"
                );

                let mut delivered = false;
                let mut denial: Option<PermissionDenied> = None;
                if !tm.session.is_empty() {
                    for &target in tm.session.iter() {
                        if target == session {
                            continue;
                        }
                        let mut out = TextMessage::default();
                        out.actor = Some(session);
                        out.message = tm.message.clone();
                        out.session = vec![target];
                        let ok = _state
                            .send_to(target, MumbleMessage::TextMessage(out.clone()))
                            .await;
                        tracing::info!(session, target, delivered = ok, "server: private text");
                        delivered = delivered || ok;
                    }
                } else {
                    let current = _state.user_info(session).await;
                    let target_channel = tm
                        .channel_id
                        .get(0)
                        .copied()
                        .or_else(|| current.as_ref().map(|u| u.channel_id));
                    match (current, target_channel) {
                        (_, None) => {
                            let mut pd = PermissionDenied::default();
                            pd.r#type = Some(PermissionDenyType::Text as i32);
                            pd.reason = Some("Missing target channel".to_string());
                            pd.session = Some(session);
                            denial = Some(pd);
                        }
                        (Some(user), Some(chan_id)) => {
                            if user.channel_id != chan_id {
                                let mut pd = PermissionDenied::default();
                                pd.r#type = Some(PermissionDenyType::Permission as i32);
                                pd.reason = Some(
                                    "Cannot broadcast to a channel you are not in".to_string(),
                                );
                                pd.session = Some(session);
                                pd.channel_id = Some(chan_id);
                                denial = Some(pd);
                            } else if _state.channel_info(chan_id).await.is_none() {
                                let mut pd = PermissionDenied::default();
                                pd.r#type = Some(PermissionDenyType::Permission as i32);
                                pd.reason = Some("Unknown channel".to_string());
                                pd.session = Some(session);
                                pd.channel_id = Some(chan_id);
                                denial = Some(pd);
                            } else {
                                let mut out = TextMessage::default();
                                out.actor = Some(session);
                                out.message = tm.message.clone();
                                out.channel_id = vec![chan_id];
                                let sent = _state
                                    .broadcast_channel(
                                        chan_id,
                                        Some(session),
                                        MumbleMessage::TextMessage(out),
                                    )
                                    .await;
                                tracing::info!(
                                    session,
                                    sent,
                                    channel = chan_id,
                                    "server: channel text broadcasted"
                                );
                                delivered = sent > 0;
                            }
                        }
                        (None, Some(_)) => {
                            let mut pd = PermissionDenied::default();
                            pd.r#type = Some(PermissionDenyType::Permission as i32);
                            pd.reason = Some("Unknown session".to_string());
                            pd.session = Some(session);
                            denial = Some(pd);
                        }
                    }
                }

                let denial_message = if let Some(pd) = denial {
                    Some(MumbleMessage::PermissionDenied(pd))
                } else if !delivered {
                    let mut pd = PermissionDenied::default();
                    pd.r#type = Some(PermissionDenyType::Text as i32);
                    pd.reason = Some("Invalid text target".to_string());
                    pd.session = Some(session);
                    Some(MumbleMessage::PermissionDenied(pd))
                } else {
                    None
                };

                if let Some(msg) = denial_message {
                    if let Err(err) = writer_tx.send(msg).await {
                        tracing::warn!(
                            session,
                            error = ?err,
                            "server: failed to queue text denial"
                        );
                        send_failure = Some(Box::new(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            err.to_string(),
                        )));
                    }
                }
            }
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(session, error=?err, "server: failed to decode message");
                continue;
            }
        }

        if send_failure.is_some() {
            break;
        }
    }

    if let Some(err) = send_failure {
        let mut remove = UserRemove::default();
        remove.session = session;
        let _ = _state
            .broadcast_except(session, MumbleMessage::UserRemove(remove))
            .await;
        _state.remove_user(session).await;
        drop(writer_task);
        return Err(err);
    }

    drop(writer_task);
    Ok(())
}

async fn handle_authenticated(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    state: ServerState,
    auth: Authenticate,
) -> Result<super::state::SessionId, Box<dyn std::error::Error + Send + Sync>> {
    let allow_anonymous = state.cfg.allow_anonymous.unwrap_or(true);
    let mut requested_name = auth.username.clone().unwrap_or_default();
    requested_name = requested_name.trim().to_string();
    if requested_name.is_empty() && !allow_anonymous {
        send_reject(tls, RejectType::InvalidUsername, "Username required").await?;
        return Err(Box::new(HandshakeRejected));
    }
    if !requested_name.is_empty() && state.username_in_use(&requested_name).await {
        send_reject(tls, RejectType::UsernameInUse, "Username already in use").await?;
        return Err(Box::new(HandshakeRejected));
    }

    let session = state.alloc_session().await;
    if requested_name.is_empty() {
        requested_name = format!("Guest{}", session);
    }

    let cs = create_and_store_crypt(session, &state).await;
    let mut crypt = CryptSetup::default();
    crypt.key = Some(cs.key.to_vec());
    crypt.server_nonce = Some(cs.server_nonce.to_vec());
    crypt.client_nonce = Some(cs.client_nonce.to_vec());
    write_message(tls, &MumbleMessage::CryptSetup(crypt)).await?;

    let default_channel = state.default_channel_id().await;
    for info in state.channels_snapshot().await {
        let chan = make_channel_state(&info);
        write_message(tls, &MumbleMessage::ChannelState(chan)).await?;
    }

    let mut self_state = UserState::default();
    self_state.session = Some(session);
    self_state.name = Some(requested_name.clone());
    self_state.channel_id = Some(default_channel);
    write_message(tls, &MumbleMessage::UserState(self_state)).await?;

    let mut sync = ServerSync::default();
    sync.session = Some(session);
    if let Some(text) = state.cfg.welcome_text.clone() {
        sync.welcome_text = Some(text);
    }
    if let Some(bw) = state.cfg.max_bandwidth {
        sync.max_bandwidth = Some(bw);
    }
    sync.permissions = Some(0xffff_ffffu64);
    write_message(tls, &MumbleMessage::ServerSync(sync)).await?;

    let existing_users = state.list_users().await;
    state
        .add_user(UserInfo {
            session,
            name: Some(requested_name.clone()),
            channel_id: default_channel,
        })
        .await;

    for u in existing_users {
        if u.session == session {
            continue;
        }
        let mut ustate = UserState::default();
        ustate.session = Some(u.session);
        ustate.name = u.name.clone();
        ustate.channel_id = Some(u.channel_id);
        write_message(tls, &MumbleMessage::UserState(ustate)).await?;
    }

    let mut newcomer = UserState::default();
    newcomer.session = Some(session);
    newcomer.name = Some(requested_name.clone());
    newcomer.channel_id = Some(default_channel);
    let _ = state
        .broadcast_except(session, MumbleMessage::UserState(newcomer))
        .await;

    let mut codec = CodecVersion::default();
    codec.alpha = state.cfg.codec_alpha;
    codec.beta = state.cfg.codec_beta;
    codec.prefer_alpha = state.cfg.codec_prefer_alpha;
    codec.opus = Some(state.cfg.enable_opus && auth.opus.unwrap_or(false));
    write_message(tls, &MumbleMessage::CodecVersion(codec)).await?;

    Ok(session)
}

async fn send_reject(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    rtype: RejectType,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reject = Reject::default();
    reject.r#type = Some(rtype as i32);
    reject.reason = Some(reason.to_string());
    write_message(tls, &MumbleMessage::Reject(reject)).await?;
    Ok(())
}

fn make_channel_state(info: &ChannelInfo) -> ChannelState {
    let mut chan = ChannelState::default();
    chan.channel_id = Some(info.id);
    if let Some(parent) = info.parent {
        chan.parent = Some(parent);
    }
    chan.name = Some(info.name.clone());
    if let Some(desc) = info.description.as_ref() {
        chan.description = Some(desc.clone());
    }
    if let Some(pos) = info.position {
        chan.position = Some(pos);
    }
    if let Some(max) = info.max_users {
        chan.max_users = Some(max);
    }
    if info.no_enter {
        chan.is_enter_restricted = Some(true);
        chan.can_enter = Some(false);
    } else {
        chan.can_enter = Some(true);
    }
    chan
}

async fn spawn_writer_task(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: ServerState,
    session: super::state::SessionId,
) -> (
    tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    mpsc::Sender<MumbleMessage>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::split;
    let (reader, mut writer) = split(tls);
    let (tx, mut rx) = mpsc::channel::<MumbleMessage>(CONN_QUEUE_CAPACITY);
    state.register_conn(session, tx.clone()).await;
    let reg_state = state.clone();
    let task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match &msg {
                MumbleMessage::UserState(us) => {
                    tracing::debug!(
                        session,
                        target_session = ?us.session,
                        channel = ?us.channel_id,
                        actor = ?us.actor,
                        "server: sending user state"
                    );
                }
                MumbleMessage::TextMessage(_) => {
                    tracing::debug!(session, kind=%message_name(&msg), "server: sending message");
                }
                _ => {
                    tracing::debug!(session, kind=%message_name(&msg), "server: sending message");
                }
            }
            if let Err(err) = write_message(&mut writer, &msg).await {
                tracing::warn!(
                    session,
                    error=?err,
                    kind=%message_name(&msg),
                    "server: write failed"
                );
                break;
            }
            if let Err(err) = writer.flush().await {
                tracing::warn!(
                    session,
                    error=?err,
                    kind=%message_name(&msg),
                    "server: flush failed"
                );
                break;
            }
            tracing::debug!(session, kind = %message_name(&msg), "server: message flushed to wire");
        }
        reg_state.unregister_conn(session).await;
    });
    (reader, tx, task)
}

fn message_name(msg: &MumbleMessage) -> &'static str {
    match msg {
        MumbleMessage::Version(_) => "Version",
        MumbleMessage::Authenticate(_) => "Authenticate",
        MumbleMessage::Reject(_) => "Reject",
        MumbleMessage::ServerSync(_) => "ServerSync",
        MumbleMessage::Ping(_) => "Ping",
        MumbleMessage::CryptSetup(_) => "CryptSetup",
        MumbleMessage::ChannelRemove(_) => "ChannelRemove",
        MumbleMessage::ChannelState(_) => "ChannelState",
        MumbleMessage::UserRemove(_) => "UserRemove",
        MumbleMessage::UserState(_) => "UserState",
        MumbleMessage::TextMessage(_) => "TextMessage",
        MumbleMessage::PermissionDenied(_) => "PermissionDenied",
        MumbleMessage::CodecVersion(_) => "CodecVersion",
        MumbleMessage::Unknown(_) => "Unknown",
    }
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

pub(crate) fn spawn_udp_receiver(state: ServerState) {
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
                match sock.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        if n == 0 {
                            continue;
                        }
                        let data = buf[..n].to_vec();
                        if let Err(err) =
                            handle_udp_datagram(&state, Arc::clone(&sock), data, addr).await
                        {
                            tracing::debug!(
                                error = ?err,
                                addr = %addr,
                                "server: udp datagram handling failed"
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error=?err, "server: udp receive failed");
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

async fn handle_udp_datagram(
    state: &ServerState,
    socket: Arc<tokio::net::UdpSocket>,
    data: Vec<u8>,
    addr: SocketAddr,
) -> Result<(), String> {
    let first_byte = data.get(0).copied().unwrap_or(0);
    tracing::debug!(%addr, size = data.len(), first_byte, "server: udp datagram received");
    if try_handle_unencrypted_ping(state, &socket, &data, addr).await? {
        return Ok(());
    }
    let (session, plain, metrics) = match decrypt_datagram(state, &data, addr).await {
        Some(res) => res,
        None => {
            tracing::debug!(%addr, "server: udp datagram ignored (no crypt match)");
            return Ok(());
        }
    };
    process_udp_plain(state, &socket, session, plain, addr, metrics).await
}

async fn try_handle_unencrypted_ping(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    data: &[u8],
    addr: SocketAddr,
) -> Result<bool, String> {
    if data.is_empty() {
        return Ok(false);
    }
    if data[0] == UDP_MSG_TYPE_PING {
        tracing::debug!(%addr, "server: plaintext proto ping detected");
        if respond_proto_udp_probe(state, socket, &data[1..], addr).await? {
            return Ok(true);
        }
        tracing::debug!(%addr, "server: plaintext proto ping decode failed, falling back");
    }
    if data[0] == 0 && data.len() >= 12 {
        if data.len() == 12 {
            tracing::debug!(%addr, "server: legacy UDP probe received");
            respond_legacy_udp_probe(state, socket, data, addr).await?;
            return Ok(true);
        }
        tracing::debug!(%addr, len = data.len(), "server: extended plaintext ping candidate");
        if respond_proto_udp_probe(state, socket, &data[1..], addr).await? {
            return Ok(true);
        }
        tracing::debug!(%addr, "server: extended ping fallback to legacy reply");
        respond_legacy_udp_probe(state, socket, data, addr).await?;
        return Ok(true);
    }
    Ok(false)
}

async fn respond_legacy_udp_probe(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    data: &[u8],
    addr: SocketAddr,
) -> Result<(), String> {
    let mut reply = [0u8; 24];
    let copy_len = data.len().min(reply.len());
    reply[..copy_len].copy_from_slice(&data[..copy_len]);

    let version_v1 = ((PROTOCOL_VERSION.0 as u32) << 16)
        | ((PROTOCOL_VERSION.1 as u32) << 8)
        | (PROTOCOL_VERSION.2.min(255) as u32);
    reply[0..4].copy_from_slice(&version_v1.to_be_bytes());

    let users = state.list_users().await;
    let user_count = users.len() as u32;
    reply[12..16].copy_from_slice(&user_count.to_be_bytes());

    let max_users: u32 = 0;
    reply[16..20].copy_from_slice(&max_users.to_be_bytes());

    let max_bandwidth = state.cfg.max_bandwidth.unwrap_or(0);
    reply[20..24].copy_from_slice(&max_bandwidth.to_be_bytes());

    socket
        .send_to(&reply, addr)
        .await
        .map_err(|err| err.to_string())?;
    tracing::debug!(
        %addr,
        version = version_v1,
        users = user_count,
        max_users,
        max_bandwidth,
        "server: legacy UDP probe answered"
    );
    Ok(())
}

fn protocol_version_v2() -> u64 {
    let (major, minor, patch) = PROTOCOL_VERSION;
    ((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16)
}

async fn respond_proto_udp_probe(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    payload: &[u8],
    addr: SocketAddr,
) -> Result<bool, String> {
    match udp_proto::Ping::decode(payload) {
        Ok(request) => {
            let mut reply = udp_proto::Ping::default();
            reply.timestamp = request.timestamp;
            reply.server_version_v2 = protocol_version_v2();
            if request.request_extended_information {
                let users = state.list_users().await;
                reply.user_count = users.len() as u32;
                reply.max_user_count = 0;
                if let Some(bw) = state.cfg.max_bandwidth {
                    reply.max_bandwidth_per_user = bw;
                }
            }
            let mut out = reply.encode_to_vec();
            out.insert(0, UDP_MSG_TYPE_PING);
            socket
                .send_to(&out, addr)
                .await
                .map_err(|err| err.to_string())?;
            tracing::debug!(
                %addr,
                extended = request.request_extended_information,
                "server: protobuf UDP ping answered"
            );
            Ok(true)
        }
        Err(err) => {
            tracing::debug!(%addr, error=?err, "server: plaintext ping decode failed");
            Ok(false)
        }
    }
}

async fn decrypt_datagram(
    state: &ServerState,
    data: &[u8],
    addr: SocketAddr,
) -> Option<(super::state::SessionId, Vec<u8>, VoiceMetrics)> {
    if let Some(session) = state.session_by_udp_addr(&addr).await {
        if let Some(crypt_arc) = state.crypt_state(session).await {
            let (result, last_good, metrics) = {
                let mut guard = crypt_arc.lock().await;
                let result = guard.decrypt(data);
                let metrics = VoiceMetrics {
                    good: guard.ui_good,
                    late: guard.ui_late,
                    lost: guard.ui_lost,
                };
                (result, guard.t_last_good, metrics)
            };
            match result {
                Ok(plain) => {
                    return Some((session, plain, metrics));
                }
                Err(err) => {
                    tracing::debug!(session, error=?err, %addr, "server: udp decrypt failed");
                    maybe_request_resync(state, session, last_good).await;
                    return None;
                }
            }
        }
    }

    let entries = state.crypt_entries().await;
    for (session, crypt) in entries {
        let mut trial = CryptStateOcb2::new();
        trial.set_key(&crypt.key, &crypt.server_nonce, &crypt.client_nonce);
        if let Ok(plain) = trial.decrypt(data) {
            let metrics = VoiceMetrics {
                good: trial.ui_good,
                late: trial.ui_late,
                lost: trial.ui_lost,
            };
            if let Some(arc) = state.crypt_state(session).await {
                let mut guard = arc.lock().await;
                *guard = trial.clone();
            } else {
                state.set_crypt(session, crypt).await;
                if let Some(arc) = state.crypt_state(session).await {
                    let mut guard = arc.lock().await;
                    *guard = trial.clone();
                }
            }
            state.set_udp_pair(session, addr).await;
            tracing::info!(session, %addr, "udp paired");
            return Some((session, plain, metrics));
        }
    }
    None
}

async fn maybe_request_resync(
    state: &ServerState,
    session: super::state::SessionId,
    last_good: Option<Instant>,
) {
    let now = Instant::now();
    let stale = last_good
        .map(|good| now.duration_since(good) > UDP_RESYNC_INTERVAL)
        .unwrap_or(true);
    if !stale {
        return;
    }
    if !state
        .mark_resync_request(session, now, UDP_RESYNC_INTERVAL)
        .await
    {
        return;
    }
    if let Some(crypt) = state.get_crypt(session).await {
        let mut setup = CryptSetup::default();
        setup.server_nonce = Some(crypt.server_nonce.to_vec());
        let sent = state
            .send_to(session, MumbleMessage::CryptSetup(setup))
            .await;
        if !sent {
            tracing::debug!(session, "server: failed to send UDP resync");
        } else {
            tracing::info!(session, "server: requested UDP resync");
        }
    }
}

#[cfg(test)]
mod udp_resync_tests {
    use super::*;
    use crate::server::state::UdpCrypt;
    use crate::server::ServerConfig;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn udp_decrypt_failure_requests_resync() {
        let cfg = ServerConfig::default();
        let state = ServerState::new(cfg);
        let session = state.alloc_session().await;
        let (tx, mut rx) = mpsc::channel(1);
        state.register_conn(session, tx).await;

        let crypt = UdpCrypt {
            key: [1u8; 16],
            server_nonce: [2u8; 16],
            client_nonce: [3u8; 16],
        };
        state.set_crypt(session, crypt).await;
        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        state.set_udp_pair(session, addr).await;

        if let Some(arc) = state.crypt_state(session).await {
            let mut guard = arc.lock().await;
            guard.t_last_good = Some(Instant::now() - UDP_RESYNC_INTERVAL - Duration::from_secs(1));
        }

        let data = vec![0u8; 8];
        let _ = decrypt_datagram(&state, &data, addr).await;

        match rx.recv().await.expect("resync message") {
            MumbleMessage::CryptSetup(setup) => {
                assert!(setup.server_nonce.is_some());
                assert!(setup.key.is_none());
                assert!(setup.client_nonce.is_none());
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }
}

async fn process_udp_plain(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    session: super::state::SessionId,
    plain: Vec<u8>,
    addr: SocketAddr,
    metrics: VoiceMetrics,
) -> Result<(), String> {
    if plain.is_empty() {
        return Ok(());
    }
    match plain[0] {
        UDP_MSG_TYPE_PING => handle_udp_ping(state, socket, session, &plain[1..], addr).await,
        UDP_MSG_TYPE_AUDIO => handle_udp_audio(state, socket, session, &plain[1..], metrics).await,
        other => {
            tracing::debug!(session, ty = other, "server: unknown UDP message type");
            Ok(())
        }
    }
}

async fn handle_udp_ping(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    session: super::state::SessionId,
    payload: &[u8],
    addr: SocketAddr,
) -> Result<(), String> {
    match udp_proto::Ping::decode(payload) {
        Ok(mut ping) => {
            tracing::debug!(session, ts=?ping.timestamp, "server: udp ping received");
            if ping.request_extended_information {
                let users = state.list_users().await;
                ping.user_count = users.len() as u32;
                ping.max_user_count = users.len() as u32;
                if let Some(bw) = state.cfg.max_bandwidth {
                    ping.max_bandwidth_per_user = bw;
                }
            }
            let mut out = ping.encode_to_vec();
            out.insert(0, UDP_MSG_TYPE_PING);
            send_udp_plain(socket, state, session, addr, &out)
                .await
                .map_err(|err| err.to_string())
        }
        Err(err) => {
            tracing::debug!(session, error=?err, "server: failed to decode udp ping");
            Err(err.to_string())
        }
    }
}

async fn handle_udp_audio(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    session: super::state::SessionId,
    payload: &[u8],
    metrics: VoiceMetrics,
) -> Result<(), String> {
    let mut audio =
        udp_proto::Audio::decode(payload).map_err(|err| format!("decode audio failed: {err}"))?;
    audio.sender_session = session;
    let frame_number = if audio.frame_number == 0 {
        None
    } else {
        Some(audio.frame_number)
    };

    let header = match audio.header.clone() {
        Some(h) => h,
        None => {
            tracing::debug!(session, "server: audio packet missing header");
            return Err("audio missing header".into());
        }
    };
    tracing::info!(
        session,
        frame = audio.frame_number,
        header = ?header,
        "server: udp audio received"
    );

    match header {
        udp_proto::audio::Header::Target(target) => {
            if target == 0x1f {
                // Loopback
                let mut loopback = audio.clone();
                loopback.header = Some(udp_proto::audio::Header::Context(0));
                let mut payload = loopback.encode_to_vec();
                payload.insert(0, UDP_MSG_TYPE_AUDIO);
                if let Some(addr) = state.get_udp_pair(session).await {
                    if let Err(err) = send_udp_plain(socket, state, session, addr, &payload).await {
                        tracing::debug!(session, error=?err, "server: loopback audio send failed");
                    }
                } else {
                    tracing::debug!(session, "server: loopback audio dropped (no udp pair)");
                }
            } else if target == 0 {
                route_channel_audio(state, socket, session, &audio).await?;
            } else {
                tracing::debug!(session, target, "server: unsupported voice target");
            }
        }
        udp_proto::audio::Header::Context(_) => {
            // Already contextualised – forward as-is to channel peers.
            route_channel_audio(state, socket, session, &audio).await?;
        }
    }

    state
        .record_voice_packet(session, frame_number, metrics)
        .await;
    Ok(())
}

async fn route_channel_audio(
    state: &ServerState,
    socket: &Arc<tokio::net::UdpSocket>,
    session: super::state::SessionId,
    audio: &udp_proto::Audio,
) -> Result<(), String> {
    let user = match state.user_info(session).await {
        Some(info) => info,
        None => {
            tracing::debug!(session, "server: channel audio from unknown session");
            return Err("unknown session".into());
        }
    };
    if let Some(info) = state.channel_info(user.channel_id).await {
        if info.silent {
            tracing::debug!(
                session,
                channel = info.id,
                "server: channel is silent; dropping audio"
            );
            return Ok(());
        }
    }
    let recipients = state.channel_members(user.channel_id).await;
    for target in recipients {
        if target == session {
            continue;
        }
        let addr = match state.get_udp_pair(target).await {
            Some(addr) => addr,
            None => {
                tracing::debug!(session, target, "server: skipping audio, no UDP pair");
                continue;
            }
        };
        let mut packet = audio.clone();
        packet.header = Some(udp_proto::audio::Header::Context(0));
        packet.sender_session = session;
        let mut payload = packet.encode_to_vec();
        payload.insert(0, UDP_MSG_TYPE_AUDIO);
        tracing::info!(
            session,
            target,
            frame = packet.frame_number,
            "server: forwarding audio frame"
        );
        if let Err(err) = send_udp_plain(socket, state, target, addr, &payload).await {
            tracing::debug!(
                session,
                target,
                error=?err,
                "server: failed to forward audio"
            );
        } else {
            tracing::trace!(session, target, "server: forwarded audio frame");
        }
    }
    Ok(())
}

async fn send_udp_plain(
    socket: &Arc<tokio::net::UdpSocket>,
    state: &ServerState,
    session: super::state::SessionId,
    addr: SocketAddr,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let crypt_arc = match state.crypt_state(session).await {
        Some(arc) => arc,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing crypt state",
            ));
        }
    };
    let encrypted = {
        let mut guard = crypt_arc.lock().await;
        let encrypted = guard.encrypt(payload).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("encrypt failed: {err}"))
        })?;
        encrypted
    };
    if let Some(raw) = state.get_crypt(session).await {
        let mut client_view = CryptStateOcb2::new();
        client_view.set_key(&raw.key, &raw.client_nonce, &raw.server_nonce);
        if let Err(err) = client_view.decrypt(&encrypted) {
            tracing::debug!(session, error=?err, "server: client-view decrypt failed");
        }
    }
    socket.send_to(&encrypted, addr).await?;
    Ok(())
}
