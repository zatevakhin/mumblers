use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;

use super::state::{ChannelError, ChannelInfo, ServerState, UserInfo};
use crate::crypto::ocb2::CryptStateOcb2;
use crate::messages::{read_envelope, write_message, MumbleMessage};
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
        match MumbleMessage::try_from(env) {
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
            Err(_) => {}
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
                if let Err(err) = writer_tx.send(MumbleMessage::Ping(reply)).await {
                    tracing::warn!(session, error = ?err, "server: failed to queue ping reply");
                    send_failure = Some(Box::new(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        err.to_string(),
                    )));
                }
            }
            Ok(MumbleMessage::CryptSetup(req)) => {
                if let Some(cn) = req.client_nonce.as_ref() {
                    if cn.len() == 16 {
                        let mut cs = _state
                            .get_crypt(session)
                            .await
                            .unwrap_or(create_and_store_crypt(session, &_state).await);
                        cs.client_nonce.copy_from_slice(&cn[..16]);
                        cs.server_nonce = rand_nonce();
                        _state.set_crypt(session, cs).await;
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
            Err(_) => {}
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
                    tracing::info!(
                        session,
                        target_session = ?us.session,
                        channel = ?us.channel_id,
                        actor = ?us.actor,
                        "server: sending user state"
                    );
                }
                MumbleMessage::TextMessage(_) => {
                    tracing::info!(session, kind=%message_name(&msg), "server: sending message");
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
            tracing::info!(session, kind = %message_name(&msg), "server: message flushed to wire");
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
