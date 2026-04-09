use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

use super::config::{ChannelConfig, ServerConfig};
use crate::crypto::ocb2::CryptStateOcb2;
use crate::messages::MumbleMessage;
use crate::proto::mumble::voice_target::Target as VoiceTargetEntry;

pub type SessionId = u32;

type ChannelBuild = (
    HashMap<u32, ChannelInfo>,
    HashMap<String, u32>,
    HashMap<u32, HashSet<SessionId>>,
    u32,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpTunnelMode {
    /// UDPTunnel payload contains plaintext MumbleUDP frames.
    Plain,
    /// UDPTunnel payload contains OCB2-encrypted UDP datagrams.
    Encrypted,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub id: u32,
    pub name: String,
    pub parent: Option<u32>,
    pub description: Option<String>,
    pub position: Option<i32>,
    pub max_users: Option<u32>,
    pub no_enter: bool,
    pub silent: bool,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub session: SessionId,
    pub name: Option<String>,
    pub channel_id: u32,
    pub self_mute: bool,
    pub self_deaf: bool,
    pub mute: bool,
    pub deaf: bool,
    pub suppress: bool,
    pub priority_speaker: bool,
    pub recording: bool,
    pub user_id: Option<u32>,
    pub comment: Option<String>,
    pub hash: Option<String>,
}

impl UserInfo {
    /// Create a new `UserInfo` with all flags defaulted to false/None.
    pub fn new(session: SessionId, channel_id: u32) -> Self {
        Self {
            session,
            name: None,
            channel_id,
            self_mute: false,
            self_deaf: false,
            mute: false,
            deaf: false,
            suppress: false,
            priority_speaker: false,
            recording: false,
            user_id: None,
            comment: None,
            hash: None,
        }
    }

    /// Convert to a protobuf `UserState` with all tracked fields populated.
    pub fn to_user_state(&self) -> crate::proto::mumble::UserState {
        crate::proto::mumble::UserState {
            session: Some(self.session),
            name: self.name.clone(),
            channel_id: Some(self.channel_id),
            self_mute: Some(self.self_mute),
            self_deaf: Some(self.self_deaf),
            mute: Some(self.mute),
            deaf: Some(self.deaf),
            suppress: Some(self.suppress),
            priority_speaker: Some(self.priority_speaker),
            recording: Some(self.recording),
            user_id: self.user_id,
            comment: self.comment.clone(),
            hash: self.hash.clone(),
            ..Default::default()
        }
    }

    /// Apply fields from an incoming `UserState` protobuf.
    ///
    /// Only fields that are `Some` in the incoming message are updated;
    /// unset fields are left unchanged.
    pub fn apply_update(&mut self, us: &crate::proto::mumble::UserState) {
        if let Some(v) = us.self_mute {
            self.self_mute = v;
        }
        if let Some(v) = us.self_deaf {
            self.self_deaf = v;
        }
        if let Some(v) = us.mute {
            self.mute = v;
        }
        if let Some(v) = us.deaf {
            self.deaf = v;
        }
        if let Some(v) = us.suppress {
            self.suppress = v;
        }
        if let Some(v) = us.priority_speaker {
            self.priority_speaker = v;
        }
        if let Some(v) = us.recording {
            self.recording = v;
        }
        if us.user_id.is_some() {
            self.user_id = us.user_id;
        }
        if us.comment.is_some() {
            self.comment = us.comment.clone();
        }
        if us.hash.is_some() {
            self.hash = us.hash.clone();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpCrypt {
    pub key: [u8; 16],
    pub server_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
}

#[derive(Debug, Clone, Default)]
pub struct VoiceStats {
    pub packets: u64,
    pub last_frame: Option<u64>,
    pub last_update: Option<Instant>,
    pub good: u32,
    pub late: u32,
    pub lost: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct VoiceMetrics {
    pub good: u32,
    pub late: u32,
    pub lost: i32,
}

#[derive(Debug)]
pub enum ChannelError {
    UnknownUser(SessionId),
    UnknownChannel(u32),
    NoEnter(String),
    Full(String),
}

#[derive(Debug, Default)]
struct InnerState {
    next_session: SessionId,
    users: HashMap<SessionId, UserInfo>,
    user_names: HashMap<String, SessionId>,
    conns: HashMap<SessionId, mpsc::Sender<MumbleMessage>>,
    crypt: HashMap<SessionId, UdpCrypt>,
    udp_pair: HashMap<SessionId, SocketAddr>,
    udp_pair_by_addr: HashMap<SocketAddr, SessionId>,
    crypt_states: HashMap<SessionId, Arc<tokio::sync::Mutex<CryptStateOcb2>>>,
    tcp_tunnel_mode: HashMap<SessionId, TcpTunnelMode>,
    voice_stats: HashMap<SessionId, VoiceStats>,
    last_resync_request: HashMap<SessionId, Instant>,
    /// Per-session voice target storage: session -> (target_id -> targets).
    voice_targets: HashMap<SessionId, HashMap<u32, Vec<VoiceTargetEntry>>>,
    channels: HashMap<u32, ChannelInfo>,
    channel_name_idx: HashMap<String, u32>,
    channel_members: HashMap<u32, HashSet<SessionId>>,
    default_channel: u32,
}

#[derive(Debug, Clone)]
pub struct ServerState {
    inner: Arc<RwLock<InnerState>>,
    pub cfg: ServerConfig,
    pub udp: Arc<tokio::sync::Mutex<Option<Arc<tokio::net::UdpSocket>>>>,
}

impl ServerState {
    pub fn new(cfg: ServerConfig) -> Self {
        let (channels, name_idx, members, default_channel) = build_channels(&cfg);
        Self {
            inner: Arc::new(RwLock::new(InnerState {
                next_session: 1,
                users: HashMap::new(),
                user_names: HashMap::new(),
                conns: HashMap::new(),
                crypt: HashMap::new(),
                udp_pair: HashMap::new(),
                udp_pair_by_addr: HashMap::new(),
                crypt_states: HashMap::new(),
                tcp_tunnel_mode: HashMap::new(),
                voice_stats: HashMap::new(),
                last_resync_request: HashMap::new(),
                voice_targets: HashMap::new(),
                channels,
                channel_name_idx: name_idx,
                channel_members: members,
                default_channel,
            })),
            cfg,
            udp: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub async fn alloc_session(&self) -> SessionId {
        let mut g = self.inner.write().await;
        let id = g.next_session;
        g.next_session += 1;
        id
    }

    pub async fn default_channel_id(&self) -> u32 {
        let g = self.inner.read().await;
        g.default_channel
    }

    pub async fn channel_info(&self, channel_id: u32) -> Option<ChannelInfo> {
        let g = self.inner.read().await;
        g.channels.get(&channel_id).cloned()
    }

    pub async fn channel_id_by_name(&self, name: &str) -> Option<u32> {
        let g = self.inner.read().await;
        g.channel_name_idx.get(name).copied()
    }

    pub async fn channels_snapshot(&self) -> Vec<ChannelInfo> {
        let g = self.inner.read().await;
        let mut chans: Vec<_> = g.channels.values().cloned().collect();
        chans.sort_by_key(|c| c.id);
        chans
    }

    pub async fn username_in_use(&self, name: &str) -> bool {
        let g = self.inner.read().await;
        g.user_names.contains_key(name)
    }

    pub async fn user_info(&self, session: SessionId) -> Option<UserInfo> {
        let g = self.inner.read().await;
        g.users.get(&session).cloned()
    }

    pub async fn add_user(&self, user: UserInfo) {
        let mut g = self.inner.write().await;
        if let Some(name) = user.name.as_ref() {
            g.user_names.insert(name.clone(), user.session);
        }
        g.channel_members
            .entry(user.channel_id)
            .or_default()
            .insert(user.session);
        g.users.insert(user.session, user);
    }

    pub async fn update_username(&self, session: SessionId, name: Option<String>) {
        let mut g = self.inner.write().await;
        let (old_name, new_name) = if let Some(info) = g.users.get_mut(&session) {
            let previous = info.name.clone();
            info.name = name.clone();
            (previous, info.name.clone())
        } else {
            return;
        };
        if let Some(old) = old_name {
            g.user_names.remove(&old);
        }
        if let Some(new_name) = new_name {
            g.user_names.insert(new_name, session);
        }
    }

    pub async fn remove_user(&self, session: SessionId) {
        let mut g = self.inner.write().await;
        if let Some(info) = g.users.remove(&session) {
            if let Some(name) = info.name {
                g.user_names.remove(&name);
            }
            if let Some(members) = g.channel_members.get_mut(&info.channel_id) {
                members.remove(&session);
            }
        }
        g.conns.remove(&session);
        g.crypt.remove(&session);
        if let Some(addr) = g.udp_pair.remove(&session) {
            g.udp_pair_by_addr.remove(&addr);
        }
        g.crypt_states.remove(&session);
        g.tcp_tunnel_mode.remove(&session);
        g.voice_stats.remove(&session);
        g.last_resync_request.remove(&session);
        g.voice_targets.remove(&session);
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        let g = self.inner.read().await;
        g.users.values().cloned().collect()
    }

    pub async fn register_conn(&self, session: SessionId, tx: mpsc::Sender<MumbleMessage>) {
        let mut g = self.inner.write().await;
        g.conns.insert(session, tx);
    }

    pub async fn broadcast_except(&self, except: SessionId, msg: MumbleMessage) -> usize {
        let targets: Vec<(SessionId, mpsc::Sender<MumbleMessage>)> = {
            let g = self.inner.read().await;
            g.conns
                .iter()
                .filter_map(|(sess, tx)| {
                    if *sess == except {
                        None
                    } else {
                        Some((*sess, tx.clone()))
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut delivered = 0;
        for (sess, tx) in targets {
            match tx.send(msg.clone()).await {
                Ok(_) => {
                    tracing::info!(from = except, to = sess, "broadcast deliver");
                    delivered += 1;
                }
                Err(err) => {
                    tracing::warn!(from = except, to = sess, error = ?err, "broadcast failed");
                }
            }
        }
        delivered
    }

    pub async fn broadcast_channel(
        &self,
        channel_id: u32,
        except: Option<SessionId>,
        msg: MumbleMessage,
    ) -> usize {
        let targets: Vec<(SessionId, mpsc::Sender<MumbleMessage>)> = {
            let g = self.inner.read().await;
            g.channel_members
                .get(&channel_id)
                .into_iter()
                .flat_map(|members| members.iter())
                .filter_map(|sess| {
                    if except.is_some() && except == Some(*sess) {
                        None
                    } else {
                        g.conns.get(sess).cloned().map(|tx| (*sess, tx))
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut delivered = 0;
        for (sess, tx) in targets {
            match tx.send(msg.clone()).await {
                Ok(_) => delivered += 1,
                Err(err) => {
                    tracing::warn!(session = sess, channel_id, error = ?err, "broadcast_channel failed");
                }
            }
        }
        delivered
    }

    pub async fn send_to(&self, session: SessionId, msg: MumbleMessage) -> bool {
        let tx = {
            let g = self.inner.read().await;
            g.conns.get(&session).cloned()
        };
        match tx {
            Some(sender) => match sender.send(msg).await {
                Ok(_) => true,
                Err(err) => {
                    tracing::warn!(session, error = ?err, "send_to failed (receiver closed)");
                    false
                }
            },
            None => {
                tracing::warn!(session, "send_to missing channel");
                false
            }
        }
    }

    pub async fn unregister_conn(&self, session: SessionId) {
        let mut g = self.inner.write().await;
        g.conns.remove(&session);
    }

    pub async fn move_user_to_channel(
        &self,
        session: SessionId,
        channel_id: u32,
    ) -> Result<UserInfo, ChannelError> {
        let mut g = self.inner.write().await;
        let current_channel = match g.users.get(&session) {
            Some(user) => {
                if user.channel_id == channel_id {
                    return Ok(user.clone());
                }
                user.channel_id
            }
            None => return Err(ChannelError::UnknownUser(session)),
        };

        let channel = g
            .channels
            .get(&channel_id)
            .cloned()
            .ok_or(ChannelError::UnknownChannel(channel_id))?;

        if channel.no_enter {
            return Err(ChannelError::NoEnter(channel.name));
        }

        if let Some(limit) = channel.max_users {
            let count = g
                .channel_members
                .get(&channel_id)
                .map(|set| set.len())
                .unwrap_or(0);
            if count >= limit as usize {
                return Err(ChannelError::Full(channel.name));
            }
        }

        let updated = {
            let user = g
                .users
                .get_mut(&session)
                .ok_or(ChannelError::UnknownUser(session))?;
            user.channel_id = channel_id;
            user.clone()
        };

        if let Some(members) = g.channel_members.get_mut(&current_channel) {
            members.remove(&session);
        }
        g.channel_members
            .entry(channel_id)
            .or_default()
            .insert(session);

        Ok(updated)
    }

    pub async fn set_crypt(&self, session: SessionId, c: UdpCrypt) {
        let key = c.key;
        let server_nonce = c.server_nonce;
        let client_nonce = c.client_nonce;
        let entry = {
            let mut g = self.inner.write().await;
            g.crypt.insert(session, c);
            g.voice_stats.entry(session).or_default();
            g.crypt_states
                .entry(session)
                .or_insert_with(|| {
                    let mut cs = CryptStateOcb2::new();
                    cs.set_key(&key, &server_nonce, &client_nonce);
                    Arc::new(tokio::sync::Mutex::new(cs))
                })
                .clone()
        };
        let mut guard = entry.lock().await;
        guard.set_key(&key, &server_nonce, &client_nonce);
    }

    pub async fn get_crypt(&self, session: SessionId) -> Option<UdpCrypt> {
        let g = self.inner.read().await;
        g.crypt.get(&session).copied()
    }

    pub async fn ensure_udp_bound(&self, bind_host: &str, port: u16) -> std::io::Result<bool> {
        let mut guard = self.udp.lock().await;
        if guard.is_some() {
            return Ok(false);
        }
        let addr = SocketAddr::new(
            bind_host.parse().unwrap_or(IpAddr::from([127, 0, 0, 1])),
            port,
        );
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        tracing::info!(%addr, "udp bound");
        *guard = Some(Arc::new(sock));
        Ok(true)
    }

    pub async fn crypt_entries(&self) -> Vec<(SessionId, UdpCrypt)> {
        let g = self.inner.read().await;
        g.crypt.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub async fn set_udp_pair(&self, session: SessionId, addr: SocketAddr) {
        let mut g = self.inner.write().await;
        if let Some(prev) = g.udp_pair.insert(session, addr) {
            g.udp_pair_by_addr.remove(&prev);
        }
        g.udp_pair_by_addr.insert(addr, session);
    }

    pub async fn get_udp_pair(&self, session: SessionId) -> Option<SocketAddr> {
        let g = self.inner.read().await;
        g.udp_pair.get(&session).copied()
    }

    pub async fn session_by_udp_addr(&self, addr: &SocketAddr) -> Option<SessionId> {
        let g = self.inner.read().await;
        g.udp_pair_by_addr.get(addr).copied()
    }

    pub async fn udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        let guard = self.udp.lock().await;
        guard.clone()
    }

    pub async fn crypt_state(
        &self,
        session: SessionId,
    ) -> Option<Arc<tokio::sync::Mutex<CryptStateOcb2>>> {
        let g = self.inner.read().await;
        g.crypt_states.get(&session).cloned()
    }

    pub async fn get_tcp_tunnel_mode(&self, session: SessionId) -> Option<TcpTunnelMode> {
        let g = self.inner.read().await;
        g.tcp_tunnel_mode.get(&session).copied()
    }

    pub async fn set_tcp_tunnel_mode(&self, session: SessionId, mode: TcpTunnelMode) {
        let mut g = self.inner.write().await;
        g.tcp_tunnel_mode.insert(session, mode);
    }

    pub async fn channel_members(&self, channel_id: u32) -> Vec<SessionId> {
        let g = self.inner.read().await;
        g.channel_members
            .get(&channel_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Apply a `UserState` update to the stored user and return the updated info.
    ///
    /// Returns `None` if the session is unknown.
    pub async fn update_user_state(
        &self,
        session: SessionId,
        us: &crate::proto::mumble::UserState,
    ) -> Option<UserInfo> {
        let mut g = self.inner.write().await;
        let info = g.users.get_mut(&session)?;
        info.apply_update(us);
        Some(info.clone())
    }

    /// Store voice target entries for a given session and target ID (1-30).
    pub async fn set_voice_targets(
        &self,
        session: SessionId,
        target_id: u32,
        targets: Vec<VoiceTargetEntry>,
    ) {
        let mut g = self.inner.write().await;
        g.voice_targets
            .entry(session)
            .or_default()
            .insert(target_id, targets);
    }

    /// Retrieve the raw voice target entries for a given session and target ID.
    pub async fn get_voice_targets(
        &self,
        session: SessionId,
        target_id: u32,
    ) -> Option<Vec<VoiceTargetEntry>> {
        let g = self.inner.read().await;
        g.voice_targets
            .get(&session)
            .and_then(|m| m.get(&target_id))
            .cloned()
    }

    /// Resolve a voice target into the set of recipient session IDs.
    ///
    /// Collects sessions from direct session targets and channel-based targets.
    /// The sender is always excluded from the result.
    pub async fn resolve_voice_target(
        &self,
        sender: SessionId,
        target_id: u32,
    ) -> HashSet<SessionId> {
        let g = self.inner.read().await;
        let mut recipients = HashSet::new();

        let entries = match g.voice_targets.get(&sender).and_then(|m| m.get(&target_id)) {
            Some(e) => e,
            None => return recipients,
        };

        for entry in entries {
            // Direct session whisper
            for &sess in &entry.session {
                if sess != sender {
                    recipients.insert(sess);
                }
            }

            // Channel-based whisper
            if let Some(channel_id) = entry.channel_id {
                if let Some(members) = g.channel_members.get(&channel_id) {
                    for &sess in members {
                        if sess != sender {
                            recipients.insert(sess);
                        }
                    }
                }

                // If children flag is set, include members of child channels
                if entry.children.unwrap_or(false) {
                    for (cid, info) in &g.channels {
                        if info.parent == Some(channel_id) {
                            if let Some(members) = g.channel_members.get(cid) {
                                for &sess in members {
                                    if sess != sender {
                                        recipients.insert(sess);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        recipients
    }

    pub async fn record_voice_packet(
        &self,
        session: SessionId,
        frame_number: Option<u64>,
        metrics: VoiceMetrics,
    ) {
        let mut g = self.inner.write().await;
        let stats = g.voice_stats.entry(session).or_default();
        stats.packets = stats.packets.saturating_add(1);
        if let Some(frame) = frame_number {
            stats.last_frame = Some(frame);
        }
        stats.last_update = Some(Instant::now());
        stats.good = metrics.good;
        stats.late = metrics.late;
        stats.lost = metrics.lost;
    }

    pub async fn mark_resync_request(
        &self,
        session: SessionId,
        now: Instant,
        interval: std::time::Duration,
    ) -> bool {
        let mut g = self.inner.write().await;
        match g.last_resync_request.get(&session) {
            Some(prev) if now.duration_since(*prev) < interval => false,
            _ => {
                g.last_resync_request.insert(session, now);
                true
            }
        }
    }
}

fn build_channels(cfg: &ServerConfig) -> ChannelBuild {
    let mut channels = HashMap::new();
    let mut name_idx = HashMap::new();
    let mut members: HashMap<u32, HashSet<SessionId>> = HashMap::new();

    let root = ChannelInfo {
        id: 0,
        name: "Root".to_string(),
        parent: None,
        description: None,
        position: Some(0),
        max_users: None,
        no_enter: false,
        silent: false,
    };
    name_idx.insert(root.name.clone(), root.id);
    members.insert(root.id, HashSet::new());
    channels.insert(root.id, root);

    let mut next_id: u32 = 1;
    let mut pending: Vec<&ChannelConfig> = cfg.channels.iter().collect();
    while !pending.is_empty() {
        let mut progressed = false;
        let mut idx = 0;
        while idx < pending.len() {
            let def = pending[idx];
            let parent_name = def.parent.as_deref().unwrap_or("Root");
            if let Some(&parent_id) = name_idx.get(parent_name) {
                if name_idx.contains_key(&def.name) {
                    panic!("duplicate channel name '{}'", def.name);
                }
                let info = ChannelInfo {
                    id: next_id,
                    name: def.name.clone(),
                    parent: Some(parent_id),
                    description: def.description.clone(),
                    position: def.position,
                    max_users: def.max_users,
                    no_enter: def.noenter.unwrap_or(false),
                    silent: def.silent.unwrap_or(false),
                };
                name_idx.insert(info.name.clone(), info.id);
                members.insert(info.id, HashSet::new());
                channels.insert(info.id, info);
                next_id += 1;
                pending.remove(idx);
                progressed = true;
            } else {
                idx += 1;
            }
        }
        if !progressed {
            let unresolved: Vec<String> = pending.iter().map(|c| c.name.clone()).collect();
            panic!(
                "invalid channel configuration, unresolved parents for {:?}",
                unresolved
            );
        }
    }

    let target_default = cfg.default_channel.trim();
    let default_channel = if let Some(id) = name_idx.get(target_default) {
        *id
    } else {
        if target_default != "Root" {
            tracing::warn!(
                channel = %target_default,
                "default channel not found, falling back to Root"
            );
        }
        0u32
    };

    (channels, name_idx, members, default_channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::mumble::voice_target::Target;
    use crate::server::config::ServerConfig;

    fn test_state() -> ServerState {
        ServerState::new(ServerConfig::default())
    }

    #[tokio::test]
    async fn set_and_get_voice_target() {
        let state = test_state();
        let session: SessionId = 1;

        // Register a voice target with two session whispers
        let targets = vec![Target {
            session: vec![10, 20],
            channel_id: None,
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(session, 5, targets.clone()).await;

        let retrieved = state.get_voice_targets(session, 5).await;
        assert!(retrieved.is_some(), "should retrieve stored targets");
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].session, vec![10, 20]);
    }

    #[tokio::test]
    async fn get_voice_target_missing_returns_none() {
        let state = test_state();
        assert!(state.get_voice_targets(1, 5).await.is_none());
    }

    #[tokio::test]
    async fn overwrite_voice_target() {
        let state = test_state();
        let session: SessionId = 1;

        let targets_a = vec![Target {
            session: vec![10],
            channel_id: None,
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(session, 3, targets_a).await;

        let targets_b = vec![Target {
            session: vec![30, 40],
            channel_id: None,
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(session, 3, targets_b).await;

        let retrieved = state.get_voice_targets(session, 3).await.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].session, vec![30, 40]);
    }

    #[tokio::test]
    async fn clear_voice_targets_on_user_remove() {
        let state = test_state();
        let session = state.alloc_session().await;
        let mut user = UserInfo::new(session, 0);
        user.name = Some("alice".into());
        state.add_user(user).await;

        let targets = vec![Target {
            session: vec![10],
            channel_id: None,
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(session, 5, targets).await;
        assert!(state.get_voice_targets(session, 5).await.is_some());

        state.remove_user(session).await;
        assert!(state.get_voice_targets(session, 5).await.is_none());
    }

    #[tokio::test]
    async fn resolve_voice_target_sessions() {
        let state = test_state();
        let session: SessionId = 1;

        // Target with specific session IDs
        let targets = vec![Target {
            session: vec![10, 20, 30],
            channel_id: None,
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(session, 5, targets).await;

        let recipients = state.resolve_voice_target(session, 5).await;
        assert_eq!(recipients.len(), 3);
        assert!(recipients.contains(&10));
        assert!(recipients.contains(&20));
        assert!(recipients.contains(&30));
    }

    #[tokio::test]
    async fn resolve_voice_target_channel() {
        let state = test_state();
        let sender: SessionId = 1;

        // Put users 10 and 20 into channel 0 (Root)
        for s in [10u32, 20] {
            let mut u = UserInfo::new(s, 0);
            u.name = Some(format!("user{s}"));
            state.add_user(u).await;
        }

        // Target channel 0
        let targets = vec![Target {
            session: vec![],
            channel_id: Some(0),
            group: None,
            links: None,
            children: None,
        }];
        state.set_voice_targets(sender, 2, targets).await;

        let recipients = state.resolve_voice_target(sender, 2).await;
        assert!(recipients.contains(&10));
        assert!(recipients.contains(&20));
        // Sender should not be in the result
        assert!(!recipients.contains(&sender));
    }

    #[tokio::test]
    async fn resolve_voice_target_missing_returns_empty() {
        let state = test_state();
        let recipients = state.resolve_voice_target(1, 99).await;
        assert!(recipients.is_empty());
    }

    #[tokio::test]
    async fn user_info_has_full_state_fields() {
        let user = UserInfo {
            session: 1,
            name: Some("alice".into()),
            channel_id: 0,
            self_mute: true,
            self_deaf: false,
            mute: false,
            deaf: false,
            suppress: false,
            priority_speaker: false,
            recording: true,
            user_id: Some(42),
            comment: Some("hello".into()),
            hash: Some("abc123".into()),
        };
        assert!(user.self_mute);
        assert!(!user.self_deaf);
        assert!(user.recording);
        assert_eq!(user.user_id, Some(42));
        assert_eq!(user.comment.as_deref(), Some("hello"));
        assert_eq!(user.hash.as_deref(), Some("abc123"));
    }

    #[tokio::test]
    async fn user_info_defaults_to_false_flags() {
        let user = UserInfo::new(1, 0);
        assert_eq!(user.session, 1);
        assert_eq!(user.channel_id, 0);
        assert_eq!(user.name, None);
        assert!(!user.self_mute);
        assert!(!user.self_deaf);
        assert!(!user.mute);
        assert!(!user.deaf);
        assert!(!user.suppress);
        assert!(!user.priority_speaker);
        assert!(!user.recording);
        assert_eq!(user.user_id, None);
        assert_eq!(user.comment, None);
        assert_eq!(user.hash, None);
    }

    #[tokio::test]
    async fn update_user_state_self_mute() {
        let state = test_state();
        let session = state.alloc_session().await;
        let mut user = UserInfo::new(session, 0);
        user.name = Some("alice".into());
        state.add_user(user).await;

        let us = crate::proto::mumble::UserState {
            session: Some(session),
            self_mute: Some(true),
            self_deaf: Some(true),
            ..Default::default()
        };
        let updated = state.update_user_state(session, &us).await;
        assert!(updated.is_some());
        let info = updated.unwrap();
        assert!(info.self_mute);
        assert!(info.self_deaf);

        // Verify it persists
        let info2 = state.user_info(session).await.unwrap();
        assert!(info2.self_mute);
        assert!(info2.self_deaf);
    }

    #[tokio::test]
    async fn update_user_state_does_not_clear_unset_fields() {
        let state = test_state();
        let session = state.alloc_session().await;
        let mut user = UserInfo::new(session, 0);
        user.name = Some("bob".into());
        user.self_mute = true;
        user.comment = Some("old comment".into());
        state.add_user(user).await;

        // Send an update that only sets recording, leaves self_mute unset
        let us = crate::proto::mumble::UserState {
            session: Some(session),
            recording: Some(true),
            ..Default::default()
        };
        let updated = state.update_user_state(session, &us).await.unwrap();
        assert!(updated.recording);
        // self_mute and comment should be preserved
        assert!(updated.self_mute);
        assert_eq!(updated.comment.as_deref(), Some("old comment"));
    }

    #[tokio::test]
    async fn update_user_state_unknown_session_returns_none() {
        let state = test_state();
        let us = crate::proto::mumble::UserState {
            session: Some(999),
            self_mute: Some(true),
            ..Default::default()
        };
        assert!(state.update_user_state(999, &us).await.is_none());
    }

    #[tokio::test]
    async fn user_info_to_proto_roundtrip() {
        let mut user = UserInfo::new(5, 2);
        user.name = Some("carol".into());
        user.self_mute = true;
        user.recording = true;
        user.priority_speaker = true;
        user.comment = Some("test".into());
        user.hash = Some("deadbeef".into());
        user.user_id = Some(100);

        let proto = user.to_user_state();
        assert_eq!(proto.session, Some(5));
        assert_eq!(proto.channel_id, Some(2));
        assert_eq!(proto.name, Some("carol".into()));
        assert_eq!(proto.self_mute, Some(true));
        assert_eq!(proto.self_deaf, Some(false));
        assert_eq!(proto.mute, Some(false));
        assert_eq!(proto.deaf, Some(false));
        assert_eq!(proto.recording, Some(true));
        assert_eq!(proto.priority_speaker, Some(true));
        assert_eq!(proto.comment, Some("test".into()));
        assert_eq!(proto.hash, Some("deadbeef".into()));
        assert_eq!(proto.user_id, Some(100));
    }
}
