use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

use super::config::{ChannelConfig, ServerConfig};
use crate::crypto::ocb2::CryptStateOcb2;
use crate::messages::MumbleMessage;

pub type SessionId = u32;

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
}

#[derive(Debug, Clone, Copy)]
pub struct UdpCrypt {
    pub key: [u8; 16],
    pub server_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct VoiceStats {
    pub packets: u64,
    pub last_frame: Option<u64>,
    pub last_update: Option<Instant>,
    pub good: u32,
    pub late: u32,
    pub lost: i32,
}

impl Default for VoiceStats {
    fn default() -> Self {
        Self {
            packets: 0,
            last_frame: None,
            last_update: None,
            good: 0,
            late: 0,
            lost: 0,
        }
    }
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
    voice_stats: HashMap<SessionId, VoiceStats>,
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
                voice_stats: HashMap::new(),
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
        g.voice_stats.remove(&session);
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

    pub async fn channel_members(&self, channel_id: u32) -> Vec<SessionId> {
        let g = self.inner.read().await;
        g.channel_members
            .get(&channel_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
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
}

fn build_channels(
    cfg: &ServerConfig,
) -> (
    HashMap<u32, ChannelInfo>,
    HashMap<String, u32>,
    HashMap<u32, HashSet<SessionId>>,
    u32,
) {
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
