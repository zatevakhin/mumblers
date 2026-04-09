use std::collections::HashMap;

use crate::channels::SharedChannels;
use crate::proto::mumble::{CodecVersion, UserState};

/// Client-side representation of a remote user's state.
#[derive(Clone, Debug, Default)]
pub struct ClientUserInfo {
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

impl ClientUserInfo {
    /// Apply incremental fields from a `UserState` protobuf message.
    pub fn apply_update(&mut self, us: &UserState) {
        if let Some(name) = &us.name {
            self.name = Some(name.clone());
        }
        if let Some(channel_id) = us.channel_id {
            self.channel_id = channel_id;
        }
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

/// Client-side state captured after connecting.
#[derive(Clone, Debug)]
pub struct ClientState {
    /// True if the client completed the authentication handshake.
    pub is_connected: bool,
    /// Total number of pings sent.
    pub ping_sent: u64,
    /// Total number of pings received from the server.
    pub ping_received: u64,
    /// Average round-trip time in milliseconds.
    pub ping_average_ms: f64,
    /// Timestamp (ms since UNIX epoch) when the last ping was received.
    pub last_ping_received_ms: Option<u128>,
    /// Session identifier assigned by the server.
    pub session_id: Option<u32>,
    /// Cache of user info keyed by session id.
    pub users: HashMap<u32, ClientUserInfo>,
    /// Server's max bandwidth allocation for this client.
    pub max_bandwidth: Option<u32>,
    /// Aggregated permissions for the root channel.
    pub permissions: Option<u64>,
    /// Welcome text presented by the server.
    pub welcome_text: Option<String>,
    /// Server-provided codec negotiation preferences.
    pub codec_version: Option<CodecVersion>,
    /// Server configuration limits received via ServerConfig message.
    pub server_config: Option<crate::proto::mumble::ServerConfig>,
    /// Cryptographic parameters provided via CryptSetup for the UDP tunnel.
    pub udp: Option<UdpState>,
    /// Channel hierarchy and management.
    pub channels: SharedChannels,
}

impl ClientState {
    pub fn get_users_in_channel(&self, channel_id: u32) -> Vec<u32> {
        self.users
            .iter()
            .filter_map(|(session, info)| {
                if info.channel_id == channel_id {
                    Some(*session)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_user_session(&self, name: &str) -> Option<u32> {
        self.users.iter().find_map(|(session, info)| {
            if info.name.as_deref() == Some(name) {
                Some(*session)
            } else {
                None
            }
        })
    }

    /// Get the channel ID for a given user session.
    pub fn user_channel(&self, session: u32) -> Option<u32> {
        self.users.get(&session).map(|info| info.channel_id)
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self {
            is_connected: false,
            ping_sent: 0,
            ping_received: 0,
            ping_average_ms: 0.0,
            last_ping_received_ms: None,
            session_id: None,
            users: HashMap::new(),
            max_bandwidth: None,
            permissions: None,
            welcome_text: None,
            codec_version: None,
            server_config: None,
            udp: None,
            channels: crate::channels::new_shared_channels(),
        }
    }
}

/// Parameters required to initialise the UDP voice tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpState {
    /// Symmetric AES key.
    pub key: [u8; 16],
    /// Client nonce provided by the server.
    pub client_nonce: [u8; 16],
    /// Server nonce provided by the server.
    pub server_nonce: [u8; 16],
}
