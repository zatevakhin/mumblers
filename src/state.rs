use std::collections::HashMap;

use crate::channels::SharedChannels;
use crate::proto::mumble::CodecVersion;

/// Minimal client-side state captured after connecting.
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
    /// Cache of user names keyed by session id.
    pub users: HashMap<u32, String>,
    /// Cache of user channel IDs keyed by session id.
    pub user_channels: HashMap<u32, u32>,
    /// Server's max bandwidth allocation for this client.
    pub max_bandwidth: Option<u32>,
    /// Aggregated permissions for the root channel.
    pub permissions: Option<u64>,
    /// Welcome text presented by the server.
    pub welcome_text: Option<String>,
    /// Server-provided codec negotiation preferences.
    pub codec_version: Option<CodecVersion>,
    /// Cryptographic parameters provided via CryptSetup for the UDP tunnel.
    pub udp: Option<UdpState>,
    /// Channel hierarchy and management.
    pub channels: SharedChannels,
}

impl ClientState {
    pub fn get_users_in_channel(&self, channel_id: u32) -> Vec<u32> {
        self.user_channels
            .iter()
            .filter_map(|(session, &ch_id)| {
                if ch_id == channel_id {
                    Some(*session)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn get_user_session(&self, name: &str) -> Option<u32> {
        self.users.iter().find_map(|(session, user_name)| {
            if user_name == name {
                Some(*session)
            } else {
                None
            }
        })
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
            user_channels: HashMap::new(),
            max_bandwidth: None,
            permissions: None,
            welcome_text: None,
            codec_version: None,
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
