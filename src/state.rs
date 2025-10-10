use std::collections::HashMap;

use crate::proto::mumble::CodecVersion;

/// Minimal client-side state captured after connecting.
#[derive(Clone, Debug, Default)]
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
