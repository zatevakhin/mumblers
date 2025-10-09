use std::collections::HashMap;

/// Minimal client-side state captured after connecting.
#[derive(Clone, Debug, Default)]
pub struct ClientState {
    /// True if the client completed the authentication handshake.
    pub is_connected: bool,
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
}
