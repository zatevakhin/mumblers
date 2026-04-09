use std::time::Duration;

/// Identifies the type of client connecting to the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientType {
    Regular = 0,
    #[default]
    Bot = 1,
}

impl From<ClientType> for i32 {
    fn from(value: ClientType) -> Self {
        value as i32
    }
}

impl TryFrom<i32> for ClientType {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientType::Regular),
            1 => Ok(ClientType::Bot),
            _ => Err("invalid client type"),
        }
    }
}

/// User-provided parameters that describe how to reach a Mumble server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Hostname or IP address of the server.
    pub host: String,
    /// TCP port, defaults to the public Mumble port.
    pub port: u16,
    /// Optional TLS server name override.
    pub tls_server_name: Option<String>,
    /// Duration to wait for the initial TCP connection attempt.
    pub connect_timeout: Duration,
    /// Allow invalid or self-signed TLS certificates (temporary development default).
    pub accept_invalid_certs: bool,
    /// Username presented to the server during authentication.
    pub username: String,
    /// Optional password required by the server or user account.
    pub password: Option<String>,
    /// Additional access tokens supplied during authentication.
    pub tokens: Vec<String>,
    /// Client type flag (0 regular, 1 bot).
    pub client_type: ClientType,
    /// Enable UDP voice tunnel negotiation once CryptSetup is received.
    pub enable_udp: bool,
    /// Enable automatic reconnection on disconnect.
    pub reconnect: bool,
    /// Interval between reconnection attempts.
    pub reconnect_interval: Duration,
    /// Maximum number of reconnection attempts (None = unlimited).
    pub max_reconnect_attempts: Option<u32>,
}

fn normalize_host_and_port(raw: &str) -> (String, Option<u16>) {
    if raw.is_empty() {
        return (raw.to_string(), None);
    }

    if raw.starts_with('[') {
        if let Some(end) = raw.find(']') {
            let host = raw[1..end].to_string();
            let remainder = &raw[end + 1..];
            if let Some(stripped) = remainder.strip_prefix(':') {
                if let Ok(port) = stripped.parse::<u16>() {
                    return (host, Some(port));
                }
            }
            return (host, None);
        }
    }

    if let Some(idx) = raw.rfind(':') {
        if raw[..idx].contains(':') {
            return (raw.to_string(), None);
        }
        let (host_part, port_part) = raw.split_at(idx);
        let port_str = &port_part[1..];
        if !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host_part.to_string(), Some(port));
            }
        }
    }

    (raw.to_string(), None)
}

impl ConnectionConfig {
    /// Create a new configuration for the given host, using the default port.
    pub fn new(host: impl Into<String>) -> Self {
        let raw_host = host.into();
        let (host, port_override) = normalize_host_and_port(&raw_host);
        Self {
            host,
            port: port_override.unwrap_or(64738),
            tls_server_name: None,
            connect_timeout: Duration::from_secs(10),
            accept_invalid_certs: true,
            username: "mumble-rs".to_string(),
            password: None,
            tokens: Vec::new(),
            client_type: ClientType::Bot,
            enable_udp: false,
            reconnect: false,
            reconnect_interval: Duration::from_secs(10),
            max_reconnect_attempts: None,
        }
    }

    /// Begin building a custom configuration for the given host.
    pub fn builder(host: impl Into<String>) -> ConnectionConfigBuilder {
        ConnectionConfigBuilder {
            config: ConnectionConfig::new(host),
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new("localhost")
    }
}

/// Fluent builder for configuring a [`ConnectionConfig`].
#[derive(Clone, Debug)]
pub struct ConnectionConfigBuilder {
    config: ConnectionConfig,
}

impl ConnectionConfigBuilder {
    /// Override the TCP port used when connecting.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set a custom TLS server name for SNI/certificate matching.
    pub fn tls_server_name(mut self, name: impl Into<String>) -> Self {
        self.config.tls_server_name = Some(name.into());
        self
    }

    /// Configure the duration to wait for the TCP handshake.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Control whether invalid/self-signed certificates are accepted.
    pub fn accept_invalid_certs(mut self, accept: bool) -> Self {
        self.config.accept_invalid_certs = accept;
        self
    }

    /// Set the username presented to the server.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.config.username = username.into();
        self
    }

    /// Provide a password used during authentication.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.config.password = Some(password.into());
        self
    }

    /// Clear any previously assigned password.
    pub fn clear_password(mut self) -> Self {
        self.config.password = None;
        self
    }

    /// Replace the entire access token list.
    pub fn tokens(mut self, tokens: impl Into<Vec<String>>) -> Self {
        self.config.tokens = tokens.into();
        self
    }

    /// Append a single access token to the configuration.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.config.tokens.push(token.into());
        self
    }

    /// Configure the client type flag (0 regular, 1 bot).
    pub fn client_type(mut self, client_type: ClientType) -> Self {
        self.config.client_type = client_type;
        self
    }

    /// Enable or disable UDP voice tunnel negotiation.
    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.config.enable_udp = enable;
        self
    }

    /// Enable automatic reconnection on disconnect.
    pub fn reconnect(mut self, enable: bool) -> Self {
        self.config.reconnect = enable;
        self
    }

    /// Set the interval between reconnection attempts.
    pub fn reconnect_interval(mut self, interval: Duration) -> Self {
        self.config.reconnect_interval = interval;
        self
    }

    /// Set the maximum number of reconnection attempts (None = unlimited).
    pub fn max_reconnect_attempts(mut self, max: Option<u32>) -> Self {
        self.config.max_reconnect_attempts = max;
        self
    }

    /// Finalise the builder, producing an owned [`ConnectionConfig`].
    pub fn build(self) -> ConnectionConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ipv4_with_port() {
        let (h, p) = normalize_host_and_port("127.0.0.1:12345");
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, Some(12345));
    }

    #[test]
    fn normalize_ipv4_no_port() {
        let (h, p) = normalize_host_and_port("192.168.1.1");
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, None);
    }

    #[test]
    fn normalize_ipv6_bracketed() {
        let (h, p) = normalize_host_and_port("[::1]:9999");
        assert_eq!(h, "::1");
        assert_eq!(p, Some(9999));
    }

    #[test]
    fn normalize_ipv6_no_port() {
        let (h, p) = normalize_host_and_port("::1");
        assert_eq!(h, "::1");
        assert_eq!(p, None);
    }

    #[test]
    fn normalize_empty() {
        let (h, p) = normalize_host_and_port("");
        assert_eq!(h, "");
        assert_eq!(p, None);
    }

    #[test]
    fn connection_config_builder_sets_fields() {
        let config = ConnectionConfig::builder("mumble.example.com")
            .port(12345)
            .tls_server_name("server.example.org")
            .connect_timeout(Duration::from_secs(30))
            .accept_invalid_certs(false)
            .username("bot")
            .password("secret")
            .token("alpha")
            .token("beta")
            .client_type(ClientType::Regular)
            .enable_udp(true)
            .build();

        assert_eq!(config.host, "mumble.example.com");
        assert_eq!(config.port, 12345);
        assert_eq!(
            config.tls_server_name.as_deref(),
            Some("server.example.org")
        );
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(!config.accept_invalid_certs);
        assert_eq!(config.username, "bot");
        assert_eq!(config.password.as_deref(), Some("secret"));
        assert_eq!(config.tokens, vec!["alpha", "beta"]);
        assert_eq!(config.client_type, ClientType::Regular);
        assert!(config.enable_udp);
    }
}
