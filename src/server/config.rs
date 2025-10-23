use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_host: String,
    pub bind_port: u16,
    pub udp_bind_port: u16,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub server_name: Option<String>,
    pub welcome_text: Option<String>,
    pub max_bandwidth: Option<u32>,
    pub allow_anonymous: Option<bool>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_host: "127.0.0.1".to_string(),
            bind_port: 64738,
            udp_bind_port: 64738,
            certificate: None,
            private_key: None,
            server_name: Some("mumblers".to_string()),
            welcome_text: Some("Welcome".to_string()),
            max_bandwidth: Some(72000),
            allow_anonymous: Some(true),
        }
    }
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        let mut cfg: ServerConfig = toml::from_str(s)?;
        // Apply env overrides
        if let Ok(v) = std::env::var("MUMBLE_BIND_HOST") { cfg.bind_host = v; }
        if let Ok(v) = std::env::var("MUMBLE_BIND_PORT") { if let Ok(p) = v.parse() { cfg.bind_port = p; } }
        if let Ok(v) = std::env::var("MUMBLE_UDP_BIND_PORT") { if let Ok(p) = v.parse() { cfg.udp_bind_port = p; } }
        if let Ok(v) = std::env::var("MUMBLE_CERTIFICATE") { cfg.certificate = Some(v); }
        if let Ok(v) = std::env::var("MUMBLE_PRIVATE_KEY") { cfg.private_key = Some(v); }
        if let Ok(v) = std::env::var("MUMBLE_SERVER_NAME") { cfg.server_name = Some(v); }
        if let Ok(v) = std::env::var("MUMBLE_WELCOME_TEXT") { cfg.welcome_text = Some(v); }
        if let Ok(v) = std::env::var("MUMBLE_MAX_BANDWIDTH") { if let Ok(p) = v.parse() { cfg.max_bandwidth = Some(p); } }
        if let Ok(v) = std::env::var("MUMBLE_ALLOW_ANONYMOUS") { if let Ok(b) = v.parse() { cfg.allow_anonymous = Some(b); } }
        Ok(cfg)
    }
}

