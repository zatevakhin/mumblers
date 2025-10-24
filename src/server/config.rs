use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelConfig {
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub position: Option<i32>,
    #[serde(default)]
    pub max_users: Option<u32>,
    #[serde(default)]
    pub noenter: Option<bool>,
    #[serde(default)]
    pub silent: Option<bool>,
}

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
    #[serde(default = "default_channel_name")]
    pub default_channel: String,
    #[serde(default)]
    pub channels: Vec<ChannelConfig>,
    #[serde(default = "default_codec_alpha")]
    pub codec_alpha: i32,
    #[serde(default = "default_codec_beta")]
    pub codec_beta: i32,
    #[serde(default = "default_codec_prefer_alpha")]
    pub codec_prefer_alpha: bool,
    #[serde(default = "default_enable_opus")]
    pub enable_opus: bool,
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
            default_channel: default_channel_name(),
            channels: Vec::new(),
            codec_alpha: default_codec_alpha(),
            codec_beta: default_codec_beta(),
            codec_prefer_alpha: default_codec_prefer_alpha(),
            enable_opus: default_enable_opus(),
        }
    }
}

fn default_channel_name() -> String {
    "Root".to_string()
}

fn default_codec_alpha() -> i32 {
    0x8000_000bu32 as i32
}

fn default_codec_beta() -> i32 {
    0x8000_000bu32 as i32
}

fn default_codec_prefer_alpha() -> bool {
    true
}

fn default_enable_opus() -> bool {
    true
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        let mut cfg: ServerConfig = toml::from_str(s)?;
        // Apply env overrides
        if let Ok(v) = std::env::var("MUMBLE_BIND_HOST") {
            cfg.bind_host = v;
        }
        if let Ok(v) = std::env::var("MUMBLE_BIND_PORT") {
            if let Ok(p) = v.parse() {
                cfg.bind_port = p;
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_UDP_BIND_PORT") {
            if let Ok(p) = v.parse() {
                cfg.udp_bind_port = p;
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_CERTIFICATE") {
            cfg.certificate = Some(v);
        }
        if let Ok(v) = std::env::var("MUMBLE_PRIVATE_KEY") {
            cfg.private_key = Some(v);
        }
        if let Ok(v) = std::env::var("MUMBLE_SERVER_NAME") {
            cfg.server_name = Some(v);
        }
        if let Ok(v) = std::env::var("MUMBLE_WELCOME_TEXT") {
            cfg.welcome_text = Some(v);
        }
        if let Ok(v) = std::env::var("MUMBLE_MAX_BANDWIDTH") {
            if let Ok(p) = v.parse() {
                cfg.max_bandwidth = Some(p);
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_ALLOW_ANONYMOUS") {
            if let Ok(b) = v.parse() {
                cfg.allow_anonymous = Some(b);
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_DEFAULT_CHANNEL") {
            cfg.default_channel = v;
        }
        if let Ok(v) = std::env::var("MUMBLE_CODEC_ALPHA") {
            if let Ok(p) = v.parse::<i32>() {
                cfg.codec_alpha = p;
            } else if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                if let Ok(p) = i32::from_str_radix(hex, 16) {
                    cfg.codec_alpha = p;
                }
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_CODEC_BETA") {
            if let Ok(p) = v.parse::<i32>() {
                cfg.codec_beta = p;
            } else if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                if let Ok(p) = i32::from_str_radix(hex, 16) {
                    cfg.codec_beta = p;
                }
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_CODEC_PREFER_ALPHA") {
            if let Ok(b) = v.parse() {
                cfg.codec_prefer_alpha = b;
            }
        }
        if let Ok(v) = std::env::var("MUMBLE_ENABLE_OPUS") {
            if let Ok(b) = v.parse() {
                cfg.enable_opus = b;
            }
        }
        Ok(cfg)
    }
}
