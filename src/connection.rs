use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "audio")]
use std::time::Instant;
use std::time::{Duration, SystemTime};

use rand::{rngs::OsRng, RngCore};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout, Instant as TokioInstant};
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

#[cfg(feature = "audio")]
use crate::audio::AudioPlaybackManager;
use crate::audio::VoicePacket;
use crate::error::MumbleError;
use crate::messages::{
    read_envelope, MessageDecodeError, MessageEnvelope, MumbleMessage, TcpFrameDecoder,
    TcpMessageKind,
};
use crate::proto::mumble::{
    reject::RejectType, Authenticate, ChannelRemove, ChannelState, CodecVersion, CryptSetup,
    PermissionDenied, TextMessage, UserRemove, UserState, Version,
};
use crate::state::{ClientState, UdpState};
use crate::udp::UdpTunnel;

enum ConnectionCommand {
    SendPing,
    SendAudio(VoicePacket),
    SendMessage(MumbleMessage),
}

#[derive(Clone, Debug)]
enum CryptUpdate {
    Full(UdpState),
    Resync {
        server_nonce: [u8; 16],
        client_nonce: [u8; 16],
    },
}

#[derive(Clone, Copy)]
struct UdpOptions {
    target: Option<SocketAddr>,
    enable: bool,
}

/// Events emitted by the connection when new control messages arrive.
#[derive(Debug, Clone)]
pub enum MumbleEvent {
    Version(Version),
    ServerSync(crate::proto::mumble::ServerSync),
    Ping {
        message: crate::proto::mumble::Ping,
        round_trip_ms: Option<f64>,
    },
    /// Encrypted UDP ping event emitted by the tunnel keepalive loop.
    UdpPing(crate::proto::mumble_udp::Ping),
    /// Decrypted UDP audio frame delivered by the voice tunnel.
    UdpAudio(crate::audio::VoicePacket),
    #[cfg(feature = "audio")]
    /// Jitter-buffered PCM chunk ready for playback.
    AudioChunk {
        session_id: u32,
        chunk: crate::audio::SoundChunk,
    },
    /// Codec negotiation message indicating server preferences.
    CodecVersion(CodecVersion),
    CryptSetup(CryptSetup),
    ChannelState(ChannelState),
    ChannelRemove(ChannelRemove),
    UserState(UserState),
    UserRemove(UserRemove),
    TextMessage(TextMessage),
    PermissionDenied(PermissionDenied),
    Other(MumbleMessage),
    Unknown(MessageEnvelope),
}

/// Identifies the type of client connecting to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientType {
    Regular = 0,
    Bot = 1,
}

impl Default for ClientType {
    fn default() -> Self {
        ClientType::Bot
    }
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

    /// Finalise the builder, producing an owned [`ConnectionConfig`].
    pub fn build(self) -> ConnectionConfig {
        self.config
    }
}

/// Represents an async connection to a Mumble server.
pub struct MumbleConnection {
    config: ConnectionConfig,
    server_version: Option<Version>,
    shared_state: Arc<Mutex<ClientState>>,
    command_tx: Option<mpsc::Sender<ConnectionCommand>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    connection_task: Option<JoinHandle<()>>,
    event_tx: broadcast::Sender<MumbleEvent>,
    #[cfg(feature = "audio")]
    audio_playback: Option<Arc<AudioPlaybackManager>>,
    #[cfg(feature = "audio")]
    audio_task: Option<JoinHandle<()>>,
    udp_target: Option<SocketAddr>,
}

impl MumbleConnection {
    /// Create a connection handle with the provided configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        let state = ClientState::default();
        let (event_tx, _event_rx) = broadcast::channel(256);
        #[cfg(feature = "audio")]
        let playback = Some(Arc::new(AudioPlaybackManager::new()));
        Self {
            config,
            server_version: None,
            shared_state: Arc::new(Mutex::new(state)),
            command_tx: None,
            shutdown_tx: None,
            connection_task: None,
            event_tx,
            #[cfg(feature = "audio")]
            audio_playback: playback,
            #[cfg(feature = "audio")]
            audio_task: None,
            udp_target: None,
        }
    }

    /// Establish a TLS connection to the configured server and read the initial Version message.
    pub async fn connect(&mut self) -> Result<(), MumbleError> {
        if self.config.username.trim().is_empty() {
            return Err(MumbleError::InvalidConfig(
                "username may not be empty".into(),
            ));
        }

        let tcp_future = TcpStream::connect((self.config.host.as_str(), self.config.port));
        let tcp_stream = match timeout(self.config.connect_timeout, tcp_future).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(MumbleError::Network(err)),
            Err(_) => {
                return Err(MumbleError::Network(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timeout",
                )));
            }
        };

        tcp_stream.set_nodelay(true)?;
        self.udp_target = Some(tcp_stream.peer_addr().map_err(MumbleError::Network)?);

        let server_name_str = self
            .config
            .tls_server_name
            .as_deref()
            .unwrap_or(&self.config.host);

        let server_name = ServerName::try_from(server_name_str.to_string())
            .map_err(|_| MumbleError::InvalidConfig("invalid TLS server name".into()))?;

        let connector = create_tls_connector(self.config.accept_invalid_certs)?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        send_version(&mut tls_stream).await?;
        send_authenticate(&mut tls_stream, &self.config).await?;
        send_codec_version(&mut tls_stream).await?;

        loop {
            let envelope =
                match timeout(self.config.connect_timeout, read_envelope(&mut tls_stream)).await {
                    Ok(Ok(envelope)) => envelope,
                    Ok(Err(err)) => return Err(MumbleError::Network(err)),
                    Err(_) => {
                        return Err(MumbleError::Network(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "handshake message timeout",
                        )))
                    }
                };

            let message = match MumbleMessage::try_from(envelope) {
                Ok(message) => message,
                Err(MessageDecodeError::Decode { kind, source }) => {
                    return Err(MumbleError::Protocol(format!(
                        "failed to decode {kind:?}: {source}"
                    )))
                }
            };

            match message {
                MumbleMessage::Version(version) => {
                    let _ = self.event_tx.send(MumbleEvent::Version(version.clone()));
                    self.server_version = Some(version);
                }
                MumbleMessage::ServerSync(sync) => {
                    let mut state = self.shared_state.lock().await;
                    state.is_connected = true;
                    state.session_id = sync.session;
                    state.max_bandwidth = sync.max_bandwidth;
                    state.welcome_text = sync.welcome_text.clone();
                    state.permissions = sync.permissions;
                    drop(state);
                    let _ = self.event_tx.send(MumbleEvent::ServerSync(sync.clone()));
                    if self.config.enable_udp {
                        initiate_udp_handshake(&mut tls_stream, &self.shared_state).await?;
                    }
                    break;
                }
                MumbleMessage::CryptSetup(setup) => {
                    let params = match (
                        setup.key.as_ref(),
                        setup.client_nonce.as_ref(),
                        setup.server_nonce.as_ref(),
                    ) {
                        (Some(key), Some(client), Some(server))
                            if key.len() == 16 && client.len() == 16 && server.len() == 16 =>
                        {
                            let mut state = self.shared_state.lock().await;
                            let params = UdpState {
                                key: key.clone().try_into().unwrap(),
                                client_nonce: client.clone().try_into().unwrap(),
                                server_nonce: server.clone().try_into().unwrap(),
                            };
                            state.udp = Some(params);
                            drop(state);
                            Some(())
                        }
                        _ => {
                            tracing::warn!("received malformed CryptSetup message");
                            None
                        }
                    };
                    let _ = self.event_tx.send(MumbleEvent::CryptSetup(setup.clone()));
                    if params.is_some() && self.config.enable_udp {
                        tracing::debug!("CryptSetup received (UDP enablement pending)");
                    }
                }
                MumbleMessage::CodecVersion(codec) => {
                    {
                        let mut state = self.shared_state.lock().await;
                        state.codec_version = Some(codec.clone());
                    }
                    let _ = self.event_tx.send(MumbleEvent::CodecVersion(codec.clone()));
                }
                MumbleMessage::Reject(reject) => {
                    let mut reason = reject
                        .reason
                        .unwrap_or_else(|| "unknown reason".to_string());
                    if let Some(value) = reject.r#type {
                        if let Ok(kind) = RejectType::try_from(value) {
                            reason = format!("{kind:?}: {reason}");
                        }
                    }
                    return Err(MumbleError::Rejected(reason));
                }
                MumbleMessage::ChannelState(message) => {
                    apply_channel_state_update(&self.shared_state, &message).await;
                    let _ = self.event_tx.send(MumbleEvent::ChannelState(message));
                }
                MumbleMessage::ChannelRemove(message) => {
                    apply_channel_remove_update(&self.shared_state, &message).await;
                    let _ = self.event_tx.send(MumbleEvent::ChannelRemove(message));
                }
                MumbleMessage::UserState(message) => {
                    {
                        let mut state = self.shared_state.lock().await;
                        apply_user_state_update(&mut state, &message);
                    }
                    let _ = self.event_tx.send(MumbleEvent::UserState(message));
                }
                MumbleMessage::UserRemove(message) => {
                    {
                        let mut state = self.shared_state.lock().await;
                        apply_user_remove_update(&mut state, &message);
                    }
                    let _ = self.event_tx.send(MumbleEvent::UserRemove(message));
                }
                MumbleMessage::TextMessage(message) => {
                    let _ = self.event_tx.send(MumbleEvent::TextMessage(message));
                }
                MumbleMessage::PermissionDenied(message) => {
                    let _ = self.event_tx.send(MumbleEvent::PermissionDenied(message));
                }
                MumbleMessage::Authenticate(_)
                | MumbleMessage::Ping(_)
                | MumbleMessage::Unknown(_) => {
                    // Ignore other handshake-time messages for now.
                }
            }
        }

        self.spawn_connection_task(tls_stream).await?;
        Ok(())
    }

    /// Return the connection configuration.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Send a message to the server.
    pub async fn send_message(
        &self,
        message: crate::messages::MumbleMessage,
    ) -> Result<(), MumbleError> {
        if let Some(tx) = &self.command_tx {
            tx.send(ConnectionCommand::SendMessage(message))
                .await
                .map_err(|_| MumbleError::ConnectionLost("failed to send command"))?;
            Ok(())
        } else {
            Err(MumbleError::ConnectionLost("not connected"))
        }
    }

    /// Join a channel by sending a UserState message.
    pub async fn join_channel(&self, channel_id: u32) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let user_state = state.channels.lock().await.move_user_to_channel(
            state
                .session_id
                .ok_or(MumbleError::Channel("not authenticated".to_string()))?,
            channel_id,
        );
        drop(state);
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Send a text message to a channel.
    pub async fn send_channel_message(
        &self,
        channel_id: u32,
        message: String,
    ) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let text_message = state
            .channels
            .lock()
            .await
            .send_channel_message(channel_id, message);
        drop(state);
        self.send_message(crate::messages::MumbleMessage::TextMessage(text_message))
            .await
    }

    /// Send a private text message to a user.
    pub async fn send_private_message(
        &self,
        session_id: u32,
        message: String,
    ) -> Result<(), MumbleError> {
        let text_message = TextMessage {
            session: vec![session_id],
            message,
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::TextMessage(text_message))
            .await
    }

    /// Mute a user by sending a UserState message.
    pub async fn mute_user(&self, session_id: u32) -> Result<(), MumbleError> {
        let user_state = UserState {
            session: Some(session_id),
            mute: Some(true),
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Unmute a user by sending a UserState message.
    pub async fn unmute_user(&self, session_id: u32) -> Result<(), MumbleError> {
        let user_state = UserState {
            session: Some(session_id),
            mute: Some(false),
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Deafen a user by sending a UserState message.
    pub async fn deafen_user(&self, session_id: u32) -> Result<(), MumbleError> {
        let user_state = UserState {
            session: Some(session_id),
            deaf: Some(true),
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Undeafen a user by sending a UserState message.
    pub async fn undeafen_user(&self, session_id: u32) -> Result<(), MumbleError> {
        let user_state = UserState {
            session: Some(session_id),
            deaf: Some(false),
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Move a user to a different channel by sending a UserState message.
    pub async fn move_user_to_channel(
        &self,
        session_id: u32,
        channel_id: u32,
    ) -> Result<(), MumbleError> {
        let user_state = UserState {
            session: Some(session_id),
            channel_id: Some(channel_id),
            ..Default::default()
        };
        self.send_message(crate::messages::MumbleMessage::UserState(user_state))
            .await
    }

    /// Version message received from the server during connection setup.
    pub fn server_version(&self) -> Option<&Version> {
        self.server_version.as_ref()
    }

    /// Subscribe to the stream of Mumble events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<MumbleEvent> {
        self.event_tx.subscribe()
    }

    /// Current snapshot of the server-provided state.
    pub async fn state(&self) -> ClientState {
        self.shared_state.lock().await.clone()
    }

    /// Last codec negotiation preferences announced by the server, if any.
    pub async fn codec_version(&self) -> Option<crate::proto::mumble::CodecVersion> {
        self.shared_state.lock().await.codec_version.clone()
    }

    /// Access the shared playback manager that buffers incoming voice audio.
    #[cfg(feature = "audio")]
    pub fn audio_playback(&self) -> Option<Arc<AudioPlaybackManager>> {
        self.audio_playback.clone()
    }

    /// Return the most recently received UDP handshake parameters, if any.
    pub async fn udp_state(&self) -> Option<UdpState> {
        self.shared_state.lock().await.udp.clone()
    }

    /// Block until UDP CryptSetup parameters are available (or timeout elapses).
    pub async fn wait_for_udp_ready(&self, timeout: Option<Duration>) -> Result<(), MumbleError> {
        if !self.config.enable_udp {
            return Err(MumbleError::InvalidConfig(
                "UDP support disabled in connection config".into(),
            ));
        }
        if self.shared_state.lock().await.udp.is_some() {
            return Ok(());
        }

        let check_interval = Duration::from_millis(20);
        let deadline = timeout.map(|limit| TokioInstant::now() + limit);
        loop {
            {
                if self.shared_state.lock().await.udp.is_some() {
                    return Ok(());
                }
            }
            if let Some(deadline) = deadline {
                if TokioInstant::now() >= deadline {
                    return Err(MumbleError::Timeout(
                        "timed out waiting for UDP CryptSetup".into(),
                    ));
                }
            }
            sleep(check_interval).await;
        }
    }

    /// Send a ping message immediately and update latency statistics.
    pub async fn send_ping(&mut self) -> Result<(), MumbleError> {
        if let Some(tx) = &self.command_tx {
            tx.send(ConnectionCommand::SendPing)
                .await
                .map_err(|_| MumbleError::ConnectionLost("connection task stopped"))?
        } else {
            return Err(MumbleError::InvalidConfig(
                "connection not established".into(),
            ));
        }
        Ok(())
    }

    /// Enqueue an Opus frame for delivery over the UDP tunnel.
    pub async fn send_audio(&self, packet: VoicePacket) -> Result<(), MumbleError> {
        if !self.config.enable_udp {
            return Err(MumbleError::InvalidConfig(
                "UDP support disabled in connection config".into(),
            ));
        }
        if let Some(tx) = &self.command_tx {
            tx.send(ConnectionCommand::SendAudio(packet))
                .await
                .map_err(|_| MumbleError::ConnectionLost("connection task stopped"))?;
        } else {
            return Err(MumbleError::InvalidConfig(
                "connection not established".into(),
            ));
        }
        Ok(())
    }

    /// Handle an inbound ping response from the server.
    pub async fn handle_pong(&self, ping: crate::proto::mumble::Ping) {
        let round_trip = ping
            .timestamp
            .map(|ts| current_millis().saturating_sub(ts) as f64);
        let mut state = self.shared_state.lock().await;
        state.ping_received += 1;
        apply_latency_metrics(&mut state, &ping);
        drop(state);
        let _ = self.event_tx.send(MumbleEvent::Ping {
            message: ping,
            round_trip_ms: round_trip,
        });
    }

    /// Join a channel by name by resolving the name to an ID.
    pub async fn join_channel_by_name(&self, channel_name: &str) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let channel_id = state
            .channels
            .lock()
            .await
            .find_by_name(channel_name)
            .ok_or(MumbleError::Channel(format!(
                "channel '{}' not found",
                channel_name
            )))?
            .channel_id;
        drop(state);
        self.join_channel(channel_id).await
    }

    /// Move a user to a channel by names by resolving the names to IDs.
    pub async fn move_user_to_channel_by_names(
        &self,
        user_name: &str,
        channel_name: &str,
    ) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        let channel_id = state
            .channels
            .lock()
            .await
            .find_by_name(channel_name)
            .ok_or(MumbleError::Channel(format!(
                "channel '{}' not found",
                channel_name
            )))?
            .channel_id;
        drop(state);
        self.move_user_to_channel(session_id, channel_id).await
    }

    /// Send a text message to a channel by name.
    pub async fn send_channel_message_by_name(
        &self,
        channel_name: &str,
        message: String,
    ) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let channel_id = state
            .channels
            .lock()
            .await
            .find_by_name(channel_name)
            .ok_or(MumbleError::Channel(format!(
                "channel '{}' not found",
                channel_name
            )))?
            .channel_id;
        drop(state);
        self.send_channel_message(channel_id, message).await
    }

    /// Send a private text message to a user by name.
    pub async fn send_private_message_by_name(
        &self,
        user_name: &str,
        message: String,
    ) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        drop(state);
        self.send_private_message(session_id, message).await
    }

    /// Mute a user by name.
    pub async fn mute_user_by_name(&self, user_name: &str) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        drop(state);
        self.mute_user(session_id).await
    }

    /// Unmute a user by name.
    pub async fn unmute_user_by_name(&self, user_name: &str) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        drop(state);
        self.unmute_user(session_id).await
    }

    /// Deafen a user by name.
    pub async fn deafen_user_by_name(&self, user_name: &str) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        drop(state);
        self.deafen_user(session_id).await
    }

    /// Undeafen a user by name.
    pub async fn undeafen_user_by_name(&self, user_name: &str) -> Result<(), MumbleError> {
        let state = self.shared_state.lock().await;
        let session_id = state
            .get_user_session(user_name)
            .ok_or(MumbleError::Channel(format!(
                "user '{}' not found",
                user_name
            )))?;
        drop(state);
        self.undeafen_user(session_id).await
    }

    async fn spawn_connection_task(
        &mut self,
        stream: TlsStream<TcpStream>,
    ) -> Result<(), MumbleError> {
        const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
        const UDP_RESYNC_INTERVAL: Duration = Duration::from_secs(5);

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (resync_tx, resync_rx) = mpsc::channel(4);

        let shared_state = Arc::clone(&self.shared_state);
        let event_tx = self.event_tx.clone();
        let udp_options = UdpOptions {
            target: self.udp_target,
            enable: self.config.enable_udp,
        };

        #[cfg(feature = "audio")]
        let playback = if self.config.enable_udp {
            self.audio_playback.clone()
        } else {
            None
        };

        #[cfg(feature = "audio")]
        let mut audio_flush_handle: Option<JoinHandle<()>> = None;

        #[cfg(feature = "audio")]
        if let Some(manager) = playback.as_ref() {
            let manager = Arc::clone(manager);
            let mut flush_shutdown = shutdown_rx.clone();
            let event_tx_clone = event_tx.clone();
            audio_flush_handle = Some(tokio::spawn(async move {
                let mut ticker = interval(Duration::from_millis(10));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let ready = manager.drain_ready(Instant::now()).await;
                            for (session_id, chunk) in ready {
                                let _ = event_tx_clone.send(MumbleEvent::AudioChunk { session_id, chunk });
                            }
                        }
                        changed = flush_shutdown.changed() => {
                            if changed.is_ok() && *flush_shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
                let remaining = manager.drain_all().await;
                for (session_id, chunk) in remaining {
                    let _ = event_tx_clone.send(MumbleEvent::AudioChunk { session_id, chunk });
                }
            }));
        }

        #[cfg(feature = "audio")]
        {
            if let Some(handle) = self.audio_task.take() {
                handle.abort();
            }
            self.audio_task = audio_flush_handle;
        }

        let handle = tokio::spawn(async move {
            connection_loop(
                stream,
                shared_state,
                event_tx,
                udp_options,
                DEFAULT_INTERVAL,
                shutdown_rx,
                cmd_rx,
                resync_rx,
                resync_tx,
                UDP_RESYNC_INTERVAL,
                #[cfg(feature = "audio")]
                playback,
            )
            .await;
        });

        self.shutdown_tx = Some(shutdown_tx);
        self.command_tx = Some(cmd_tx);
        self.connection_task = Some(handle);
        Ok(())
    }
}

impl Drop for MumbleConnection {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }
        #[cfg(feature = "audio")]
        if let Some(handle) = self.audio_task.take() {
            handle.abort();
        }
    }
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn apply_latency_metrics(state: &mut ClientState, ping: &crate::proto::mumble::Ping) {
    state.last_ping_received_ms = Some(current_millis() as u128);
    if let Some(send_ts) = ping.timestamp {
        let now = current_millis();
        if now > send_ts {
            let rtt = (now - send_ts) as f64;
            let count = state.ping_received as f64;
            let avg = if count > 0.0 {
                ((state.ping_average_ms * (count - 1.0)) + rtt) / count
            } else {
                rtt
            };
            state.ping_average_ms = avg;
        }
    }
}

async fn connection_loop(
    stream: TlsStream<TcpStream>,
    state: Arc<Mutex<ClientState>>,
    event_tx: broadcast::Sender<MumbleEvent>,
    udp_options: UdpOptions,
    interval_duration: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut cmd_rx: mpsc::Receiver<ConnectionCommand>,
    mut resync_rx: mpsc::Receiver<()>,
    resync_tx: mpsc::Sender<()>,
    udp_resync_interval: Duration,
    #[cfg(feature = "audio")] playback: Option<Arc<AudioPlaybackManager>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut reader_shutdown = shutdown.clone();

    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Result<MessageEnvelope, io::Error>>(64);
    let reader_task = tokio::spawn(async move {
        let mut decoder = TcpFrameDecoder::new();
        loop {
            tokio::select! {
                changed = reader_shutdown.changed() => {
                    if changed.is_ok() && *reader_shutdown.borrow() {
                        break;
                    }
                }
                res = decoder.read_next(&mut reader) => {
                    let is_err = res.is_err();
                    if inbound_tx.send(res).await.is_err() {
                        break;
                    }
                    if is_err {
                        break;
                    }
                }
            }
        }
    });

    let mut udp_tunnel: Option<UdpTunnel> = None;

    if udp_options.enable {
        if udp_options.target.is_none() {
            tracing::warn!("UDP enabled but no resolved target address; skipping tunnel startup");
        }
        let initial_params = {
            let guard = state.lock().await;
            guard.udp.clone()
        };
        if let (Some(params), Some(target)) = (initial_params, udp_options.target) {
            match UdpTunnel::start(
                target,
                Arc::new(params),
                event_tx.clone(),
                #[cfg(feature = "audio")]
                playback.clone(),
                resync_tx.clone(),
                udp_resync_interval,
            )
            .await
            {
                Ok(tunnel) => {
                    tracing::info!("UDP tunnel established");
                    udp_tunnel = Some(tunnel);
                }
                Err(err) => tracing::warn!("failed to start UDP tunnel: {err}"),
            }
        }
    }

    let mut ticker = interval(interval_duration);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if send_ping_internal(&mut writer, &state).await.is_err() {
                    break;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ConnectionCommand::SendPing) => {
                        if send_ping_internal(&mut writer, &state).await.is_err() {
                            break;
                        }
                    }
                     Some(ConnectionCommand::SendAudio(packet)) => {
                         if let Some(tunnel) = udp_tunnel.as_ref() {
                             if let Err(err) = tunnel.send_audio(packet).await {
                                 tracing::warn!("failed to send UDP audio: {err}");
                             }
                         } else {
                             tracing::debug!("discarding audio frame: UDP tunnel not yet established");
                         }
                     }
                     Some(ConnectionCommand::SendMessage(message)) => {
                         if let Err(err) = crate::messages::write_message(&mut writer, &message).await {
                             tracing::warn!("failed to send message: {err}");
                         }
                     }
                    None => break,
                }
            }
            resync = resync_rx.recv() => {
                if resync.is_some() {
                    if let Err(err) = send_cryptsetup_request(&mut writer).await {
                        tracing::warn!("failed to request UDP resync: {err}");
                    }
                }
            }
            inbound = inbound_rx.recv() => {
                match inbound {
                    Some(Ok(envelope)) => {
                        let conn_session = {
                            let guard = state.lock().await;
                            guard.session_id
                        };
                        tracing::info!(
                            conn_session,
                            kind = ?envelope.kind,
                            "client: envelope received"
                        );
                        if let Some(update) =
                            handle_inbound_message(envelope.clone(), &state, &event_tx).await
                        {
                            handle_crypt_update(
                                update,
                                &state,
                                &event_tx,
                                &udp_options,
                                &mut udp_tunnel,
                                &mut writer,
                                &resync_tx,
                                udp_resync_interval,
                                #[cfg(feature = "audio")]
                                playback.clone(),
                            )
                            .await;
                        }
                    }
                    Some(Err(err)) => {
                        let conn_session = {
                            let guard = state.lock().await;
                            guard.session_id
                        };
                        tracing::warn!(
                            conn_session,
                            error = ?err,
                            "client: read_envelope failed, terminating connection loop"
                        );
                        break;
                    }
                    None => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    reader_task.abort();
}

async fn send_ping_internal<W>(writer: &mut W, state: &Arc<Mutex<ClientState>>) -> Result<(), ()>
where
    W: AsyncWrite + Unpin,
{
    let mut guard = state.lock().await;
    let mut ping = crate::proto::mumble::Ping::default();
    ping.timestamp = Some(current_millis());
    ping.tcp_packets = Some(guard.ping_sent as u32);
    ping.tcp_ping_avg = Some(guard.ping_average_ms as f32);
    guard.ping_sent += 1;
    drop(guard);

    let message = MumbleMessage::Ping(ping);
    crate::messages::write_message(writer, &message)
        .await
        .map_err(|err| {
            tracing::warn!("failed to send ping: {err}");
        })
}

async fn handle_inbound_message(
    envelope: MessageEnvelope,
    state: &Arc<Mutex<ClientState>>,
    event_tx: &broadcast::Sender<MumbleEvent>,
) -> Option<CryptUpdate> {
    match MumbleMessage::try_from(envelope.clone()) {
        Ok(MumbleMessage::CryptSetup(setup)) => {
            let action = {
                let mut guard = state.lock().await;
                update_udp_state_with_cryptsetup(&mut guard, &setup)
            };
            let _ = event_tx.send(MumbleEvent::CryptSetup(setup));
            action
        }
        Ok(MumbleMessage::CodecVersion(message)) => {
            {
                let mut guard = state.lock().await;
                guard.codec_version = Some(message.clone());
            }
            let _ = event_tx.send(MumbleEvent::CodecVersion(message));
            None
        }
        Ok(MumbleMessage::Ping(ping)) => {
            let round_trip = ping
                .timestamp
                .map(|ts| current_millis().saturating_sub(ts) as f64);
            {
                let mut guard = state.lock().await;
                guard.ping_received += 1;
                apply_latency_metrics(&mut guard, &ping);
            }
            let _ = event_tx.send(MumbleEvent::Ping {
                message: ping,
                round_trip_ms: round_trip,
            });
            None
        }
        Ok(MumbleMessage::ServerSync(sync)) => {
            {
                let mut guard = state.lock().await;
                guard.is_connected = true;
                guard.session_id = sync.session;
                guard.max_bandwidth = sync.max_bandwidth;
                guard.welcome_text = sync.welcome_text.clone();
                guard.permissions = sync.permissions;
            }
            let _ = event_tx.send(MumbleEvent::ServerSync(sync));
            None
        }
        Ok(MumbleMessage::Version(version)) => {
            let _ = event_tx.send(MumbleEvent::Version(version));
            None
        }
        Ok(MumbleMessage::ChannelState(message)) => {
            apply_channel_state_update(state, &message).await;
            let _ = event_tx.send(MumbleEvent::ChannelState(message));
            None
        }
        Ok(MumbleMessage::ChannelRemove(message)) => {
            apply_channel_remove_update(state, &message).await;
            let _ = event_tx.send(MumbleEvent::ChannelRemove(message));
            None
        }
        Ok(MumbleMessage::UserState(message)) => {
            {
                let mut guard = state.lock().await;
                let conn_session = guard.session_id;
                tracing::info!(
                    conn_session,
                    session = ?message.session,
                    channel = ?message.channel_id,
                    actor = ?message.actor,
                    "client: received user state"
                );
                apply_user_state_update(&mut guard, &message);
                if let Some(session) = message.session {
                    if message.channel_id.is_some() {
                        let current = guard.user_channels.get(&session).copied();
                        tracing::info!(
                            conn_session,
                            session,
                            new_value = ?current,
                            "client: user channel updated"
                        );
                    }
                }
            }
            let conn_session = {
                let guard = state.lock().await;
                guard.session_id
            };
            let delivered = match event_tx.send(MumbleEvent::UserState(message.clone())) {
                Ok(count) => {
                    tracing::info!(
                        conn_session,
                        delivered = count,
                        "client: dispatched user state event"
                    );
                    count
                }
                Err(err) => {
                    tracing::warn!(
                        conn_session,
                        error = ?err,
                        "client: failed to dispatch user state event"
                    );
                    0
                }
            };
            if delivered == 0 {
                tracing::debug!(
                    conn_session,
                    "client: user state event had no active subscribers"
                );
            }
            None
        }
        Ok(MumbleMessage::UserRemove(message)) => {
            {
                let mut guard = state.lock().await;
                apply_user_remove_update(&mut guard, &message);
            }
            let _ = event_tx.send(MumbleEvent::UserRemove(message));
            None
        }
        Ok(MumbleMessage::TextMessage(message)) => {
            let _ = event_tx.send(MumbleEvent::TextMessage(message));
            None
        }
        Ok(MumbleMessage::PermissionDenied(message)) => {
            let _ = event_tx.send(MumbleEvent::PermissionDenied(message));
            None
        }
        Ok(other) => {
            let _ = event_tx.send(MumbleEvent::Other(other));
            None
        }
        Err(err) => {
            tracing::warn!("failed to decode inbound message: {err}");
            let _ = event_tx.send(MumbleEvent::Unknown(envelope));
            None
        }
    }
}

fn update_udp_state_with_cryptsetup(
    state: &mut ClientState,
    setup: &CryptSetup,
) -> Option<CryptUpdate> {
    let key = setup.key.as_deref();
    let client = setup.client_nonce.as_deref();
    let server = setup.server_nonce.as_deref();

    if let (Some(key), Some(client), Some(server)) = (key, client, server) {
        if key.len() == 16 && client.len() == 16 && server.len() == 16 {
            let params = UdpState {
                key: slice_to_array(key),
                client_nonce: slice_to_array(client),
                server_nonce: slice_to_array(server),
            };
            state.udp = Some(params.clone());
            return Some(CryptUpdate::Full(params));
        }
    }

    if let Some(server) = server {
        if server.len() == 16 {
            if let Some(existing) = state.udp.as_mut() {
                let server_nonce = slice_to_array(server);
                existing.server_nonce = server_nonce;
                return Some(CryptUpdate::Resync {
                    server_nonce,
                    client_nonce: existing.client_nonce,
                });
            } else {
                tracing::warn!("received CryptSetup resync without existing UDP state");
            }
        }
    }
    None
}

async fn apply_channel_state_update(state: &Arc<Mutex<ClientState>>, message: &ChannelState) {
    let channels = {
        let guard = state.lock().await;
        guard.channels.clone()
    };
    channels.lock().await.update(message);
}

async fn apply_channel_remove_update(state: &Arc<Mutex<ClientState>>, message: &ChannelRemove) {
    if message.channel_id == 0 {
        return;
    }
    let channels = {
        let guard = state.lock().await;
        guard.channels.clone()
    };
    channels.lock().await.remove(message.channel_id);
}

fn apply_user_state_update(state: &mut ClientState, message: &UserState) {
    if let Some(session) = message.session {
        match (&message.name, message.channel_id) {
            (Some(name), Some(channel_id)) => {
                tracing::debug!(session, channel_id, user=%name, "UserState: name+channel");
                state.users.insert(session, name.clone());
                state.user_channels.insert(session, channel_id);
            }
            (Some(name), None) => {
                tracing::debug!(session, user=%name, "UserState: name only");
                state.users.insert(session, name.clone());
                // Heuristic: some servers omit channel_id for users in root.
                // If we don't yet have a mapping for this session, assume root (0).
                state.user_channels.entry(session).or_insert(0);
            }
            (None, Some(channel_id)) => {
                let existing = state.users.get(&session).cloned();
                tracing::debug!(session, channel_id, known_user=?existing, "UserState: channel only");
                state.user_channels.insert(session, channel_id);
            }
            (None, None) => {
                tracing::debug!(session, "UserState: no name/channel");
            }
        }
    } else {
        tracing::debug!("UserState without session; ignoring");
    }
}

fn apply_user_remove_update(state: &mut ClientState, message: &UserRemove) {
    let session = message.session;
    state.users.remove(&session);
    state.user_channels.remove(&session);
}

fn slice_to_array(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}

fn generate_udp_state() -> UdpState {
    let mut key = [0u8; 16];
    let mut client_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut client_nonce);
    UdpState {
        key,
        client_nonce,
        server_nonce: [0u8; 16],
    }
}

async fn ensure_udp_state(state: &Arc<Mutex<ClientState>>) -> UdpState {
    let mut guard = state.lock().await;
    if let Some(existing) = guard.udp.clone() {
        return existing;
    }
    let generated = generate_udp_state();
    guard.udp = Some(generated.clone());
    generated
}

async fn send_udp_state_message<W>(
    writer: &mut W,
    state: &Arc<Mutex<ClientState>>,
    include_key: bool,
    include_client: bool,
) -> Result<(), MumbleError>
where
    W: AsyncWrite + Unpin,
{
    let params = {
        let guard = state.lock().await;
        guard.udp.clone()
    };

    if let Some(params) = params {
        let mut setup = CryptSetup::default();
        if include_key {
            setup.key = Some(params.key.to_vec());
        }
        if include_client {
            setup.client_nonce = Some(params.client_nonce.to_vec());
        }
        send_message(writer, TcpMessageKind::CryptSetup, &setup).await?;
    }

    Ok(())
}

async fn send_cryptsetup_request<W>(writer: &mut W) -> Result<(), MumbleError>
where
    W: AsyncWrite + Unpin,
{
    let setup = CryptSetup::default();
    send_message(writer, TcpMessageKind::CryptSetup, &setup).await
}

async fn handle_crypt_update(
    update: CryptUpdate,
    state: &Arc<Mutex<ClientState>>,
    event_tx: &broadcast::Sender<MumbleEvent>,
    udp_options: &UdpOptions,
    udp_tunnel: &mut Option<UdpTunnel>,
    writer: &mut (impl AsyncWrite + Unpin),
    resync_tx: &mpsc::Sender<()>,
    udp_resync_interval: Duration,
    #[cfg(feature = "audio")] playback: Option<Arc<AudioPlaybackManager>>,
) {
    if !udp_options.enable {
        return;
    }

    match update {
        CryptUpdate::Full(params) => {
            let arc_params = Arc::new(params.clone());
            if let Some(tunnel) = udp_tunnel.as_ref() {
                if let Err(err) = tunnel.update_key(Arc::clone(&arc_params)).await {
                    tracing::warn!("failed to update UDP key: {err}");
                }
            } else {
                if let Some(target) = udp_options.target {
                    match UdpTunnel::start(
                        target,
                        Arc::clone(&arc_params),
                        event_tx.clone(),
                        #[cfg(feature = "audio")]
                        playback.clone(),
                        resync_tx.clone(),
                        udp_resync_interval,
                    )
                    .await
                    {
                        Ok(tunnel) => {
                            tracing::info!("UDP tunnel established");
                            *udp_tunnel = Some(tunnel);
                        }
                        Err(err) => tracing::warn!("failed to start UDP tunnel: {err}"),
                    }
                } else {
                    tracing::warn!(
                        "UDP parameters received but no resolved target address; cannot start tunnel"
                    );
                }
            }
        }
        CryptUpdate::Resync {
            server_nonce,
            client_nonce,
        } => {
            if udp_tunnel.is_none() {
                if let Some(params) = {
                    let guard = state.lock().await;
                    guard.udp.clone()
                } {
                    if let Some(target) = udp_options.target {
                        match UdpTunnel::start(
                            target,
                            Arc::new(params),
                            event_tx.clone(),
                            #[cfg(feature = "audio")]
                            playback.clone(),
                            resync_tx.clone(),
                            udp_resync_interval,
                        )
                        .await
                        {
                            Ok(tunnel) => {
                                tracing::info!("UDP tunnel established");
                                *udp_tunnel = Some(tunnel);
                            }
                            Err(err) => tracing::warn!("failed to start UDP tunnel: {err}"),
                        }
                    } else {
                        tracing::warn!(
                            "UDP resync requested but no resolved target address; cannot start tunnel"
                        );
                    }
                }
            }

            if let Some(tunnel) = udp_tunnel.as_ref() {
                if let Err(err) = tunnel.resync(server_nonce, client_nonce).await {
                    tracing::warn!("failed to apply UDP resync: {err}");
                }
            }

            if let Err(err) = send_udp_state_message(writer, state, false, true).await {
                tracing::warn!("failed to acknowledge UDP resync: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn latency_metrics_update_average() {
        let mut state = ClientState::default();
        state.ping_received = 1;
        state.ping_average_ms = 0.0;
        let mut ping = crate::proto::mumble::Ping::default();
        ping.timestamp = Some(current_millis().saturating_sub(5));
        apply_latency_metrics(&mut state, &ping);
        assert!(state.last_ping_received_ms.is_some());
        assert!(state.ping_average_ms >= 0.0);
    }

    #[test]
    fn connection_config_builder_sets_fields() {
        let config = ConnectionConfig::builder("example.org")
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

        assert_eq!(config.host, "example.org");
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

    #[test]
    fn connection_config_parses_host_and_port() {
        let config = ConnectionConfig::new("voice.example.net:12345");
        assert_eq!(config.host, "voice.example.net");
        assert_eq!(config.port, 12345);

        let rebuilt = ConnectionConfig::builder("voice.example.net:23456").build();
        assert_eq!(rebuilt.host, "voice.example.net");
        assert_eq!(rebuilt.port, 23456);
    }

    #[test]
    fn connection_config_handles_ipv6_variants() {
        let ipv6_default = ConnectionConfig::new("2001:db8::1");
        assert_eq!(ipv6_default.host, "2001:db8::1");
        assert_eq!(ipv6_default.port, 64738);

        let bracketed = ConnectionConfig::new("[2001:db8::2]:51234");
        assert_eq!(bracketed.host, "2001:db8::2");
        assert_eq!(bracketed.port, 51234);
    }

    #[test]
    fn authenticate_message_contains_credentials() {
        let config = ConnectionConfig::builder("example")
            .username("alice")
            .password("pw")
            .tokens(vec!["one".into(), "two".into()])
            .client_type(ClientType::Bot)
            .build();

        let message = build_authenticate_message(&config);
        assert_eq!(message.username.as_deref(), Some("alice"));
        assert_eq!(message.password.as_deref(), Some("pw"));
        assert_eq!(message.tokens, vec!["one", "two"]);
        assert_eq!(message.client_type, Some(i32::from(ClientType::Bot)));
        assert_eq!(message.opus, Some(true));
    }

    #[tokio::test]
    async fn handle_pong_emits_event() {
        let connection = MumbleConnection::new(ConnectionConfig::new("localhost"));
        let mut receiver = connection.subscribe_events();
        let mut ping = crate::proto::mumble::Ping::default();
        ping.timestamp = Some(super::current_millis());

        connection.handle_pong(ping.clone()).await;

        match receiver.recv().await.expect("event available") {
            MumbleEvent::Ping { message, .. } => assert_eq!(message, ping),
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn cryptsetup_updates_state_and_emits_event() {
        let state = Arc::new(Mutex::new(ClientState::default()));
        let (event_tx, mut event_rx) = broadcast::channel(4);

        let mut crypt = CryptSetup::default();
        crypt.key = Some(vec![1; 16]);
        crypt.client_nonce = Some(vec![2; 16]);
        crypt.server_nonce = Some(vec![3; 16]);
        let envelope =
            MessageEnvelope::try_from_message(TcpMessageKind::CryptSetup, &crypt).unwrap();

        let update = handle_inbound_message(envelope, &state, &event_tx).await;
        match update {
            Some(CryptUpdate::Full(params)) => {
                assert_eq!(params.key, [1; 16]);
                assert_eq!(params.client_nonce, [2; 16]);
                assert_eq!(params.server_nonce, [3; 16]);
            }
            other => panic!("unexpected crypt update: {:?}", other),
        }

        let guard = state.lock().await;
        let udp = guard.udp.as_ref().expect("udp state");
        assert_eq!(udp.key, [1; 16]);
        assert_eq!(udp.client_nonce, [2; 16]);
        assert_eq!(udp.server_nonce, [3; 16]);
        drop(guard);

        match event_rx.recv().await.expect("event message") {
            MumbleEvent::CryptSetup(event) => {
                assert_eq!(event.key.unwrap(), vec![1; 16]);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }
}

fn create_tls_connector(accept_invalid_certs: bool) -> Result<TlsConnector, MumbleError> {
    let builder = rustls::ClientConfig::builder();

    let builder = if accept_invalid_certs {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::default()))
    } else {
        let root_store = rustls::RootCertStore::empty();
        builder.with_root_certificates(root_store)
    };

    let mut config = builder.with_no_client_auth();

    config.alpn_protocols.push(b"mumble".to_vec());

    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Debug, Default)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

async fn send_version(stream: &mut TlsStream<TcpStream>) -> Result<(), MumbleError> {
    let version = build_version_message();
    send_message(stream, TcpMessageKind::Version, &version).await
}

async fn send_authenticate(
    stream: &mut TlsStream<TcpStream>,
    config: &ConnectionConfig,
) -> Result<(), MumbleError> {
    let message = build_authenticate_message(config);
    send_message(stream, TcpMessageKind::Authenticate, &message).await
}

async fn send_codec_version(stream: &mut TlsStream<TcpStream>) -> Result<(), MumbleError> {
    let message = build_codec_version_message();
    send_message(stream, TcpMessageKind::CodecVersion, &message).await
}

async fn send_message<W, M>(
    writer: &mut W,
    kind: TcpMessageKind,
    message: &M,
) -> Result<(), MumbleError>
where
    W: AsyncWrite + Unpin,
    M: prost::Message,
{
    let envelope = MessageEnvelope::try_from_message(kind, message)
        .map_err(|e| MumbleError::Protocol(format!("encode {kind:?} failed: {e}")))?;
    envelope
        .write_to(writer)
        .await
        .map_err(MumbleError::Network)
}

async fn initiate_udp_handshake(
    stream: &mut TlsStream<TcpStream>,
    state: &Arc<Mutex<ClientState>>,
) -> Result<(), MumbleError> {
    let _ = ensure_udp_state(state).await;
    send_udp_state_message(stream, state, true, true).await
}

fn build_version_message() -> Version {
    use crate::messages::PROTOCOL_VERSION;
    use std::env;

    let major = PROTOCOL_VERSION.0 as u64;
    let minor = PROTOCOL_VERSION.1 as u64;
    let patch = PROTOCOL_VERSION.2 as u64;

    let mut version = Version::default();

    let version_v1_patch = PROTOCOL_VERSION.2.min(255) as u32;
    let version_v1 =
        ((PROTOCOL_VERSION.0 as u32) << 16) | ((PROTOCOL_VERSION.1 as u32) << 8) | version_v1_patch;
    let version_v2 = (major << 48) | (minor << 32) | (patch << 16);

    version.version_v1 = Some(version_v1);
    version.version_v2 = Some(version_v2);
    version.release = Some(format!("mumble-rs {}", env!("CARGO_PKG_VERSION")));
    version.os = Some(format!("{} {}", env::consts::OS, env::consts::ARCH));
    version.os_version = Some(format!("Rust {}", env!("CARGO_PKG_VERSION")));
    version
}

fn build_authenticate_message(config: &ConnectionConfig) -> Authenticate {
    let mut auth = Authenticate::default();
    auth.username = Some(config.username.clone());
    if let Some(password) = &config.password {
        auth.password = Some(password.clone());
    }
    auth.tokens = config.tokens.clone();
    auth.opus = Some(true);
    auth.client_type = Some(i32::from(config.client_type));
    auth
}

fn build_codec_version_message() -> CodecVersion {
    let mut codec = CodecVersion::default();
    codec.alpha = -2147483637;
    codec.beta = -2147483637;
    codec.prefer_alpha = false;
    codec.opus = Some(true);
    codec
}
