use std::convert::TryFrom;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::{rngs::OsRng, RngCore};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout};
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::audio::VoicePacket;
use crate::error::MumbleError;
use crate::messages::{
    read_envelope, MessageDecodeError, MessageEnvelope, MumbleMessage, TcpMessageKind,
};
use crate::proto::mumble::{
    reject::RejectType, Authenticate, ChannelRemove, ChannelState, CodecVersion, CryptSetup,
    TextMessage, UserRemove, UserState, Version,
};
use crate::state::{ClientState, UdpState};
use crate::udp::UdpTunnel;

enum ConnectionCommand {
    SendPing,
    SendAudio(VoicePacket),
}

#[derive(Clone, Debug)]
enum CryptUpdate {
    Full(UdpState),
    Resync {
        server_nonce: [u8; 16],
        client_nonce: [u8; 16],
    },
}

#[derive(Clone)]
struct UdpOptions {
    host: String,
    port: u16,
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
    /// Codec negotiation message indicating server preferences.
    CodecVersion(CodecVersion),
    CryptSetup(CryptSetup),
    ChannelState(ChannelState),
    ChannelRemove(ChannelRemove),
    UserState(UserState),
    UserRemove(UserRemove),
    TextMessage(TextMessage),
    Other(MumbleMessage),
    Unknown(MessageEnvelope),
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
    pub client_type: i32,
    /// Enable UDP voice tunnel negotiation once CryptSetup is received.
    pub enable_udp: bool,
}

impl ConnectionConfig {
    /// Create a new configuration for the given host, using the default port.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 64738,
            tls_server_name: None,
            connect_timeout: Duration::from_secs(10),
            accept_invalid_certs: true,
            username: "mumble-rs".to_string(),
            password: None,
            tokens: Vec::new(),
            client_type: 1,
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
    pub fn client_type(mut self, client_type: i32) -> Self {
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
}

impl MumbleConnection {
    /// Create a connection handle with the provided configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        let state = ClientState::default();
        Self {
            config,
            server_version: None,
            shared_state: Arc::new(Mutex::new(state)),
            command_tx: None,
            shutdown_tx: None,
            connection_task: None,
            event_tx: broadcast::channel(32).0,
        }
    }

    /// Establish a TLS connection to the configured server and read the initial Version message.
    pub async fn connect(&mut self) -> Result<(), MumbleError> {
        if self.config.username.trim().is_empty() {
            return Err(MumbleError::InvalidConfig(
                "username may not be empty".into(),
            ));
        }

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let tcp_future = TcpStream::connect(&addr);
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
                    let _ = self.event_tx.send(MumbleEvent::ChannelState(message));
                }
                MumbleMessage::ChannelRemove(message) => {
                    let _ = self.event_tx.send(MumbleEvent::ChannelRemove(message));
                }
                MumbleMessage::UserState(message) => {
                    let _ = self.event_tx.send(MumbleEvent::UserState(message));
                }
                MumbleMessage::UserRemove(message) => {
                    let _ = self.event_tx.send(MumbleEvent::UserRemove(message));
                }
                MumbleMessage::TextMessage(message) => {
                    let _ = self.event_tx.send(MumbleEvent::TextMessage(message));
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

    /// Return the most recently received UDP handshake parameters, if any.
    pub async fn udp_state(&self) -> Option<UdpState> {
        self.shared_state.lock().await.udp.clone()
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

    async fn spawn_connection_task(
        &mut self,
        stream: TlsStream<TcpStream>,
    ) -> Result<(), MumbleError> {
        const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);

        let shared_state = Arc::clone(&self.shared_state);
        let event_tx = self.event_tx.clone();
        let udp_options = UdpOptions {
            host: self.config.host.clone(),
            port: self.config.port,
            enable: self.config.enable_udp,
        };

        let handle = tokio::spawn(async move {
            connection_loop(
                stream,
                shared_state,
                event_tx,
                udp_options,
                DEFAULT_INTERVAL,
                shutdown_rx,
                cmd_rx,
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
    mut stream: TlsStream<TcpStream>,
    state: Arc<Mutex<ClientState>>,
    event_tx: broadcast::Sender<MumbleEvent>,
    udp_options: UdpOptions,
    interval_duration: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut cmd_rx: mpsc::Receiver<ConnectionCommand>,
) {
    let mut udp_tunnel: Option<UdpTunnel> = None;

    if udp_options.enable {
        let initial_params = {
            let guard = state.lock().await;
            guard.udp.clone()
        };
        if let Some(params) = initial_params {
            match UdpTunnel::start(
                udp_options.host.clone(),
                udp_options.port,
                Arc::new(params),
                event_tx.clone(),
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
                if send_ping_internal(&mut stream, &state).await.is_err() {
                    break;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ConnectionCommand::SendPing) => {
                        if send_ping_internal(&mut stream, &state).await.is_err() {
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
                    None => break,
                }
            }
            result = read_envelope(&mut stream) => {
                match result {
                    Ok(envelope) => {
                        if let Some(update) =
                            handle_inbound_message(envelope.clone(), &state, &event_tx).await
                        {
                            handle_crypt_update(
                                update,
                                &state,
                                &event_tx,
                                &udp_options,
                                &mut udp_tunnel,
                                &mut stream,
                            )
                            .await;
                        }
                    }
                    Err(_) => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn send_ping_internal(
    stream: &mut TlsStream<TcpStream>,
    state: &Arc<Mutex<ClientState>>,
) -> Result<(), ()> {
    let mut guard = state.lock().await;
    let mut ping = crate::proto::mumble::Ping::default();
    ping.timestamp = Some(current_millis());
    ping.tcp_packets = Some(guard.ping_sent as u32);
    ping.tcp_ping_avg = Some(guard.ping_average_ms as f32);
    guard.ping_sent += 1;
    drop(guard);

    let message = MumbleMessage::Ping(ping);
    crate::messages::write_message(stream, &message)
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
            let _ = event_tx.send(MumbleEvent::ChannelState(message));
            None
        }
        Ok(MumbleMessage::ChannelRemove(message)) => {
            let _ = event_tx.send(MumbleEvent::ChannelRemove(message));
            None
        }
        Ok(MumbleMessage::UserState(message)) => {
            let _ = event_tx.send(MumbleEvent::UserState(message));
            None
        }
        Ok(MumbleMessage::UserRemove(message)) => {
            let _ = event_tx.send(MumbleEvent::UserRemove(message));
            None
        }
        Ok(MumbleMessage::TextMessage(message)) => {
            let _ = event_tx.send(MumbleEvent::TextMessage(message));
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

async fn send_udp_state_message(
    stream: &mut TlsStream<TcpStream>,
    state: &Arc<Mutex<ClientState>>,
    include_key: bool,
    include_client: bool,
) -> Result<(), MumbleError> {
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
        send_message(stream, TcpMessageKind::CryptSetup, &setup).await?;
    }

    Ok(())
}

async fn handle_crypt_update(
    update: CryptUpdate,
    state: &Arc<Mutex<ClientState>>,
    event_tx: &broadcast::Sender<MumbleEvent>,
    udp_options: &UdpOptions,
    udp_tunnel: &mut Option<UdpTunnel>,
    stream: &mut TlsStream<TcpStream>,
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
                match UdpTunnel::start(
                    udp_options.host.clone(),
                    udp_options.port,
                    Arc::clone(&arc_params),
                    event_tx.clone(),
                )
                .await
                {
                    Ok(tunnel) => {
                        tracing::info!("UDP tunnel established");
                        *udp_tunnel = Some(tunnel);
                    }
                    Err(err) => tracing::warn!("failed to start UDP tunnel: {err}"),
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
                    match UdpTunnel::start(
                        udp_options.host.clone(),
                        udp_options.port,
                        Arc::new(params),
                        event_tx.clone(),
                    )
                    .await
                    {
                        Ok(tunnel) => {
                            tracing::info!("UDP tunnel established");
                            *udp_tunnel = Some(tunnel);
                        }
                        Err(err) => tracing::warn!("failed to start UDP tunnel: {err}"),
                    }
                }
            }

            if let Some(tunnel) = udp_tunnel.as_ref() {
                if let Err(err) = tunnel.resync(server_nonce, client_nonce).await {
                    tracing::warn!("failed to apply UDP resync: {err}");
                }
            }

            if let Err(err) = send_udp_state_message(stream, state, false, true).await {
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
            .client_type(0)
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
        assert_eq!(config.client_type, 0);
        assert!(config.enable_udp);
    }

    #[test]
    fn authenticate_message_contains_credentials() {
        let config = ConnectionConfig::builder("example")
            .username("alice")
            .password("pw")
            .tokens(vec!["one".into(), "two".into()])
            .client_type(1)
            .build();

        let message = build_authenticate_message(&config);
        assert_eq!(message.username.as_deref(), Some("alice"));
        assert_eq!(message.password.as_deref(), Some("pw"));
        assert_eq!(message.tokens, vec!["one", "two"]);
        assert_eq!(message.client_type, Some(1));
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

async fn send_message<M: prost::Message>(
    stream: &mut TlsStream<TcpStream>,
    kind: TcpMessageKind,
    message: &M,
) -> Result<(), MumbleError> {
    let envelope = MessageEnvelope::try_from_message(kind, message)
        .map_err(|e| MumbleError::Protocol(format!("encode {kind:?} failed: {e}")))?;
    envelope
        .write_to(stream)
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
    auth.client_type = Some(config.client_type);
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
