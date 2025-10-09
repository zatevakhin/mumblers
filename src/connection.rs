use std::convert::TryFrom;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout};
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::error::MumbleError;
use crate::messages::{
    read_envelope, MessageDecodeError, MessageEnvelope, MumbleMessage, TcpMessageKind,
};
use crate::proto::mumble::{reject::RejectType, Authenticate, Version};
use crate::state::ClientState;

enum ConnectionCommand {
    SendPing,
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
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new("localhost")
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
                    self.server_version = Some(version);
                }
                MumbleMessage::ServerSync(sync) => {
                    let mut state = self.shared_state.lock().await;
                    state.is_connected = true;
                    state.session_id = sync.session;
                    state.max_bandwidth = sync.max_bandwidth;
                    state.welcome_text = sync.welcome_text;
                    state.permissions = sync.permissions;
                    break;
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

    /// Current snapshot of the server-provided state.
    pub async fn state(&self) -> ClientState {
        self.shared_state.lock().await.clone()
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

    /// Handle an inbound ping response from the server.
    pub async fn handle_pong(&self, ping: crate::proto::mumble::Ping) {
        let mut state = self.shared_state.lock().await;
        state.ping_received += 1;
        apply_latency_metrics(&mut state, &ping);
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

        let handle = tokio::spawn(async move {
            connection_loop(stream, shared_state, DEFAULT_INTERVAL, shutdown_rx, cmd_rx).await;
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
    interval_duration: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut cmd_rx: mpsc::Receiver<ConnectionCommand>,
) {
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
                    None => break,
                }
            }
            result = read_envelope(&mut stream) => {
                match result {
                    Ok(envelope) => {
                        if let Ok(MumbleMessage::Ping(ping)) = MumbleMessage::try_from(envelope) {
                            let mut guard = state.lock().await;
                            guard.ping_received += 1;
                            apply_latency_metrics(&mut guard, &ping);
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

#[cfg(test)]
mod tests {
    use super::*;

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
