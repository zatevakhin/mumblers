use thiserror::Error;
use tokio_rustls::rustls;

/// Crate-wide error type capturing common failure cases.
#[derive(Debug, Error)]
pub enum MumbleError {
    /// Input parameters failed validation.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Networking failure while communicating with the server.
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),
    /// TLS handshake or certificate validation failure.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    /// Protocol-level violation or serialization failure.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Server rejected the authentication attempt.
    #[error("server rejected connection: {0}")]
    Rejected(String),
    /// Operation timed out waiting for a server response.
    #[error("operation timed out: {0}")]
    Timeout(String),
    /// The connection dropped unexpectedly while the heartbeat was active.
    #[error("connection lost: {0}")]
    ConnectionLost(&'static str),
    /// Placeholder for functionality that remains to be implemented.
    #[error("unimplemented: {0}")]
    Unimplemented(&'static str),
    /// Channel operation failed.
    #[error("channel error: {0}")]
    Channel(String),
}
