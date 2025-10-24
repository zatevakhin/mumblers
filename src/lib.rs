//! High-level client primitives for interacting with a Mumble server.
//!
//! The crate is under active development; expect rapid iteration while we build out
//! feature parity with the reference Python implementation.
//!
//! ## Example
//!
//! ```no_run
//! use mumblers::{ConnectionConfig, MumbleConnection};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ConnectionConfig::builder("mumble.example")
//!         .username("rust-bot")
//!         .accept_invalid_certs(true)
//!         .build();
//!
//!     let mut connection = MumbleConnection::new(config);
//!     connection.connect().await?;
//!     let state = connection.state().await;
//!     Ok(())
//! }
//! ```

pub mod audio;
pub mod channels;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod messages;
pub mod proto;
pub mod server;
pub mod state;
mod udp;

#[cfg(feature = "audio")]
pub use audio::{
    AudioDecodeError, AudioEncodeError, AudioEncoder, AudioPlaybackManager, ReceivedAudioQueue,
    SoundChunk,
};
pub use audio::{AudioHeader, VoicePacket};
pub use channels::{Channel, Channels, SharedChannels};
pub use connection::{
    ClientType, ConnectionConfig, ConnectionConfigBuilder, MumbleConnection, MumbleEvent,
};
pub use crypto::ocb2::{
    CryptStateOcb2, DecryptError as OcbDecryptError, EncryptError as OcbEncryptError,
};
pub use error::MumbleError;
