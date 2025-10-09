//! High-level client primitives for interacting with a Mumble server.
//!
//! The crate is under active development; expect rapid iteration while we build out
//! feature parity with the reference Python implementation.
//!
//! ## Example
//!
//! ```no_run
//! use mumble_rs::{ConnectionConfig, MumbleConnection};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut config = ConnectionConfig::new("mumble.example");
//!     config.username = "rust-bot".to_string();
//!     config.accept_invalid_certs = true;
//!
//!     let mut connection = MumbleConnection::new(config);
//!     connection.connect().await?;
//!     let state = connection.state().await;
//!     Ok(())
//! }
//! ```

pub mod connection;
pub mod error;
pub mod messages;
pub mod proto;
pub mod state;

pub use connection::{ConnectionConfig, MumbleConnection};
pub use error::MumbleError;
