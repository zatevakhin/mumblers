use prost::{EncodeError, Message};
use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::mumble::{
    Authenticate, ChannelRemove, ChannelState, CodecVersion, CryptSetup, PermissionDenied, Ping,
    Reject, ServerSync, TextMessage, UserRemove, UserState, Version,
};

/// Protocol revision tuple (major, minor, patch) advertised to the server.
pub const PROTOCOL_VERSION: (u32, u32, u32) = (1, 5, 735);
/// Size of the Mumble TCP framing header in bytes.
pub const TCP_PREAMBLE_SIZE: usize = 6;
/// Umurmur-compatible maximum TCP payload size (BUFSIZE 8192 - preamble).
pub const MAX_TCP_FRAME_SIZE: usize = 8192 - TCP_PREAMBLE_SIZE;

/// Stateful TCP frame decoder (umurmur-style).
///
/// This decoder retains partial reads across `.read_next()` calls, preventing framing
/// desynchronization when frames arrive fragmented.
#[derive(Debug)]
pub struct TcpFrameDecoder {
    rxbuf: [u8; 8192],
    rxcount: usize,
    msgsize: Option<usize>,
}

impl Default for TcpFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpFrameDecoder {
    pub fn new() -> Self {
        Self {
            rxbuf: [0u8; 8192],
            rxcount: 0,
            msgsize: None,
        }
    }

    pub async fn read_next<R>(&mut self, reader: &mut R) -> Result<MessageEnvelope, io::Error>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            let target = match self.msgsize {
                None => TCP_PREAMBLE_SIZE,
                Some(len) => TCP_PREAMBLE_SIZE + len,
            };

            if self.rxcount < target {
                let n = reader.read(&mut self.rxbuf[self.rxcount..target]).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading Mumble frame",
                    ));
                }
                self.rxcount += n;
            }

            if self.msgsize.is_none() && self.rxcount >= TCP_PREAMBLE_SIZE {
                let msg_type = u16::from_be_bytes([self.rxbuf[0], self.rxbuf[1]]);
                let length = u32::from_be_bytes([
                    self.rxbuf[2],
                    self.rxbuf[3],
                    self.rxbuf[4],
                    self.rxbuf[5],
                ]) as usize;

                if length > MAX_TCP_FRAME_SIZE {
                    let header = [
                        self.rxbuf[0],
                        self.rxbuf[1],
                        self.rxbuf[2],
                        self.rxbuf[3],
                        self.rxbuf[4],
                        self.rxbuf[5],
                    ];
                    self.rxcount = 0;
                    self.msgsize = None;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "frame too large: {length} bytes (type={msg_type}, header={:02x?})",
                            header
                        ),
                    ));
                }

                self.msgsize = Some(length);
            }

            if let Some(len) = self.msgsize {
                if self.rxcount >= TCP_PREAMBLE_SIZE + len {
                    let msg_type = u16::from_be_bytes([self.rxbuf[0], self.rxbuf[1]]);
                    let payload = self.rxbuf[TCP_PREAMBLE_SIZE..TCP_PREAMBLE_SIZE + len].to_vec();
                    self.rxcount = 0;
                    self.msgsize = None;
                    return Ok(MessageEnvelope::new(
                        TcpMessageKind::from_id(msg_type),
                        payload,
                    ));
                }
            }
        }
    }
}

/// High-level message identifier for TCP traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMessageKind {
    /// Server's initial Version message.
    Version,
    /// Authentication payload containing username, password, and tokens.
    Authenticate,
    /// Server rejected the connection attempt.
    Reject,
    /// Server synchronization payload delivered post-authentication.
    ServerSync,
    /// Ping/Pong keepalive message.
    Ping,
    /// Cryptographic setup for establishing the UDP tunnel.
    CryptSetup,
    /// Channel removal notification.
    ChannelRemove,
    /// Channel state update.
    ChannelState,
    /// User removal notification.
    UserRemove,
    /// User state update.
    UserState,
    /// Text message.
    TextMessage,
    /// Permission denied response.
    PermissionDenied,
    /// Codec version negotiation.
    CodecVersion,
    /// Any message that does not yet have an explicit mapping.
    Unknown(u16),
}

impl TcpMessageKind {
    /// Construct a message kind from its wire identifier.
    pub fn from_id(value: u16) -> Self {
        match value {
            0 => TcpMessageKind::Version,
            2 => TcpMessageKind::Authenticate,
            3 => TcpMessageKind::Ping,
            4 => TcpMessageKind::Reject,
            5 => TcpMessageKind::ServerSync,
            6 => TcpMessageKind::ChannelRemove,
            7 => TcpMessageKind::ChannelState,
            8 => TcpMessageKind::UserRemove,
            9 => TcpMessageKind::UserState,
            11 => TcpMessageKind::TextMessage,
            12 => TcpMessageKind::PermissionDenied,
            21 => TcpMessageKind::CodecVersion,
            15 => TcpMessageKind::CryptSetup,
            other => TcpMessageKind::Unknown(other),
        }
    }

    /// Return the numeric identifier associated with this message kind.
    pub fn as_id(self) -> u16 {
        match self {
            TcpMessageKind::Version => 0,
            TcpMessageKind::Authenticate => 2,
            TcpMessageKind::Ping => 3,
            TcpMessageKind::Reject => 4,
            TcpMessageKind::ServerSync => 5,
            TcpMessageKind::ChannelRemove => 6,
            TcpMessageKind::ChannelState => 7,
            TcpMessageKind::UserRemove => 8,
            TcpMessageKind::UserState => 9,
            TcpMessageKind::TextMessage => 11,
            TcpMessageKind::PermissionDenied => 12,
            TcpMessageKind::CodecVersion => 21,
            TcpMessageKind::CryptSetup => 15,
            TcpMessageKind::Unknown(value) => value,
        }
    }
}

/// Placeholder for the eventual strongly typed message abstraction.
#[derive(Debug, Clone)]
pub struct MessageEnvelope {
    /// Message identifier.
    pub kind: TcpMessageKind,
    /// Serialized protobuf payload.
    pub payload: Vec<u8>,
}

impl MessageEnvelope {
    /// Build an envelope from raw parts.
    pub fn new(kind: TcpMessageKind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }

    /// Build an envelope from a protobuf message.
    pub fn try_from_message<M: Message>(
        kind: TcpMessageKind,
        message: &M,
    ) -> Result<Self, EncodeError> {
        let mut payload = Vec::new();
        message.encode(&mut payload)?;
        Ok(Self { kind, payload })
    }

    /// Attempt to decode the payload as a Version message.
    pub fn decode_version(&self) -> Option<Version> {
        if self.kind != TcpMessageKind::Version {
            return None;
        }
        Version::decode(self.payload.as_slice()).ok()
    }

    /// Serialize the message envelope to the provided async writer.
    pub async fn write_to<W>(&self, writer: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let id = self.kind.as_id();
        let length = self.payload.len() as u32;

        let mut header = [0u8; TCP_PREAMBLE_SIZE];
        header[..2].copy_from_slice(&id.to_be_bytes());
        header[2..].copy_from_slice(&length.to_be_bytes());

        writer.write_all(&header).await?;
        writer.write_all(&self.payload).await?;

        Ok(())
    }

    /// Serialize the envelope into a contiguous byte buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TCP_PREAMBLE_SIZE + self.payload.len());
        bytes.extend_from_slice(&self.kind.as_id().to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// Read a single message from the wire using the standard Mumble framing.
pub async fn read_envelope<R>(reader: &mut R) -> Result<MessageEnvelope, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TCP_PREAMBLE_SIZE];
    reader.read_exact(&mut header).await?;

    let msg_type = u16::from_be_bytes([header[0], header[1]]);
    let length = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if length > MAX_TCP_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {length} bytes"),
        ));
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    Ok(MessageEnvelope::new(
        TcpMessageKind::from_id(msg_type),
        payload,
    ))
}

/// Fully typed representation of a TCP control message.
#[derive(Debug, Clone)]
pub enum MumbleMessage {
    Version(Version),
    Authenticate(Authenticate),
    Reject(Reject),
    ServerSync(ServerSync),
    Ping(Ping),
    CryptSetup(CryptSetup),
    ChannelRemove(ChannelRemove),
    ChannelState(ChannelState),
    UserRemove(UserRemove),
    UserState(UserState),
    TextMessage(TextMessage),
    PermissionDenied(crate::proto::mumble::PermissionDenied),
    CodecVersion(CodecVersion),
    /// Message type not yet modeled by this enum.
    Unknown(MessageEnvelope),
}

impl MumbleMessage {
    /// Return the message identifier corresponding to this variant.
    pub fn kind(&self) -> TcpMessageKind {
        match self {
            MumbleMessage::Version(_) => TcpMessageKind::Version,
            MumbleMessage::Authenticate(_) => TcpMessageKind::Authenticate,
            MumbleMessage::Reject(_) => TcpMessageKind::Reject,
            MumbleMessage::ServerSync(_) => TcpMessageKind::ServerSync,
            MumbleMessage::Ping(_) => TcpMessageKind::Ping,
            MumbleMessage::ChannelRemove(_) => TcpMessageKind::ChannelRemove,
            MumbleMessage::ChannelState(_) => TcpMessageKind::ChannelState,
            MumbleMessage::UserRemove(_) => TcpMessageKind::UserRemove,
            MumbleMessage::UserState(_) => TcpMessageKind::UserState,
            MumbleMessage::TextMessage(_) => TcpMessageKind::TextMessage,
            MumbleMessage::PermissionDenied(_) => TcpMessageKind::PermissionDenied,
            MumbleMessage::CryptSetup(_) => TcpMessageKind::CryptSetup,
            MumbleMessage::CodecVersion(_) => TcpMessageKind::CodecVersion,
            MumbleMessage::Unknown(envelope) => envelope.kind,
        }
    }

    /// Convert the message into a framed envelope ready to send on the wire.
    pub fn encode(&self) -> Result<MessageEnvelope, EncodeError> {
        match self {
            MumbleMessage::Version(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::Authenticate(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::Reject(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::ServerSync(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::Ping(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::CryptSetup(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::ChannelRemove(msg) => {
                MessageEnvelope::try_from_message(self.kind(), msg)
            }
            MumbleMessage::ChannelState(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::UserRemove(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::UserState(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::TextMessage(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::PermissionDenied(msg) => {
                MessageEnvelope::try_from_message(self.kind(), msg)
            }
            MumbleMessage::CodecVersion(msg) => MessageEnvelope::try_from_message(self.kind(), msg),
            MumbleMessage::Unknown(envelope) => Ok(envelope.clone()),
        }
    }
}

/// Errors that can occur while decoding a `MessageEnvelope` into a `MumbleMessage`.
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// Protobuf decoding failed for the given message type.
    #[error("failed to decode {kind:?}: {source}")]
    Decode {
        /// Message identifier that failed to decode.
        kind: TcpMessageKind,
        /// Underlying protobuf decode error.
        #[source]
        source: prost::DecodeError,
    },
}

impl TryFrom<MessageEnvelope> for MumbleMessage {
    type Error = MessageDecodeError;

    fn try_from(envelope: MessageEnvelope) -> Result<Self, Self::Error> {
        let result = match envelope.kind {
            TcpMessageKind::Version => Version::decode(envelope.payload.as_slice())
                .map(MumbleMessage::Version)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::Version,
                    source,
                })?,
            TcpMessageKind::Authenticate => Authenticate::decode(envelope.payload.as_slice())
                .map(MumbleMessage::Authenticate)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::Authenticate,
                    source,
                })?,
            TcpMessageKind::Reject => Reject::decode(envelope.payload.as_slice())
                .map(MumbleMessage::Reject)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::Reject,
                    source,
                })?,
            TcpMessageKind::ServerSync => ServerSync::decode(envelope.payload.as_slice())
                .map(MumbleMessage::ServerSync)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::ServerSync,
                    source,
                })?,
            TcpMessageKind::Ping => Ping::decode(envelope.payload.as_slice())
                .map(MumbleMessage::Ping)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::Ping,
                    source,
                })?,
            TcpMessageKind::CryptSetup => CryptSetup::decode(envelope.payload.as_slice())
                .map(MumbleMessage::CryptSetup)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::CryptSetup,
                    source,
                })?,
            TcpMessageKind::CodecVersion => CodecVersion::decode(envelope.payload.as_slice())
                .map(MumbleMessage::CodecVersion)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::CodecVersion,
                    source,
                })?,
            TcpMessageKind::ChannelRemove => ChannelRemove::decode(envelope.payload.as_slice())
                .map(MumbleMessage::ChannelRemove)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::ChannelRemove,
                    source,
                })?,
            TcpMessageKind::ChannelState => ChannelState::decode(envelope.payload.as_slice())
                .map(MumbleMessage::ChannelState)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::ChannelState,
                    source,
                })?,
            TcpMessageKind::UserRemove => UserRemove::decode(envelope.payload.as_slice())
                .map(MumbleMessage::UserRemove)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::UserRemove,
                    source,
                })?,
            TcpMessageKind::UserState => UserState::decode(envelope.payload.as_slice())
                .map(MumbleMessage::UserState)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::UserState,
                    source,
                })?,
            TcpMessageKind::TextMessage => TextMessage::decode(envelope.payload.as_slice())
                .map(MumbleMessage::TextMessage)
                .map_err(|source| MessageDecodeError::Decode {
                    kind: TcpMessageKind::TextMessage,
                    source,
                })?,
            TcpMessageKind::PermissionDenied => {
                PermissionDenied::decode(envelope.payload.as_slice())
                    .map(MumbleMessage::PermissionDenied)
                    .map_err(|source| MessageDecodeError::Decode {
                        kind: TcpMessageKind::PermissionDenied,
                        source,
                    })?
            }
            TcpMessageKind::Unknown(_) => MumbleMessage::Unknown(envelope),
        };
        Ok(result)
    }
}

/// Encode and write a typed message to the provided writer.
pub async fn write_message<W>(writer: &mut W, message: &MumbleMessage) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let envelope = message
        .encode()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    envelope.write_to(writer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    fn golden_version_message() -> Version {
        let mut version = Version::default();
        version.version_v1 = Some(1);
        version.release = Some("rs".into());
        version
    }

    #[test]
    fn decode_version_payload() {
        let mut version = Version::default();
        version.version_v1 = Some(0x0105_00ff);
        version.release = Some("mumble-rs".into());

        let envelope = MessageEnvelope::try_from_message(TcpMessageKind::Version, &version)
            .expect("encoding should succeed");
        let decoded = envelope.decode_version().expect("should parse version");

        assert_eq!(decoded.release.as_deref(), Some("mumble-rs"));
    }

    #[tokio::test]
    async fn write_and_read_roundtrip() {
        let (mut tx, mut rx) = duplex(64);

        let mut version = Version::default();
        version.version_v1 = Some(0x0105_0001);

        let envelope = MessageEnvelope::try_from_message(TcpMessageKind::Version, &version)
            .expect("encoding should succeed");
        let expected_payload = envelope.payload.clone();
        envelope.write_to(&mut tx).await.unwrap();

        let received = super::read_envelope(&mut rx).await.unwrap();
        assert_eq!(received.kind, TcpMessageKind::Version);
        assert_eq!(received.payload, expected_payload);
    }

    #[test]
    fn envelope_to_bytes_produces_expected_header() {
        let version = golden_version_message();
        let envelope =
            MessageEnvelope::try_from_message(TcpMessageKind::Version, &version).unwrap();
        let bytes = envelope.to_bytes();

        assert_eq!(
            bytes,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0x01, 0x12, 0x02, 0x72, 0x73]
        );
    }

    #[test]
    fn message_try_from_envelope_handles_unknown() {
        let envelope = MessageEnvelope::new(TcpMessageKind::Unknown(42), vec![1, 2, 3]);
        let message = MumbleMessage::try_from(envelope.clone()).unwrap();
        match message {
            MumbleMessage::Unknown(inner) => {
                assert_eq!(inner.kind, TcpMessageKind::Unknown(42));
                assert_eq!(inner.payload, vec![1, 2, 3]);
            }
            other => panic!("unexpected variant {other:?}"),
        }
    }

    #[test]
    fn message_roundtrip_encoding() {
        let version = golden_version_message();
        let message = MumbleMessage::Version(version.clone());
        let envelope = message.encode().unwrap();
        let decoded = MumbleMessage::try_from(envelope).unwrap();
        match decoded {
            MumbleMessage::Version(decoded_version) => assert_eq!(decoded_version, version),
            _ => panic!("expected Version message"),
        }
    }

    #[tokio::test]
    async fn read_envelope_rejects_oversize() {
        let (mut tx, mut rx) = duplex(64);
        let kind = TcpMessageKind::Version.as_id();
        let length = (MAX_TCP_FRAME_SIZE + 1) as u32;
        let mut header = [0u8; TCP_PREAMBLE_SIZE];
        header[..2].copy_from_slice(&kind.to_be_bytes());
        header[2..].copy_from_slice(&length.to_be_bytes());
        tx.write_all(&header).await.unwrap();

        let err = super::read_envelope(&mut rx).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
