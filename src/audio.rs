//! Helpers for working with UDP audio packets.
//!
//! The Mumble UDP protocol wraps Opus frames inside the `MumbleUDP.Audio`
//! protobuf message.  This module provides a light-weight Rust wrapper that
//! keeps the wire representation at arm's length while giving higher level code
//! a more idiomatic API.

use crate::proto::mumble_udp;

#[cfg(feature = "audio")]
use opus::{Application, Bitrate, Channels, Encoder as OpusEncoder};
#[cfg(feature = "audio")]
use thiserror::Error;

/// Identifies how the recipient should interpret the audio payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioHeader {
    /// Client originated audio targeting a specific voice target.
    Target(u32),
    /// Server originated audio describing the transmission context.
    Context(u32),
}

impl From<AudioHeader> for mumble_udp::audio::Header {
    fn from(value: AudioHeader) -> Self {
        match value {
            AudioHeader::Target(id) => mumble_udp::audio::Header::Target(id),
            AudioHeader::Context(ctx) => mumble_udp::audio::Header::Context(ctx),
        }
    }
}

impl From<mumble_udp::audio::Header> for AudioHeader {
    fn from(value: mumble_udp::audio::Header) -> Self {
        match value {
            mumble_udp::audio::Header::Target(id) => AudioHeader::Target(id),
            mumble_udp::audio::Header::Context(ctx) => AudioHeader::Context(ctx),
        }
    }
}

/// Encapsulated Opus frame ready for UDP transport.
#[derive(Debug, Clone, PartialEq)]
pub struct VoicePacket {
    /// Header instruction describing the routing semantics.
    pub header: AudioHeader,
    /// Session identifier of the sending client, if known.
    pub sender_session: Option<u32>,
    /// Monotonically increasing frame number within the audio stream.
    pub frame_number: u64,
    /// Raw Opus-encoded audio payload.
    pub opus_data: Vec<u8>,
    /// Optional XYZ positional coordinates.
    pub positional_data: Option<[f32; 3]>,
    /// Optional volume multiplier provided by the server.
    pub volume_adjustment: Option<f32>,
    /// True if this packet terminates the stream.
    pub is_terminator: bool,
}

impl VoicePacket {
    /// Serialise the packet into the protobuf structure used on the wire.
    pub fn into_proto(self) -> mumble_udp::Audio {
        let positional = self.positional_data.map(Vec::from).unwrap_or_default();
        mumble_udp::Audio {
            header: Some(self.header.into()),
            sender_session: self.sender_session.unwrap_or_default(),
            frame_number: self.frame_number,
            opus_data: self.opus_data,
            positional_data: positional,
            volume_adjustment: self.volume_adjustment.unwrap_or_default(),
            is_terminator: self.is_terminator,
        }
    }

    /// Construct a packet from the protobuf representation delivered by the server.
    pub fn from_proto(proto: &mumble_udp::Audio) -> Option<Self> {
        let header = proto.header.as_ref().copied()?.into();
        let positional_data = if proto.positional_data.len() == 3 {
            Some([
                proto.positional_data[0],
                proto.positional_data[1],
                proto.positional_data[2],
            ])
        } else {
            None
        };
        let volume_adjustment = if proto.volume_adjustment == 0.0 {
            None
        } else {
            Some(proto.volume_adjustment)
        };
        Some(Self {
            header,
            sender_session: if proto.sender_session == 0 {
                None
            } else {
                Some(proto.sender_session)
            },
            frame_number: proto.frame_number,
            opus_data: proto.opus_data.clone(),
            positional_data,
            volume_adjustment,
            is_terminator: proto.is_terminator,
        })
    }
}

#[cfg(feature = "audio")]
const SAMPLE_RATE: u32 = 48_000;
#[cfg(feature = "audio")]
const DEFAULT_CHANNELS: Channels = Channels::Mono;
#[cfg(feature = "audio")]
const AUDIO_FRAME_MS: u32 = 20;
#[cfg(feature = "audio")]
const FRAME_SIZE_MONO: usize = (SAMPLE_RATE as usize * AUDIO_FRAME_MS as usize) / 1000;
#[cfg(feature = "audio")]
const MAX_COMPRESSED_SIZE: usize = 4 * 1024;

/// Stateful Opus encoder that mirrors pymumble's default audio settings.
#[cfg(feature = "audio")]
pub struct AudioEncoder {
    encoder: OpusEncoder,
    frame_size: usize,
    frame_number: u64,
    target: u32,
    positional_data: Option<[f32; 3]>,
    volume_adjustment: Option<f32>,
}

#[cfg(feature = "audio")]
impl AudioEncoder {
    /// Create a VOIP-mode Opus encoder with mono output and 20 ms frames.
    pub fn new(target: u32) -> Result<Self, opus::Error> {
        let mut encoder = OpusEncoder::new(SAMPLE_RATE, DEFAULT_CHANNELS, Application::Voip)?;
        encoder.set_bitrate(Bitrate::Auto)?;
        Ok(Self {
            encoder,
            frame_size: FRAME_SIZE_MONO,
            frame_number: 0,
            target,
            positional_data: None,
            volume_adjustment: None,
        })
    }

    /// Return the number of PCM samples (per channel) expected for each frame.
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Override the VoiceTarget identifier attached to each packet.
    pub fn set_target(&mut self, target: u32) {
        self.target = target;
    }

    /// Attach positional coordinates (XYZ metres) to subsequent packets.
    pub fn set_positional(&mut self, coords: Option<[f32; 3]>) {
        self.positional_data = coords;
    }

    /// Configure the server-provided volume multiplier propagated to listeners.
    pub fn set_volume_adjustment(&mut self, volume: Option<f32>) {
        self.volume_adjustment = volume;
    }

    /// Reset the running frame counter (useful when starting a fresh stream).
    pub fn reset_sequence(&mut self) {
        self.frame_number = 0;
    }

    /// Encode a PCM frame (16-bit little endian) into a [`VoicePacket`].
    ///
    /// The input slice must contain exactly 960 samples (20 ms at 48 kHz mono),
    /// matching pymumble's defaults.
    pub fn encode_frame(&mut self, pcm: &[i16]) -> Result<VoicePacket, AudioEncodeError> {
        if pcm.len() != self.frame_size {
            return Err(AudioEncodeError::InvalidFrameSize {
                expected: self.frame_size,
                actual: pcm.len(),
            });
        }

        let mut buffer = vec![0u8; MAX_COMPRESSED_SIZE];
        let encoded_bytes = self.encoder.encode(pcm, &mut buffer)?;
        buffer.truncate(encoded_bytes);

        let packet = VoicePacket {
            header: AudioHeader::Target(self.target),
            sender_session: None,
            frame_number: self.frame_number,
            opus_data: buffer,
            positional_data: self.positional_data,
            volume_adjustment: self.volume_adjustment,
            is_terminator: false,
        };

        self.frame_number = self.frame_number.wrapping_add(1);
        Ok(packet)
    }
}

/// Errors that can occur while encoding PCM frames into Opus packets.
#[cfg(feature = "audio")]
#[derive(Debug, Error)]
pub enum AudioEncodeError {
    /// Input slice did not match the expected frame size.
    #[error("invalid frame size: expected {expected} samples, got {actual}")]
    InvalidFrameSize { expected: usize, actual: usize },
    /// Underlying Opus encoder failure.
    #[error(transparent)]
    Opus(#[from] opus::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> VoicePacket {
        VoicePacket {
            header: AudioHeader::Target(1),
            sender_session: Some(42),
            frame_number: 123,
            opus_data: vec![1, 2, 3, 4],
            positional_data: Some([0.0, 1.0, 2.0]),
            volume_adjustment: Some(0.75),
            is_terminator: false,
        }
    }

    #[test]
    fn roundtrip_voice_packet() {
        let packet = sample_packet();
        let proto = packet.clone().into_proto();
        let decoded = VoicePacket::from_proto(&proto).expect("header");
        assert_eq!(packet, decoded);
    }

    #[test]
    fn missing_positional_data_is_optional() {
        let mut proto = sample_packet().into_proto();
        proto.positional_data.clear();
        let decoded = VoicePacket::from_proto(&proto).expect("header");
        assert_eq!(decoded.positional_data, None);
    }

    #[test]
    fn zero_volume_is_treated_as_none() {
        let mut proto = sample_packet().into_proto();
        proto.volume_adjustment = 0.0;
        let decoded = VoicePacket::from_proto(&proto).expect("header");
        assert_eq!(decoded.volume_adjustment, None);
    }

    #[test]
    fn sender_session_roundtrips_via_zero() {
        let mut proto = sample_packet().into_proto();
        proto.sender_session = 0;
        let decoded = VoicePacket::from_proto(&proto).expect("header");
        assert_eq!(decoded.sender_session, None);
    }
}

#[cfg(all(test, feature = "audio"))]
mod audio_feature_tests {
    use super::*;

    #[test]
    fn encoder_produces_voice_packet() {
        let mut encoder = AudioEncoder::new(0).expect("encoder");
        let frame = vec![0i16; encoder.frame_size()];
        let packet = encoder.encode_frame(&frame).expect("encode");
        assert_eq!(packet.frame_number, 0);
        assert_eq!(packet.header, AudioHeader::Target(0));
        assert!(!packet.opus_data.is_empty());
    }
}
