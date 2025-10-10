//! Helpers for working with UDP audio packets.
//!
//! The Mumble UDP protocol wraps Opus frames inside the `MumbleUDP.Audio`
//! protobuf message.  This module provides a light-weight Rust wrapper that
//! keeps the wire representation at arm's length while giving higher level code
//! a more idiomatic API.

use crate::proto::mumble_udp;

#[cfg(feature = "audio")]
use crate::proto::mumble::CodecVersion;
#[cfg(feature = "audio")]
use opus::{Application, Bitrate, Channels, Decoder as OpusDecoder, Encoder as OpusEncoder};
#[cfg(feature = "audio")]
use std::collections::VecDeque;
#[cfg(feature = "audio")]
use std::time::{Duration, Instant};
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
const SEQUENCE_TICK_MS: u64 = 10;
#[cfg(feature = "audio")]
const SEQUENCE_RESET_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(feature = "audio")]
const FRAME_DURATION_DOUBLE: Duration = Duration::from_millis((AUDIO_FRAME_MS as u64) * 2);
#[cfg(feature = "audio")]
const FRAME_TICKS: u64 = (AUDIO_FRAME_MS as u64) / SEQUENCE_TICK_MS;
#[cfg(feature = "audio")]
const MAX_COMPRESSED_SIZE: usize = 4 * 1024;
#[cfg(feature = "audio")]
const UDP_OVERHEAD_BYTES_PER_PACKET: u32 = 35;
#[cfg(feature = "audio")]
const UDP_OVERHEAD_BITS_PER_PACKET: u32 = UDP_OVERHEAD_BYTES_PER_PACKET * 8;
#[cfg(feature = "audio")]
const PACKETS_PER_SECOND: u32 = 1000 / AUDIO_FRAME_MS;
#[cfg(feature = "audio")]
const UDP_OVERHEAD_BITS_PER_SECOND: u32 = UDP_OVERHEAD_BITS_PER_PACKET * PACKETS_PER_SECOND;
#[cfg(feature = "audio")]
const MIN_AUDIO_BITRATE: u32 = 6_000;
#[cfg(feature = "audio")]
const MAX_DECODE_SAMPLES: usize = (SAMPLE_RATE as usize / 1000) * 120;

/// Stateful Opus encoder that mirrors pymumble's default audio settings.
#[cfg(feature = "audio")]
pub struct AudioEncoder {
    encoder: OpusEncoder,
    frame_size: usize,
    target: u32,
    positional_data: Option<[f32; 3]>,
    volume_adjustment: Option<f32>,
    sequence: u64,
    sequence_start: Option<Instant>,
    sequence_last: Option<Instant>,
    bandwidth_limit: Option<u32>,
}

#[cfg(feature = "audio")]
impl AudioEncoder {
    /// Create a VOIP-mode Opus encoder with mono output and 20 ms frames.
    pub fn new(target: u32) -> Result<Self, AudioEncodeError> {
        Self::with_codec(target, None)
    }

    /// Construct an encoder that honours the negotiated codec settings.
    pub fn with_codec(target: u32, codec: Option<&CodecVersion>) -> Result<Self, AudioEncodeError> {
        if let Some(codec) = codec {
            if !codec.opus.unwrap_or_default() {
                return Err(AudioEncodeError::UnsupportedCodec);
            }
        }
        let mut encoder = OpusEncoder::new(SAMPLE_RATE, DEFAULT_CHANNELS, Application::Voip)?;
        encoder.set_bitrate(Bitrate::Auto)?;
        Ok(Self {
            encoder,
            frame_size: FRAME_SIZE_MONO,
            target,
            positional_data: None,
            volume_adjustment: None,
            sequence: 0,
            sequence_start: None,
            sequence_last: None,
            bandwidth_limit: None,
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
        self.sequence = 0;
        self.sequence_start = None;
        self.sequence_last = None;
    }

    /// Apply the negotiated bandwidth limit and adjust the encoder bitrate.
    ///
    /// The server's `max_bandwidth` value is expressed in bits per second. We subtract
    /// protocol overhead approximated from pymumble to derive the Opus target bitrate.
    pub fn set_bandwidth_limit(
        &mut self,
        total_bits_per_second: Option<u32>,
    ) -> Result<(), AudioEncodeError> {
        self.bandwidth_limit = total_bits_per_second;
        match total_bits_per_second {
            Some(total) => {
                let effective = total
                    .saturating_sub(UDP_OVERHEAD_BITS_PER_SECOND)
                    .max(MIN_AUDIO_BITRATE)
                    .min(i32::MAX as u32) as i32;
                self.encoder.set_bitrate(Bitrate::Bits(effective))?;
            }
            None => {
                self.encoder.set_bitrate(Bitrate::Auto)?;
            }
        }
        Ok(())
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

        let frame_number = self.next_frame_number();

        let packet = VoicePacket {
            header: AudioHeader::Target(self.target),
            sender_session: None,
            frame_number,
            opus_data: buffer,
            positional_data: self.positional_data,
            volume_adjustment: self.volume_adjustment,
            is_terminator: false,
        };

        Ok(packet)
    }

    fn next_frame_number(&mut self) -> u64 {
        let now = Instant::now();

        match self.sequence_last {
            None => {
                self.sequence = 0;
                self.sequence_start = Some(now);
                self.sequence_last = Some(now);
            }
            Some(last) => {
                if now.duration_since(last) >= SEQUENCE_RESET_INTERVAL {
                    self.sequence = 0;
                    self.sequence_start = Some(now);
                    self.sequence_last = Some(now);
                } else if now.duration_since(last) >= FRAME_DURATION_DOUBLE {
                    let start = self.sequence_start.unwrap_or(now);
                    let elapsed = now.duration_since(start);
                    let ticks = (elapsed.as_millis() / SEQUENCE_TICK_MS as u128) as u64;
                    self.sequence = ticks;
                    let theoretical =
                        start + Duration::from_millis(self.sequence * SEQUENCE_TICK_MS);
                    self.sequence_last = Some(theoretical);
                } else {
                    self.sequence = self.sequence.saturating_add(FRAME_TICKS);
                    let start = self.sequence_start.unwrap_or(now);
                    let theoretical =
                        start + Duration::from_millis(self.sequence * SEQUENCE_TICK_MS);
                    self.sequence_last = Some(theoretical);
                }
            }
        }

        self.sequence
    }
}

/// Errors that can occur while encoding PCM frames into Opus packets.
#[cfg(feature = "audio")]
#[derive(Debug, Error)]
pub enum AudioEncodeError {
    /// Input slice did not match the expected frame size.
    #[error("invalid frame size: expected {expected} samples, got {actual}")]
    InvalidFrameSize { expected: usize, actual: usize },
    /// Selected codec is not currently supported by the encoder.
    #[error("codec negotiation requested unsupported encoder")]
    UnsupportedCodec,
    /// Underlying Opus encoder failure.
    #[error(transparent)]
    Opus(#[from] opus::Error),
}

/// Errors that can occur while decoding Opus packets from the network.
#[cfg(feature = "audio")]
#[derive(Debug, Error)]
pub enum AudioDecodeError {
    /// Unsupported or invalid codec payload encountered.
    #[error("unsupported audio codec")]
    UnsupportedCodec,
    /// Underlying Opus decoder failure.
    #[error(transparent)]
    Opus(#[from] opus::Error),
}

/// Decoded audio frame coupled with scheduling metadata for jitter buffering.
#[cfg(feature = "audio")]
#[derive(Clone, Debug)]
pub struct SoundChunk {
    /// Raw PCM data decoded to 16-bit mono.
    pub pcm: Vec<i16>,
    /// Monotonic frame number as supplied by the sender.
    pub frame_number: u64,
    /// Voice routing header.
    pub header: AudioHeader,
    /// Session identifier of the sender, when provided.
    pub sender_session: Option<u32>,
    /// Timestamp when this chunk arrived locally.
    pub arrival_time: Instant,
    /// Scheduled playout time derived from the frame sequence numbers.
    pub target_playback_time: Instant,
    /// Duration of the PCM slice.
    pub duration: Duration,
}

/// Jitter-buffer queue that mirrors pymumble's receive-side ordering logic.
#[cfg(feature = "audio")]
pub struct ReceivedAudioQueue {
    decoder: OpusDecoder,
    queue: VecDeque<SoundChunk>,
    start_sequence: Option<u64>,
    start_time: Option<Instant>,
    receive_sound: bool,
}

#[cfg(feature = "audio")]
impl ReceivedAudioQueue {
    /// Create a new queue configured for 48 kHz mono Opus streams.
    pub fn new() -> Result<Self, AudioDecodeError> {
        let decoder = OpusDecoder::new(SAMPLE_RATE, Channels::Mono)?;
        Ok(Self {
            decoder,
            queue: VecDeque::new(),
            start_sequence: None,
            start_time: None,
            receive_sound: true,
        })
    }

    /// Enable or disable buffering of received audio.
    pub fn set_receive_sound(&mut self, value: bool) {
        self.receive_sound = value;
        if !value {
            self.queue.clear();
        }
    }

    /// Return the number of buffered chunks waiting to be played.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True when no chunks are buffered.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Drop all buffered audio.
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Access the next chunk scheduled for playout without removing it.
    pub fn front(&self) -> Option<&SoundChunk> {
        self.queue.front()
    }

    /// Pop the next chunk scheduled for playout if its target time has arrived.
    pub fn pop_ready(&mut self, now: Instant) -> Option<SoundChunk> {
        if let Some(chunk) = self.queue.front() {
            if chunk.target_playback_time <= now {
                return self.queue.pop_front();
            }
        }
        None
    }

    /// Pop the next buffered chunk regardless of its target time.
    pub fn pop_front(&mut self) -> Option<SoundChunk> {
        self.queue.pop_front()
    }

    /// Decode an inbound voice packet and enqueue it for ordered playout.
    ///
    /// Returns the decoded chunk for immediate inspection.
    pub fn add(&mut self, packet: &VoicePacket) -> Result<Option<SoundChunk>, AudioDecodeError> {
        if !self.receive_sound {
            return Ok(None);
        }

        let chunk = self.decode_packet(packet)?;
        self.enqueue(chunk.clone());
        Ok(Some(chunk))
    }

    fn decode_packet(&mut self, packet: &VoicePacket) -> Result<SoundChunk, AudioDecodeError> {
        let arrival = Instant::now();

        let mut buffer = vec![0i16; MAX_DECODE_SAMPLES];
        let samples = self.decoder.decode(&packet.opus_data, &mut buffer, false)?;
        buffer.truncate(samples);

        let duration = if samples == 0 {
            Duration::from_millis(0)
        } else {
            Duration::from_secs_f64(samples as f64 / SAMPLE_RATE as f64)
        };

        let target_playback_time = self.compute_target_time(packet.frame_number, arrival);

        Ok(SoundChunk {
            pcm: buffer,
            frame_number: packet.frame_number,
            header: packet.header,
            sender_session: packet.sender_session,
            arrival_time: arrival,
            target_playback_time,
            duration,
        })
    }

    fn compute_target_time(&mut self, frame_number: u64, arrival: Instant) -> Instant {
        match (self.start_sequence, self.start_time) {
            (Some(start_seq), Some(start_time)) if frame_number > start_seq => {
                let ticks = frame_number.saturating_sub(start_seq);
                let offset = Duration::from_millis(ticks.saturating_mul(SEQUENCE_TICK_MS));
                start_time + offset
            }
            _ => {
                self.start_sequence = Some(frame_number);
                self.start_time = Some(arrival);
                arrival
            }
        }
    }

    fn enqueue(&mut self, chunk: SoundChunk) {
        let position = self
            .queue
            .iter()
            .position(|existing| existing.target_playback_time > chunk.target_playback_time);
        match position {
            Some(index) => self.queue.insert(index, chunk),
            None => self.queue.push_back(chunk),
        }
    }
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

    #[test]
    fn received_queue_orders_frames() {
        let mut encoder = AudioEncoder::new(0).expect("encoder");
        let frame = vec![0i16; encoder.frame_size()];
        let first = encoder.encode_frame(&frame).expect("encode first");
        let second = encoder.encode_frame(&frame).expect("encode second");

        let mut queue = ReceivedAudioQueue::new().expect("queue");
        queue.add(&second).expect("second");
        queue.add(&first).expect("first");

        let chunk1 = queue.pop_front().expect("pop first");
        assert_eq!(chunk1.frame_number, first.frame_number);
        let chunk2 = queue.pop_front().expect("pop second");
        assert_eq!(chunk2.frame_number, second.frame_number);
    }
}
