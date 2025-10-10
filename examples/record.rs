#![cfg_attr(not(feature = "audio"), allow(dead_code))]

#[cfg(feature = "audio")]
use std::path::PathBuf;
#[cfg(feature = "audio")]
use std::time::{Duration, Instant};

#[cfg(feature = "audio")]
use clap::Parser;
#[cfg(feature = "audio")]
use hound::{SampleFormat, WavSpec, WavWriter};
#[cfg(feature = "audio")]
use mumble_rs::{ConnectionConfig, MumbleConnection, MumbleEvent};
#[cfg(feature = "audio")]
use opus::{Channels, Decoder as OpusDecoder};
#[cfg(feature = "audio")]
use tokio::sync::Mutex;

#[cfg(feature = "audio")]
const SAMPLE_RATE: u32 = 48_000;
#[cfg(feature = "audio")]
const MAX_FRAME_SAMPLES: usize = (SAMPLE_RATE as usize / 1000) * 120;

#[cfg(feature = "audio")]
/// Capture UDP audio packets, decode them with Opus, and persist to a WAV file.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Amount of time to run (seconds, 0 = infinite)
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    timeout_secs: u64,
    /// Target host to connect to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
    /// Destination WAV path for captured audio
    #[arg(short = 'o', long, default_value = "udp_capture.wav")]
    output: PathBuf,
}

#[cfg(feature = "audio")]
struct Recorder {
    decoder: Mutex<OpusDecoder>,
    writer: Mutex<WavWriter<std::io::BufWriter<std::fs::File>>>,
}

#[cfg(feature = "audio")]
impl Recorder {
    fn new(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let decoder = OpusDecoder::new(SAMPLE_RATE, Channels::Mono)?;
        let spec = WavSpec {
            channels: 1,
            sample_rate: SAMPLE_RATE,
            bits_per_sample: 16,
            sample_format: SampleFormat::Int,
        };
        let writer = WavWriter::create(path, spec)?;
        Ok(Self {
            decoder: Mutex::new(decoder),
            writer: Mutex::new(writer),
        })
    }

    async fn write_frame(&self, opus_frame: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut decoder = self.decoder.lock().await;
        let mut pcm = vec![0i16; MAX_FRAME_SAMPLES];
        let samples_written = decoder.decode(opus_frame, &mut pcm, false)?;
        drop(decoder);

        let mut writer = self.writer.lock().await;
        for sample in pcm.into_iter().take(samples_written) {
            writer.write_sample(sample)?;
        }
        Ok(())
    }

    fn finalize(self) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = self.writer.into_inner();
        writer.finalize()?;
        Ok(())
    }
}

#[cfg(feature = "audio")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut config = ConnectionConfig::builder(&args.host)
        .accept_invalid_certs(true)
        .enable_udp(true)
        .build();
    if let Ok(username) = std::env::var("MUMBLE_USERNAME") {
        config.username = username;
    }
    if let Ok(password) = std::env::var("MUMBLE_PASSWORD") {
        config.password = Some(password);
    }
    config.client_type = 0;

    let recorder = Recorder::new(&args.output)?;

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    if let Some(version) = connection.server_version() {
        println!("Connected. Server version: {:?}", version);
    }

    let mut events = connection.subscribe_events();
    let deadline = if args.timeout_secs == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(args.timeout_secs))
    };

    loop {
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                println!("Timeout reached, shutting down.");
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(result) => match result {
                    Ok(event) => handle_event(event, &recorder).await?,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        println!("Warning: skipped {skipped} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        println!("Event stream closed");
                        break;
                    }
                },
                Err(_) => {
                    println!("Timeout reached, shutting down.");
                    break;
                }
            }
        } else {
            match events.recv().await {
                Ok(event) => handle_event(event, &recorder).await?,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    println!("Warning: skipped {skipped} events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    println!("Event stream closed");
                    break;
                }
            }
        }
    }

    recorder.finalize()?;
    println!(
        "Recording complete. Captured audio written to {}",
        args.output.display()
    );
    Ok(())
}

#[cfg(feature = "audio")]
async fn handle_event(
    event: MumbleEvent,
    recorder: &Recorder,
) -> Result<(), Box<dyn std::error::Error>> {
    match event {
        MumbleEvent::UdpAudio(packet) => {
            let frame_number = packet.frame_number;
            let payload_len = packet.opus_data.len();
            let opus = packet.opus_data;
            println!(
                "Event: UdpAudio {{ frame: {}, bytes: {} }}",
                frame_number, payload_len
            );
            recorder.write_frame(&opus).await?;
        }
        MumbleEvent::UdpPing(ping) => {
            println!("Event: UdpPing({ping:?})");
        }
        MumbleEvent::CryptSetup(setup) => {
            println!("Event: CryptSetup({setup:?})");
        }
        other => {
            println!("Event: {other:?}");
        }
    }
    Ok(())
}

#[cfg(not(feature = "audio"))]
fn main() {
    eprintln!("This example requires building with --features audio");
}
