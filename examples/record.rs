use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use hound::{SampleFormat, WavSpec, WavWriter};
use mumblers::{ClientType, ConnectionConfig, MumbleConnection, MumbleEvent, SoundChunk};
use tokio::sync::Mutex;

const SAMPLE_RATE: u32 = 48_000;

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

struct Recorder {
    writer: Mutex<WavWriter<std::io::BufWriter<std::fs::File>>>,
}

impl Recorder {
    fn new(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let spec = WavSpec {
            channels: 1,
            sample_rate: SAMPLE_RATE,
            bits_per_sample: 16,
            sample_format: SampleFormat::Int,
        };
        let writer = WavWriter::create(path, spec)?;
        Ok(Self {
            writer: Mutex::new(writer),
        })
    }

    async fn write_chunk(
        &self,
        session_id: u32,
        chunk: SoundChunk,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = self.writer.lock().await;
        for sample in &chunk.pcm {
            writer.write_sample(*sample)?;
        }
        println!(
            "Captured {} samples from session {} (target {:?})",
            chunk.pcm.len(),
            session_id,
            chunk.header
        );
        Ok(())
    }

    fn finalize(self) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = self.writer.into_inner();
        writer.finalize()?;
        Ok(())
    }
}

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
    config.client_type = ClientType::Regular;

    let recorder = Recorder::new(&args.output)?;

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    connection
        .wait_for_udp_ready(Some(Duration::from_secs(5)))
        .await?;

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

    if let Some(playback) = connection.audio_playback() {
        for (session_id, chunk) in playback.drain_all().await {
            recorder.write_chunk(session_id, chunk).await?;
        }
    }
    recorder.finalize()?;
    println!(
        "Recording complete. Captured audio written to {}",
        args.output.display()
    );
    Ok(())
}

async fn handle_event(
    event: MumbleEvent,
    recorder: &Recorder,
) -> Result<(), Box<dyn std::error::Error>> {
    match event {
        MumbleEvent::AudioChunk { session_id, chunk } => {
            recorder.write_chunk(session_id, chunk).await?;
        }
        MumbleEvent::UdpAudio(_) => {
            // Raw packets still arrive for logging scenarios.
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
