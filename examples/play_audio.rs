#![cfg_attr(not(feature = "audio"), allow(dead_code))]

#[cfg(feature = "audio")]
use std::path::PathBuf;
#[cfg(feature = "audio")]
use std::time::Duration;

#[cfg(feature = "audio")]
use clap::Parser;
#[cfg(feature = "audio")]
use hound::WavReader;
#[cfg(feature = "audio")]
use mumble_rs::{AudioEncoder, ConnectionConfig, MumbleConnection};
#[cfg(feature = "audio")]
use tokio::time::sleep;

#[cfg(feature = "audio")]
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Target host to connect to.
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
    /// Path to a 48 kHz mono 16-bit PCM WAV file.
    #[arg(short = 'f', long)]
    file: PathBuf,
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

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    println!("Connected. Waiting for UDP CryptSetup…");
    connection
        .wait_for_udp_ready(Some(Duration::from_secs(5)))
        .await?;
    println!("UDP tunnel negotiated, starting playback.");

    let negotiated_codec = connection.codec_version().await;
    if let Some(codec) = &negotiated_codec {
        println!("Codec preferences: {:?}", codec);
    }

    let mut reader = WavReader::open(&args.file)?;
    let spec = reader.spec();
    if spec.sample_rate != 48_000 {
        return Err("example requires 48 kHz audio".into());
    }
    if spec.channels != 1 {
        return Err("example currently supports mono audio only".into());
    }
    if spec.bits_per_sample != 16 {
        return Err("example requires 16-bit PCM WAV input".into());
    }

    let mut encoder = AudioEncoder::with_codec(0, negotiated_codec.as_ref())?;
    let frame_size = encoder.frame_size();
    let mut frame = Vec::with_capacity(frame_size);

    for sample in reader.samples::<i16>() {
        frame.push(sample?);
        if frame.len() == frame_size {
            send_frame(&connection, &mut encoder, &frame).await?;
            frame.clear();
        }
    }

    if !frame.is_empty() {
        frame.resize(frame_size, 0);
        send_frame(&connection, &mut encoder, &frame).await?;
    }

    println!("Playback finished.");
    Ok(())
}

#[cfg(feature = "audio")]
async fn send_frame(
    connection: &MumbleConnection,
    encoder: &mut AudioEncoder,
    samples: &[i16],
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = encoder.encode_frame(samples)?;
    connection.send_audio(packet).await?;
    sleep(Duration::from_millis(20)).await;
    Ok(())
}

#[cfg(not(feature = "audio"))]
fn main() {
    eprintln!("This example requires building with --features audio");
}
