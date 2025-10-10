use std::time::{Duration, Instant};

use clap::Parser;
use mumble_rs::{ConnectionConfig, MumbleConnection, MumbleEvent};

/// Listen for UDP-capable Mumble events and print them to stdout.
///
/// Note: Some Murmur deployments delay or suppress the `CryptSetup` control message;
/// track that open item in the roadmap before relying on UDP output.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Amount of time to run (seconds, 0 = infinite)
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    timeout_secs: u64,
    /// Target host to connect to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
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
    config.client_type = 0;

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
                    Ok(event) => log_event(event),
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
                Ok(event) => log_event(event),
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

    Ok(())
}

fn log_event(event: MumbleEvent) {
    match event {
        MumbleEvent::UdpPing(ping) => println!("Event: UdpPing({ping:?})"),
        MumbleEvent::CryptSetup(message) => println!("Event: CryptSetup({message:?})"),
        other => println!("Event: {other:?}"),
    }
}
