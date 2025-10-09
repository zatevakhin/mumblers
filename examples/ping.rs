use std::time::Duration;

use clap::Parser;
use mumble_rs::{ConnectionConfig, MumbleConnection};

/// Simple CLI to monitor Mumble ping statistics.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Number of statistics samples to print (0 for infinite)
    #[arg(short = 'n', long = "samples", default_value_t = 4)]
    samples: u32,
    /// Target host to connect to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut config = ConnectionConfig::new(&args.host);
    config.accept_invalid_certs = true;
    if let Ok(username) = std::env::var("MUMBLE_USERNAME") {
        config.username = username;
    }
    if let Ok(password) = std::env::var("MUMBLE_PASSWORD") {
        config.password = Some(password);
    }

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    if let Some(version) = connection.server_version() {
        println!("Connected. Server version: {:?}", version);
    }

    println!(
        "Reporting ping stats every 5 seconds ({} samples)...",
        if args.samples == 0 {
            "infinite".into()
        } else {
            args.samples.to_string()
        }
    );

    let mut remaining = if args.samples == 0 {
        None
    } else {
        Some(args.samples)
    };

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let state = connection.state().await;
        let last = state
            .last_ping_received_ms
            .map(|ms| format!("{ms} ms since epoch"))
            .unwrap_or_else(|| "never".to_string());
        println!(
            "sent: {:>4}, received: {:>4}, avg RTT: {:>7.2} ms, last pong: {}",
            state.ping_sent, state.ping_received, state.ping_average_ms, last
        );

        if let Some(ref mut left) = remaining {
            if *left <= 1 {
                break;
            }
            *left -= 1;
        }
    }

    Ok(())
}
