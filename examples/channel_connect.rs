use std::time::Duration;

use clap::Parser;
use mumblers::{ConnectionConfig, MumbleConnection};
use tracing_subscriber::{fmt, EnvFilter};

/// Connect and join a channel by name, stay for a while.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Target host to connect to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
    /// Channel to join (by path or name)
    #[arg(short = 'c', long = "channel", default_value = "Root")]
    channel: String,
    /// Time to stay in the channel (seconds, 0 = exit immediately)
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init logging (honours RUST_LOG)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    let args = Args::parse();

    let mut config = ConnectionConfig::builder(&args.host)
        .accept_invalid_certs(true)
        .enable_udp(false)
        .build();
    if let Ok(username) = std::env::var("MUMBLE_USERNAME") {
        config.username = username;
    }
    if let Ok(password) = std::env::var("MUMBLE_PASSWORD") {
        config.password = Some(password);
    }

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    // Best-effort join by name, falling back to direct channel_id if numeric
    let joined = if let Ok(id) = args.channel.parse::<u32>() {
        connection
            .join_channel(id)
            .await
            .map(|_| true)
            .unwrap_or(false)
    } else {
        // Resolve by name via state
        let state = connection.state().await;
        let channels = state.channels.lock().await;
        let target_id = channels.find_by_name(&args.channel).map(|c| c.channel_id);
        drop(channels);
        match target_id {
            Some(id) => connection
                .join_channel(id)
                .await
                .map(|_| true)
                .unwrap_or(false),
            None => false,
        }
    };

    if joined {
        println!("Joined channel: {}", args.channel);
    } else {
        eprintln!(
            "Warning: failed to join channel '{}'; staying in current channel",
            args.channel
        );
    }

    if args.timeout_secs > 0 {
        tokio::time::sleep(Duration::from_secs(args.timeout_secs)).await;
    }

    Ok(())
}
