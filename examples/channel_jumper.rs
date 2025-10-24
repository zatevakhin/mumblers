use std::time::{Duration, Instant};

use clap::Parser;
use mumblers::{ConnectionConfig, MumbleConnection};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about = "Cycle through channels at a fixed cadence")]
struct Args {
    /// Server host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(short = 'p', long, default_value_t = 64738)]
    port: u16,

    /// Username to connect with
    #[arg(short = 'u', long, default_value = "channel-jumper")]
    username: String,

    /// Accept invalid/self-signed TLS certificates
    #[arg(long, default_value_t = true)]
    insecure: bool,

    /// Seconds to wait between jumps
    #[arg(short = 'j', long = "jump-after", default_value_t = 5)]
    jump_after_secs: u64,

    /// Total duration to keep jumping (seconds, 0 = run indefinitely)
    #[arg(short = 't', long = "timeout", default_value_t = 60)]
    timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(env).with_target(false).try_init();

    let cfg = ConnectionConfig::builder(&args.host)
        .port(args.port)
        .username(&args.username)
        .accept_invalid_certs(args.insecure)
        .build();

    let mut conn = MumbleConnection::new(cfg);
    conn.connect().await?;

    // Drain a few initial events to let the state populate.
    let mut events = conn.subscribe_events();
    let drain_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < drain_until {
        match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    let state = conn.state().await;
    let channels_guard = state.channels.lock().await;
    let mut available: Vec<(u32, String)> = channels_guard
        .iter()
        .filter_map(|(id, chan)| {
            let name = chan
                .name
                .clone()
                .unwrap_or_else(|| format!("Channel {}", id));
            Some((*id, name))
        })
        .collect();
    drop(channels_guard);

    available.sort_by_key(|(id, _)| *id);

    if available.is_empty() {
        eprintln!("No channels known yet; exiting.");
        return Ok(());
    }

    let mut idx = 0usize;
    let jump_interval = Duration::from_secs(args.jump_after_secs.max(1));
    let timeout = if args.timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(args.timeout_secs))
    };
    let start = Instant::now();

    loop {
        if let Some(limit) = timeout {
            if Instant::now().duration_since(start) >= limit {
                break;
            }
        }

        let (channel_id, channel_name) = &available[idx];
        tracing::info!(
            channel = channel_name,
            id = channel_id,
            "jumping to channel"
        );
        match conn.join_channel(*channel_id).await {
            Ok(()) => {
                println!("Joined channel '{}'", channel_name);
            }
            Err(err) => {
                tracing::warn!(channel = channel_name, error = ?err, "failed to join channel");
            }
        }

        idx = (idx + 1) % available.len();
        tokio::time::sleep(jump_interval).await;
    }

    Ok(())
}
