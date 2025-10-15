use std::time::Duration;

use clap::Parser;
use mumblers::{ConnectionConfig, MumbleConnection};
use tracing_subscriber::{fmt, EnvFilter};

/// List the channel tree with users in each channel.
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

    // Init logging if RUST_LOG is set (default to info)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

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

    if let Some(version) = connection.server_version() {
        println!("Connected. Server version: {:?}", version);
    }

    // Drain a small number of initial events to allow state to populate
    let mut events = connection.subscribe_events();
    let mut drained = 0u32;
    while drained < 5 {
        match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Ok(_)) => drained += 1,
            _ => break,
        }
    }

    // Get current state
    let state = connection.state().await;
    let channels = state.channels.lock().await;

    println!("Channel Tree:");
    print_channel_tree(&channels, &state, 0, 0);

    Ok(())
}

fn print_channel_tree(channels: &mumblers::channels::Channels, state: &mumblers::state::ClientState, channel_id: u32, depth: usize) {
    if let Some(channel) = channels.get(channel_id) {
        let indent = "  ".repeat(depth);
        println!("{}{}", indent, channel.name.as_deref().unwrap_or("Unnamed Channel"));

        // List users in this channel
        let users = state.get_users_in_channel(channel_id);
        if !users.is_empty() {
            let user_names: Vec<String> = users.iter()
                .map(|&session| {
                    state.users.get(&session)
                        .cloned()
                        .unwrap_or_else(|| format!("Unknown User (session: {})", session))
                })
                .collect();
            println!("{}  Users: {}", indent, user_names.join(", "));
        }

        // Recursively print sub-channels
        for child in channels.get_childs(channel_id) {
            print_channel_tree(channels, state, child.channel_id, depth + 1);
        }
    }
}
