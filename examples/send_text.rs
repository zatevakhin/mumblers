use clap::Parser;
use mumblers::{ConnectionConfig, MumbleConnection};

#[derive(Parser, Debug)]
#[command(name = "send_text", about = "Send a text message to a Mumble channel")]
struct Args {
    /// Server host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(short = 'p', long, default_value_t = 64738)]
    port: u16,

    /// Username to use
    #[arg(short = 'u', long, default_value = "mumble-rs")] 
    username: String,

    /// Channel name to send into
    #[arg(short = 'c', long, default_value = "Root")]
    channel: String,

    /// Message to send
    #[arg(short = 'm', long)]
    message: String,

    /// Accept invalid/self-signed TLS certs
    #[arg(long, default_value_t = true)]
    insecure: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();

    let mut cfg = ConnectionConfig::builder(&args.host)
        .port(args.port)
        .username(&args.username)
        .accept_invalid_certs(args.insecure)
        .build();

    let mut conn = MumbleConnection::new(cfg);
    conn.connect().await?;
    // Ensure handshake settles
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    conn.join_channel_by_name(&args.channel).await?;
    conn.send_channel_message_by_name(&args.channel, args.message).await?;
    println!("Message sent to '{}'@{}:{}", args.channel, args.host, args.port);
    Ok(())
}

