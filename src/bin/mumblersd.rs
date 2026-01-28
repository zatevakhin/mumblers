use clap::{Parser, Subcommand};
use mumblers::server::{ChannelConfig, MumbleServer, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::rustls;

const DEFAULT_CONFIG_PATH: &str = "mumblers.toml";
const DEFAULT_CERT_PATH: &str = "certs/mumblers.crt";
const DEFAULT_KEY_PATH: &str = "certs/mumblers.key";

#[derive(Parser)]
#[command(name = "mumblersd", version, about = "Mumble server daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the Mumble server using a TOML configuration file.
    Serve {
        /// Path to the server configuration TOML file.
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Inspect or initialize the server configuration.
    Config {
        /// Path to the server configuration TOML file.
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        path: PathBuf,
        /// Create a new config and generate certificates.
        #[arg(long)]
        init: bool,
        /// Overwrite existing config/certs when used with --init.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => serve(&config).await?,
        Command::Config { path, init, force } => {
            if init {
                init_config(&path, force)?;
            } else {
                show_config(&path)?;
            }
        }
    }
    Ok(())
}

async fn serve(config_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();
    let config_str = fs::read_to_string(config_path)
        .map_err(|err| format!("failed to read config at {}: {err}", config_path.display()))?;
    let cfg: ServerConfig = toml::from_str(&config_str)?;

    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let cert_path = resolve_path(config_dir, cfg.certificate.as_deref())
        .ok_or("certificate path missing from config")?;
    let key_path = resolve_path(config_dir, cfg.private_key.as_deref())
        .ok_or("private_key path missing from config")?;
    let tls = build_tls_config(&cert_path, &key_path)?;

    tracing::info!(
        config = %config_path.display(),
        cert = %cert_path.display(),
        key = %key_path.display(),
        "starting mumblersd"
    );

    let server = MumbleServer::new(cfg, tls);
    let mut handle = tokio::spawn(async move { server.serve().await });

    tokio::select! {
        result = &mut handle => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown requested");
            handle.abort();
            Ok(())
        }
    }
}

fn show_config(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Config path: {}", path.display());
    if path.exists() {
        let contents = fs::read_to_string(path)?;
        println!("{contents}");
    } else {
        println!("Config file not found. Use `mumblersd config --init` to create one.");
    }
    Ok(())
}

fn init_config(path: &Path, force: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if path.exists() && !force {
        return Err(format!(
            "config already exists at {} (use --force to overwrite)",
            path.display()
        )
        .into());
    }

    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let cert_path = config_dir.join(DEFAULT_CERT_PATH);
    let key_path = config_dir.join(DEFAULT_KEY_PATH);
    if force || !cert_path.exists() || !key_path.exists() {
        generate_self_signed_cert(&cert_path, &key_path)?;
    }

    let cfg = ServerConfig {
        default_channel: "Lobby".to_string(),
        channels: vec![
            ChannelConfig {
                name: "Lobby".to_string(),
                parent: Some("Root".to_string()),
                description: Some("General chat".to_string()),
                position: Some(1),
                max_users: None,
                noenter: None,
                silent: None,
            },
            ChannelConfig {
                name: "Games".to_string(),
                parent: Some("Lobby".to_string()),
                description: Some("Gaming rooms".to_string()),
                position: Some(2),
                max_users: None,
                noenter: None,
                silent: None,
            },
            ChannelConfig {
                name: "AFK".to_string(),
                parent: Some("Root".to_string()),
                description: Some("Away from keyboard".to_string()),
                position: Some(3),
                max_users: Some(1),
                noenter: Some(true),
                silent: Some(true),
            },
        ],
        certificate: Some(DEFAULT_CERT_PATH.to_string()),
        private_key: Some(DEFAULT_KEY_PATH.to_string()),
        ..Default::default()
    };
    let toml = toml::to_string_pretty(&cfg)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, toml)?;
    println!("Wrote config to {}", path.display());
    Ok(())
}

fn resolve_path(base: &Path, raw: Option<&str>) -> Option<PathBuf> {
    let raw = raw?;
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(base.join(path))
    }
}

fn build_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let mut cert_cursor = std::io::Cursor::new(&cert_pem);
    let certs_iter = rustls_pemfile::certs(&mut cert_cursor);
    let certs: Vec<_> = certs_iter.collect::<Result<_, _>>()?;

    let mut key_cursor = std::io::Cursor::new(&key_pem);
    let keys_iter = rustls_pemfile::pkcs8_private_keys(&mut key_cursor);
    let mut keys: Vec<_> = keys_iter.collect::<Result<_, _>>()?;
    let key = keys.pop().ok_or("no private keys found in key file")?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key.clone_key());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    write_file_if_changed(cert_path, cert_pem.as_bytes())?;
    write_file_if_changed(key_path, key_pem.as_bytes())?;
    Ok(())
}

fn write_file_if_changed(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Ok(existing) = fs::read(path) {
        if existing == contents {
            return Ok(());
        }
    }
    let mut file = fs::File::create(path)?;
    file.write_all(contents)
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
