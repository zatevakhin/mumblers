use mumble_rs::{ConnectionConfig, MumbleConnection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ConnectionConfig::new("127.0.0.1");
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
        println!("Server version: {:?}", version);
    } else {
        println!("Connected, but server version was not received.");
    }

    let state = connection.state().await;
    if let Some(welcome) = state.welcome_text.as_deref() {
        println!("Welcome text: {welcome}");
    }

    Ok(())
}
