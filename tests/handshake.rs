use std::time::Duration;

use mumble_rs::{ConnectionConfig, MumbleConnection};

fn read_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn connect_when_env_provided() -> Result<(), Box<dyn std::error::Error>> {
    let host = match read_env("MUMBLE_TEST_HOST") {
        Some(host) => host,
        None => return Ok(()), // skip when not configured.
    };

    let mut config = ConnectionConfig::new(host);
    if let Some(port) = read_env("MUMBLE_TEST_PORT") {
        config.port = port.parse().unwrap_or(config.port);
    }
    if let Some(username) = read_env("MUMBLE_TEST_USERNAME") {
        config.username = username;
    }
    if let Some(password) = read_env("MUMBLE_TEST_PASSWORD") {
        config.password = Some(password);
    }
    if let Some(tls_name) = read_env("MUMBLE_TEST_TLS_NAME") {
        config.tls_server_name = Some(tls_name);
    }
    if let Some(timeout) = read_env("MUMBLE_TEST_TIMEOUT") {
        if let Ok(secs) = timeout.parse::<u64>() {
            config.connect_timeout = Duration::from_secs(secs);
        }
    }
    config.accept_invalid_certs = read_env("MUMBLE_TEST_ACCEPT_INVALID_CERTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    assert!(connection.server_version().is_some());
    assert!(connection.state().await.is_connected);

    Ok(())
}
