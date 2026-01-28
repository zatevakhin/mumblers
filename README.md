# mumblers

Experimental Rust client/server library for Mumble, aiming to mirror the feature set of [`pymumble`](https://codeberg.org/pymumble/pymumble) / [`umurmur`](https://github.com/umurmur/umurmur).

## Status

Work in progress. Expect frequent API changes and incomplete coverage of the Mumble protocol.

## Library Usage

### Minimal client
```rust
use mumblers::{ConnectionConfig, MumbleConnection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConnectionConfig::builder("127.0.0.1")
        .username("rust-bot")
        .accept_invalid_certs(true)
        .build();

    let mut connection = MumbleConnection::new(config);
    connection.connect().await?;

    let state = connection.state().await;
    println!("session id = {:?}", state.session_id);
    Ok(())
}
```

### Minimal Server

```rust
use mumblers::server::{MumbleServer, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio_rustls::rustls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = ServerConfig::default();
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der()?);
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    let server = MumbleServer::new(cfg, Arc::new(tls));
    server.serve().await?;
    Ok(())
}
```



## Server (mumblersd)

Generate a default config and self-signed certs:

```bash
mumblersd config --init
```

Inspect the config (path + contents):

```bash
mumblersd config
```

Start the server:

```bash
mumblersd serve --config mumblers.toml
```

## Running via Nix

Local checkout (default app):

```bash
nix run . -- config --init
nix run . -- serve --config mumblers.toml
```

Remote (replace owner/repo):

```bash
nix run github:zatevakhin/mumblers -- config --init
nix run github:zatevakhin/mumblers -- serve --config mumblers.toml
```

## NixOS Service

This repo exposes a NixOS module at `nixosModules.mumblersd`.

Example flake-based NixOS config:

```nix
{
  inputs.mumblers.url = "github:zatevakhin/mumblers";

  outputs = { self, nixpkgs, mumblers, ... }:
  let
    system = "x86_64-linux";
  in {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        mumblers.nixosModules.mumblersd
        ({ pkgs, ... }: {
          services.mumblersd.enable = true;
          services.mumblersd.openFirewall = true;

          # Fully declarative config (written to the service StateDirectory).
          services.mumblersd.settings = {
            bind_host = "0.0.0.0";
            bind_port = 64738;
            udp_bind_port = 64738;
            server_name = "mumblers";
            allow_anonymous = true;
          };
        })
      ];
    };
  };
}
```

## Examples

```bash
cargo run --example connect -- --host 127.0.0.1
```

Audio features are behind the `audio` feature flag:

```bash
cargo run --features audio --example record -- --host 127.0.0.1 --timeout 10

cargo run --features audio --example playback -- --host 127.0.0.1 --file audio.wav
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
