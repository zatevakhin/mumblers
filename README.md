# mumblers

Experimental Rust client for Mumble, aiming to mirror the feature set of pymumble.

## Status

Work in progress. Expect frequent API changes and incomplete coverage of the Mumble protocol.

## Getting Started

```bash
cargo run --example connect -- --host 127.0.0.1
```

Audio features are behind the `audio` feature flag:

```bash
cargo run --features audio --example record -- --host 127.0.0.1 --timeout 10

cargo run --features audio --example playback -- --host 127.0.0.1 --file audio.wav
```
