use std::net::SocketAddr;
use std::sync::Arc;

use prost::Message;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::audio::VoicePacket;
use crate::connection::MumbleEvent;
use crate::crypto::ocb2::{CryptStateOcb2, DecryptError};
use crate::proto::mumble_udp;
use crate::state::UdpState;

const UDP_PING_INTERVAL: Duration = Duration::from_secs(5);
const UDP_BUFFER_SIZE: usize = 2048;
const MSG_TYPE_AUDIO: u8 = 0;
const MSG_TYPE_PING: u8 = 1;

/// Manages the UDP tunnel lifecycle.
pub struct UdpTunnel {
    shutdown_tx: watch::Sender<bool>,
    cmd_tx: mpsc::Sender<TunnelCommand>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
enum TunnelCommand {
    SendAudio(VoicePacket),
    UpdateKey(Arc<UdpState>),
    Resync {
        server_nonce: [u8; 16],
        client_nonce: [u8; 16],
    },
}

impl UdpTunnel {
    /// Spawn a UDP tunnel task which encrypts/decrypts packets using OCB2.
    pub async fn start(
        host: String,
        port: u16,
        params: Arc<UdpState>,
        event_tx: tokio::sync::broadcast::Sender<MumbleEvent>,
    ) -> std::io::Result<Self> {
        let addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;

        let mut crypt = CryptStateOcb2::new();
        crypt.set_key(&params.key, &params.client_nonce, &params.server_nonce);
        let crypt = Arc::new(Mutex::new(crypt));

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let crypt_clone = Arc::clone(&crypt);
        let event_tx_clone = event_tx.clone();
        let task = tokio::spawn(async move {
            let mut ticker = interval(UDP_PING_INTERVAL);
            let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(err) = send_ping(&socket, &crypt_clone).await {
                            tracing::warn!("failed to send UDP ping: {err}");
                        }
                    }
                    recv = socket.recv(&mut buffer) => {
                        match recv {
                            Ok(len) => {
                                if len == 0 {
                                    continue;
                                }
                                let packet = &buffer[..len];
                                match decrypt_packet(&crypt_clone, packet).await {
                                    Ok(plain) => {
                                        if let Err(err) = handle_plain_packet(&plain, &event_tx_clone) {
                                            tracing::warn!("unable to handle UDP packet: {err}");
                                        }
                                    }
                                    Err(err) => {
                                        tracing::debug!("dropping UDP packet: {err:?}");
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::warn!("UDP receive error: {err}");
                            }
                        }
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(TunnelCommand::SendAudio(packet)) => {
                                if let Err(err) = send_audio(&socket, &crypt_clone, packet).await {
                                    tracing::warn!("failed to send audio frame: {err}");
                                }
                            }
                            Some(TunnelCommand::UpdateKey(params)) => {
                                if let Err(err) = apply_full_key(&crypt_clone, &params).await {
                                    tracing::warn!("failed to update UDP key: {err}");
                                }
                            }
                            Some(TunnelCommand::Resync {
                                server_nonce,
                                client_nonce,
                            }) => {
                                if let Err(err) =
                                    apply_resync(&crypt_clone, server_nonce, client_nonce).await
                                {
                                    tracing::warn!("failed to apply UDP resync: {err}");
                                }
                            }
                            None => break,
                        }
                    }
                    result = shutdown_rx.changed() => {
                        if result.is_ok() && *shutdown_rx.borrow() {
                            tracing::debug!("udp tunnel shutdown");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown_tx,
            cmd_tx,
            task,
        })
    }

    /// Queue an encrypted audio frame for transmission to the server.
    pub async fn send_audio(&self, packet: VoicePacket) -> std::io::Result<()> {
        self.cmd_tx
            .send(TunnelCommand::SendAudio(packet))
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
    }

    pub async fn update_key(&self, params: Arc<UdpState>) -> std::io::Result<()> {
        self.cmd_tx
            .send(TunnelCommand::UpdateKey(params))
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
    }

    pub async fn resync(
        &self,
        server_nonce: [u8; 16],
        client_nonce: [u8; 16],
    ) -> std::io::Result<()> {
        self.cmd_tx
            .send(TunnelCommand::Resync {
                server_nonce,
                client_nonce,
            })
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

async fn send_ping(socket: &UdpSocket, crypt: &Arc<Mutex<CryptStateOcb2>>) -> std::io::Result<()> {
    let mut ping = crate::proto::mumble_udp::Ping::default();
    ping.timestamp = current_millis();
    let mut payload = ping.encode_to_vec();
    payload.insert(0, MSG_TYPE_PING);
    let packet = {
        let mut guard = crypt.lock().await;
        guard
            .encrypt(&payload)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?
    };
    socket.send(&packet).await?;
    Ok(())
}

async fn send_audio(
    socket: &UdpSocket,
    crypt: &Arc<Mutex<CryptStateOcb2>>,
    packet: VoicePacket,
) -> std::io::Result<()> {
    let mut payload = packet.into_proto().encode_to_vec();
    payload.insert(0, MSG_TYPE_AUDIO);
    let encrypted = {
        let mut guard = crypt.lock().await;
        guard
            .encrypt(&payload)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?
    };
    socket.send(&encrypted).await?;
    Ok(())
}

async fn apply_full_key(
    crypt: &Arc<Mutex<CryptStateOcb2>>,
    params: &UdpState,
) -> std::io::Result<()> {
    let mut guard = crypt.lock().await;
    guard.set_key(&params.key, &params.client_nonce, &params.server_nonce);
    Ok(())
}

async fn apply_resync(
    crypt: &Arc<Mutex<CryptStateOcb2>>,
    server_nonce: [u8; 16],
    client_nonce: [u8; 16],
) -> std::io::Result<()> {
    let mut guard = crypt.lock().await;
    guard.set_decrypt_iv(&server_nonce);
    guard.set_encrypt_iv(&client_nonce);
    Ok(())
}

async fn decrypt_packet(
    crypt: &Arc<Mutex<CryptStateOcb2>>,
    packet: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let mut guard = crypt.lock().await;
    guard.decrypt(packet)
}

fn handle_plain_packet(
    plain: &[u8],
    event_tx: &tokio::sync::broadcast::Sender<MumbleEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if plain.is_empty() {
        return Ok(());
    }
    match plain[0] {
        MSG_TYPE_AUDIO => {
            let audio = mumble_udp::Audio::decode(&plain[1..])?;
            if let Some(packet) = VoicePacket::from_proto(&audio) {
                let _ = event_tx.send(MumbleEvent::UdpAudio(packet));
            } else {
                tracing::debug!("audio packet missing header metadata");
            }
        }
        MSG_TYPE_PING => {
            let ping = mumble_udp::Ping::decode(&plain[1..])?;
            let _ = event_tx.send(MumbleEvent::UdpPing(ping));
        }
        _ => {
            tracing::debug!("unhandled UDP message type: {}", plain[0]);
        }
    }
    Ok(())
}

fn current_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
