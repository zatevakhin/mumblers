use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use prost::Message;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

#[cfg(feature = "audio")]
use crate::audio::AudioPlaybackManager;
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
        target: SocketAddr,
        params: Arc<UdpState>,
        event_tx: tokio::sync::broadcast::Sender<MumbleEvent>,
        #[cfg(feature = "audio")] playback: Option<Arc<AudioPlaybackManager>>,
        resync_tx: mpsc::Sender<()>,
        resync_interval: Duration,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target).await?;

        let mut crypt = CryptStateOcb2::new();
        crypt.set_key(&params.key, &params.client_nonce, &params.server_nonce);
        let crypt = Arc::new(Mutex::new(crypt));

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let crypt_clone = Arc::clone(&crypt);
        let event_tx_clone = event_tx.clone();
        #[cfg(feature = "audio")]
        let playback_clone = playback.clone();
        let task = tokio::spawn(async move {
            let mut ticker = interval(UDP_PING_INTERVAL);
            let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
            let mut last_resync_request: Option<Instant> = None;
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
                                        if let Err(err) = handle_plain_packet(
                                            &plain,
                                            &event_tx_clone,
                                            #[cfg(feature = "audio")]
                                            playback_clone.as_ref(),
                                        ).await {
                                            tracing::warn!("unable to handle UDP packet: {err}");
                                        }
                                    }
                                    Err(err) => {
                                        tracing::debug!("dropping UDP packet: {err:?}");
                                        let now = Instant::now();
                                        let last_good = {
                                            let guard = crypt_clone.lock().await;
                                            guard.t_last_good
                                        };
                                        let stale = last_good
                                            .map(|good| now.duration_since(good) > resync_interval)
                                            .unwrap_or(true);
                                        let can_request = last_resync_request
                                            .map(|prev| now.duration_since(prev) > resync_interval)
                                            .unwrap_or(true);
                                        if stale
                                            && can_request
                                            && resync_tx.try_send(()).is_ok()
                                        {
                                            last_resync_request = Some(now);
                                        }
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
    let ping = crate::proto::mumble_udp::Ping {
        timestamp: current_millis(),
        ..Default::default()
    };
    let mut payload = ping.encode_to_vec();
    payload.insert(0, MSG_TYPE_PING);
    let packet = {
        let mut guard = crypt.lock().await;
        guard
            .encrypt(&payload)
            .map_err(|err| std::io::Error::other(err.to_string()))?
    };
    socket.send(&packet).await?;
    Ok(())
}

async fn send_audio(
    socket: &UdpSocket,
    crypt: &Arc<Mutex<CryptStateOcb2>>,
    packet: VoicePacket,
) -> std::io::Result<()> {
    let proto = packet.into_proto();
    let frame = proto.frame_number;
    let mut payload = proto.encode_to_vec();
    payload.insert(0, MSG_TYPE_AUDIO);
    let encrypted = {
        let mut guard = crypt.lock().await;
        guard
            .encrypt(&payload)
            .map_err(|err| std::io::Error::other(err.to_string()))?
    };
    tracing::debug!(frame, bytes = encrypted.len(), "client: udp audio sent");
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

async fn handle_plain_packet(
    plain: &[u8],
    event_tx: &tokio::sync::broadcast::Sender<MumbleEvent>,
    #[cfg(feature = "audio")] playback: Option<&Arc<AudioPlaybackManager>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if plain.is_empty() {
        return Ok(());
    }
    match plain[0] {
        MSG_TYPE_AUDIO => {
            let audio = mumble_udp::Audio::decode(&plain[1..])?;
            if let Some(packet) = VoicePacket::from_proto(&audio) {
                #[cfg(feature = "audio")]
                if let Some(manager) = playback {
                    if let Err(err) = manager.ingest(&packet).await {
                        tracing::warn!("failed to buffer audio packet: {err}");
                    }
                }
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

#[cfg(test)]
mod resync_tests {
    use super::*;
    use tokio::time::{sleep, timeout, Duration};

    fn sample_packet() -> VoicePacket {
        VoicePacket {
            header: crate::audio::AudioHeader::Target(0),
            sender_session: None,
            frame_number: 1,
            opus_data: vec![1, 2, 3],
            positional_data: None,
            volume_adjustment: None,
            is_terminator: false,
        }
    }

    #[tokio::test]
    async fn decrypt_failure_triggers_resync_request() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let params = Arc::new(UdpState {
            key: [1u8; 16],
            client_nonce: [2u8; 16],
            server_nonce: [3u8; 16],
        });
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(4);
        let (resync_tx, mut resync_rx) = mpsc::channel(1);
        let tunnel = UdpTunnel::start(
            server_addr,
            params,
            event_tx,
            #[cfg(feature = "audio")]
            None,
            resync_tx,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        tunnel.send_audio(sample_packet()).await.unwrap();

        let mut buf = [0u8; 1500];
        let (_, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();

        sleep(Duration::from_millis(2)).await;
        server_socket.send_to(&[0u8; 8], client_addr).await.unwrap();

        timeout(Duration::from_secs(1), resync_rx.recv())
            .await
            .expect("resync signal")
            .expect("resync message");
        drop(tunnel);
    }
}
