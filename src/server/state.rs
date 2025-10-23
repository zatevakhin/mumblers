use std::sync::Arc;
use tokio::sync::RwLock;

use super::config::ServerConfig;

pub type SessionId = u32;

#[derive(Debug, Clone)]
pub struct ServerState {
    inner: Arc<RwLock<InnerState>>,
    pub cfg: ServerConfig,
    pub udp: Arc<tokio::sync::Mutex<Option<std::sync::Arc<tokio::net::UdpSocket>>>>,
}

#[derive(Debug, Default)]
struct InnerState {
    next_session: SessionId,
    users: std::collections::HashMap<SessionId, UserInfo>,
    conns: std::collections::HashMap<SessionId, tokio::sync::mpsc::UnboundedSender<crate::messages::MumbleMessage>>, 
    crypt: std::collections::HashMap<SessionId, UdpCrypt>,
    udp_pair: std::collections::HashMap<SessionId, std::net::SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub session: SessionId,
    pub name: Option<String>,
    pub channel_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpCrypt {
    pub key: [u8; 16],
    pub server_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
}

impl ServerState {
    pub fn new(cfg: ServerConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerState {
                next_session: 1,
                users: std::collections::HashMap::new(),
                conns: std::collections::HashMap::new(),
                crypt: std::collections::HashMap::new(),
                udp_pair: std::collections::HashMap::new(),
            })),
            cfg,
            udp: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn clone(&self) -> Self { Self { inner: self.inner.clone(), cfg: self.cfg.clone(), udp: self.udp.clone() } }

    pub async fn alloc_session(&self) -> SessionId {
        let mut g = self.inner.write().await;
        let id = g.next_session;
        g.next_session += 1;
        id
    }

    pub async fn add_user(&self, user: UserInfo) {
        let mut g = self.inner.write().await;
        g.users.insert(user.session, user);
    }

    pub async fn remove_user(&self, session: SessionId) {
        let mut g = self.inner.write().await;
        g.users.remove(&session);
        g.conns.remove(&session);
        g.crypt.remove(&session);
        g.udp_pair.remove(&session);
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        let g = self.inner.read().await;
        g.users.values().cloned().collect()
    }

    pub async fn register_conn(&self, session: SessionId, tx: tokio::sync::mpsc::UnboundedSender<crate::messages::MumbleMessage>) {
        let mut g = self.inner.write().await;
        g.conns.insert(session, tx);
    }

    pub async fn broadcast_except(&self, except: SessionId, msg: crate::messages::MumbleMessage) -> usize {
        let g = self.inner.read().await;
        let mut count = 0;
        for (sess, tx) in g.conns.iter() {
            if *sess == except { continue; }
            if tx.send(msg.clone()).is_ok() {
                count += 1;
            }
        }
        count
    }

    pub async fn send_to(&self, session: SessionId, msg: crate::messages::MumbleMessage) -> bool {
        let g = self.inner.read().await;
        if let Some(tx) = g.conns.get(&session) {
            let _ = tx.send(msg);
            true
        } else {
            false
        }
    }

    pub async fn set_crypt(&self, session: SessionId, c: UdpCrypt) {
        let mut g = self.inner.write().await;
        g.crypt.insert(session, c);
    }

    pub async fn get_crypt(&self, session: SessionId) -> Option<UdpCrypt> {
        let g = self.inner.read().await;
        g.crypt.get(&session).copied()
    }

    pub async fn ensure_udp_bound(&self, bind_host: &str, port: u16) -> std::io::Result<bool> {
        let mut guard = self.udp.lock().await;
        if guard.is_some() {
            return Ok(false);
        }
        let addr = std::net::SocketAddr::new(bind_host.parse().unwrap_or(std::net::IpAddr::from([127,0,0,1])), port);
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        tracing::info!(%addr, "udp bound");
        *guard = Some(std::sync::Arc::new(sock));
        Ok(true)
    }

    pub async fn crypt_entries(&self) -> Vec<(SessionId, UdpCrypt)> {
        let g = self.inner.read().await;
        g.crypt.iter().map(|(k,v)| (*k, *v)).collect()
    }

    pub async fn set_udp_pair(&self, session: SessionId, addr: std::net::SocketAddr) {
        let mut g = self.inner.write().await;
        g.udp_pair.insert(session, addr);
    }

    pub async fn get_udp_pair(&self, session: SessionId) -> Option<std::net::SocketAddr> {
        let g = self.inner.read().await;
        g.udp_pair.get(&session).copied()
    }

    pub async fn udp_socket(&self) -> Option<std::sync::Arc<tokio::net::UdpSocket>> {
        let guard = self.udp.lock().await;
        guard.clone()
    }
}
