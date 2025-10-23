use std::sync::Arc;
use tokio::sync::RwLock;

use super::config::ServerConfig;

pub type SessionId = u32;

#[derive(Debug, Clone)]
pub struct ServerState {
    inner: Arc<RwLock<InnerState>>,
    pub cfg: ServerConfig,
}

#[derive(Debug, Default)]
struct InnerState {
    next_session: SessionId,
    users: std::collections::HashMap<SessionId, UserInfo>,
    conns: std::collections::HashMap<SessionId, tokio::sync::mpsc::UnboundedSender<crate::messages::MumbleMessage>>, 
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub session: SessionId,
    pub name: Option<String>,
    pub channel_id: u32,
}

impl ServerState {
    pub fn new(cfg: ServerConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerState {
                next_session: 1,
                users: std::collections::HashMap::new(),
                conns: std::collections::HashMap::new(),
            })),
            cfg,
        }
    }

    pub fn clone(&self) -> Self { Self { inner: self.inner.clone(), cfg: self.cfg.clone() } }

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
    }

    pub async fn list_users(&self) -> Vec<UserInfo> {
        let g = self.inner.read().await;
        g.users.values().cloned().collect()
    }

    pub async fn register_conn(&self, session: SessionId, tx: tokio::sync::mpsc::UnboundedSender<crate::messages::MumbleMessage>) {
        let mut g = self.inner.write().await;
        g.conns.insert(session, tx);
    }

    pub async fn broadcast_except(&self, except: SessionId, msg: crate::messages::MumbleMessage) {
        let g = self.inner.read().await;
        for (sess, tx) in g.conns.iter() {
            if *sess == except { continue; }
            let _ = tx.send(msg.clone());
        }
    }
}
