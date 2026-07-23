use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use hydra_protocol::{Session, SessionStatus, HydraError, Result};

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<u64, Session>>>,
    next_id: u64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_id: 1,
        }
    }

    pub async fn create_session(&mut self, client_addr: std::net::SocketAddr) -> Result<Session> {
        let id = self.next_id;
        self.next_id += 1;

        let session = Session {
            id,
            client: client_addr,
            nodes: Vec::new(),
            streams: Vec::new(),
            status: SessionStatus::Connecting,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(id, session.clone());

        Ok(session)
    }

    pub async fn get_session(&self, id: u64) -> Result<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(&id)
            .cloned()
            .ok_or_else(|| HydraError::SessionError(format!("Session {} not found", id)))
    }

    pub async fn update_session_status(&self, id: u64, status: SessionStatus) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&id) {
            session.status = status;
            Ok(())
        } else {
            Err(HydraError::SessionError(format!("Session {} not found", id)))
        }
    }

    pub async fn close_session(&self, id: u64) -> Result<()> {
        self.update_session_status(id, SessionStatus::Closed).await
    }
}