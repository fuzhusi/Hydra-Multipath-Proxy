use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub max_connections: u32,
    pub buffer_size: usize,
    pub log_level: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            max_connections: 1000,
            buffer_size: 65536,
            log_level: "info".to_string(),
        }
    }
}