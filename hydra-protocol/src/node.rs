use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub address: SocketAddr,
    pub max_connections: u32,
    pub buffer_size: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".parse().unwrap(),
            max_connections: 1000,
            buffer_size: 65536,
        }
    }
}