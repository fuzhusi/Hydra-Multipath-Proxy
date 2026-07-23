use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: u64,
    pub client: SocketAddr,
    pub nodes: Vec<NodeInfo>,
    pub streams: Vec<Stream>,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub address: SocketAddr,
    pub bandwidth: f64,
    pub latency: f64,
    pub loss_rate: f64,
    pub load: f64,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    pub id: u32,
    pub offset: u64,
    pub length: u64,
    pub status: StreamStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStatus {
    Connecting,
    Active,
    Closed,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamStatus {
    Pending,
    Active,
    Completed,
    Failed,
}

impl NodeInfo {
    pub fn calculate_score(&self) -> f64 {
        self.bandwidth * 0.5 - self.latency * 0.3 - self.loss_rate * 0.2
    }
}