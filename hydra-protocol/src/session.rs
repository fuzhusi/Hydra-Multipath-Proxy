use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// 审查 R-30（2026-10-05 Wave 2）：QUIC 时代的 Session / Stream / SessionStatus /
// StreamStatus 死代码已删除（零生产引用）；本文件仅保留调度器与 GUI 共用的
// NodeInfo / NodeStatus。

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
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
}

impl NodeInfo {
    pub fn calculate_score(&self) -> f64 {
        self.bandwidth * 0.5 - self.latency * 0.3 - self.loss_rate * 0.2
    }
}
