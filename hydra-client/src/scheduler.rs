use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Scheduler {
    nodes: Arc<RwLock<HashMap<std::net::SocketAddr, NodeInfo>>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_node(&self, node: NodeInfo) {
        let mut nodes = self.nodes.write().await;
        nodes.insert(node.address, node);
    }

    pub async fn remove_node(&self, addr: &std::net::SocketAddr) {
        let mut nodes = self.nodes.write().await;
        nodes.remove(addr);
    }

    pub async fn get_best_node(&self) -> Option<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values()
            .filter(|n| matches!(n.status, NodeStatus::Online))
            .max_by(|a, b| {
                let score_a = a.calculate_score();
                let score_b = b.calculate_score();
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }

    pub async fn update_node_stats(
        &self,
        addr: &std::net::SocketAddr,
        bandwidth: f64,
        latency: f64,
        loss_rate: f64,
        load: f64,
    ) {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(addr) {
            node.bandwidth = bandwidth;
            node.latency = latency;
            node.loss_rate = loss_rate;
            node.load = load;
        }
    }

    pub async fn update_node_status(
        &self,
        addr: &std::net::SocketAddr,
        status: NodeStatus,
    ) {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(addr) {
            node.status = status;
        }
    }

    pub async fn mark_node_offline(&self, addr: &std::net::SocketAddr) {
        self.update_node_status(addr, NodeStatus::Offline).await;
    }

    pub async fn get_online_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values()
            .filter(|n| matches!(n.status, NodeStatus::Online))
            .cloned()
            .collect()
    }

    pub async fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }
}