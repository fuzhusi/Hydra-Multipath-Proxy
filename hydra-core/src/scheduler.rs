use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 指标兜底：非法（非有限/越界）→ 旧值，合法 → 新值（09-P1-4 防御纵深）
fn sanitize(new: f64, min: f64, max: f64, old: f64) -> f64 {
    if new.is_finite() && new >= min && new <= max {
        new
    } else {
        old
    }
}

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
        nodes
            .values()
            .filter(|n| matches!(n.status, NodeStatus::Online))
            .max_by(|a, b| {
                let score_a = a.calculate_score();
                let score_b = b.calculate_score();
                // 平分时按地址升序取最小者（09-P3-7：与 get_nodes_by_priority
                // 的 tie-break 统一——此前 max_by 平分取向"取后者"、HashMap
                // 随机序导致观测层与调度层对同一批节点给出不同最优）
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.address.cmp(&a.address))
            })
            .cloned()
    }

    /// 按优先级返回全部节点：Online 优先（按评分降序），其后 Degraded，最后 Offline。
    /// Offline 节点仍保留在候选尾部，用于自动恢复探测。
    pub async fn get_nodes_by_priority(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        let rank = |n: &NodeInfo| match n.status {
            NodeStatus::Online => 0u8,
            NodeStatus::Degraded => 1,
            NodeStatus::Offline => 2,
        };
        let mut list: Vec<NodeInfo> = nodes.values().cloned().collect();
        list.sort_by(|a, b| {
            rank(a).cmp(&rank(b)).then_with(|| {
                // 平分时按地址升序（09-P3-7：确定序，与 get_best_node 一致）
                b.calculate_score()
                    .partial_cmp(&a.calculate_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.address.cmp(&b.address))
            })
        });
        list
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
            // 防御性 clamp（09-P1-4）：所有写进入口统一兜底——NaN/inf/越界值
            // 保持旧值（NaN 比较恒 false 时会以旧值落下；显式判断更清晰）
            node.bandwidth = sanitize(bandwidth, 0.0, 1_000_000.0, node.bandwidth);
            node.latency = sanitize(latency, 0.0, 1_000_000.0, node.latency);
            node.loss_rate = sanitize(loss_rate, 0.0, 1.0, node.loss_rate);
            node.load = sanitize(load, 0.0, 1.0, node.load);
        }
    }

    pub async fn update_node_status(&self, addr: &std::net::SocketAddr, status: NodeStatus) {
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
        nodes
            .values()
            .filter(|n| matches!(n.status, NodeStatus::Online))
            .cloned()
            .collect()
    }

    pub async fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn node(addr: SocketAddr, bandwidth: f64) -> NodeInfo {
        NodeInfo {
            address: addr,
            bandwidth,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        }
    }

    fn addr_of(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    /// 无实测数据时用静态初始值评分：带宽高者优先（get_best_node 的初始序即 proxy
    /// start 注入的递减静态评分序）
    #[tokio::test]
    async fn test_static_score_without_measurements() {
        let s = Scheduler::new();
        let fast = addr_of(10001);
        let slow = addr_of(10002);
        s.add_node(node(fast, 100.0)).await;
        s.add_node(node(slow, 90.0)).await;
        assert_eq!(s.get_best_node().await.unwrap().address, fast);

        // 未被注入实测数据的节点保持静态初始值（混合评分的"无数据"侧）
        s.update_node_stats(&slow, 1000.0, 5.0, 0.01, 0.5).await;
        let nodes = s.get_all_nodes().await;
        let fast_node = nodes.iter().find(|n| n.address == fast).unwrap();
        assert_eq!(fast_node.bandwidth, 100.0);
        assert_eq!(fast_node.latency, 10.0);
    }

    /// 动态评分：update_node_stats 注入实测值后 get_best_node 随之变化——
    /// 静态次位节点实测反超 → 跃居首位；再被反超 → 退回次位
    #[tokio::test]
    async fn test_dynamic_score_changes_best_node() {
        let s = Scheduler::new();
        let a = addr_of(20001);
        let b = addr_of(20002);
        s.add_node(node(a, 100.0)).await;
        s.add_node(node(b, 90.0)).await;
        assert_eq!(s.get_best_node().await.unwrap().address, a);

        // b 实测带宽反超 → best 变 b
        s.update_node_stats(&b, 500.0, 8.0, 0.01, 0.5).await;
        assert_eq!(s.get_best_node().await.unwrap().address, b);

        // a 实测更快 → best 变回 a
        s.update_node_stats(&a, 900.0, 3.0, 0.01, 0.5).await;
        assert_eq!(s.get_best_node().await.unwrap().address, a);

        // get_nodes_by_priority 的 Online 段同样按动态评分降序
        let ranked = s.get_nodes_by_priority().await;
        assert_eq!(ranked[0].address, a);
        assert_eq!(ranked[1].address, b);
    }
}
