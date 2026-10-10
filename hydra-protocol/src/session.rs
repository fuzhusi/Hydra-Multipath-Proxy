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
    /// 节点评分（内核优化 #11：量纲归一化的效用和）。
    ///
    /// 旧式 `bw*0.5 - lat*0.3 - loss*0.2` 的量纲脱节：带宽（Mbps，数百）压倒
    /// 延迟（ms）与 loss（≤1，最大罚 -0.2 ≈ 无效），load 权重 0。改为各维度
    /// 归一化到 [0,1] 后加权和：
    /// - 带宽效用 `1-exp(-bw/100)`（100Mbps 半饱和，>300Mbps 趋饱和）
    /// - 延迟效用 `1/(1+lat/200)`（200ms 半衰）
    /// - 丢包效用 `1-loss`（真正咬合）
    /// - 负载效用 `1-load`（死维度复活）
    ///
    /// 权重 0.4/0.3/0.2/0.1；全维度相同得分的节点得分相等（可比较）。
    pub fn calculate_score(&self) -> f64 {
        let bw_u = 1.0 - (-self.bandwidth / 100.0).exp();
        let lat_u = 1.0 / (1.0 + self.latency / 200.0);
        let loss_u = (1.0 - self.loss_rate).clamp(0.0, 1.0);
        let load_u = (1.0 - self.load).clamp(0.0, 1.0);
        0.4 * bw_u + 0.3 * lat_u + 0.2 * loss_u + 0.1 * load_u
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_归一化后各维度有效且有序() {
        let n = |bw: f64, lat: f64, loss: f64, load: f64| NodeInfo {
            address: "127.0.0.1:1".parse().unwrap(),
            bandwidth: bw,
            latency: lat,
            loss_rate: loss,
            load,
            status: NodeStatus::Online,
        };
        // 高带宽低延迟零丢包 > 低带宽高延迟高丢包
        let good = n(100.0, 20.0, 0.0, 0.1).calculate_score();
        let bad = n(5.0, 300.0, 0.3, 0.8).calculate_score();
        assert!(good > bad, "好节点 {good} 应优于差节点 {bad}");
        // loss 真正咬合：其他相同，loss 0 vs 0.5 差异显著（旧式仅 0.1）
        let l0 = n(100.0, 50.0, 0.0, 0.5).calculate_score();
        let l5 = n(100.0, 50.0, 0.5, 0.5).calculate_score();
        assert!(l0 - l5 > 0.05, "loss 应显著影响评分（{l0} vs {l5}）");
        // 全相同节点得分相等（并列）
        assert_eq!(
            n(50.0, 100.0, 0.1, 0.5).calculate_score(),
            n(50.0, 100.0, 0.1, 0.5).calculate_score()
        );
        // 得分落在 [0, 1]（效用和）
        let s = n(1000.0, 1.0, 0.0, 0.0).calculate_score();
        assert!((0.0..=1.0).contains(&s), "满分应在 [0,1]，实际 {s}");
    }
}
