//! V3.3 会话层多路径聚合 —— 方案 B：连接级多节点分发 + 故障切换 + 评分加权。
//!
//! ## 设计裁决（V3 方案 §4 V3.3 执行定版）
//!
//! **本期交付方案 B（连接级多路径分发）**：对每个客户端连接，在建立节点流时
//! 按节点评分加权挑选一个节点（而非永远取评分最高者），使流量按权重分布在
//! 多个 Online 节点上；节点故障时沿既有 open_target 故障切换路径落到其余候选。
//! 纯客户端侧实现，节点完全无感知（每条节点流就是普通的"地址+转发"流）。
//!
//! **单连接字节级分片聚合（Splitter/Assembler 方案）如实标注为需要协议扩展
//! （V3.4）**：透明代理架构下，客户端到 N 个节点各开一条流，每条流各自声明
//! 同一目标地址——节点侧会建立 N 条独立的目标 TCP 连接、产生 N 份响应，下行
//! 无法拼回一份。要实现单连接字节级聚合，需要目标侧/节点间配合（连接共享或
//! 分段协议），超出本期"会话层、节点无感知"的边界。因此 Splitter/Assembler
//! 在方案 B 中**不进入数据路径**（每条连接仍是单条有序 QUIC 流），V3 方案 §6
//! 风险 3（分片丢失 = GB 级静默损坏）在本期路径上结构性不存在；该风险随 V3.4
//! 字节级聚合立项时才需按 §6-3 强制测试项（丢包注入/1GB 校验/乱序 fuzz）管控。
//!
//! **未来方向（仅记录，不实现）**：HTTP 明文请求可按 Range 请求级并行聚合
//! （多节点各取一段响应拼合），但 HTTPS 内容加密后无法分片定位，覆盖面受限。
//!
//! ## 行为约定
//!
//! - **默认关闭**：未设置 `HYDRA_AGGREGATE=1` 时 [`maybe_reorder_candidates`]
//!   是空操作，候选顺序与启用前逐位一致（`get_nodes_by_priority` 评分降序），
//!   数据路径零改动（回归保障）。
//! - **启用条件**：聚合启用且候选中 **Online 节点 ≥ 2** 才生效；只有 1 个
//!   Online 节点时自动退化为现路径（[`aggregate_eligible`]）。
//! - **加权规则**：在 Online 前缀内以 `NodeInfo::calculate_score`
//!   （clamp 到 ≥0）为权重随机挑选，权重相近时流量近似均分，权重悬殊时
//!   向高分节点倾斜；全零权重退化为评分最高者。
//! - **故障切换**：分发只是重排候选首位，传输失败仍走 open_target 既有的
//!   标记 Offline + 换下一候选逻辑——杀 1 节点后新连接全部由存活节点承接。
//! - **日志脱敏**：分发决策日志的目标一律 [`mask_target`] 短哈希（明文仅
//!   RUST_LOG=debug）。
//!
//! ## 观测（测试断言用）
//!
//! - [`record_node_served`]：每次 open_target 成功后按实际承接节点计数
//!   （无条件记录，含未启用聚合时——用于断言"未启用时全部走评分最高节点"）；
//! - [`aggregate_served_counts`] / [`aggregate_dispatch_counts`]：按节点地址
//!   汇总；[`reset_aggregate_stats`] 供测试清零。

use hydra_protocol::{mask_target, NodeInfo, NodeStatus};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use tracing::{debug, info};

/// 触发聚合的最少 Online 节点数（少于该数自动退化为现路径）
pub const MIN_NODES_FOR_AGGREGATION: usize = 2;

// ── 开关 ────────────────────────────────────────────────────────────────

/// 强制开关（测试/调试覆盖 env）：0=未设置（按 env 判断） 1=强制启用 2=强制关闭
static FORCE: AtomicU8 = AtomicU8::new(0);
/// env 解析缓存（进程内只读一次，避免每次建连都查环境变量）
static ENV_CACHE: OnceLock<bool> = OnceLock::new();

/// 聚合是否启用：`HYDRA_AGGREGATE=1` 时启用（默认关闭）。
/// 测试/调试可用 [`force_aggregate`] 覆盖，优先于 env。
pub fn aggregate_enabled() -> bool {
    match FORCE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    *ENV_CACHE
        .get_or_init(|| aggregate_env_enabled(std::env::var("HYDRA_AGGREGATE").ok().as_deref()))
}

/// 强制启用/禁用聚合（覆盖 env；供测试与调试，不改变默认关闭的交付语义）
pub fn force_aggregate(enabled: bool) {
    FORCE.store(if enabled { 1 } else { 2 }, Ordering::Relaxed);
}

/// 清除强制开关，恢复按 env 判断
pub fn clear_force_aggregate() {
    FORCE.store(0, Ordering::Relaxed);
}

/// env 值解析（纯函数，无全局状态，单测覆盖）：仅 `1` 视为启用
pub fn aggregate_env_enabled(val: Option<&str>) -> bool {
    val == Some("1")
}

// ── 候选与加权挑选 ──────────────────────────────────────────────────────

/// 候选表中的 Online 前缀长度。
/// 依赖 `Scheduler::get_nodes_by_priority` 的排序保证：Online 全部排在
/// Degraded/Offline 之前，因此 Online 构成连续前缀。
pub fn online_node_count(candidates: &[NodeInfo]) -> usize {
    candidates
        .iter()
        .take_while(|n| matches!(n.status, NodeStatus::Online))
        .count()
}

/// 聚合启用条件：候选中 Online 节点 ≥ 2
pub fn aggregate_eligible(candidates: &[NodeInfo]) -> bool {
    online_node_count(candidates) >= MIN_NODES_FOR_AGGREGATION
}

/// 在 Online 前缀内按评分加权随机挑选一个候选下标。
/// - 权重 = `calculate_score`（clamp 到 ≥0；负分节点不参与加权分发）；
/// - 全零权重（所有在线节点评分 ≤ 0）退化为前缀首位（评分最高者）；
/// - 无 Online 节点返回 None（调用方走既有错误路径）。
pub fn pick_weighted_node(candidates: &[NodeInfo]) -> Option<usize> {
    let n = online_node_count(candidates);
    if n == 0 {
        return None;
    }
    if n == 1 {
        return Some(0);
    }
    let weights: Vec<f64> = candidates[..n]
        .iter()
        .map(|node| node.calculate_score().max(0.0))
        .collect();
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return Some(0);
    }
    let mut dart = pseudo_random_01() * total;
    for (i, w) in weights.iter().enumerate() {
        dart -= w;
        if dart < 0.0 {
            return Some(i);
        }
    }
    Some(n - 1)
}

/// 伪随机数 [0,1)：RandomState 每实例随机种子 + 进程级计数器做输入，
/// 经 SipHash 扩散——不引第三方 rand 依赖、无锁。
fn pseudo_random_01() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(SEQ.fetch_add(1, Ordering::Relaxed));
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

// ── 分发决策与观测 ──────────────────────────────────────────────────────

#[derive(Default)]
struct AggregateStats {
    /// 各节点被分发决策选中的次数（仅聚合实际生效时记录）
    dispatch: HashMap<SocketAddr, u64>,
    /// 各节点实际成功承接的连接数（无条件记录）
    served: HashMap<SocketAddr, u64>,
}

static STATS: OnceLock<Mutex<AggregateStats>> = OnceLock::new();

fn stats() -> &'static Mutex<AggregateStats> {
    STATS.get_or_init(|| Mutex::new(AggregateStats::default()))
}

/// open_target 成功后调用：按实际承接节点计数（无条件，含未启用聚合时）
pub fn record_node_served(addr: SocketAddr) {
    if let Ok(mut s) = stats().lock() {
        *s.served.entry(addr).or_insert(0) += 1;
    }
}

/// 各节点实际承接连接数（测试/观测用）
pub fn aggregate_served_counts() -> HashMap<SocketAddr, u64> {
    stats().lock().map(|s| s.served.clone()).unwrap_or_default()
}

/// 各节点被分发选中的次数（测试/观测用）
pub fn aggregate_dispatch_counts() -> HashMap<SocketAddr, u64> {
    stats()
        .lock()
        .map(|s| s.dispatch.clone())
        .unwrap_or_default()
}

/// 清零统计（测试用）
pub fn reset_aggregate_stats() {
    if let Ok(mut s) = stats().lock() {
        s.dispatch.clear();
        s.served.clear();
    }
}

/// 连接级多路径分发入口（open_target 专用）：
/// 聚合启用且 Online ≥ 2 时，把加权挑选出的节点换到候选首位，其余候选保持
/// 评分降序作为故障切换后备；否则不动候选表（未启用/单节点退化 = 现路径）。
pub fn maybe_reorder_candidates(
    candidates: &mut Vec<NodeInfo>,
    peer_addr: SocketAddr,
    target: &str,
) {
    if aggregate_enabled() {
        reorder_candidates(candidates, peer_addr, target);
    }
}

/// 分发决策主体（不检查开关，单测直接覆盖以避免全局 FORCE 状态竞争）
fn reorder_candidates(candidates: &mut Vec<NodeInfo>, peer_addr: SocketAddr, target: &str) {
    let online = online_node_count(candidates);
    if !aggregate_eligible(candidates) {
        debug!(
            "[{}] Aggregate enabled but only {} online node(s) < {}, using default single-node path",
            peer_addr,
            online,
            MIN_NODES_FOR_AGGREGATION
        );
        return;
    }
    let Some(idx) = pick_weighted_node(candidates) else {
        return;
    };
    if idx != 0 {
        candidates.swap(0, idx);
    }
    let chosen = candidates[0].address;
    if let Ok(mut s) = stats().lock() {
        *s.dispatch.entry(chosen).or_insert(0) += 1;
    }
    // 日志脱敏（总则：目标一律短哈希，明文仅 debug 级别）
    info!(
        "[{}] Aggregate dispatch: new connection → node {} (score-weighted, {} online candidates), target {}",
        peer_addr,
        chosen,
        online,
        mask_target(target)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(addr: SocketAddr, status: NodeStatus, score: f64) -> NodeInfo {
        // score = bandwidth*0.5 - latency*0.3 - loss_rate*0.2，反推 bandwidth 即可
        NodeInfo {
            address: addr,
            bandwidth: score * 2.0,
            latency: 0.0,
            loss_rate: 0.0,
            load: 0.0,
            status,
        }
    }

    fn addr_octet(n: u8) -> SocketAddr {
        format!("127.0.0.1:{}", 30000 + n as u16).parse().unwrap()
    }

    #[test]
    fn test_env_enabled_parsing() {
        // 仅 "1" 启用；未设置/其他值一律关闭（默认关闭语义）
        assert!(!aggregate_env_enabled(None));
        assert!(aggregate_env_enabled(Some("1")));
        assert!(!aggregate_env_enabled(Some("0")));
        assert!(!aggregate_env_enabled(Some("true")));
        assert!(!aggregate_env_enabled(Some("")));
        assert!(!aggregate_env_enabled(Some("on")));
    }

    #[test]
    fn test_online_prefix_and_eligibility() {
        let candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 50.0),
            node(addr_octet(2), NodeStatus::Online, 40.0),
            node(addr_octet(3), NodeStatus::Offline, 90.0),
        ];
        assert_eq!(online_node_count(&candidates), 2);
        assert!(aggregate_eligible(&candidates));

        let single = vec![
            node(addr_octet(1), NodeStatus::Online, 50.0),
            node(addr_octet(2), NodeStatus::Offline, 90.0),
        ];
        assert_eq!(online_node_count(&single), 1);
        // 只有 1 个 Online → 不聚合（自动退化）
        assert!(!aggregate_eligible(&single));

        assert!(!aggregate_eligible(&[]));
    }

    #[test]
    fn test_pick_weighted_empty_and_single() {
        assert_eq!(pick_weighted_node(&[]), None);
        let one = vec![node(addr_octet(1), NodeStatus::Online, 50.0)];
        assert_eq!(pick_weighted_node(&one), Some(0));
        // Offline 不算
        let off = vec![node(addr_octet(1), NodeStatus::Offline, 50.0)];
        assert_eq!(pick_weighted_node(&off), None);
    }

    #[test]
    fn test_pick_weighted_extreme_skew_favors_high_score() {
        // 权重悬殊：A 评分 1000，B 评分 0.000001 → B 几乎不可能被选中
        let candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 1000.0),
            node(addr_octet(2), NodeStatus::Online, 0.0000005),
        ];
        let mut a = 0;
        for _ in 0..200 {
            if pick_weighted_node(&candidates) == Some(0) {
                a += 1;
            }
        }
        assert!(a >= 195, "high-score node should dominate: {}/200", a);
    }

    #[test]
    fn test_pick_weighted_zero_weights_falls_back_to_best() {
        // 全负分（clamp 后全零权重）→ 退化为前缀首位（评分最高者）
        let candidates = vec![
            node(addr_octet(1), NodeStatus::Online, -1.0),
            node(addr_octet(2), NodeStatus::Online, -2.0),
        ];
        for _ in 0..50 {
            assert_eq!(pick_weighted_node(&candidates), Some(0));
        }
    }

    #[test]
    fn test_pick_weighted_near_equal_spreads() {
        // 权重相近（51/49）：200 次抽样两节点都应被命中
        let candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 51.0),
            node(addr_octet(2), NodeStatus::Online, 49.0),
        ];
        let mut counts = [0usize; 2];
        for _ in 0..200 {
            counts[pick_weighted_node(&candidates).unwrap()] += 1;
        }
        assert!(counts[0] > 0 && counts[1] > 0, "both picked: {:?}", counts);
    }

    #[test]
    fn test_reorder_noop_when_disabled() {
        let mut candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 50.0),
            node(addr_octet(2), NodeStatus::Online, 40.0),
        ];
        let before = candidates.clone();
        // 直接测决策主体（enabled=false 时不进入）——不触碰全局 FORCE，避免并行测试竞争
        maybe_reorder_candidates(&mut candidates, addr_octet(9), "example.com:443");
        assert_eq!(
            candidates.iter().map(|n| n.address).collect::<Vec<_>>(),
            before.iter().map(|n| n.address).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_reorder_noop_when_single_online_node() {
        let mut candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 50.0),
            node(addr_octet(2), NodeStatus::Offline, 90.0),
        ];
        let before = candidates.clone();
        reorder_candidates(&mut candidates, addr_octet(9), "example.com:443");
        assert_eq!(
            candidates.iter().map(|n| n.address).collect::<Vec<_>>(),
            before.iter().map(|n| n.address).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_reorder_swaps_weighted_pick_to_front() {
        // 权重悬殊 → 高分节点稳定被换到首位，其余候选顺序保持（故障切换后备）
        let mut candidates = vec![
            node(addr_octet(1), NodeStatus::Online, 0.0000005),
            node(addr_octet(2), NodeStatus::Online, 1000.0),
        ];
        reorder_candidates(&mut candidates, addr_octet(9), "example.com:443");
        assert_eq!(candidates[0].address, addr_octet(2));
        assert_eq!(candidates[1].address, addr_octet(1));
    }
}
