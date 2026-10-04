//! 节点自动恢复探测（A2）+ 被动测速动态评分（WS-E）。
//!
//! 随 `ProxyServer::start` 常驻的后台任务：每 `HYDRA_PROBE_INTERVAL_SECS`
//! （默认 30，测试可设 1-2）±随机抖动做一轮探测：
//! - 非 Online 节点：QUIC connect 探测（`tokio::time::timeout(5s)` 外包，不动 transport.rs）。
//!   成功 → 恢复 Online+日志；连续 3 次失败保持 Offline。
//! - Online 节点（`HYDRA_SPEEDTEST=0` 关闭，默认开）：测速评分写回 scheduler——
//!   延迟 = 探测连接 `Connection::stats().path.rtt`（每周期一次主动 connect，轻量）；
//!   吞吐 = 该节点窗口期 relay 字节差分（被动，来自流量统计的按节点计数），
//!   窗口累计 ≥1KB 才更新否则保持旧值；loss ≈ 最近一次 Offline/探测失败事件的指数衰减。
//!   评分混合策略：无实测数据的字段沿用静态初始值，`get_best_node` 因此从"静态恒值"
//!   变为"动态实测"。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use hydra_protocol::NodeInfo;
use hydra_protocol::NodeStatus;

use crate::scheduler::Scheduler;
use crate::traffic::TrafficMonitor;
use crate::transport::Transport;

/// 单次探测超时（由 tokio::time::timeout 外包；不影响 transport.rs）
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// 连续失败达此次数后，仅以 debug 级记录后续失败（节点保持 Offline）
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// 探测间隔环境变量
pub const PROBE_INTERVAL_ENV: &str = "HYDRA_PROBE_INTERVAL_SECS";
/// 默认探测间隔（秒）
pub const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
/// 测速开关环境变量：设为 `0` 关闭测速评分（退回纯恢复探测），其余值/未设 = 开启
pub const SPEEDTEST_ENV: &str = "HYDRA_SPEEDTEST";
/// 吞吐窗口更新阈值：窗口内上下行合计 ≥1KB 才更新带宽，否则保持旧值
pub const THROUGHPUT_MIN_BYTES: u64 = 1024;
/// 无 Offline 事件时的基础丢包率（与节点初始静态值一致）
pub const BASE_LOSS_RATE: f64 = 0.01;
/// 一次 Offline/探测失败事件的瞬时丢包率峰值
pub const EVENT_LOSS_RATE: f64 = 0.5;
/// Offline 事件衰减时间常数（秒）：loss = BASE + EVENT * exp(-elapsed/该值)
pub const LOSS_DECAY_SECS: f64 = 30.0;

/// 读取探测间隔：`HYDRA_PROBE_INTERVAL_SECS`，默认 30；非法值回退默认，clamp 到 1..=3600 秒
pub fn probe_interval_from_env() -> Duration {
    let secs = std::env::var(PROBE_INTERVAL_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS);
    Duration::from_secs(secs.clamp(1, 3600))
}

/// 测速评分开关：`HYDRA_SPEEDTEST=0` 关闭（退回纯恢复探测，评分保持现状），默认开启
pub fn speedtest_enabled_from_env() -> bool {
    std::env::var(SPEEDTEST_ENV).ok().as_deref() != Some("0")
}

/// 吞吐计算：窗口字节差 → Mbps（与节点初始静态带宽同量纲）
pub fn throughput_mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    bytes as f64 * 8.0 / 1_000_000.0 / secs
}

/// loss 近似：最近一次 Offline/探测失败事件的指数衰减；无事件时为基础值，上限 1.0
pub fn loss_from_offline_event(elapsed: Option<Duration>) -> f64 {
    match elapsed {
        None => BASE_LOSS_RATE,
        Some(d) => {
            let decay = (-d.as_secs_f64() / LOSS_DECAY_SECS).exp();
            (BASE_LOSS_RATE + EVENT_LOSS_RATE * decay).min(1.0)
        }
    }
}

/// 吞吐窗口差分器：基线建立后，窗口内累计 ≥[`THROUGHPUT_MIN_BYTES`] 才给出一次
/// 吞吐读数并重置基线；不足则保留基线继续累计（跨窗口慢流量不丢账）。
#[derive(Debug, Default)]
pub struct ThroughputTracker {
    base: Option<(Instant, u64, u64)>,
}

impl ThroughputTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// 采样一次：`sent`/`received` 为该节点单调累计字节。返回 `Some(Mbps)` 表示本次窗口有效。
    pub fn sample(&mut self, now: Instant, sent: u64, received: u64) -> Option<f64> {
        match self.base {
            None => {
                self.base = Some((now, sent, received));
                None
            }
            Some((at, base_sent, base_recv)) => {
                let elapsed = now.duration_since(at);
                let diff = sent
                    .saturating_sub(base_sent)
                    .saturating_add(received.saturating_sub(base_recv));
                if diff >= THROUGHPUT_MIN_BYTES && elapsed.as_secs_f64() > 0.0 {
                    self.base = Some((now, sent, received));
                    Some(throughput_mbps(diff, elapsed))
                } else {
                    None
                }
            }
        }
    }
}

/// 评分混合策略：实测字段覆盖，未实测字段沿用旧静态值；load 无数据来源保持不变。
/// 返回 (bandwidth, latency, loss_rate, load)。
fn merge_stats(
    old: &NodeInfo,
    rtt: Option<Duration>,
    bandwidth_mbps: Option<f64>,
    loss_rate: f64,
) -> (f64, f64, f64, f64) {
    let bandwidth = bandwidth_mbps.unwrap_or(old.bandwidth);
    let latency = rtt.map_or(old.latency, |d| d.as_secs_f64() * 1000.0);
    (bandwidth, latency, loss_rate, old.load)
}

/// 启动常驻探测任务（随 ProxyServer::start 调用）。
///
/// 探测用独立 Transport（证书 pinning 与主链路一致）；`traffic` 为中继计数同一实例，
/// 按节点字节计数是吞吐差分的数据源。任务永不返回，随 runtime 关闭而结束。
pub fn spawn_recovery_probe(
    scheduler: Arc<Scheduler>,
    node_certs: Vec<Vec<u8>>,
    sni: String,
    traffic: Arc<TrafficMonitor>,
) {
    tokio::spawn(async move {
        let interval = probe_interval_from_env();
        let speedtest_enabled = speedtest_enabled_from_env();
        let transport = match Transport::new_client(node_certs, &sni).await {
            Ok(t) => t,
            Err(e) => {
                warn!("恢复探测器启动失败（无法创建传输）: {}", e);
                return;
            }
        };
        if speedtest_enabled {
            info!(
                "恢复探测器已启动（间隔 {}s±20% 抖动，单次超时 {}s，测速评分开启）",
                interval.as_secs(),
                PROBE_TIMEOUT.as_secs()
            );
        } else {
            info!(
                "恢复探测器已启动（间隔 {}s±20% 抖动，单次超时 {}s，测速评分关闭）",
                interval.as_secs(),
                PROBE_TIMEOUT.as_secs()
            );
        }
        let mut consecutive_failures: HashMap<SocketAddr, u32> = HashMap::new();
        let mut last_offline_event: HashMap<SocketAddr, Instant> = HashMap::new();
        let mut throughput: HashMap<SocketAddr, ThroughputTracker> = HashMap::new();
        loop {
            // ±最多 20% 随机抖动（双向，纯正向只会拉长周期），避免整周期探测的被动特征
            let fifth = (interval.as_millis() as i64) / 5;
            let offset = rand::Rng::gen_range(&mut rand::thread_rng(), -fifth..=fifth);
            let sleep_ms = ((interval.as_millis() as i64) + offset).max(500) as u64;
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

            for node in scheduler.get_all_nodes().await {
                if matches!(node.status, NodeStatus::Online) {
                    if speedtest_enabled {
                        speedtest_online_node(
                            &scheduler,
                            &transport,
                            &traffic,
                            &node,
                            &mut last_offline_event,
                            &mut throughput,
                        )
                        .await;
                    }
                    continue;
                }
                // 非 Online 节点：恢复探测（测速开启时顺带以实测 RTT 更新延迟）
                probe_offline_node(
                    &scheduler,
                    &transport,
                    &node,
                    speedtest_enabled,
                    &mut consecutive_failures,
                    &mut last_offline_event,
                )
                .await;
            }
        }
    });
}

/// Online 节点测速：主动 connect 取 RTT，被动差分取吞吐，衰减近似取 loss，写回评分。
async fn speedtest_online_node(
    scheduler: &Scheduler,
    transport: &Transport,
    traffic: &TrafficMonitor,
    node: &NodeInfo,
    last_offline_event: &mut HashMap<SocketAddr, Instant>,
    throughput: &mut HashMap<SocketAddr, ThroughputTracker>,
) {
    let addr = node.address;
    // 1. 主动延迟：探测连接的 path RTT（每周期一次，轻量）
    let rtt = match tokio::time::timeout(PROBE_TIMEOUT, transport.connect(addr)).await {
        Ok(Ok(conn)) => {
            let rtt = conn.stats().path.rtt;
            drop(conn);
            Some(rtt)
        }
        _ => {
            // Online 节点探测失败：不改状态（避免与中继故障切换路径打架），记一次 loss 事件
            last_offline_event.insert(addr, Instant::now());
            None
        }
    };

    // 2. 被动吞吐：该节点窗口期 relay 字节差分（≥1KB 才更新，否则保持旧值）
    let entry = traffic.node_entry(addr);
    let measured_bw =
        throughput
            .entry(addr)
            .or_default()
            .sample(Instant::now(), entry.sent(), entry.received());

    // 3. loss 近似：最近 Offline/探测失败事件的指数衰减
    let loss = loss_from_offline_event(last_offline_event.get(&addr).map(|t| t.elapsed()));

    // 4. 混合写回：无实测字段沿用静态初始值
    let (bandwidth, latency, loss_rate, load) = merge_stats(node, rtt, measured_bw, loss);
    scheduler
        .update_node_stats(&addr, bandwidth, latency, loss_rate, load)
        .await;
    if rtt.is_some() || measured_bw.is_some() {
        let score = bandwidth * 0.5 - latency * 0.3 - loss_rate * 0.2;
        info!(
            "节点 {} 测速写回：rtt {}ms，吞吐 {:.1}Mbps，loss {:.3}，评分 {:.1}",
            addr,
            rtt.map_or(-1.0, |d| d.as_secs_f64() * 1000.0),
            measured_bw.unwrap_or(-1.0),
            loss_rate,
            score
        );
    } else {
        debug!(
            "节点 {} 本窗口无实测数据，仅 loss 衰减写回（{:.3}）",
            addr, loss
        );
    }
}

/// 非 Online 节点恢复探测（A2 原逻辑）；测速开启时以实测 RTT 顺带更新延迟。
async fn probe_offline_node(
    scheduler: &Scheduler,
    transport: &Transport,
    node: &NodeInfo,
    speedtest_enabled: bool,
    consecutive_failures: &mut HashMap<SocketAddr, u32>,
    last_offline_event: &mut HashMap<SocketAddr, Instant>,
) {
    let addr = node.address;
    let attempt = tokio::time::timeout(PROBE_TIMEOUT, transport.connect(addr));
    match attempt.await {
        Ok(Ok(conn)) => {
            let rtt = if speedtest_enabled {
                Some(conn.stats().path.rtt)
            } else {
                None
            };
            drop(conn);
            consecutive_failures.remove(&addr);
            scheduler
                .update_node_status(&addr, NodeStatus::Online)
                .await;
            info!("节点 {} 探测成功，恢复 Online", addr);
            if let Some(rtt) = rtt {
                // 刚恢复的节点先以实测 RTT 修正延迟，其余字段沿用静态值
                let (_, latency, loss_rate, load) =
                    merge_stats(node, Some(rtt), None, node.loss_rate);
                scheduler
                    .update_node_stats(&addr, node.bandwidth, latency, loss_rate, load)
                    .await;
            }
        }
        Ok(Err(e)) => {
            if speedtest_enabled {
                last_offline_event.insert(addr, Instant::now());
            }
            record_failure(scheduler, consecutive_failures, addr, &e.to_string()).await;
        }
        Err(_) => {
            if speedtest_enabled {
                last_offline_event.insert(addr, Instant::now());
            }
            record_failure(scheduler, consecutive_failures, addr, "探测超时").await;
        }
    }
}

/// 记录一次探测失败：累计连续失败数，达到阈值后保持 Offline 且日志降级防洪水
async fn record_failure(
    scheduler: &Scheduler,
    consecutive_failures: &mut HashMap<SocketAddr, u32>,
    addr: SocketAddr,
    reason: &str,
) {
    let count = {
        let c = consecutive_failures.entry(addr).or_insert(0);
        *c += 1;
        *c
    };
    if count < MAX_CONSECUTIVE_FAILURES {
        warn!(
            "节点 {} 探测失败（第 {} 次，{}），保持 Offline，将继续探测",
            addr, count, reason
        );
    } else {
        // 连续 3 次失败：确认 Offline，此后仅 debug 记录，避免日志洪水
        debug!(
            "节点 {} 连续 {} 次探测失败（{}），保持 Offline",
            addr, count, reason
        );
        scheduler
            .update_node_status(&addr, NodeStatus::Offline)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speedtest_enabled_default_and_zero_off() {
        // 进程级 env 断言放在单测：默认开启，显式 "0" 关闭，其余值开启
        std::env::remove_var(SPEEDTEST_ENV);
        assert!(speedtest_enabled_from_env(), "default must be enabled");
        std::env::set_var(SPEEDTEST_ENV, "0");
        assert!(!speedtest_enabled_from_env(), "0 must disable");
        std::env::set_var(SPEEDTEST_ENV, "1");
        assert!(speedtest_enabled_from_env(), "non-zero stays enabled");
        std::env::remove_var(SPEEDTEST_ENV);
    }

    #[test]
    fn test_throughput_mbps_conversion() {
        // 1MB over 1s = 8 Mbps（10^6 进制，与静态带宽同量纲）
        assert!((throughput_mbps(1_000_000, Duration::from_secs(1)) - 8.0).abs() < 1e-9);
        assert!((throughput_mbps(1_000_000, Duration::from_millis(500)) - 16.0).abs() < 1e-9);
        assert_eq!(throughput_mbps(0, Duration::from_secs(1)), 0.0);
    }

    /// 吞吐窗口差分：首样建基线；不足 1KB 保留基线跨窗口累计；达阈值给出读数并重置
    #[test]
    fn test_throughput_tracker_window_diff() {
        let mut t = ThroughputTracker::new();
        let t0 = Instant::now();
        assert_eq!(t.sample(t0, 0, 0), None, "first sample only sets baseline");
        assert_eq!(
            t.sample(t0 + Duration::from_millis(900), 500, 400),
            None,
            "below 1KB keeps accumulating"
        );
        // 跨窗口累计达 1024B：差分按基线而非上一窗口，慢流量不丢账
        let mbps = t.sample(t0 + Duration::from_millis(1900), 700, 1300);
        let expect = throughput_mbps(2000, Duration::from_millis(1900));
        assert!(mbps.is_some());
        assert!((mbps.unwrap() - expect).abs() < 1e-9);
        // 重置后新窗口：新增 <1KB 不更新
        assert_eq!(t.sample(t0 + Duration::from_millis(2400), 1000, 1400), None);
        // 单调计数回退（计数面重建）按 0 差分处理，不 panic 不误读
        assert_eq!(t.sample(t0 + Duration::from_millis(3400), 0, 0), None);
    }

    #[test]
    fn test_loss_decay_from_offline_event() {
        assert!((loss_from_offline_event(None) - BASE_LOSS_RATE).abs() < 1e-12);
        let peak = loss_from_offline_event(Some(Duration::ZERO));
        assert!(
            (peak - (BASE_LOSS_RATE + EVENT_LOSS_RATE)).abs() < 1e-12,
            "no decay at t=0"
        );
        // 衰减随时间单调下降，趋向基础值；永不超 1.0
        let mid = loss_from_offline_event(Some(Duration::from_secs(30)));
        assert!(mid < peak && mid > BASE_LOSS_RATE);
        assert!(loss_from_offline_event(Some(Duration::from_secs(3600))) < mid);
        assert!(loss_from_offline_event(Some(Duration::from_secs(0))) <= 1.0);
    }

    /// 评分混合策略：实测字段覆盖，未实测字段沿用静态初始值，load 不变
    #[test]
    fn test_merge_stats_mixed_strategy() {
        let old = NodeInfo {
            address: "127.0.0.1:1".parse().unwrap(),
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        };
        // 无实测数据：全部沿用静态初始值
        let (bw, lat, loss, load) = merge_stats(&old, None, None, BASE_LOSS_RATE);
        assert_eq!((bw, lat, load), (100.0, 10.0, 0.5));
        assert!((loss - BASE_LOSS_RATE).abs() < 1e-12);
        // 仅实测 RTT：带宽保持静态值
        let (bw, lat, _, _) = merge_stats(&old, Some(Duration::from_millis(23)), None, 0.02);
        assert_eq!(bw, 100.0);
        assert!((lat - 23.0).abs() < 1e-9);
        // 仅实测吞吐：延迟保持静态值
        let (bw, lat, _, _) = merge_stats(&old, None, Some(42.0), 0.02);
        assert!((bw - 42.0).abs() < 1e-12);
        assert_eq!(lat, 10.0);
    }
}
