//! 节点自动恢复探测（A2）+ 被动测速动态评分（WS-E）。
//!
//! 随 `ProxyServer::start` 常驻的后台任务：每 `HYDRA_PROBE_INTERVAL_SECS`
//! （默认 30，测试可设 1-2）±随机抖动做一轮探测：
//! - 非 Online 节点：完整链路探测（TCP + TLS + Noise-PSK + 地址帧 + 应答，
//!   `tokio::time::timeout(5s)` 外包）。成功 → 恢复 Online+日志；连续 3 次
//!   失败保持 Offline。
//! - Online 节点：同样纳入活性探测（09-P2-3：此前测速关闭时零活性探测，
//!   死节点恒被选中靠每连接失败转移兜底）；连续 3 次探测失败转 **Degraded**
//!   （下一轮起走恢复探测路径，成功即回 Online）。测速开启时顺带写回评分——
//!   延迟 = 完整探测链路总耗时；吞吐 = 该节点窗口期 relay 字节差分（被动，
//!   来自流量统计的按节点计数），窗口累计 ≥1KB 才更新否则保持旧值；
//!   loss ≈ 最近一次 Offline/探测失败事件的指数衰减。评分混合策略：无实测
//!   数据的字段沿用静态初始值。
//! - 探测含 Noise-PSK（09-P2-2）：认证面故障（PSK 错配/轮换不同步）在探测
//!   复现——此前探测只测 TCP+TLS，认证失败时恢复探测恒成功，节点在
//!   Online/Offline 间永久振荡。探测目标用 UDP 中继保留前缀（节点回 OK 后
//!   即收流清理，不产生真实转发）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use hydra_protocol::NodeInfo;
use hydra_protocol::NodeStatus;

use crate::scheduler::Scheduler;
use crate::traffic::TrafficMonitor;

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

/// 探测目标：UDP 中继保留前缀下的哑目标——节点完成 TCP+TLS+Noise-PSK 认证、
/// 回 2B OK 后即进入 UDP 中继服务等待帧；探测方读完应答立即弃流，节点侧
/// 读到 EOF 自行清理（09-P2-2：完整握手探测，认证面故障可在探测复现）。
const PROBE_TARGET: &str = "@udp-relay/hydra-probe";

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

/// 完整链路探测（09-P2-2）：TCP 建连 + TLS 握手 + Noise-PSK + 地址帧 + 应答。
/// 此前只测 TCP+TLS——认证面故障（PSK 错配）时探测恒成功而数据面恒失败，
/// 节点在 Online/Offline 间永久振荡；现探测与主链路同一条代码路径
/// （[`crate::tcp_transport::connect_target`]），返回总耗时。
async fn probe_connect(
    addr: SocketAddr,
    sni: &str,
    trust: &crate::tcp_transport::TlsTrust,
    auth_key: &[u8],
) -> std::result::Result<Duration, String> {
    let start = Instant::now();
    // 探测流在返回后立即 drop：节点侧 UDP 中继读到 EOF 自行清理
    let _tls = crate::tcp_transport::connect_target(addr, sni, trust, auth_key, PROBE_TARGET)
        .await
        .map_err(|e| e.to_string())?;
    Ok(start.elapsed())
}

/// 单轮探测的最大并发数（09-P3-7）：串行探测 N 个离线节点最坏 5N 秒/轮，
/// 超过探测间隔时背靠背不间断、恢复延迟随节点数线性增长。限流并发后单轮
/// 耗时 ≈ ⌈N/并发⌉ × 5s；评分/状态写回仍在单线程收敛（无共享可变状态）。
pub const MAX_CONCURRENT_PROBES: usize = 4;

/// 单次探测的网络部分（并发任务内执行；不带任何共享可变状态）。
#[derive(Debug)]
enum ProbeOutcome {
    Reachable(Duration),
    Failed(String),
    TimedOut,
}

async fn probe_node(
    addr: SocketAddr,
    sni: &str,
    trust: &crate::tcp_transport::TlsTrust,
    auth_key: &[u8],
) -> ProbeOutcome {
    match tokio::time::timeout(PROBE_TIMEOUT, probe_connect(addr, sni, trust, auth_key)).await {
        Ok(Ok(d)) => ProbeOutcome::Reachable(d),
        Ok(Err(e)) => ProbeOutcome::Failed(e),
        Err(_) => ProbeOutcome::TimedOut,
    }
}

/// 单次节点连通性探测（完整握手：TCP+TLS+Noise-PSK+地址帧+应答）。
/// Android 绑定层"测试连接/连通性自检"用——与数据面同路径，认证面故障
/// 同样可在探测复现。公开包装（probe_connect 为内部实现）。
pub async fn probe_node_once(
    addr: SocketAddr,
    sni: &str,
    trust: &crate::tcp_transport::TlsTrust,
    auth_key: &[u8],
) -> std::result::Result<Duration, String> {
    probe_connect(addr, sni, trust, auth_key).await
}

/// 启动常驻探测任务（随 ProxyServer::start 调用）。
///
/// 探测走完整链路（TCP+TLS+Noise-PSK，证书 pinning 与主链路一致）；`traffic`
/// 为中继计数同一实例，按节点字节计数是吞吐差分的数据源。任务永不返回，随 runtime 关闭而结束。
/// 每轮：并发探测（限流 [`MAX_CONCURRENT_PROBES`]）→ 单线程按序应用状态/评分。
pub fn spawn_recovery_probe(
    scheduler: Arc<Scheduler>,
    trust: crate::tcp_transport::TlsTrust,
    sni: String,
    auth_key: Arc<Vec<u8>>,
    traffic: Arc<TrafficMonitor>,
) {
    tokio::spawn(async move {
        let interval = probe_interval_from_env();
        let speedtest_enabled = speedtest_enabled_from_env();
        if speedtest_enabled {
            info!(
                "恢复探测器已启动（间隔 {}s±20% 抖动，单次超时 {}s，完整握手探测，并发 {}，测速评分开启）",
                interval.as_secs(),
                PROBE_TIMEOUT.as_secs(),
                MAX_CONCURRENT_PROBES
            );
        } else {
            info!(
                "恢复探测器已启动（间隔 {}s±20% 抖动，单次超时 {}s，完整握手探测，并发 {}，测速评分关闭）",
                interval.as_secs(),
                PROBE_TIMEOUT.as_secs(),
                MAX_CONCURRENT_PROBES
            );
        }
        let mut consecutive_failures: HashMap<SocketAddr, u32> = HashMap::new();
        let mut online_failures: HashMap<SocketAddr, u32> = HashMap::new();
        let mut last_offline_event: HashMap<SocketAddr, Instant> = HashMap::new();
        let mut throughput: HashMap<SocketAddr, ThroughputTracker> = HashMap::new();
        loop {
            // ±最多 20% 随机抖动（双向，纯正向只会拉长周期），避免整周期探测的被动特征
            let fifth = (interval.as_millis() as i64) / 5;
            let offset = rand::Rng::gen_range(&mut rand::thread_rng(), -fifth..=fifth);
            let sleep_ms = ((interval.as_millis() as i64) + offset).max(500) as u64;
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

            // ── 并发探测阶段：全部节点一起发探测，信号量限流 ──
            let nodes = scheduler.get_all_nodes().await;
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
            let mut set = tokio::task::JoinSet::new();
            for node in nodes {
                let sem = sem.clone();
                let trust = trust.clone();
                let sni = sni.clone();
                let auth_key = auth_key.clone();
                set.spawn(async move {
                    // permit 在探测全程持有（离开作用域自动释放）
                    let _permit = sem.acquire().await;
                    let outcome = probe_node(node.address, &sni, &trust, &auth_key).await;
                    (node, outcome)
                });
            }
            // ── 应用阶段：单线程按完成顺序收敛状态/评分（网络等待已全部并行）──
            while let Some(joined) = set.join_next().await {
                let (node, outcome) = match joined {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("探测任务 join 失败（忽略本轮该节点）: {e}");
                        continue;
                    }
                };
                if matches!(node.status, NodeStatus::Online) {
                    apply_online_probe(
                        &scheduler,
                        &traffic,
                        &node,
                        outcome,
                        speedtest_enabled,
                        &mut online_failures,
                        &mut last_offline_event,
                        &mut throughput,
                    )
                    .await;
                } else {
                    apply_offline_probe(
                        &scheduler,
                        &node,
                        outcome,
                        speedtest_enabled,
                        &mut consecutive_failures,
                        &mut last_offline_event,
                    )
                    .await;
                }
            }
        }
    });
}

/// Online 节点探测结果应用：连续失败达阈值转 Degraded；成功清除计数。
/// 测速开启时写回评分（主动完整握手时延 + 被动吞吐差分 + 衰减 loss）。
#[allow(clippy::too_many_arguments)]
async fn apply_online_probe(
    scheduler: &Scheduler,
    traffic: &TrafficMonitor,
    node: &NodeInfo,
    outcome: ProbeOutcome,
    speedtest_enabled: bool,
    online_failures: &mut HashMap<SocketAddr, u32>,
    last_offline_event: &mut HashMap<SocketAddr, Instant>,
    throughput: &mut HashMap<SocketAddr, ThroughputTracker>,
) {
    let addr = node.address;
    let rtt = match outcome {
        ProbeOutcome::Reachable(d) => {
            online_failures.remove(&addr);
            Some(d)
        }
        ProbeOutcome::Failed(e) => {
            let fails = online_failures.entry(addr).or_insert(0);
            *fails += 1;
            debug!("节点 {addr} 活性探测失败（第 {} 次）: {e}", *fails);
            if *fails >= MAX_CONSECUTIVE_FAILURES {
                warn!(
                    "节点 {addr} 连续 {} 次活性探测失败，转 Degraded（继续探测，成功即恢复）",
                    *fails
                );
                scheduler
                    .update_node_status(&addr, NodeStatus::Degraded)
                    .await;
                online_failures.remove(&addr);
                if speedtest_enabled {
                    last_offline_event.insert(addr, Instant::now());
                }
                return;
            }
            if speedtest_enabled {
                last_offline_event.insert(addr, Instant::now());
            }
            None
        }
        ProbeOutcome::TimedOut => {
            let fails = online_failures.entry(addr).or_insert(0);
            *fails += 1;
            if *fails >= MAX_CONSECUTIVE_FAILURES {
                warn!(
                    "节点 {addr} 连续 {} 次活性探测超时，转 Degraded（继续探测，成功即恢复）",
                    *fails
                );
                scheduler
                    .update_node_status(&addr, NodeStatus::Degraded)
                    .await;
                online_failures.remove(&addr);
                if speedtest_enabled {
                    last_offline_event.insert(addr, Instant::now());
                }
                return;
            }
            if speedtest_enabled {
                last_offline_event.insert(addr, Instant::now());
            }
            None
        }
    };

    // 测速评分（HYDRA_SPEEDTEST=0 时跳过，仅保留活性探测语义）
    if !speedtest_enabled {
        return;
    }
    // 被动吞吐：该节点窗口期 relay 字节差分（≥1KB 才更新，否则保持旧值）
    let entry = traffic.node_entry(addr);
    let measured_bw =
        throughput
            .entry(addr)
            .or_default()
            .sample(Instant::now(), entry.sent(), entry.received());

    // loss 近似：最近 Offline/探测失败事件的指数衰减
    let loss = loss_from_offline_event(last_offline_event.get(&addr).map(|t| t.elapsed()));

    // 混合写回：无实测字段沿用静态初始值
    let (bandwidth, latency, loss_rate, load) = merge_stats(node, rtt, measured_bw, loss);
    scheduler
        .update_node_stats(&addr, bandwidth, latency, loss_rate, load)
        .await;
    if rtt.is_some() || measured_bw.is_some() {
        let score = bandwidth * 0.5 - latency * 0.3 - loss_rate * 0.2;
        info!(
            "节点 {addr} 测速写回：rtt {}ms，吞吐 {:.1}Mbps，loss {:.3}，评分 {:.1}",
            rtt.map_or(-1.0, |d| d.as_secs_f64() * 1000.0),
            measured_bw.unwrap_or(-1.0),
            loss_rate,
            score
        );
    } else {
        debug!("节点 {addr} 本窗口无实测数据，仅 loss 衰减写回（{loss:.3}）");
    }
}

/// 非 Online 节点探测结果应用（A2 恢复语义）；测速开启时以实测时延更新延迟。
async fn apply_offline_probe(
    scheduler: &Scheduler,
    node: &NodeInfo,
    outcome: ProbeOutcome,
    speedtest_enabled: bool,
    consecutive_failures: &mut HashMap<SocketAddr, u32>,
    last_offline_event: &mut HashMap<SocketAddr, Instant>,
) {
    let addr = node.address;
    match outcome {
        ProbeOutcome::Reachable(rtt) => {
            let rtt = if speedtest_enabled { Some(rtt) } else { None };
            consecutive_failures.remove(&addr);
            scheduler
                .update_node_status(&addr, NodeStatus::Online)
                .await;
            info!("节点 {addr} 探测成功，恢复 Online");
            if let Some(rtt) = rtt {
                // 刚恢复的节点先以实测 RTT 修正延迟，其余字段沿用静态值
                let (_, latency, loss_rate, load) =
                    merge_stats(node, Some(rtt), None, node.loss_rate);
                scheduler
                    .update_node_stats(&addr, node.bandwidth, latency, loss_rate, load)
                    .await;
            }
        }
        ProbeOutcome::Failed(e) => {
            if speedtest_enabled {
                last_offline_event.insert(addr, Instant::now());
            }
            record_failure(scheduler, consecutive_failures, addr, &e).await;
        }
        ProbeOutcome::TimedOut => {
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
