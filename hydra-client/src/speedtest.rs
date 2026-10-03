//! Offline 节点自动恢复探测（A2）。
//!
//! 随 `ProxyServer::start` 常驻的后台任务：每 `HYDRA_PROBE_INTERVAL_SECS`
//! （默认 30，测试可设 1-2）±随机抖动，对非 Online 节点做 QUIC connect 探测
//! （`tokio::time::timeout(5s)` 外包，不动 transport.rs）。成功 → 恢复 Online+日志；
//! 连续 3 次失败保持 Offline。
//!
//! 完整测速（带宽/延迟评分）显式推迟至 WS-E / V3.3——现阶段评分维持静态初始值。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use hydra_protocol::NodeStatus;

use crate::scheduler::Scheduler;
use crate::transport::Transport;

/// 单次探测超时（由 tokio::time::timeout 外包；不影响 transport.rs）
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// 连续失败达此次数后，仅以 debug 级记录后续失败（节点保持 Offline）
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// 探测间隔环境变量
pub const PROBE_INTERVAL_ENV: &str = "HYDRA_PROBE_INTERVAL_SECS";
/// 默认探测间隔（秒）
pub const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;

/// 读取探测间隔：`HYDRA_PROBE_INTERVAL_SECS`，默认 30；非法值回退默认，clamp 到 1..=3600 秒
pub fn probe_interval_from_env() -> Duration {
    let secs = std::env::var(PROBE_INTERVAL_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROBE_INTERVAL_SECS);
    Duration::from_secs(secs.clamp(1, 3600))
}

/// 启动常驻恢复探测任务（随 ProxyServer::start 调用）。
///
/// 探测用独立 Transport（证书 pinning 与主链路一致）；节点 Online 后由正常流量
/// 经连接池重新建连。任务永不返回，随 runtime 关闭而结束。
pub fn spawn_recovery_probe(scheduler: Arc<Scheduler>, node_certs: Vec<Vec<u8>>, sni: String) {
    tokio::spawn(async move {
        let interval = probe_interval_from_env();
        let transport = match Transport::new_client(node_certs, &sni).await {
            Ok(t) => t,
            Err(e) => {
                warn!("恢复探测器启动失败（无法创建传输）: {}", e);
                return;
            }
        };
        info!(
            "恢复探测器已启动（间隔 {}s±20% 抖动，单次超时 {}s）",
            interval.as_secs(),
            PROBE_TIMEOUT.as_secs()
        );
        let mut consecutive_failures: HashMap<SocketAddr, u32> = HashMap::new();
        loop {
            // ±最多 20% 随机抖动（双向，纯正向只会拉长周期），避免整周期探测的被动特征
            let fifth = (interval.as_millis() as i64) / 5;
            let offset = rand::Rng::gen_range(&mut rand::thread_rng(), -fifth..=fifth);
            let sleep_ms = ((interval.as_millis() as i64) + offset).max(500) as u64;
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

            for node in scheduler.get_all_nodes().await {
                // 只探测非 Online 节点
                if matches!(node.status, NodeStatus::Online) {
                    continue;
                }
                let attempt = tokio::time::timeout(PROBE_TIMEOUT, transport.connect(node.address));
                match attempt.await {
                    Ok(Ok(conn)) => {
                        drop(conn);
                        consecutive_failures.remove(&node.address);
                        scheduler
                            .update_node_status(&node.address, NodeStatus::Online)
                            .await;
                        info!("节点 {} 探测成功，恢复 Online", node.address);
                    }
                    Ok(Err(e)) => {
                        record_failure(
                            &scheduler,
                            &mut consecutive_failures,
                            node.address,
                            &e.to_string(),
                        )
                        .await;
                    }
                    Err(_) => {
                        record_failure(
                            &scheduler,
                            &mut consecutive_failures,
                            node.address,
                            "探测超时",
                        )
                        .await;
                    }
                }
            }
        }
    });
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
