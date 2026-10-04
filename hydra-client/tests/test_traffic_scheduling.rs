//! WS-E：流量统计接线 + 被动测速动态调度 集成测试。
//!
//! 1. 流量计数 E2E：经节点中继传输已知字节数后，全局 TrafficMonitor 与按节点
//!    计数条目与实际字节数一致（±小余量；SOCKS5/QUIC 握手字节不在计数面内）。
//! 2. 测速写回冒烟：探测周期后节点评分字段由静态初始值变为实测值
//!    （延迟 = QUIC path RTT，吞吐 = 中继字节窗口差分）；
//!    update_node_stats 注入后 get_best_node 动态换位，且后续流量实际路由到新节点。

mod common;

use std::time::Duration;

use hydra_protocol::{NodeStatus, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD_LEN: usize = 64 * 1024;

/// 容忍窗口：握手/分块不产生计数偏差，仅留少量余量防偶发重连
fn counted_within(actual: u64, expect: u64) -> bool {
    actual >= expect && actual <= expect + 2048
}

/// 流量统计 E2E：64KB 经节点中继往返 → 全局与按节点计数一致，直连计数面不归属节点
#[tokio::test]
async fn test_traffic_monitor_counts_relay_bytes() -> Result<()> {
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let (proxy_addr, _proxy, monitor) =
        common::spawn_proxy_with_monitor(vec![(node.addr, node.cert.clone())]).await;
    let target = format!("127.0.0.1:{}", echo_port);

    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    s.write_all(&payload).await?;
    let mut got = vec![0u8; PAYLOAD_LEN];
    s.read_exact(&mut got).await?;
    assert_eq!(got, payload, "echo must round-trip byte-identical");
    drop(s);

    // 等中继任务完全收敛，计数无残余
    for _ in 0..50 {
        if hydra_client::active_relay_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let stats = monitor.get_stats().await;
    assert!(
        counted_within(stats.bytes_sent, PAYLOAD_LEN as u64),
        "monitor up {} must equal relayed payload {}",
        stats.bytes_sent,
        PAYLOAD_LEN
    );
    assert!(
        counted_within(stats.bytes_received, PAYLOAD_LEN as u64),
        "monitor down {} must equal relayed payload {}",
        stats.bytes_received,
        PAYLOAD_LEN
    );

    // 按节点条目：节点路径的上下行都归属该节点
    let per_node = monitor.node_traffic_snapshot();
    assert_eq!(
        per_node.len(),
        1,
        "only the serving node must have an entry"
    );
    let (addr, sent, received) = per_node[0];
    assert_eq!(addr, node.addr, "entry must be keyed by node address");
    assert!(
        counted_within(sent, PAYLOAD_LEN as u64),
        "node up {} mismatch",
        sent
    );
    assert!(
        counted_within(received, PAYLOAD_LEN as u64),
        "node down {} mismatch",
        received
    );
    Ok(())
}

/// 测速写回 + 动态调度冒烟（env 断言与主流程合并串行执行，避免并行 env 竞争）
#[tokio::test]
async fn test_speedtest_updates_scheduler_and_routing() -> Result<()> {
    // HYDRA_SPEEDTEST 开关：默认开启，"0" 关闭（其余值开启）
    std::env::remove_var("HYDRA_SPEEDTEST");
    assert!(
        hydra_client::speedtest_enabled_from_env(),
        "speedtest must default to enabled"
    );
    std::env::set_var("HYDRA_SPEEDTEST", "0");
    assert!(!hydra_client::speedtest_enabled_from_env());
    std::env::remove_var("HYDRA_SPEEDTEST");

    // 短探测周期用于主流程
    std::env::set_var("HYDRA_PROBE_INTERVAL_SECS", "1");

    let node_a = common::spawn_node().await;
    let node_b = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let (proxy_addr, proxy, monitor) = common::spawn_proxy_with_monitor(vec![
        (node_a.addr, node_a.cert.clone()),
        (node_b.addr, node_b.cert.clone()),
    ])
    .await;
    let scheduler = proxy.scheduler();
    let target = format!("127.0.0.1:{}", echo_port);

    let node_stats = |nodes: &[hydra_protocol::NodeInfo], addr| {
        nodes
            .iter()
            .find(|n| n.address == addr)
            .map(|n| (n.bandwidth, n.latency))
            .expect("node not found")
    };

    // 1. 初始静态评分：A 带宽 100 > B 90，best = A
    assert_eq!(
        scheduler.get_best_node().await.unwrap().address,
        node_a.addr
    );

    // 2. 先做一次小传输预热链路，等待探测周期把 A 的延迟写回为实测 RTT（≠初始 10.0）
    {
        let mut s = common::socks5_connect(proxy_addr, &target).await?;
        s.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await?;
    }
    let mut latency_updated = false;
    for _ in 0..80 {
        let (bw, lat) = node_stats(&scheduler.get_all_nodes().await, node_a.addr);
        if lat != 10.0 {
            latency_updated = true;
            assert_eq!(
                bw, 100.0,
                "no qualifying traffic yet, bandwidth stays static"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        latency_updated,
        "probe cycle must write back measured rtt to node A latency"
    );

    // 3. 传输 64KB（首个探测周期已建立吞吐基线）→ 窗口差分 ≥1KB → 带宽由静态 100 变实测
    {
        let mut s = common::socks5_connect(proxy_addr, &target).await?;
        let payload = vec![7u8; PAYLOAD_LEN];
        s.write_all(&payload).await?;
        let mut got = vec![0u8; PAYLOAD_LEN];
        s.read_exact(&mut got).await?;
    }
    let mut bandwidth_updated = false;
    for _ in 0..80 {
        let (bw, _) = node_stats(&scheduler.get_all_nodes().await, node_a.addr);
        if bw != 100.0 {
            assert!(
                bw > 0.0 && bw < 100.0,
                "measured loopback throughput should be a positive value, got {}",
                bw
            );
            bandwidth_updated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        bandwidth_updated,
        "window diff of relayed bytes must update node A bandwidth"
    );

    // 4. 注入 B 高带宽实测值 → get_best_node 动态换位到 B
    scheduler
        .update_node_stats(&node_b.addr, 1000.0, 5.0, 0.01, 0.5)
        .await;
    assert_eq!(
        scheduler.get_best_node().await.unwrap().address,
        node_b.addr,
        "best node must follow measured score"
    );

    // 5. 调度真正生效：新连接路由到 B，B 的按节点计数增长
    {
        let mut s = common::socks5_connect(proxy_addr, &target).await?;
        s.write_all(b"routed-via-b").await?;
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await?;
    }
    let mut b_served = false;
    for _ in 0..50 {
        if let Some((_, _, received)) = monitor
            .node_traffic_snapshot()
            .into_iter()
            .find(|(a, _, _)| *a == node_b.addr)
        {
            if received > 0 {
                b_served = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(b_served, "traffic after score flip must route via node B");

    // 6. 探测/测速不得误降节点状态
    for addr in [node_a.addr, node_b.addr] {
        assert!(
            scheduler
                .get_all_nodes()
                .await
                .iter()
                .any(|n| n.address == addr && matches!(n.status, NodeStatus::Online)),
            "node {} must stay Online",
            addr
        );
    }

    std::env::remove_var("HYDRA_PROBE_INTERVAL_SECS");
    Ok(())
}
