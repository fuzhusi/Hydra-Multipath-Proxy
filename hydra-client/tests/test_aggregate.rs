//! V3.3 方案 B（连接级多路径分发）集成测试——聚合启用态。
//! 本文件内所有测试统一 force_aggregate(true)（进程级开关，二进制内一致）；
//! 统计断言按节点地址隔离，测试间互不干扰。

mod common;

use hydra_protocol::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn served_of(addr: std::net::SocketAddr) -> u64 {
    hydra_client::aggregate::aggregate_served_counts()
        .get(&addr)
        .copied()
        .unwrap_or(0)
}

fn dispatched_of(addr: std::net::SocketAddr) -> u64 {
    hydra_client::aggregate::aggregate_dispatch_counts()
        .get(&addr)
        .copied()
        .unwrap_or(0)
}

async fn echo_round_trip(proxy_addr: std::net::SocketAddr, target: &str, msg: &str) -> Result<()> {
    let mut s = common::socks5_connect(proxy_addr, target).await?;
    s.write_all(msg.as_bytes()).await?;
    let mut buf = vec![0u8; msg.len()];
    s.read_exact(&mut buf).await?;
    assert_eq!(buf, msg.as_bytes(), "echo mismatch for {:?}", msg);
    Ok(())
}

/// 验收①：HYDRA_AGGREGATE=1 + 2 个 Online 节点 → 连接按评分加权分发到两节点，
/// 两节点都实际收到并承接流量（评分加权 51/49，24 连接全落单侧概率 ~1e-7 量级）。
#[tokio::test]
async fn test_aggregate_weighted_dispatch() -> Result<()> {
    hydra_client::aggregate::force_aggregate(true);
    assert!(hydra_client::aggregate::aggregate_enabled());

    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;
    let target = format!("127.0.0.1:{}", echo_port);

    const N: usize = 24;
    for i in 0..N {
        echo_round_trip(proxy_addr, &target, &format!("aggregate-conn-{}", i)).await?;
    }

    // 每个连接恰好由一个节点成功承接
    let served1 = served_of(node1.addr);
    let served2 = served_of(node2.addr);
    assert_eq!(
        served1 + served2,
        N as u64,
        "each connection must be served by exactly one node"
    );
    // 两个节点都收到流量（连接级加权分发生效）
    assert!(
        served1 > 0 && served2 > 0,
        "both nodes must receive traffic, got {}/{}",
        served1,
        served2
    );
    // 每个连接都产生一次分发决策
    let d1 = dispatched_of(node1.addr);
    let d2 = dispatched_of(node2.addr);
    assert_eq!(
        d1 + d2,
        N as u64,
        "every connection must make a dispatch decision"
    );

    Ok(())
}

/// 验收②：聚合中杀 1 节点 → 新连接全部由存活节点承接，传输不中断；
/// 被杀节点不再承接任何新连接。
#[tokio::test]
async fn test_aggregate_failover_on_node_kill() -> Result<()> {
    hydra_client::aggregate::force_aggregate(true);

    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;
    let target = format!("127.0.0.1:{}", echo_port);

    // 杀节点前：正常分发与传输
    for i in 0..4 {
        echo_round_trip(proxy_addr, &target, &format!("pre-kill-{}", i)).await?;
    }
    let served1_pre = served_of(node1.addr);
    let served2_pre = served_of(node2.addr);
    assert_eq!(served1_pre + served2_pre, 4, "pre-kill baseline");

    // 杀死节点1（关闭其 QUIC endpoint：拒绝新连接并断开存量连接）
    node1.endpoint.close(0u32.into(), b"test shutdown");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 新连接全部成功（传输不中断），且全部由存活的节点2承接
    const N: usize = 8;
    for i in 0..N {
        echo_round_trip(proxy_addr, &target, &format!("post-kill-{}", i)).await?;
    }
    assert_eq!(
        served_of(node1.addr),
        served1_pre,
        "killed node must not serve any new connection"
    );
    assert_eq!(
        served_of(node2.addr) - served2_pre,
        N as u64,
        "all post-kill connections must be served by the surviving node"
    );

    Ok(())
}
