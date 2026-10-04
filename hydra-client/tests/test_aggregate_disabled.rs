//! V3.3 方案 B 集成测试——聚合默认关闭态（验收③）。
//! 独立测试二进制：进程内统一 force_aggregate(false)，与启用态测试文件隔离。

mod common;

use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn served_of(addr: std::net::SocketAddr) -> u64 {
    hydra_client::aggregate::aggregate_served_counts()
        .get(&addr)
        .copied()
        .unwrap_or(0)
}

/// 验收③：未启用聚合（默认）→ 行为与现状完全一致：
/// - 全部连接走评分最高节点（get_nodes_by_priority 首位），第二节点零流量；
/// - 零分发决策记录（聚合从未介入候选选择）；
/// - 数据路径不变：64KB 载荷逐字节往返。
/// （全量既有回归套件不设 HYDRA_AGGREGATE，共同保障"未启用时代码路径与现在一致"。）
#[tokio::test]
async fn test_aggregate_disabled_keeps_single_node_path() -> Result<()> {
    hydra_client::aggregate::force_aggregate(false);
    assert!(!hydra_client::aggregate::aggregate_enabled());

    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;
    let target = format!("127.0.0.1:{}", echo_port);

    // 小消息多次往返
    const N: usize = 6;
    for i in 0..N {
        let msg = format!("default-path-{}", i);
        let mut s = common::socks5_connect(proxy_addr, &target).await?;
        s.write_all(msg.as_bytes()).await?;
        let mut buf = vec![0u8; msg.len()];
        s.read_exact(&mut buf).await?;
        assert_eq!(buf, msg.as_bytes(), "echo mismatch for {:?}", msg);
    }

    // 64KB 载荷逐字节往返（与 test_full_multipath 同规格）
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    s.write_all(&payload).await?;
    let mut received = vec![0u8; payload.len()];
    s.read_exact(&mut received).await?;
    assert_eq!(received, payload);

    // 断言：行为与现状一致
    // 1) 零分发决策（聚合从未介入）
    assert!(
        hydra_client::aggregate::aggregate_dispatch_counts().is_empty(),
        "no dispatch decisions may be recorded while aggregation is disabled"
    );
    // 2) 全部连接由评分最高的节点1承接，节点2 零流量
    assert_eq!(
        served_of(node1.addr),
        (N + 1) as u64,
        "all connections must go to the highest-score node (unchanged behavior)"
    );
    assert_eq!(
        served_of(node2.addr),
        0,
        "second node must receive no traffic while aggregation is disabled"
    );

    Ok(())
}
