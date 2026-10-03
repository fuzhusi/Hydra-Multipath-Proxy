mod common;

use hydra_client::Scheduler;
use hydra_protocol::{NodeInfo, NodeStatus, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 端到端：两个节点同时在线，请求经代理正常建立并传输
#[tokio::test]
async fn test_multipath_connection() -> Result<()> {
    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;

    let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;
    s.write_all(b"multipath").await?;
    let mut buf = [0u8; 9];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"multipath");

    Ok(())
}

#[tokio::test]
async fn test_node_selection() -> Result<()> {
    let scheduler = Scheduler::new();

    // 添加节点
    scheduler.add_node(NodeInfo {
        address: "127.0.0.1:8081".parse().unwrap(),
        bandwidth: 100.0,
        latency: 10.0,
        loss_rate: 0.01,
        load: 0.5,
        status: NodeStatus::Online,
    }).await;

    scheduler.add_node(NodeInfo {
        address: "127.0.0.1:8082".parse().unwrap(),
        bandwidth: 80.0,
        latency: 15.0,
        loss_rate: 0.02,
        load: 0.3,
        status: NodeStatus::Online,
    }).await;

    scheduler.add_node(NodeInfo {
        address: "127.0.0.1:8083".parse().unwrap(),
        bandwidth: 120.0,
        latency: 20.0,
        loss_rate: 0.03,
        load: 0.7,
        status: NodeStatus::Online,
    }).await;

    // 测试节点选择
    let best_node = scheduler.get_best_node().await.unwrap();
    println!("Best node: {}", best_node.address);

    // 验证选择的是评分最高的节点
    let score1 = 100.0 * 0.5 - 10.0 * 0.3 - 0.01 * 0.2;
    let score2 = 80.0 * 0.5 - 15.0 * 0.3 - 0.02 * 0.2;
    let score3 = 120.0 * 0.5 - 20.0 * 0.3 - 0.03 * 0.2;

    println!("Node scores: {}, {}, {}", score1, score2, score3);

    // 验证选择了正确的节点（分数最高的节点）
    assert_eq!(best_node.address, "127.0.0.1:8083".parse::<SocketAddr>()?);

    Ok(())
}
