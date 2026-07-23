use hydra_client::{Scheduler, Speedtest, Transport};
use hydra_node::HydraServer;
use hydra_protocol::{NodeInfo, NodeStatus, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::info;

#[tokio::test]
async fn test_failover() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();
    
    // 启动两个节点服务器
    let node1_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node2_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    
    let node1 = HydraServer::new(node1_addr).await?;
    let node2 = HydraServer::new(node2_addr).await?;
    
    let node1_addr = node1.endpoint.local_addr()?;
    let node2_addr = node2.endpoint.local_addr()?;
    
    // 启动节点服务器
    let node1_handle = tokio::spawn(async move {
        node1.start().await.unwrap();
    });
    
    let node2_handle = tokio::spawn(async move {
        node2.start().await.unwrap();
    });
    
    // 等待服务器启动
    sleep(Duration::from_millis(100)).await;
    
    // 创建调度器并添加节点
    let scheduler = Arc::new(Scheduler::new());
    scheduler.add_node(NodeInfo {
        address: node1_addr,
        bandwidth: 100.0,
        latency: 10.0,
        loss_rate: 0.01,
        load: 0.5,
        status: NodeStatus::Online,
    }).await;
    
    scheduler.add_node(NodeInfo {
        address: node2_addr,
        bandwidth: 80.0,
        latency: 15.0,
        loss_rate: 0.02,
        load: 0.3,
        status: NodeStatus::Online,
    }).await;
    
    // 创建传输层
    let transport = Arc::new(Transport::new_client().await?);
    
    // 创建测速器
    let speedtest = Speedtest::new(
        scheduler.clone(),
        transport.clone(),
        Duration::from_secs(1),
    );
    
    // 启动测速器
    let speedtest_handle = tokio::spawn(async move {
        speedtest.start().await;
    });
    
    // 等待测速器启动并完成第一次测速
    sleep(Duration::from_secs(3)).await;
    
    // 检查节点状态
    let nodes = scheduler.get_all_nodes().await;
    println!("Initial node states:");
    for node in &nodes {
        println!("  {}: {:?}", node.address, node.status);
    }
    
    // 模拟节点1故障（停止节点1）
    node1_handle.abort();
    println!("Node 1 stopped");
    
    // 等待测速器检测到节点故障（增加等待时间）
    sleep(Duration::from_secs(15)).await;
    
    // 检查节点状态
    let nodes = scheduler.get_all_nodes().await;
    println!("Node states after node 1 failure:");
    for node in &nodes {
        println!("  {}: {:?}", node.address, node.status);
    }
    
    // 验证节点1被标记为离线
    let node1 = nodes.iter().find(|n| n.address == node1_addr).unwrap();
    assert!(matches!(node1.status, NodeStatus::Offline));
    
    // 验证节点2仍然在线
    let node2 = nodes.iter().find(|n| n.address == node2_addr).unwrap();
    assert!(matches!(node2.status, NodeStatus::Online));
    
    // 验证调度器能够选择在线的节点
    let best_node = scheduler.get_best_node().await.unwrap();
    assert_eq!(best_node.address, node2_addr);
    
    // 停止测速器
    speedtest_handle.abort();
    
    // 停止节点2
    node2_handle.abort();
    
    Ok(())
}