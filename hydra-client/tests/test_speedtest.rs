use hydra_client::{Scheduler, Speedtest, Transport};
use hydra_node::HydraServer;
use hydra_protocol::{NodeInfo, NodeStatus, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_speedtest() -> Result<()> {
    // 启动一个节点服务器
    let node_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node = HydraServer::new(node_addr).await?;
    let node_addr = node.endpoint.local_addr()?;
    
    // 启动节点服务器
    tokio::spawn(async move {
        node.start().await.unwrap();
    });
    
    // 等待服务器启动
    sleep(Duration::from_millis(100)).await;
    
    // 创建调度器并添加节点
    let scheduler = Arc::new(Scheduler::new());
    scheduler.add_node(NodeInfo {
        address: node_addr,
        bandwidth: 100.0,
        latency: 10.0,
        loss_rate: 0.01,
        load: 0.5,
        status: NodeStatus::Online,
    }).await;
    
    // 创建传输层
    let transport = Arc::new(Transport::new_client().await?);
    
    // 创建测速器
    let speedtest = Speedtest::new(
        scheduler.clone(),
        transport.clone(),
        Duration::from_secs(1), // 每秒测速一次
    );
    
    // 启动测速器
    let speedtest_handle = tokio::spawn(async move {
        speedtest.start().await;
    });
    
    // 等待测速完成
    sleep(Duration::from_secs(2)).await;
    
    // 检查节点统计信息是否更新
    let nodes = scheduler.get_all_nodes().await;
    let node = nodes.first().unwrap();
    
    println!("Node stats after speedtest:");
    println!("  Bandwidth: {}", node.bandwidth);
    println!("  Latency: {}", node.latency);
    println!("  Loss rate: {}", node.loss_rate);
    println!("  Load: {}", node.load);
    println!("  Status: {:?}", node.status);
    
    // 停止测速器
    speedtest_handle.abort();
    
    Ok(())
}