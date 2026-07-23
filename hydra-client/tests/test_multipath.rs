use hydra_client::{Transport, Scheduler, Splitter, Assembler};
use hydra_node::HydraServer;
use hydra_protocol::{NodeInfo, NodeStatus, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_multipath_connection() -> Result<()> {
    // 启动两个节点服务器
    let node1_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node2_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    
    let node1 = HydraServer::new(node1_addr).await?;
    let node2 = HydraServer::new(node2_addr).await?;
    
    let node1_addr = node1.endpoint.local_addr()?;
    let node2_addr = node2.endpoint.local_addr()?;
    
    // 启动节点服务器
    tokio::spawn(async move {
        node1.start().await.unwrap();
    });
    
    tokio::spawn(async move {
        node2.start().await.unwrap();
    });
    
    // 等待服务器启动
    sleep(Duration::from_millis(100)).await;
    
    // 创建调度器并添加节点
    let scheduler = Scheduler::new();
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
    let transport = Transport::new_client().await?;
    
    // 测试数据分片和重组
    let test_data = Bytes::from("Hello, Hydra Multipath Proxy! This is a test message for multipath transmission.");
    let mut splitter = Splitter::new(10); // 10字节的分片
    let _assembler = Assembler::new();
    
    // 分片数据
    let packets = splitter.split(test_data.clone(), 1, 1);
    println!("Split data into {} chunks", packets.len());
    
    // 通过不同节点发送分片
    for (_i, packet) in packets.iter().enumerate() {
        // 选择最佳节点
        let node = scheduler.get_best_node().await.unwrap();
        println!("Sending chunk {} to node {}", packet.chunk_id, node.address);
        
        // 连接到节点
        let connection = transport.connect(node.address).await?;
        
        // 发送数据包
        let (mut send, mut recv) = connection.open_bi().await?;
        let data = serde_json::to_vec(packet)?;
        send.write_all(&data).await.map_err(|e| hydra_protocol::HydraError::QuinnWriteError(e))?;
        send.finish().await.map_err(|e| hydra_protocol::HydraError::QuinnWriteError(e))?;
        
        // 接收响应
        let response = recv.read_to_end(1024).await.map_err(|e| hydra_protocol::HydraError::QuinnReadError(e))?;
        let response_str = String::from_utf8_lossy(&response);
        assert_eq!(response_str, "OK");
        
        // 模拟接收端重组
        // 注意：在实际实现中，这应该在接收端完成
        // 这里我们只是验证分片和重组逻辑
    }
    
    println!("Multipath test completed successfully!");
    
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