use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use hydra_protocol::{NodeInfo, NodeStatus};
use crate::scheduler::Scheduler;
use crate::transport::Transport;
use tracing::{info, warn, error};
use bytes::Bytes;
use serde_json;

pub struct Speedtest {
    scheduler: Arc<Scheduler>,
    transport: Arc<Transport>,
    interval: Duration,
}

impl Speedtest {
    pub fn new(scheduler: Arc<Scheduler>, transport: Arc<Transport>, interval: Duration) -> Self {
        Self {
            scheduler,
            transport,
            interval,
        }
    }

    pub async fn start(&self) {
        loop {
            self.measure_all_nodes().await;
            sleep(self.interval).await;
        }
    }

    async fn measure_all_nodes(&self) {
        let nodes = self.scheduler.get_all_nodes().await;
        
        for node in nodes {
            let scheduler = self.scheduler.clone();
            let transport = self.transport.clone();
            
            tokio::spawn(async move {
                info!("Measuring node {}", node.address);
                match Self::measure_node(&transport, &node.address).await {
                    Ok(stats) => {
                        info!("Node {} measured: bandwidth={}, latency={}, loss={}", 
                              node.address, stats.bandwidth, stats.latency, stats.loss_rate);
                        
                        scheduler.update_node_stats(
                            &node.address,
                            stats.bandwidth,
                            stats.latency,
                            stats.loss_rate,
                            stats.load,
                        ).await;
                        
                        // 根据测量结果更新节点状态
                        let status = if stats.loss_rate > 0.1 || stats.latency > 1000.0 {
                            NodeStatus::Degraded
                        } else {
                            NodeStatus::Online
                        };
                        
                        scheduler.update_node_status(&node.address, status).await;
                    }
                    Err(e) => {
                        warn!("Failed to measure node {}: {}", node.address, e);
                        // 连接失败，标记节点为离线
                        scheduler.mark_node_offline(&node.address).await;
                    }
                }
            });
        }
    }

    async fn measure_node(transport: &Transport, addr: &std::net::SocketAddr) -> Result<NodeStats, Box<dyn std::error::Error + Send + Sync>> {
        // 简单的测速实现：发送一个测试包并测量响应时间
        let start = std::time::Instant::now();
        
        // 连接到节点
        let connection = transport.connect(*addr).await?;
        
        // 创建测试数据包
        let test_packet = hydra_protocol::Packet::new(
            0, // session_id
            0, // stream_id
            0, // chunk_id
            0, // offset
            bytes::Bytes::from("speedtest"),
        );
        let data = serde_json::to_vec(&test_packet)?;
        
        // 发送测试数据包
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&data).await?;
        send.finish().await?;
        
        // 接收响应
        let _response = recv.read_to_end(1024).await?;
        
        let latency = start.elapsed().as_millis() as f64;
        
        // 简单的带宽估算（基于响应时间）
        // 在实际实现中，应该发送更大的数据包并测量传输时间
        let bandwidth = 1000.0 / latency; // 简单估算
        
        Ok(NodeStats {
            bandwidth,
            latency,
            loss_rate: 0.0, // 简化实现
            load: 0.5,      // 简化实现
        })
    }
}

struct NodeStats {
    bandwidth: f64,
    latency: f64,
    loss_rate: f64,
    load: f64,
}