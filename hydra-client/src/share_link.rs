use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hydra_protocol::{NodeInfo, NodeStatus, Result, HydraError};

/// Hydra节点分享链接格式
/// 
/// 格式: hydra://address:port?bandwidth=100&latency=10&loss_rate=0.01&status=online&load=0.5
/// 
/// 参数说明:
/// - address: 节点地址
/// - port: 节点端口
/// - bandwidth: 带宽 (Mbps)
/// - latency: 延迟 (ms)
/// - loss_rate: 丢包率 (0-1)
/// - load: 负载 (0-1)
/// - status: 节点状态 (online/degraded/offline)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLink {
    pub address: String,
    pub port: u16,
    pub bandwidth: f64,
    pub latency: f64,
    pub loss_rate: f64,
    pub load: f64,
    pub status: NodeStatus,
}

impl ShareLink {
    pub fn new(node_info: &NodeInfo) -> Self {
        Self {
            address: node_info.address.ip().to_string(),
            port: node_info.address.port(),
            bandwidth: node_info.bandwidth,
            latency: node_info.latency,
            loss_rate: node_info.loss_rate,
            load: node_info.load,
            status: node_info.status.clone(),
        }
    }

    pub fn from_node_info(node_info: &NodeInfo) -> Self {
        Self::new(node_info)
    }

    pub fn to_node_info(&self) -> Result<NodeInfo> {
        let address: SocketAddr = format!("{}:{}", self.address, self.port)
            .parse()
            .map_err(|e| HydraError::AddrParseError(e))?;

        Ok(NodeInfo {
            address,
            bandwidth: self.bandwidth,
            latency: self.latency,
            loss_rate: self.loss_rate,
            load: self.load,
            status: self.status.clone(),
        })
    }

    pub fn to_share_url(&self) -> String {
        let status_str = match self.status {
            NodeStatus::Online => "online",
            NodeStatus::Degraded => "degraded",
            NodeStatus::Offline => "offline",
        };

        format!(
            "hydra://{}:{}?bandwidth={}&latency={}&loss_rate={}&load={}&status={}",
            self.address, self.port, self.bandwidth, self.latency, self.loss_rate, self.load, status_str
        )
    }

    pub fn from_share_url(url: &str) -> Result<Self> {
        let url = Url::parse(url)
            .map_err(|e| HydraError::ProtocolError(format!("Invalid URL: {}", e)))?;

        if url.scheme() != "hydra" {
            return Err(HydraError::ProtocolError("Invalid scheme, expected 'hydra'".to_string()));
        }

        let address = url.host_str()
            .ok_or_else(|| HydraError::ProtocolError("Missing host".to_string()))?
            .to_string();

        let port = url.port()
            .ok_or_else(|| HydraError::ProtocolError("Missing port".to_string()))?;

        let mut bandwidth = 100.0;
        let mut latency = 10.0;
        let mut loss_rate = 0.01;
        let mut load = 0.5;
        let mut status = NodeStatus::Online;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "bandwidth" => {
                    bandwidth = value.parse::<f64>()
                        .map_err(|e| HydraError::ProtocolError(format!("Invalid bandwidth: {}", e)))?;
                }
                "latency" => {
                    latency = value.parse::<f64>()
                        .map_err(|e| HydraError::ProtocolError(format!("Invalid latency: {}", e)))?;
                }
                "loss_rate" => {
                    loss_rate = value.parse::<f64>()
                        .map_err(|e| HydraError::ProtocolError(format!("Invalid loss_rate: {}", e)))?;
                }
                "load" => {
                    load = value.parse::<f64>()
                        .map_err(|e| HydraError::ProtocolError(format!("Invalid load: {}", e)))?;
                }
                "status" => {
                    status = match value.as_ref() {
                        "online" => NodeStatus::Online,
                        "degraded" => NodeStatus::Degraded,
                        "offline" => NodeStatus::Offline,
                        _ => NodeStatus::Online,
                    };
                }
                _ => {}
            }
        }

        Ok(Self {
            address,
            port,
            bandwidth,
            latency,
            loss_rate,
            load,
            status,
        })
    }

    /// 生成Base64编码的分享链接
    pub fn to_base64(&self) -> String {
        let url = self.to_share_url();
        BASE64.encode(url.as_bytes())
    }

    /// 从Base64编码解析分享链接
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = BASE64.decode(encoded)
            .map_err(|e| HydraError::ProtocolError(format!("Invalid base64: {}", e)))?;
        let url = String::from_utf8(decoded)
            .map_err(|e| HydraError::ProtocolError(format!("Invalid UTF-8: {}", e)))?;
        Self::from_share_url(&url)
    }
}

/// 解析多个分享链接（每行一个）
pub fn parse_share_links(text: &str) -> Result<Vec<ShareLink>> {
    let mut links = Vec::new();
    
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if line.starts_with("hydra://") {
            let link = ShareLink::from_share_url(line)?;
            links.push(link);
        }
    }
    
    Ok(links)
}

/// 生成多个分享链接
pub fn generate_share_links(nodes: &[NodeInfo]) -> String {
    let mut result = String::new();
    
    for node in nodes {
        let link = ShareLink::from_node_info(node);
        result.push_str(&link.to_share_url());
        result.push('\n');
    }
    
    result
}

/// 生成多个Base64编码的分享链接
pub fn generate_base64_share_links(nodes: &[NodeInfo]) -> String {
    let mut result = String::new();
    
    for node in nodes {
        let link = ShareLink::from_node_info(node);
        result.push_str(&link.to_base64());
        result.push('\n');
    }
    
    result
}

/// 解析多个Base64编码的分享链接
pub fn parse_base64_share_links(text: &str) -> Result<Vec<ShareLink>> {
    let mut links = Vec::new();
    
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // 尝试解析为Base64
        if let Ok(link) = ShareLink::from_base64(line) {
            links.push(link);
        }
        // 尝试解析为URL
        else if line.starts_with("hydra://") {
            let link = ShareLink::from_share_url(line)?;
            links.push(link);
        }
    }
    
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_share_link_roundtrip() {
        let node_info = NodeInfo {
            address: "127.0.0.1:8080".parse().unwrap(),
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        };

        let link = ShareLink::from_node_info(&node_info);
        let url = link.to_share_url();
        let parsed = ShareLink::from_share_url(&url).unwrap();

        assert_eq!(parsed.address, "127.0.0.1");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.bandwidth, 100.0);
        assert_eq!(parsed.latency, 10.0);
        assert_eq!(parsed.loss_rate, 0.01);
        assert_eq!(parsed.load, 0.5);
    }

    #[test]
    fn test_parse_multiple_links() {
        let text = r#"
# 注释行
hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&status=online
hydra://192.168.1.100:8080?bandwidth=80&latency=15&loss_rate=0.02&status=online
        "#;

        let links = parse_share_links(text).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].address, "127.0.0.1");
        assert_eq!(links[1].address, "192.168.1.100");
    }

    #[test]
    fn test_base64_roundtrip() {
        let node_info = NodeInfo {
            address: "127.0.0.1:8080".parse().unwrap(),
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        };

        let link = ShareLink::from_node_info(&node_info);
        let base64 = link.to_base64();
        let parsed = ShareLink::from_base64(&base64).unwrap();

        assert_eq!(parsed.address, "127.0.0.1");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.bandwidth, 100.0);
        assert_eq!(parsed.latency, 10.0);
        assert_eq!(parsed.loss_rate, 0.01);
        assert_eq!(parsed.load, 0.5);
    }
}