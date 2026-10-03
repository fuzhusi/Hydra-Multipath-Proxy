use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hydra_obfs::TransportMode;
use hydra_protocol::{HydraError, NodeInfo, NodeStatus, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

/// Hydra节点分享链接格式
///
/// 格式: hydra://address:port?bandwidth=100&latency=10&loss_rate=0.01&status=online&load=0.5[&mode=obfs]
///
/// 参数说明:
/// - address: 节点地址
/// - port: 节点端口
/// - bandwidth: 带宽 (Mbps)
/// - latency: 延迟 (ms)
/// - loss_rate: 丢包率 (0-1)
/// - load: 负载 (0-1)
/// - status: 节点状态 (online/degraded/offline)
/// - mode: 传输模式 (masquerade|obfs；V3.1，缺省 masquerade——不带 mode 参数的
///   既有链接照常解析为 masquerade。**不带密钥本体**，混淆密码经 HYDRA_OBFS_KEY 带外约定)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLink {
    pub address: String,
    pub port: u16,
    pub bandwidth: f64,
    pub latency: f64,
    pub loss_rate: f64,
    pub load: f64,
    pub status: NodeStatus,
    /// V3.1 传输模式（缺省 masquerade；serde default 保证旧版持久化数据反序列化兼容）
    #[serde(default)]
    pub mode: TransportMode,
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
            mode: TransportMode::Masquerade,
        }
    }

    /// 以显式传输模式构造（obfs 节点分享链接用）
    pub fn new_with_mode(node_info: &NodeInfo, mode: TransportMode) -> Self {
        let mut link = Self::new(node_info);
        link.mode = mode;
        link
    }

    /// 覆盖传输模式（builder 风格）
    pub fn with_mode(mut self, mode: TransportMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn from_node_info(node_info: &NodeInfo) -> Self {
        Self::new(node_info)
    }

    pub fn to_node_info(&self) -> Result<NodeInfo> {
        let address: SocketAddr = format!("{}:{}", self.address, self.port)
            .parse()
            .map_err(HydraError::AddrParseError)?;

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

        let mut url = format!(
            "hydra://{}:{}?bandwidth={}&latency={}&loss_rate={}&load={}&status={}",
            self.address,
            self.port,
            self.bandwidth,
            self.latency,
            self.loss_rate,
            self.load,
            status_str
        );
        // 缺省 masquerade 不写 mode 参数：既有链接/生成方零改动，GUI 不需要感知
        if self.mode == TransportMode::Obfs {
            url.push_str("&mode=obfs");
        }
        url
    }

    pub fn from_share_url(url: &str) -> Result<Self> {
        let url = Url::parse(url)
            .map_err(|e| HydraError::ProtocolError(format!("Invalid URL: {}", e)))?;

        if url.scheme() != "hydra" {
            return Err(HydraError::ProtocolError(
                "Invalid scheme, expected 'hydra'".to_string(),
            ));
        }

        let address = url
            .host_str()
            .ok_or_else(|| HydraError::ProtocolError("Missing host".to_string()))?
            .to_string();

        let port = url
            .port()
            .ok_or_else(|| HydraError::ProtocolError("Missing port".to_string()))?;

        let mut bandwidth = 100.0;
        let mut latency = 10.0;
        let mut loss_rate = 0.01;
        let mut load = 0.5;
        let mut status = NodeStatus::Online;
        let mut mode = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "bandwidth" => {
                    bandwidth = value.parse::<f64>().map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid bandwidth: {}", e))
                    })?;
                }
                "latency" => {
                    latency = value.parse::<f64>().map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid latency: {}", e))
                    })?;
                }
                "loss_rate" => {
                    loss_rate = value.parse::<f64>().map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid loss_rate: {}", e))
                    })?;
                }
                "load" => {
                    load = value
                        .parse::<f64>()
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
                "mode" => {
                    // 非法值显式报错：静默回落 masquerade = 用户以为的 obfs 变成黑洞
                    mode =
                        Some(TransportMode::parse(&value).map_err(|e| {
                            HydraError::ProtocolError(format!("Invalid mode: {}", e))
                        })?);
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
            mode: mode.unwrap_or(TransportMode::Masquerade),
        })
    }

    /// 生成Base64编码的分享链接
    pub fn to_base64(&self) -> String {
        let url = self.to_share_url();
        BASE64.encode(url.as_bytes())
    }

    /// 从Base64编码解析分享链接
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(encoded)
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

    // ===================== C4 V3.1 mode 字段 =====================

    fn sample_node() -> NodeInfo {
        NodeInfo {
            address: "127.0.0.1:8080".parse().unwrap(),
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        }
    }

    #[test]
    fn c4_default_links_stay_masquerade_and_unchanged() {
        // 缺省构造/解析 = masquerade；masquerade 不写 mode 参数（既有链接零改动）
        let link = ShareLink::from_node_info(&sample_node());
        assert_eq!(link.mode, TransportMode::Masquerade);
        let url = link.to_share_url();
        assert!(
            !url.contains("mode="),
            "masquerade 链接不应出现 mode 参数: {url}"
        );
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.mode, TransportMode::Masquerade);

        // 无 mode 参数的存量链接照常解析
        let legacy = "hydra://10.0.0.1:443?bandwidth=80&latency=15&loss_rate=0.02&status=online";
        assert_eq!(
            ShareLink::from_share_url(legacy).unwrap().mode,
            TransportMode::Masquerade
        );
    }

    #[test]
    fn c4_obfs_link_roundtrip_url_and_base64_and_serde() {
        let link = ShareLink::new_with_mode(&sample_node(), TransportMode::Obfs);
        let url = link.to_share_url();
        assert!(
            url.contains("mode=obfs"),
            "obfs 链接必须带 mode=obfs: {url}"
        );
        assert!(!url.contains("key="), "分享链接绝不携带混淆密钥本体");

        // URL 往返
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.mode, TransportMode::Obfs);
        assert_eq!(parsed.address, "127.0.0.1");
        assert_eq!(parsed.port, 8080);

        // Base64 往返
        let parsed = ShareLink::from_base64(&link.to_base64()).unwrap();
        assert_eq!(parsed.mode, TransportMode::Obfs);

        // serde JSON 往返
        let json = serde_json::to_string(&link).unwrap();
        assert!(json.contains("\"mode\":\"obfs\""));
        let parsed: ShareLink = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, TransportMode::Obfs);
    }

    #[test]
    fn c4_invalid_mode_is_rejected() {
        // 非法 mode 显式报错——静默回落 masquerade 会让用户以为的 obfs 变成黑洞
        let bad = "hydra://127.0.0.1:8080?mode=stealth";
        assert!(ShareLink::from_share_url(bad).is_err());
    }

    #[test]
    fn c4_builder_mode_roundtrip_via_parse_share_links() {
        let links = parse_share_links(
            "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&status=online&mode=obfs\n\
             hydra://192.168.1.100:8080?bandwidth=80&latency=15&loss_rate=0.02&status=online",
        )
        .unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].mode, TransportMode::Obfs);
        assert_eq!(links[1].mode, TransportMode::Masquerade);
    }
}
