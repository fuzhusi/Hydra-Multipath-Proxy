use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
    Engine as _,
};
pub use hydra_obfs::TransportMode;
use hydra_protocol::{HydraError, NodeInfo, NodeStatus, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

/// Hydra节点分享链接格式（Team-Q 分享体系 v2）
///
/// 旧格式（v1，继续兼容解析与生成）:
/// `hydra://address:port?bandwidth=100&latency=10&loss_rate=0.01&status=online&load=0.5[&mode=obfs]`
///
/// v2 格式（携带密钥信息，`v=3` 标记）:
/// `hydra://addr:port?v=3&k=<base64url(auth_key)>&cc=<base64url(cert_der)>&mode=obfs&ok=<base64url(obfs_key)>`
///
/// v2 参数说明（编码一律 base64url 无填充）:
/// - `v=3`: 分享格式版本标记；含任一密钥字段时生成方必须携带，旧客户端会忽略未知参数
/// - `k`: 节点预共享认证密钥原始字节（必带于完整分享 = 对方导入即用）
/// - `cc`: 节点证书 DER 原始字节（完整模式；对方无需另行导入证书文件）
/// - `cf`: 节点证书 SHA-256 指纹（64 位小写 hex；**紧凑模式**：省略 cc 时携带，
///   对方需另行导入证书并核对指纹）
/// - `ok`: obfs 模式独立第二混淆密码 UTF-8 字节（仅 obfs 模式携带）
/// - `mode`: 传输模式（masquerade|obfs），语义同 v1
///
/// **安全声明**：完整链接（含 `k`/`cc`）= 持有该节点，等同账号密码。
/// 仅限二维码当面扫描 / 近场 / 其他可信通道分享，**严禁**粘贴到不可信的
/// 公开渠道（群聊、公开网页、明文 http 订阅）。仅含 `cf` 指纹的紧凑链接
/// 不泄露密钥，可走普通渠道。
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
    /// v2 认证密钥（base64url(auth_key 原始字节)，无填充）；None = 不携带
    #[serde(default)]
    pub auth_key: Option<String>,
    /// v2 节点证书 DER（base64url）；None = 不携带（紧凑模式走 cert_fp）
    #[serde(default)]
    pub cert_der: Option<String>,
    /// v2 节点证书 SHA-256 指纹（小写 hex，64 字符）；紧凑模式供核对
    #[serde(default)]
    pub cert_fp: Option<String>,
    /// v2 obfs 独立第二密码（base64url(UTF-8 字节)）；仅 obfs 模式
    #[serde(default)]
    pub obfs_key: Option<String>,
    /// Team-T 传输选择（链接参数 `tp=tcp|quic`）；None/缺省 = quic（既有链接零改动）。
    /// 序列化仅在 tcp 时写 `tp=tcp`（quic 为缺省不写，与 mode 字段同一惯例）
    #[serde(default)]
    pub transport: Option<String>,
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
            auth_key: None,
            cert_der: None,
            cert_fp: None,
            obfs_key: None,
            transport: None,
        }
    }

    // ═══════════ v2 密钥字段 builder（Team-Q）═══════════

    /// 携带认证密钥原始字节（生成完整分享）
    pub fn with_auth_key_bytes(mut self, key: &[u8]) -> Self {
        self.auth_key = Some(BASE64URL.encode(key));
        self
    }

    /// 携带节点证书 DER（完整模式），同时自动写入证书指纹
    pub fn with_cert_der(mut self, der: &[u8]) -> Self {
        self.cert_fp = Some(sha256_hex(der));
        self.cert_der = Some(BASE64URL.encode(der));
        self
    }

    /// 仅携带证书指纹（紧凑模式：对方需另行导入证书并核对指纹）
    pub fn with_cert_fp(mut self, fp: String) -> Self {
        self.cert_fp = Some(fp);
        self
    }

    /// 携带 obfs 独立第二密码（仅 obfs 模式）
    pub fn with_obfs_key(mut self, key: &str) -> Self {
        self.obfs_key = Some(BASE64URL.encode(key.as_bytes()));
        self
    }

    /// 覆盖传输选择（Team-T：`tp=tcp`；builder 风格）
    pub fn with_transport(mut self, tp: crate::tcp_transport::TransportChoice) -> Self {
        self.transport = Some(tp.as_str().to_string());
        self
    }

    /// 节点是否使用 TCP/TLS 传输（Team-T；缺省 = quic）
    pub fn transport_is_tcp(&self) -> bool {
        matches!(self.transport.as_deref(), Some("tcp"))
    }

    /// 解析传输选择字段（None/非法缺省按 quic 由调用方决定；此处非法值显式报错）
    pub fn transport_choice(
        &self,
    ) -> std::result::Result<crate::tcp_transport::TransportChoice, HydraError> {
        match self.transport.as_deref() {
            None => Ok(crate::tcp_transport::TransportChoice::Quic),
            Some(s) => crate::tcp_transport::TransportChoice::parse(s),
        }
    }

    /// 是否完整分享（同时携带认证密钥与节点证书 = 对方导入即用 = 等同持有节点）
    pub fn is_full_share(&self) -> bool {
        self.auth_key.is_some() && self.cert_der.is_some()
    }

    /// 是否携带任一密钥字段（生成方据此写入 `v=3` 版本标记）
    fn has_secret_fields(&self) -> bool {
        self.auth_key.is_some() || self.cert_der.is_some() || self.obfs_key.is_some()
    }

    /// 解码认证密钥原始字节（None = 未携带）
    pub fn auth_key_bytes(&self) -> std::result::Result<Option<Vec<u8>>, HydraError> {
        self.auth_key
            .as_ref()
            .map(|s| {
                BASE64URL
                    .decode(s)
                    .map_err(|e| HydraError::ProtocolError(format!("Invalid k (auth key): {}", e)))
            })
            .transpose()
    }

    /// 解码节点证书 DER 字节（None = 未携带）
    pub fn cert_der_bytes(&self) -> std::result::Result<Option<Vec<u8>>, HydraError> {
        self.cert_der
            .as_ref()
            .map(|s| {
                BASE64URL
                    .decode(s)
                    .map_err(|e| HydraError::ProtocolError(format!("Invalid cc (cert): {}", e)))
            })
            .transpose()
    }

    /// 解码 obfs 第二密码字符串（None = 未携带）
    pub fn obfs_key_string(&self) -> std::result::Result<Option<String>, HydraError> {
        self.obfs_key
            .as_ref()
            .map(|s| {
                let bytes = BASE64URL.decode(s).map_err(|e| {
                    HydraError::ProtocolError(format!("Invalid ok (obfs key): {}", e))
                })?;
                String::from_utf8(bytes)
                    .map_err(|e| HydraError::ProtocolError(format!("Invalid ok encoding: {}", e)))
            })
            .transpose()
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

        // v1 字段保持既有顺序与格式（不带密钥时输出与旧版逐字节一致）
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
        // v2 密钥字段：携带任一密钥信息时写 v=3 版本标记（旧解析端忽略未知参数）
        if self.has_secret_fields() {
            url.push_str("&v=3");
            if let Some(k) = &self.auth_key {
                url.push_str(&format!("&k={}", k));
            }
            if let Some(cc) = &self.cert_der {
                url.push_str(&format!("&cc={}", cc));
            }
            if let Some(ok) = &self.obfs_key {
                url.push_str(&format!("&ok={}", ok));
            }
        }
        // 证书指纹独立于 has_secret_fields：紧凑模式仅带 cf（不泄露密钥，可走普通渠道）
        if let Some(cf) = &self.cert_fp {
            url.push_str(&format!("&cf={}", cf));
        }
        // Team-T：传输选择（仅 tcp 写 tp=tcp；quic 为缺省不写，既有链接零改动）
        if let Some(tp) = &self.transport {
            if tp == "tcp" {
                url.push_str("&tp=tcp");
            }
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
        let mut auth_key: Option<String> = None;
        let mut cert_der: Option<String> = None;
        let mut cert_fp: Option<String> = None;
        let mut obfs_key: Option<String> = None;
        let mut transport: Option<String> = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                // v2 密钥字段（base64url 无填充；坏字段显式报错，不静默丢弃）
                "k" => {
                    BASE64URL.decode(value.as_bytes()).map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid k (auth key): {}", e))
                    })?;
                    auth_key = Some(value.to_string());
                }
                "cc" => {
                    BASE64URL.decode(value.as_bytes()).map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid cc (cert): {}", e))
                    })?;
                    cert_der = Some(value.to_string());
                }
                "ok" => {
                    BASE64URL.decode(value.as_bytes()).map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid ok (obfs key): {}", e))
                    })?;
                    obfs_key = Some(value.to_string());
                }
                "cf" => {
                    let v = value.as_ref();
                    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(HydraError::ProtocolError(
                            "Invalid cf (cert fingerprint): expected 64 hex chars".to_string(),
                        ));
                    }
                    cert_fp = Some(v.to_ascii_lowercase());
                }
                // v=3：版本标记，当前仅识别不校验（未来版本升级入口）
                "v" => {}
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
                // Team-T：传输选择（tp=tcp|quic；非法值显式报错，不静默回落）
                "tp" => {
                    crate::tcp_transport::TransportChoice::parse(&value).map_err(|e| {
                        HydraError::ProtocolError(format!("Invalid tp (transport): {}", e))
                    })?;
                    transport = Some(value.to_string());
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
            auth_key,
            cert_der,
            cert_fp,
            obfs_key,
            transport,
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

/// SHA-256 摘要的小写 hex 编码（v2 证书指纹 `cf` 用）
pub fn sha256_hex(data: &[u8]) -> String {
    use ring::digest::{digest, SHA256};
    hex_encode_lower(digest(&SHA256, data).as_ref())
}

/// 字节 → 小写 hex 字符串（GUI 导入 v2 链接时密钥入库用）
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
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

    /// Team-T：`tp` 传输字段解析/序列化往返；缺省 quic 不写参数（既有链接零改动）
    #[test]
    fn tt_tp_field_roundtrip() {
        let url = "hydra://1.2.3.4:443?bandwidth=100&tp=tcp";
        let link = ShareLink::from_share_url(url).unwrap();
        assert!(link.transport_is_tcp());
        assert_eq!(link.transport_choice().unwrap(), crate::tcp_transport::TransportChoice::Tcp);

        // URL 往返
        let rt = ShareLink::from_share_url(&link.to_share_url()).unwrap();
        assert!(rt.transport_is_tcp());

        // serde（GUI 持久化）往返
        let json = serde_json::to_string(&link).unwrap();
        let rt2: ShareLink = serde_json::from_str(&json).unwrap();
        assert!(rt2.transport_is_tcp());

        // 显式 quic 与缺省等价：不写 tp 参数
        let quic = ShareLink::from_share_url("hydra://1.2.3.4:443?tp=quic").unwrap();
        assert!(!quic.transport_is_tcp());
        assert!(!quic.to_share_url().contains("tp="));
        let default = ShareLink::from_share_url("hydra://1.2.3.4:443?bandwidth=100").unwrap();
        assert!(!default.transport_is_tcp());

        // 非法值显式报错（不静默回落 quic）
        assert!(ShareLink::from_share_url("hydra://1.2.3.4:443?tp=obfs").is_err());
    }

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

    // ===================== Team-Q 分享体系 v2（密钥 + 二维码）=====================

    #[test]
    fn tq_v2_full_link_roundtrip_keeps_secrets() {
        let auth_key: Vec<u8> = (0u8..32).collect();
        let cert_der: Vec<u8> = vec![0x30, 0x82, 0x01, 0xAB, 0xCD, 0xEF];
        let link = ShareLink::new_with_mode(&sample_node(), TransportMode::Obfs)
            .with_auth_key_bytes(&auth_key)
            .with_cert_der(&cert_der)
            .with_obfs_key("second-password-密");

        let url = link.to_share_url();
        assert!(url.contains("v=3"), "完整分享必须带 v=3: {url}");
        assert!(url.contains("&k="));
        assert!(url.contains("&cc="));
        assert!(url.contains("&ok="));
        assert!(url.contains("&cf="), "完整分享同时带证书指纹供核对");
        assert!(url.contains("mode=obfs"));

        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.address, "127.0.0.1");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.mode, TransportMode::Obfs);
        assert_eq!(parsed.auth_key, link.auth_key);
        assert_eq!(parsed.cert_der, link.cert_der);
        assert_eq!(parsed.cert_fp, link.cert_fp);
        assert_eq!(parsed.obfs_key, link.obfs_key);

        // 解码后的字节与输入一致
        assert_eq!(parsed.auth_key_bytes().unwrap(), Some(auth_key));
        assert_eq!(parsed.cert_der_bytes().unwrap(), Some(cert_der));
        assert_eq!(
            parsed.obfs_key_string().unwrap(),
            Some("second-password-密".to_string())
        );
        assert!(parsed.is_full_share());

        // serde JSON 往返（旧版 JSON 缺 v2 字段 → None）
        let json = serde_json::to_string(&parsed).unwrap();
        let back: ShareLink = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, parsed.address);
        assert_eq!(back.auth_key, parsed.auth_key);
        assert_eq!(back.cert_der, parsed.cert_der);
        assert_eq!(back.cert_fp, parsed.cert_fp);
        assert_eq!(back.obfs_key, parsed.obfs_key);
        assert_eq!(back.mode, parsed.mode);
    }

    #[test]
    fn tq_v2_compact_link_only_carries_fingerprint() {
        let link = ShareLink::from_node_info(&sample_node()).with_cert_fp(sha256_hex(b"fake cert"));
        let url = link.to_share_url();
        assert!(url.contains("&cf="));
        assert!(!url.contains("&cc="), "紧凑模式不带证书本体: {url}");
        assert!(!url.contains("v=3"), "无密钥字段不写版本标记: {url}");

        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.cert_fp, link.cert_fp);
        assert_eq!(parsed.cert_der, None);
        assert_eq!(parsed.auth_key, None);
        assert!(!parsed.is_full_share());
    }

    #[test]
    fn tq_v2_legacy_format_still_parses() {
        // 旧格式（无 v=3、无密钥字段）继续兼容，v2 字段为 None
        let legacy =
            "hydra://10.0.0.1:443?bandwidth=80&latency=15&loss_rate=0.02&status=online&mode=obfs";
        let parsed = ShareLink::from_share_url(legacy).unwrap();
        assert_eq!(parsed.auth_key, None);
        assert_eq!(parsed.cert_der, None);
        assert_eq!(parsed.cert_fp, None);
        assert_eq!(parsed.obfs_key, None);
        assert_eq!(parsed.mode, TransportMode::Obfs);

        // 旧格式生成输出与旧版逐字节一致（无密钥时）
        let plain = ShareLink::from_node_info(&sample_node());
        assert_eq!(
            plain.to_share_url(),
            "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online"
        );
    }

    #[test]
    fn tq_v2_bad_secret_fields_are_rejected() {
        // k/cc/ok 非 base64url → 显式报错
        assert!(
            ShareLink::from_share_url("hydra://127.0.0.1:8080?k=!!!not-base64")
                .unwrap_err()
                .to_string()
                .contains("k")
        );
        assert!(ShareLink::from_share_url("hydra://127.0.0.1:8080?cc=@@bad@@").is_err());
        assert!(ShareLink::from_share_url("hydra://127.0.0.1:8080?ok=***").is_err());
        // cf 非 64 位 hex → 报错
        assert!(ShareLink::from_share_url("hydra://127.0.0.1:8080?cf=abc").is_err());
        assert!(ShareLink::from_share_url(
            "hydra://127.0.0.1:8080?cf=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_err());
    }

    #[test]
    fn tq_v2_parse_share_links_text_with_secrets() {
        let url = ShareLink::new_with_mode(&sample_node(), TransportMode::Masquerade)
            .with_auth_key_bytes(&[9u8; 16])
            .to_share_url();
        let links = parse_share_links(&format!("# 注释\n{}\n", url)).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].auth_key_bytes().unwrap(), Some(vec![9u8; 16]));
    }
}
