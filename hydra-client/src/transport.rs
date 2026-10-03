use quinn::{Endpoint, ClientConfig, Connection};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, error};
use hydra_protocol::{Result, HydraError};

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";

pub struct Transport {
    endpoint: Endpoint,
    sni: String,
}

impl Transport {
    pub async fn new_client(node_certs: Vec<Vec<u8>>, sni: &str) -> Result<Self> {
        let (endpoint, _) = Self::create_shared_endpoint(node_certs, sni)?;
        Ok(Self {
            endpoint,
            sni: sni.to_string(),
        })
    }

    /// 创建共享的客户端 Endpoint 与 ClientConfig。
    ///
    /// node_certs 中的节点自签证书会被加入本地信任根，执行标准 webpki 校验
    /// （证书 pinning），替代曾经的 SkipVerification——那是零门槛的中间人。
    pub fn create_shared_endpoint(
        node_certs: Vec<Vec<u8>>,
        sni: &str,
    ) -> Result<(Endpoint, ClientConfig)> {
        if node_certs.is_empty() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书，拒绝建立不经验证的连接".to_string(),
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for der in &node_certs {
            roots
                .add(&rustls::Certificate(der.clone()))
                .map_err(|e| HydraError::ProtocolError(format!("无效的节点证书: {:?}", e)))?;
        }

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // ALPN 与节点侧一致，使用标准 h3（QUIC Initial 明文可见，非标 ALPN 是单规则 DPI 指纹）
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        // 禁用会话恢复：防止 session ticket 被用于跨连接关联追踪
        crypto.resumption = rustls::client::Resumption::disabled();

        let mut client_config = ClientConfig::new(Arc::new(crypto));

        // 设置 QUIC 传输参数：keepalive 加随机抖动，避免整周期 beacon 特征
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
        ));
        transport_config
            .keep_alive_interval(Some(Duration::from_secs(jittered_keepalive_secs())));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config.clone());

        info!(
            "Created shared QUIC client endpoint on {} (sni={}, trusted_certs={})",
            endpoint.local_addr()?,
            sni,
            node_certs.len()
        );
        Ok((endpoint, client_config))
    }

    /// 连接到节点（带 5 秒超时，避免死节点挂起调用方）
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        info!("Attempting QUIC connection to {}...", addr);
        let connecting = self.endpoint.connect(addr, &self.sni)?;
        match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(connection)) => {
                info!("QUIC connection established to {}", addr);
                Ok(connection)
            }
            Ok(Err(e)) => {
                error!("QUIC connection failed to {}: {}", addr, e);
                Err(e.into())
            }
            Err(_) => {
                error!("QUIC connection to {} timed out", addr);
                Err(HydraError::ConnectionError(format!(
                    "Connection to {} timed out",
                    addr
                )))
            }
        }
    }

    /// Test connectivity to a node with timeout
    pub async fn test_connection(&self, addr: SocketAddr, timeout_ms: u64) -> bool {
        let connect_future = self.connect(addr);
        match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            connect_future,
        ).await {
            Ok(Ok(_connection)) => {
                info!("Test connection to {} succeeded", addr);
                true
            }
            Ok(Err(e)) => {
                error!("Test connection to {} failed: {}", addr, e);
                false
            }
            Err(_) => {
                error!("Test connection to {} timed out after {}ms", addr, timeout_ms);
                false
            }
        }
    }
}

/// 7..=12 秒随机 keepalive 间隔（防固定周期心跳的被动检测）
fn jittered_keepalive_secs() -> u64 {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 4];
    let _ = rng.fill(&mut buf);
    7 + (u32::from_be_bytes(buf) % 6) as u64
}
