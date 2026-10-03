use quinn::Endpoint;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, error};
use hydra_protocol::Result;
use crate::cert;
use crate::handler::ConnectionHandler;

/// 节点运行选项（main 入口从环境变量读取；测试可直接构造）
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub max_connections: u32,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub cert_domains: Vec<String>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            cert_file: PathBuf::from("hydra-node-cert.der"),
            key_file: PathBuf::from("hydra-node-key.der"),
            cert_domains: vec!["hydra.node".to_string(), "localhost".to_string()],
        }
    }
}

impl NodeOptions {
    /// 从环境变量读取：HYDRA_CERT_FILE / HYDRA_KEY_FILE / HYDRA_CERT_DOMAINS / HYDRA_MAX_CONNECTIONS
    pub fn from_env() -> Self {
        let mut opts = Self::default();
        if let Ok(v) = std::env::var("HYDRA_CERT_FILE") {
            opts.cert_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("HYDRA_KEY_FILE") {
            opts.key_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("HYDRA_CERT_DOMAINS") {
            let domains: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !domains.is_empty() {
                opts.cert_domains = domains;
            }
        }
        if let Ok(v) = std::env::var("HYDRA_MAX_CONNECTIONS") {
            if let Ok(n) = v.parse() {
                opts.max_connections = n;
            }
        }
        opts
    }
}

pub struct HydraServer {
    pub endpoint: Endpoint,
    handler: Arc<ConnectionHandler>,
    max_connections: u32,
    cert_der: Vec<u8>,
}

impl HydraServer {
    /// 创建节点服务器。auth_key 为必填的预共享密钥（未认证的流将被静默关闭）。
    pub async fn new(addr: SocketAddr, auth_key: Vec<u8>, opts: NodeOptions) -> Result<Self> {
        let (cert_der, key_der) = cert::load_or_generate(
            &opts.cert_file,
            &opts.key_file,
            &opts.cert_domains,
        )?;

        let server_config = Self::configure_server(cert_der.clone(), key_der)?;
        let endpoint = Endpoint::server(server_config, addr)?;
        let handler = Arc::new(ConnectionHandler::new(auth_key));

        Ok(Self {
            endpoint,
            handler,
            max_connections: opts.max_connections,
            cert_der: cert_der.0,
        })
    }

    /// 节点证书 DER（供测试/工具读取指纹）
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn configure_server(
        cert: rustls::Certificate,
        key: rustls::PrivateKey,
    ) -> Result<quinn::ServerConfig> {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        // ALPN 使用标准 h3：QUIC Initial 明文区可见，非标 ALPN 是最强的单规则 DPI 指纹
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

        // 设置 QUIC 传输参数：keepalive 加随机抖动，避免整周期 beacon 特征
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::try_from(
            std::time::Duration::from_secs(60),
        )
        .unwrap()));
        transport_config
            .keep_alive_interval(Some(std::time::Duration::from_secs(jittered_keepalive_secs())));
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    pub async fn start(&self) -> Result<()> {
        info!("Hydra server listening on {}", self.endpoint.local_addr()?);

        // 并发连接数上限：用 Semaphore 让 max_connections 真实生效（防 pre-auth 资源耗尽）
        let sem = Arc::new(tokio::sync::Semaphore::new(self.max_connections as usize));

        while let Some(conn) = self.endpoint.accept().await {
            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let handler = self.handler.clone();
            tokio::spawn(async move {
                let _permit = permit; // 连接结束（任务退出）时自动归还
                if let Err(e) = Self::handle_connection(conn, handler).await {
                    error!("Connection error: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn handle_connection(conn: quinn::Connecting, handler: Arc<ConnectionHandler>) -> Result<()> {
        let connection = conn.await?;
        let addr = connection.remote_address();
        info!("New connection from {}", addr);

        handler.handle_connection(connection).await?;

        Ok(())
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
