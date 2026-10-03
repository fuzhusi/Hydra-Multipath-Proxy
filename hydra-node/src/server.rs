use crate::cert;
use crate::handler::ConnectionHandler;
use hydra_obfs::TransportMode;
use hydra_protocol::Result;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

/// 节点运行选项（main 入口从环境变量读取；测试可直接构造）
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub max_connections: u32,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub cert_domains: Vec<String>,
    /// C2 传输模式：masquerade（默认，V2 行为零改动）| obfs（逃生舱，需 HYDRA_OBFS_KEY）
    pub mode: TransportMode,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            cert_file: PathBuf::from("hydra-node-cert.der"),
            key_file: PathBuf::from("hydra-node-key.der"),
            cert_domains: vec!["hydra.node".to_string(), "localhost".to_string()],
            mode: TransportMode::Masquerade,
        }
    }
}

impl NodeOptions {
    /// 从环境变量读取：HYDRA_CERT_FILE / HYDRA_KEY_FILE / HYDRA_CERT_DOMAINS / HYDRA_MAX_CONNECTIONS
    /// / HYDRA_MODE。HYDRA_MODE 非法值显式退出（静默回落 masquerade 会让"以为开了
    /// obfs"的用户得到黑洞，宁可启动失败）。
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
        if let Ok(v) = std::env::var(hydra_obfs::HYDRA_MODE_ENV) {
            match TransportMode::parse(&v) {
                Ok(m) => opts.mode = m,
                Err(e) => {
                    eprintln!("错误：{}", e);
                    std::process::exit(1);
                }
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
    ///
    /// C2 双模式：`opts.mode = Masquerade`（默认）走 `Endpoint::server` 原路径
    /// （V2 行为零改动）；`Obfs` 走 `hydra_obfs::new_obfs_endpoint`（线缆 =
    /// `[12B salt][ChaCha20 XOR]`，要求 HYDRA_OBFS_KEY 已设，否则启动报错）。
    /// 两端 mode 不匹配时对端报文无法解包，行为 = 静默丢包（连接超时，无错误信号）。
    pub async fn new(addr: SocketAddr, auth_key: Vec<u8>, opts: NodeOptions) -> Result<Self> {
        let (cert_der, key_der) =
            cert::load_or_generate(&opts.cert_file, &opts.key_file, &opts.cert_domains)?;

        let server_config = Self::configure_server(cert_der.clone(), key_der)?;
        let endpoint = match opts.mode {
            TransportMode::Masquerade => Endpoint::server(server_config, addr)?,
            TransportMode::Obfs => {
                let obfs = hydra_obfs::ObfsCrypto::from_env().map_err(|e| {
                    hydra_protocol::HydraError::ProtocolError(format!("obfs 模式启动失败: {}", e))
                })?;
                hydra_obfs::new_obfs_endpoint(addr, Some(server_config), Arc::new(obfs)).map_err(
                    |e| {
                        hydra_protocol::HydraError::ConnectionError(format!(
                            "创建 obfs 节点 endpoint 失败: {}",
                            e
                        ))
                    },
                )?
            }
        };
        let handler = Arc::new(ConnectionHandler::new(auth_key));

        Ok(Self {
            endpoint,
            handler,
            max_connections: opts.max_connections.max(1),
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
        // C2 顺带（B1 收尾）：节点侧复用与客户端同一份流控窗口调优——
        // 连接级 receive_window 32MB 内存封顶 + 单流窗口 8MB 吞吐杠杆（env 可调）
        hydra_obfs::tuning::apply_transport_tuning(&mut transport_config);
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(
            jittered_keepalive_secs(),
        )));
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

    async fn handle_connection(
        conn: quinn::Connecting,
        handler: Arc<ConnectionHandler>,
    ) -> Result<()> {
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
