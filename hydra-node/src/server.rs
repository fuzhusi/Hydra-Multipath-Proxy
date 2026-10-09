//! 节点服务入口（TCP 转型 Wave 3）：TCP/TLS（TLS 1.3 + Noise-PSK 应用层
//! 握手）成为唯一传输，QUIC/UDP 路径与 obfs UDP 混淆模块已整体移除。
//!
//! - `HydraServer::new`：加载/生成证书（cert.rs）→ 构造
//!   [`ConnectionHandler`]（cert_fingerprint + AuthMode::from_env）→
//!   [`spawn_tcp_listener`] 绑定监听地址（TCP 永远监听，后台接受循环）。
//! - `start()`：接受循环已在 [`spawn_tcp_listener`] 内部后台运行，
//!   此处永久挂起以维持进程存活（保留 Result 签名）。

use crate::cert;
use crate::handler::ConnectionHandler;
use crate::tcp_server::spawn_tcp_listener;
use hydra_protocol::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// 节点运行选项（main 入口从环境变量读取；测试可直接构造）
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub max_connections: u32,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub cert_domains: Vec<String>,
    /// P2P 信令模式（NAT 穿透方案 §3.2）：默认关闭 = 行为零变化
    pub p2p_signal: bool,
    /// 反代静态页回退（抗主动探测增强）：TLS 建立后的认证失败路径回复内置
    /// 静态页而非静默关流。默认关闭 = 保守升级（行为零变化）；权衡见
    /// `fallback.rs` 模块文档与 README 部署指南。env `HYDRA_FALLBACK_PAGE`。
    pub fallback_page: bool,
    /// 转发空闲看门狗超时（07-P2-4：显式注入优先于 env `HYDRA_IDLE_TIMEOUT_SECS`，
    /// 避免测试进程内 set_var 与并行线程 env 读取的数据竞争；None = env/默认值）
    pub idle_timeout: Option<std::time::Duration>,
    /// 连接最长寿命（V3.3 Tier1，防御纵深）：超龄**强制关闭**——数据路径无
    /// 应用层控制通道，对客户端表现为普通传输故障。定位是会话寿命/资源边界
    /// 而非密码学必需（rustls 已按套件约束自动刷新 TLS 流量密钥）。
    /// None/0 = 关闭；env `HYDRA_MAX_CONN_AGE_SECS`（clamp 60..=604800）
    pub max_conn_age: Option<std::time::Duration>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            cert_file: PathBuf::from("hydra-node-cert.der"),
            key_file: PathBuf::from("hydra-node-key.der"),
            cert_domains: vec!["hydra.node".to_string(), "localhost".to_string()],
            p2p_signal: false,
            fallback_page: false,
            idle_timeout: None,
            max_conn_age: None,
        }
    }
}

impl NodeOptions {
    /// 从环境变量读取：HYDRA_CERT_FILE / HYDRA_KEY_FILE / HYDRA_CERT_DOMAINS /
    /// HYDRA_MAX_CONNECTIONS / HYDRA_P2P_SIGNAL（=1 开启 P2P 信令模式）
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
        if let Ok(v) = std::env::var("HYDRA_P2P_SIGNAL") {
            opts.p2p_signal = v.trim() == "1";
        }
        if let Ok(v) = std::env::var("HYDRA_MAX_CONN_AGE_SECS") {
            // V3.3 Tier1：0 = 显式关闭；其余 clamp 60s..=7d（防误配 1s 抖动断连
            // 或一年不轮换）
            match v.trim().parse::<u64>() {
                Ok(0) => opts.max_conn_age = None,
                Ok(n) => {
                    opts.max_conn_age = Some(std::time::Duration::from_secs(n.clamp(60, 604_800)));
                }
                Err(_) => {
                    eprintln!("错误：HYDRA_MAX_CONN_AGE_SECS=\"{v}\" 非法（期望秒数，0=关闭）");
                    std::process::exit(1);
                }
            }
        }
        if let Ok(v) = std::env::var("HYDRA_FALLBACK_PAGE") {
            // 语义与 config.rs 三层解析一致（审查 P3-3）：空白=未设置、"1"/"0"，
            // 非法值显式报错退出而非静默当关闭
            let t = v.trim();
            match t {
                "" => {}
                "1" => opts.fallback_page = true,
                "0" => opts.fallback_page = false,
                other => {
                    eprintln!("错误：HYDRA_FALLBACK_PAGE=\"{other}\" 非法（期望 0 或 1）");
                    std::process::exit(1);
                }
            }
        }
        opts
    }
}

pub struct HydraServer {
    /// TCP/TLS 监听实际绑定地址（测试/工具读取；TCP 为唯一传输，恒为 Some）
    pub tcp_listen_addr: Option<SocketAddr>,
    cert_der: Vec<u8>,
}

impl HydraServer {
    /// 创建节点服务器。auth_key 为必填的预共享密钥（Noise-PSK 握手使用；
    /// 认证失败的流将被静默关闭）。
    pub async fn new(addr: SocketAddr, auth_key: Vec<u8>, opts: NodeOptions) -> Result<Self> {
        // 07-P1-1：load_or_generate 返回整条证书链（叶在前）
        let (cert_chain, key_der) =
            cert::load_or_generate(&opts.cert_file, &opts.key_file, &opts.cert_domains)?;
        // 叶证书 DER（链首）：指纹/通道绑定与对外暴露的 cert_der 均只取叶，语义不变
        let leaf_der = cert_chain[0].clone();

        let handler = Arc::new(ConnectionHandler::new(
            auth_key,
            // rustls 0.23（Wave 3）：CertificateDer 用 as_ref() 取 DER 字节
            hydra_protocol::handshake::cert_fingerprint(leaf_der.as_ref()),
            hydra_protocol::handshake::AuthMode::from_env(), // 启动时读一次，不在每流热路径读 env
        ));
        // 09-P3-5（协议层报告）：TCP 是唯一传输且仅实现 v3 握手——auth_mode 显式
        // 配置为非 v3 时 TCP 监听会静默拒绝一切连接。启动期告警把配置陷阱显性化。
        if !handler.auth_mode().accepts_v3() {
            tracing::warn!(
                "HYDRA_AUTH_MODE 非 v3（auth_mode={:?}）：TCP 仅支持 v3 握手，\
                 所有 TCP 连接将被静默拒绝！如需正常服务请改为 auto/v3",
                handler.auth_mode()
            );
        }

        // TCP/TLS 监听（唯一传输）：接受循环在 spawn_tcp_listener 内部后台运行；
        // 绑定失败显式报错（静默回落会让用户得到黑洞）。
        let tcp_listen_addr = spawn_tcp_listener(
            addr,
            cert_chain,
            key_der,
            handler.clone(),
            opts.max_connections.max(1) as usize,
            opts.p2p_signal,
            // 反代静态页回退开关（默认关闭 = 静默关流语义不变）
            opts.fallback_page,
            // 07-P2-4：显式注入优先，未注入回落 env/默认（spawn_tcp_listener 内解析）
            opts.idle_timeout,
            // V3.3 Tier1：连接最长寿命（None = 关闭）
            opts.max_conn_age,
        )
        .await?;

        Ok(Self {
            tcp_listen_addr: Some(tcp_listen_addr),
            cert_der: leaf_der.as_ref().to_vec(),
        })
    }

    /// 节点证书 DER（供测试/工具读取指纹）
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// TCP 接受循环已在 spawn_tcp_listener 内部后台运行；本方法仅永久挂起
    /// 维持进程存活（保留 Result 签名以兼容调用方）。
    pub async fn start(&self) -> Result<()> {
        if let Some(addr) = self.tcp_listen_addr {
            info!("Hydra server listening on {} (TCP/TLS)", addr);
        }
        std::future::pending::<()>().await;
        Ok(())
    }
}
