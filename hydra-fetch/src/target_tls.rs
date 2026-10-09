//! 目标站 TLS 连接器（TLS-in-TLS）：rustls webpki 公共 CA 根 + 主机名校验，
//! 跑在 hydra 隧道流（`TcpNodeStream`，同对象实现 AsyncRead+AsyncWrite）上。
//!
//! # 与节点伪装配置的边界（故意不同）
//! - **ALPN 锁定 `http/1.1`**：若沿用节点伪装的 h2 优先，服务器可能选 h2——
//!   手写 HTTP/1.1 客户端无法解析二进制帧（评审 P0）；
//! - 标准 webpki 公共 CA 根 + URL host 作 ServerName（端到端校验，不跳过）；
//! - 禁会话恢复（与全项目两端承诺一致）。

use std::sync::Arc;

use rustls::pki_types::ServerName;

/// 目标站 TLS 流（隧道流 + 目标 TLS 两层；同对象实现 AsyncRead+AsyncWrite）
pub type TargetStream<S> = tokio_rustls::client::TlsStream<S>;

/// 目标站 TLS 连接器（每个下载任务构建一次；Clone 共享同一配置）
#[derive(Clone)]
pub struct TargetTlsConnector {
    connector: tokio_rustls::TlsConnector,
}

impl TargetTlsConnector {
    pub fn new() -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS 协议版本配置失败: {e}"))?
            .with_root_certificates(root_store())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }

    /// 在隧道流上发起目标站 TLS 握手（主机名校验 + webpki 公共 CA）
    pub async fn connect<S>(&self, host: &str, tunnel: S) -> Result<TargetStream<S>, String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| format!("目标主机名非法 '{host}': {e:?}"))?;
        self.connector
            .connect(server_name, tunnel)
            .await
            .map_err(|e| format!("目标站 TLS 握手失败 ({host}): {e}"))
    }
}

fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.to_vec());
    roots
}
