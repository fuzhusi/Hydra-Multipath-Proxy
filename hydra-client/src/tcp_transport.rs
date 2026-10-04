//! Team-T：TCP/TLS 传输模式（客户端侧，v1）
//!
//! 背景：某些网络对 UDP 回程 QoS 丢包导致 QUIC 不可用；TCP+TLS 完全绕开该问题
//! 且流量形态 = 普通 HTTPS。
//!
//! 全局传输选择：env `HYDRA_TRANSPORT=quic|tcp`（默认 quic = 现状零改动）。
//!
//! TLS：tokio-rustls，节点证书 RootCertStore pinning（同 QUIC 路径）、SNI 同
//! `HYDRA_SNI`、不做 ALPN、禁会话恢复（防关联追踪，同 QUIC 路径）。
//! TLS 建立后线缆协议与 QUIC legacy 路径逐字节一致：
//! `[64B v2 token] → [len_hi=0x00][len_lo][addr]（tag 0x00 隐含在长度高字节）→ [2B 应答] → 双向裸转发`
//!
//! **已知限制（v1，如实记录）**：
//! - 无多流聚合 / 无 ACK 机制（TCP 自带可靠有序传输）；
//! - obfs 混淆不适用于 tcp 模式；
//! - 仅 v2 token 认证（无 v3 Noise 握手 / 通道绑定）；
//! - 节点侧无应用错误码通道：认证失败 / 目标失败均表现为静默关闭（读 EOF）。
use crate::transport::DEFAULT_SNI;
use hydra_protocol::{AuthToken, HydraError, Result, CLIENT_ID};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// 全局传输选择 env（quic|tcp；未设/非法值 = quic，现状零改动）
pub const HYDRA_TRANSPORT_ENV: &str = "HYDRA_TRANSPORT";

/// 传输模式选择（来自分享链接 `tp` 字段或全局 env）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportChoice {
    /// QUIC/UDP（默认，现状零改动）
    Quic,
    /// TCP/TLS（Team-T v1）
    Tcp,
}

impl TransportChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportChoice::Quic => "quic",
            TransportChoice::Tcp => "tcp",
        }
    }

    /// 解析传输字符串（分享链接 tp 字段值）；非法值显式报错
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "quic" => Ok(TransportChoice::Quic),
            "tcp" => Ok(TransportChoice::Tcp),
            other => Err(HydraError::ProtocolError(format!(
                "Invalid transport '{}': expected quic|tcp",
                other
            ))),
        }
    }
}

/// 读取全局传输选择（每次调用读 env；代理热路径为每连接一次，开销可忽略，
/// 也使测试可在进程内切换，无初始化顺序陷阱）
pub fn transport_from_env() -> TransportChoice {
    match std::env::var(HYDRA_TRANSPORT_ENV).as_deref() {
        Ok("tcp") => TransportChoice::Tcp,
        _ => TransportChoice::Quic,
    }
}

/// 客户端侧 TCP/TLS 节点流（认证与应答握手完成后，可直接双向转发）
pub type TcpNodeStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// 建连超时（同 QUIC Transport::connect 的 5s）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 应答等待超时（须大于节点侧目标连接超时 15s，同 QUIC 路径 20s）
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// 编码认证+地址请求帧：`[64B v2 token][len u16 大端][addr]`。
/// 与 QUIC legacy 路径逐字节一致（len 高字节 0x00 = 模式标签 0x00，len 低字节 =
/// 单字节地址长度；地址长度上限 256 与 QUIC 路径同一已知边界）。
fn build_request(token: &[u8], target: &str) -> Result<Vec<u8>> {
    let addr_bytes = target.as_bytes();
    if addr_bytes.is_empty() || addr_bytes.len() > 256 {
        return Err(HydraError::ProtocolError(
            "Target address too long".to_string(),
        ));
    }
    let mut request = Vec::with_capacity(token.len() + 2 + addr_bytes.len());
    request.extend_from_slice(token);
    request.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
    request.extend_from_slice(addr_bytes);
    Ok(request)
}

/// 经 TCP+TLS 连接节点并打开目标转发。
///
/// 步骤：TLS 建连（证书 pinning + SNI，5s 超时）→ 写 `[64B v2 token][len u16][addr]`
/// → 读 2B 应答（20s 超时）→ 返回可用于双向转发的 [`TcpNodeStream`]。
/// 认证失败 / 目标失败时节点静默关流：本函数以"连接被关闭"报错（无应用错误码，v1 限制）。
pub async fn connect_target(
    node_addr: SocketAddr,
    sni: &str,
    node_certs: &[Vec<u8>],
    auth_key: &[u8],
    target: &str,
) -> Result<TcpNodeStream> {
    let sni = if sni.is_empty() { DEFAULT_SNI } else { sni };
    if node_certs.is_empty() {
        return Err(HydraError::ConnectionError(
            "未提供节点证书，拒绝建立不经验证的连接".to_string(),
        ));
    }

    // 证书 pinning：节点自签证书加入本地信任根，标准 webpki 校验（同 QUIC 路径）
    let mut roots = rustls::RootCertStore::empty();
    for der in node_certs {
        roots
            .add(&rustls::Certificate(der.clone()))
            .map_err(|e| HydraError::ProtocolError(format!("无效的节点证书: {:?}", e)))?;
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // 不做 ALPN（同节点侧）；禁会话恢复防跨连接关联追踪（同 QUIC 路径）
    crypto.alpn_protocols = Vec::new();
    crypto.resumption = rustls::client::Resumption::disabled();
    let connector = TlsConnector::from(Arc::new(crypto));

    let server_name = rustls::ServerName::try_from(sni)
        .map_err(|e| HydraError::ProtocolError(format!("Invalid SNI '{}': {:?}", sni, e)))?;

    debug!("Attempting TCP/TLS connection to {} (sni={})...", node_addr, sni);
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(node_addr))
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "TCP connect to {} failed: {}",
                node_addr, e
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "TCP connect to {} timed out",
                node_addr
            )))
        }
    };
    let mut tls = match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "TLS handshake with {} failed: {}",
                node_addr, e
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "TLS handshake with {} timed out",
                node_addr
            )))
        }
    };

    // v2 token 认证 + 地址帧（与 QUIC legacy 线缆格式逐字节一致）
    let token = AuthToken::generate(auth_key, CLIENT_ID);
    let request = build_request(&token, target)?;
    tls.write_all(&request).await.map_err(|e| {
        HydraError::ConnectionError(format!("write request to {} failed: {}", node_addr, e))
    })?;

    let mut resp = [0u8; 2];
    match tokio::time::timeout(RESPONSE_TIMEOUT, tls.read_exact(&mut resp)).await {
        // 节点成功应答 [0x00,0x00]（与 QUIC 路径同一判定：首字节 0x00 即成功）
        Ok(Ok(_)) if resp[0] == 0x00 => {
            info!("✓ TCP/TLS target {} opened via node {}", target, node_addr);
            Ok(tls)
        }
        // 节点静默关闭 = 认证失败或目标不可达（v1 无错误码通道，如实报错）
        Ok(Ok(_)) => Err(HydraError::ConnectionError(format!(
            "节点报告目标连接失败: {}",
            target
        ))),
        Ok(Err(e)) => Err(HydraError::ConnectionError(format!(
            "节点静默关闭连接（认证失败或目标不可达）: {}",
            e
        ))),
        Err(_) => Err(HydraError::ConnectionError(format!(
            "Node {} response timeout",
            node_addr
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_matches_quic_legacy_wire_format() {
        // token 64B + [len_hi=0x00][len_lo][addr]：模式标签隐含在长度高字节
        let token = vec![0xABu8; AuthToken::TOKEN_LEN];
        let req = build_request(&token, "127.0.0.1:9000").unwrap();
        const ADDR_LEN: usize = "127.0.0.1:9000".len(); // 14
        assert_eq!(req.len(), 64 + 2 + ADDR_LEN);
        assert_eq!(&req[..64], &token[..]);
        assert_eq!(&req[64..66], &[0x00, ADDR_LEN as u8]);
        assert_eq!(&req[66..], b"127.0.0.1:9000");
    }

    #[test]
    fn request_rejects_empty_and_overlong_addr() {
        let token = vec![0u8; AuthToken::TOKEN_LEN];
        assert!(build_request(&token, "").is_err());
        assert!(build_request(&token, &"a".repeat(257)).is_err());
        // 256 字节：与 QUIC 路径同一已知边界（长度高字节非 0x00），放行由两端语义决定
        assert!(build_request(&token, &"a".repeat(256)).is_ok());
    }

    #[test]
    fn transport_choice_parse() {
        assert_eq!(TransportChoice::parse("quic").unwrap(), TransportChoice::Quic);
        assert_eq!(TransportChoice::parse("tcp").unwrap(), TransportChoice::Tcp);
        assert!(TransportChoice::parse("obfs").is_err());
    }
}
