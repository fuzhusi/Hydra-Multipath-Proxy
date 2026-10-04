//! Team-T：TCP/TLS 传输模式（节点侧，v1）
//!
//! 背景：某些网络对 UDP 回程 QoS 丢包导致 QUIC 不可用；TCP+TLS 完全绕开该问题
//! 且流量形态 = 普通 HTTPS。TCP 监听与 QUIC 的 UDP 监听并存、互不冲突
//! （`HYDRA_TCP_LISTEN` 未设置 = 不监听 TCP，行为零改动）。
//!
//! 线缆协议（TLS 建立后与 QUIC legacy 路径逐字节一致）：
//! `[64B v2 token] → [1B 模式标签 0x00] → [1B 地址长度 + 地址] → [2B 应答] → 双向裸转发`
//!
//! 认证 / SSRF 过滤 / DNS / 建连全部复用 handler 现有逻辑
//! （[`ConnectionHandler::tcp_auth_and_target`] 与 [`ConnectionHandler::resolve_and_connect`]）。
//!
//! **已知限制（v1，如实记录）**：
//! - 无多流聚合 / 无 ACK 机制（TCP 自带可靠有序传输，无需 QUIC 侧补偿）；
//! - obfs 混淆不适用于 TCP 模式（obfs 抽象的是 UDP socket）；
//! - 仅支持 v2 HMAC token 认证（无 v3 Noise 握手 / 通道绑定）；
//! - 无 QUIC 应用错误码通道：目标连接失败 / 认证失败一律静默关闭 TLS 流
//!   （与 QUIC 未认证路径的防探测语义一致，客户端读 EOF）。
use crate::handler::ConnectionHandler;
use hydra_protocol::{mask_target, Result};
use rustls::Certificate;
use rustls::PrivateKey;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};


/// 启动 TCP/TLS 监听（后台任务运行接受循环），返回实际绑定的本地地址。
/// 证书/密钥与 QUIC 路径同一份（cert.rs 产物）；不做 ALPN（流量形态 = 普通 HTTPS）。
pub async fn spawn_tcp_listener(
    addr: SocketAddr,
    cert: Certificate,
    key: PrivateKey,
    handler: Arc<ConnectionHandler>,
) -> Result<SocketAddr> {
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| {
            hydra_protocol::HydraError::ProtocolError(format!("TCP/TLS 证书配置失败: {}", e))
        })?;
    // 不做 ALPN：非标 ALPN 是单规则 DPI 指纹；留空 = 普通 HTTPS 客户端形态
    config.alpn_protocols = Vec::new();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!("Hydra TCP/TLS transport listening on {}", local);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls) => handle_tls_stream(tls, handler).await,
                            // 握手失败（扫描/探测）不回显任何信息，仅 debug 记录
                            Err(e) => debug!("TLS handshake from {} failed: {}", peer, e),
                        }
                    });
                }
                Err(e) => error!("TCP accept error: {}", e),
            }
        }
    });

    Ok(local)
}

/// 单条 TLS 流的服务：认证 → 地址帧 → 建目标 → 2B 应答 → 双向裸转发。
/// 认证失败 / 协议失步 / 目标失败 / 应答写失败：一律静默关闭（无错误码通道）。
async fn handle_tls_stream(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    handler: Arc<ConnectionHandler>,
) {
    let Some(target) = ConnectionHandler::tcp_auth_and_target(&mut tls, handler.auth_key()).await
    else {
        return; // 静默关闭（drop = TLS close_notify/FIN）
    };

    let mut target_stream = match ConnectionHandler::resolve_and_connect(&target).await {
        Ok(s) => s,
        Err((code, e)) => {
            debug!(
                "TCP path target failure (code 0x{:02x}), closing silently: {}",
                code, e
            );
            return;
        }
    };

    // 成功应答（与 QUIC legacy 路径一致：2B [0x00,0x00]）
    if tls.write_all(&[0x00, 0x00]).await.is_err() {
        return;
    }

    // 双向裸转发。copy_bidirectional 支持半关闭：一侧 EOF 时显式 shutdown 另一侧写端
    match tokio::io::copy_bidirectional(&mut tls, &mut target_stream).await {
        Ok((up, down)) => {
            info!(
                "TCP connection to {} closed (Client->Target: {} bytes, Target->Client: {} bytes)",
                mask_target(&target),
                up,
                down
            );
        }
        Err(e) => {
            debug!("TCP relay error for {}: {}", mask_target(&target), e);
        }
    }
}
