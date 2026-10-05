//! TCP 转型（Wave 3）后的节点连接处理器：QUIC/UDP 路径已整体移除，
//! TCP/TLS 成为唯一传输。本模块保留：
//!
//! - [`ConnectionHandler`]：Noise-PSK 握手所需的认证密钥 / 证书指纹 / 认证模式
//! - [`ConnectionHandler::resolve_and_connect`]：目标解析（字面 IP / 节点侧 DNS）
//!   + SSRF 过滤 + 目标 TCP 建连（tcp_server 路径复用）
//! - SSRF 目标过滤私有函数与其单测
//!
//! 原 QUIC 专属代码（handle_connection(quinn)、handle_stream、channel/UpOrderer/
//! ChannelShared、ACK 节流等）已随 QUIC/UDP 死路径一并删除。

use hydra_protocol::handshake::AuthMode;
use hydra_protocol::{mask_target, HydraError};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

// ── 已认证后的应用层错误码（tcp_server 映射到 2B 私有帧应答码）──
/// 0x11：节点无法连接目标（连接被拒/超时/SSRF 拒绝）
pub const ERR_TARGET_CONNECT: u32 = 0x11;
/// 0x12：节点侧 DNS 解析失败
pub const ERR_DNS_FAIL: u32 = 0x12;

// ── SSRF 目标过滤（遗留 P1-3）──
// 已认证客户端可能把节点当跳板攻击内网服务或云元数据端点（169.254.169.254）。
// 对字面 IP 与 DNS 解析结果统一在 TCP 连接前检查，命中即拒绝。

/// `HYDRA_ALLOW_PRIVATE_TARGETS=1` 时放开私有目标（测试基线依赖 127.0.0.1 回显服务器）。
/// 默认拒绝。每次调用读取 env（per-stream 一次，相对网络 IO 开销可忽略），
/// 使测试可在进程内随时打开，无初始化顺序陷阱。
fn private_targets_allowed() -> bool {
    matches!(
        std::env::var("HYDRA_ALLOW_PRIVATE_TARGETS"),
        Ok(v) if v == "1"
    )
}

/// SSRF 黑名单判定：命中返回原因（供脱敏日志），未命中返回 None。
/// 覆盖：loopback（127.0.0.0/8、::1）、链路本地（169.254.0.0/16、fe80::/10）、
/// RFC1918 私网（10/8、172.16/12、192.168/16）、0.0.0.0/8、IPv6 未指定地址（::）
/// 与 IPv6 ULA（fc00::/7，RFC1918 的 IPv6 对应物）；
/// IPv4 映射地址（::ffff:a.b.c.d）与 NAT64（64:ff9b::/96）内嵌 IPv4 一并复查，防绕过。
fn classify_blocked_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.octets()[0] == 0 {
                Some("this-network 0.0.0.0/8")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_private() {
                Some("RFC1918 private")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d 等价于对应 IPv4 目标，按 IPv4 规则复查
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_blocked_ip(IpAddr::V4(v4));
            }
            // NAT64 64:ff9b::/96：尾 4 字节内嵌 IPv4，按 IPv4 规则复查
            let seg = v6.segments();
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return classify_blocked_ip(IpAddr::V4(v4));
            }
            if v6.is_loopback() {
                Some("loopback")
            } else if (seg[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if (seg[0] & 0xfe00) == 0xfc00 {
                Some("IPv6 ULA private")
            } else if v6.is_unspecified() {
                Some("unspecified ::")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[test]
    fn loopback_blocked() {
        assert_eq!(
            classify_blocked_ip("127.0.0.1".parse().unwrap()),
            Some("loopback")
        );
        // 127.0.0.0/8 全段
        assert_eq!(
            classify_blocked_ip("127.9.9.9".parse().unwrap()),
            Some("loopback")
        );
        assert_eq!(
            classify_blocked_ip("::1".parse().unwrap()),
            Some("loopback")
        );
    }

    #[test]
    fn link_local_blocked() {
        assert_eq!(
            classify_blocked_ip("169.254.169.254".parse().unwrap()),
            Some("link-local")
        );
        assert_eq!(
            classify_blocked_ip("fe80::1".parse().unwrap()),
            Some("link-local")
        );
    }

    #[test]
    fn rfc1918_blocked() {
        assert_eq!(
            classify_blocked_ip("10.1.2.3".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("172.16.0.1".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("172.31.255.255".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("192.168.1.1".parse().unwrap()),
            Some("RFC1918 private")
        );
        // 172.16/12 边界外不误伤
        assert_eq!(classify_blocked_ip("172.32.0.1".parse().unwrap()), None);
    }

    #[test]
    fn unspecified_blocked() {
        assert_eq!(
            classify_blocked_ip("0.0.0.0".parse().unwrap()),
            Some("this-network 0.0.0.0/8")
        );
        assert_eq!(
            classify_blocked_ip("::".parse().unwrap()),
            Some("unspecified ::")
        );
    }

    #[test]
    fn ipv6_ula_blocked() {
        assert_eq!(
            classify_blocked_ip("fd00::1".parse().unwrap()),
            Some("IPv6 ULA private")
        );
        assert_eq!(
            classify_blocked_ip("fc00::1".parse().unwrap()),
            Some("IPv6 ULA private")
        );
    }

    #[test]
    fn embedded_ipv4_rechecked() {
        // IPv4 映射：内嵌回环/私网/链路本地必须被拦下（绕过向量）
        assert_eq!(
            classify_blocked_ip("::ffff:127.0.0.1".parse().unwrap()),
            Some("loopback")
        );
        assert_eq!(
            classify_blocked_ip("::ffff:169.254.169.254".parse().unwrap()),
            Some("link-local")
        );
        // NAT64 内嵌
        assert_eq!(
            classify_blocked_ip("64:ff9b::a00:1".parse().unwrap()),
            Some("RFC1918 private")
        );
        // 内嵌公网 IPv4 不拦
        assert_eq!(classify_blocked_ip("::ffff:8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn public_targets_pass() {
        assert_eq!(classify_blocked_ip("8.8.8.8".parse().unwrap()), None);
        assert_eq!(classify_blocked_ip("1.1.1.1".parse().unwrap()), None);
        assert_eq!(
            classify_blocked_ip("2606:4700::1111".parse().unwrap()),
            None
        );
    }
}

/// TCP/TLS 节点路径的连接处理器：持有认证材料，供 tcp_server 的
/// Noise-PSK 握手与 SSRF 过滤 / 目标建连复用。
pub struct ConnectionHandler {
    auth_key: Vec<u8>,
    /// 本节点证书 SHA-256 指纹：v3 握手 confirm 通道绑定材料（server.rs 注入）
    cert_fp: [u8; 32],
    /// 认证模式（启动时读一次 env；评审 P1-3：勿在每流热路径读 env）
    auth_mode: AuthMode,
}

impl ConnectionHandler {
    pub fn new(auth_key: Vec<u8>, cert_fp: [u8; 32], auth_mode: AuthMode) -> Self {
        Self {
            auth_key,
            cert_fp,
            auth_mode,
        }
    }

    /// 预共享认证密钥（TCP/TLS 路径 Noise-PSK 握手使用）
    pub(crate) fn auth_key(&self) -> &[u8] {
        &self.auth_key
    }

    /// 节点证书 SHA-256 指纹（TCP/TLS 路径 v3 握手通道绑定材料）
    pub(crate) fn cert_fingerprint(&self) -> &[u8; 32] {
        &self.cert_fp
    }

    /// 认证模式（TCP/TLS 路径判定是否接受 v3 握手）
    pub(crate) fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// 解析目标地址（字面 IP 或节点侧 DNS）并执行 SSRF 过滤 + 建立目标 TCP。
    /// 错误返回 (应用错误码, 已格式化错误)：0x12=DNS 失败、0x11=SSRF 拒绝/无法连接/超时。
    /// TCP/TLS 路径（tcp_server）复用同一函数——SSRF 过滤对 TCP 路径同样生效（强制门④）。
    pub(crate) async fn resolve_and_connect(
        target_addr_str: &str,
    ) -> std::result::Result<TcpStream, (u32, HydraError)> {
        // 日志脱敏（防追踪性）：info 级一律短哈希，完整明文仅 debug 级（RUST_LOG=debug）可见
        info!("Received target address: {}", mask_target(target_addr_str));
        debug!("Received target address (plaintext): {}", target_addr_str);

        // ── 解析为 SocketAddr，否则节点侧 DNS 解析
        let target_addr: SocketAddr = if let Ok(addr) = target_addr_str.parse() {
            addr
        } else {
            info!("Resolving DNS for: {}", mask_target(target_addr_str));
            match tokio::net::lookup_host(target_addr_str.to_string()).await {
                Ok(addrs) => {
                    let addrs_vec: Vec<_> = addrs.collect();
                    // 优先使用 IPv4 地址
                    let ipv4_addr = addrs_vec.iter().find(|a| a.is_ipv4());
                    match ipv4_addr {
                        Some(a) => *a,
                        None => match addrs_vec.first() {
                            Some(a) => *a,
                            None => {
                                error!(
                                    "DNS resolution failed for {}: no addresses",
                                    mask_target(target_addr_str)
                                );
                                debug!("DNS resolution failed (plaintext): {}", target_addr_str);
                                return Err((
                                    ERR_DNS_FAIL,
                                    HydraError::ConnectionError(format!(
                                        "DNS resolution failed for {}",
                                        mask_target(target_addr_str)
                                    )),
                                ));
                            }
                        },
                    }
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", mask_target(target_addr_str), e);
                    debug!("DNS resolution failed (plaintext): {}", target_addr_str);
                    return Err((
                        ERR_DNS_FAIL,
                        HydraError::ConnectionError(format!(
                            "DNS resolution failed for {}: {}",
                            mask_target(target_addr_str), e
                        )),
                    ));
                }
            }
        };

        info!(
            "Connecting to target: {} (with 15s timeout)",
            mask_target(&target_addr.to_string())
        );

        // ── SSRF 目标过滤（遗留 P1-3）：字面 IP 与 DNS 解析结果统一复查，命中即拒绝。
        // 默认拒绝；HYDRA_ALLOW_PRIVATE_TARGETS=1 放开（测试基线依赖 127.0.0.1 回显服务器）。
        if !private_targets_allowed() {
            if let Some(reason) = classify_blocked_ip(target_addr.ip()) {
                // 脱敏日志：只记短哈希，不落目标明文
                warn!(
                    "Blocked SSRF target (private/reserved: {}): {}",
                    reason,
                    mask_target(&target_addr.to_string())
                );
                // 走既有 0x11 错误路径（与"无法连接目标"同码，不给探测者额外指纹）
                return Err((
                    ERR_TARGET_CONNECT,
                    HydraError::ConnectionError(format!(
                        "Target blocked (private/reserved: {})",
                        reason
                    )),
                ));
            }
        }

        let connect_start = std::time::Instant::now();

        // Connect to target with timeout（须小于客户端 20s 应答超时，否则慢目标被误判为节点故障）
        match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(target_addr),
        )
        .await
        {
            Ok(Ok(mut stream)) => {
                // 禁 Nagle：目标侧交互式流量延迟敏感（审查 R-11）
                let _ = stream.set_nodelay(true);
                let elapsed = connect_start.elapsed();
                info!(
                    "Connected to target: {} (took {}ms)",
                    mask_target(&target_addr.to_string()),
                    elapsed.as_millis()
                );
                Ok(stream)
            }
            Ok(Err(e)) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Failed to connect to {}: {} (took {}ms)",
                    mask_target(&target_addr.to_string()),
                    e,
                    elapsed.as_millis()
                );
                Err((
                    ERR_TARGET_CONNECT,
                    HydraError::TargetUnreachable(format!(
                        "Failed to connect to {}: {}",
                        mask_target(&target_addr.to_string()),
                        e
                    )),
                ))
            }
            Err(_) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Timeout connecting to {} ({}ms)",
                    mask_target(&target_addr.to_string()),
                    elapsed.as_millis()
                );
                Err((
                    ERR_TARGET_CONNECT,
                    HydraError::TargetUnreachable(format!(
                        "Timeout connecting to {}",
                        mask_target(&target_addr.to_string())
                    )),
                ))
            }
        }
    }
}
