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
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
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
/// 默认拒绝。安全分审查 P3-1（Wave 3 修复）：安全边界改为进程内首次调用时固化
/// （OnceLock）——此前每次调用读 env，同机进程可在节点运行期间实时改变安全边界；
/// 测试仍可在进程内首次调用前设置 env 注入。
fn private_targets_allowed() -> bool {
    static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ALLOW.get_or_init(|| {
        matches!(
            std::env::var("HYDRA_ALLOW_PRIVATE_TARGETS"),
            Ok(v) if v == "1"
        )
    })
}

/// SSRF 黑名单判定（审查 09-P2-5 起为本仓库唯一实现源：UDP 中继路径复用本
/// 函数，不再镜像维护）：命中返回原因（供脱敏日志），未命中返回 None。
/// 覆盖：loopback（127.0.0.0/8、::1）、链路本地（169.254.0.0/16、fe80::/10）、
/// RFC1918 私网（10/8、172.16/12、192.168/16）、0.0.0.0/8、IPv6 未指定地址（::）
/// 与 IPv6 ULA（fc00::/7，RFC1918 的 IPv6 对应物）；
/// 运营商级 NAT（CGNAT 100.64.0.0/10，RFC6598）、基准测试网段（198.18.0.0/15，
/// RFC2544）、组播（224.0.0.0/4）与保留段（240.0.0.0/4，含 255.255.255.255 广播）
/// ——审查 N-06 补段（纵深防御）；
/// 文档/特殊用途段（192.0.0.0/24 RFC6890、TEST-NET-1/2/3 RFC5737）——09-P3 补齐；
/// IPv6 组播（ff00::/8）与文档段（2001:db8::/32）——09-P2-5 补齐（此前仅 UDP
/// 镜像侧有，两侧已收敛为单源）；
/// 全部内嵌 IPv4 形态（IPv4 映射 ::ffff:a.b.c.d、NAT64 64:ff9b::/96、IPv4 兼容
/// ::/96、::ffff:0:0/96——07-P2-1 补齐后两段）的尾 4 字节均按 IPv4 规则复查，防绕过。
pub(crate) fn classify_blocked_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 0 {
                Some("this-network 0.0.0.0/8")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_private() {
                Some("RFC1918 private")
            } else if o[0] == 100 && (64..=127).contains(&o[1]) {
                // CGNAT 100.64.0.0/10（RFC6598）：运营商内网，目标同样不可达且属内网面
                Some("CGNAT 100.64.0.0/10")
            } else if o[0] == 198 && (18..=19).contains(&o[1]) {
                // 基准测试网段 198.18.0.0/15（RFC2544）
                Some("benchmarking 198.18.0.0/15")
            } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
                // 192.0.0.0/24（IETF 协议分配，RFC 6890）
                Some("special 192.0.0.0/24")
            } else if o[0] == 192 && o[1] == 0 && o[2] == 2 {
                // TEST-NET-1（RFC 5737）
                Some("documentation TEST-NET-1 192.0.2.0/24")
            } else if o[0] == 198 && o[1] == 51 && o[2] == 100 {
                // TEST-NET-2（RFC 5737）
                Some("documentation TEST-NET-2 198.51.100.0/24")
            } else if o[0] == 203 && o[1] == 0 && o[2] == 113 {
                // TEST-NET-3（RFC 5737）
                Some("documentation TEST-NET-3 203.0.113.0/24")
            } else if o[0] & 0xf0 == 0xe0 {
                // 组播 224.0.0.0/4（is_multicast，显式写出便于审阅）
                Some("multicast 224.0.0.0/4")
            } else if o[0] & 0xf0 == 0xf0 {
                // 保留段 240.0.0.0/4（含受限广播 255.255.255.255）
                Some("reserved 240.0.0.0/4")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d 等价于对应 IPv4 目标，按 IPv4 规则复查
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_blocked_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            // 07-P2-1：除 IPv4 映射与 NAT64 外，::/96（IPv4 兼容段，如 ::127.0.0.1，
            // Linux 内核按 v4 兼容语义处理）与 ::ffff:0:0/96（部分栈/NAT64 同样按
            // 内嵌 IPv4 处理）两段的尾 4 字节同样按 IPv4 规则复查
            if let Some(v4) = embedded_ipv4_of_v6(seg) {
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
            } else if (seg[0] & 0xff00) == 0xff00 {
                // IPv6 组播 ff00::/8（审查 09-P2-5：与 IPv4 组播拦截对称）
                Some("IPv6 multicast ff00::/8")
            } else if (seg[0] & 0xff00) == 0x2000 && seg[1] == 0x0db8 {
                // 文档段 2001:db8::/32（RFC 3849）。注意段值是 0x0db8——此前
                // 镜像实现误写 0x01db，该分支从未命中（09 审查测试暴露）
                Some("documentation 2001:db8::/32")
            } else {
                None
            }
        }
    }
}

/// 07-P2-1：提取 IPv6 地址（非 ::ffff:a.b.c.d 映射形态）中按内嵌 IPv4 语义
/// 解释的尾 4 字节。覆盖三类前缀：
/// - `::/96`（IPv4 兼容）：前 96 位全 0；
/// - `::ffff:0:0/96`（RFC 2765 IPv4-translated）：seg[4]==0xffff 且 seg[5]==0；
/// - `64:ff9b::/96`（NAT64）。
///
/// 命中返回重组的 `Ipv4Addr`，由调用方递归按 IPv4 规则复查。
pub(crate) fn embedded_ipv4_of_v6(seg: [u16; 8]) -> Option<Ipv4Addr> {
    let v4 = Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        (seg[6] & 0xff) as u8,
        (seg[7] >> 8) as u8,
        (seg[7] & 0xff) as u8,
    );
    // ::/96（前 6 组全 0）——排除未指定地址 :: 与环回 ::1（二者是 IPv6 特殊地址，
    // 由 classify_blocked_ip 的专属分支处理，不按内嵌 IPv4 解释）
    if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && seg[7] <= 1) {
        return Some(v4);
    }
    // ::ffff:0:0/96（RFC 2765 IPv4-translated，如 ::ffff:0:7f00:1 → [0,0,0,0,ffff,0,7f00,1]）
    if seg[0..4].iter().all(|&s| s == 0) && seg[4] == 0xffff && seg[5] == 0 {
        return Some(v4);
    }
    // 64:ff9b::/96（NAT64）
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
        return Some(v4);
    }
    None
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

        // ── 解析为候选地址列表：字面 IP 单候选；域名 → 节点侧 DNS，v4 优先
        // 稳定排序 + 去重（逐候选建连见下方循环——Happy Eyeballs 式回落）
        let candidates: Vec<SocketAddr> = if let Ok(addr) = target_addr_str.parse() {
            vec![addr]
        } else {
            info!("Resolving DNS for: {}", mask_target(target_addr_str));
            // 内核优化 #6：共享 DNS 缓存 + 全局解析并发闸（负缓存 10s 防
            // 解析器故障期间每连接重打；并发 64 封顶 blocking 池占用）。
            // 解析超时/负缓存归入既有 ERR_DNS_FAIL(0x02) 路径，维持
            // DNS 5s < connect 15s < 20s 层次。
            let dns_start = std::time::Instant::now();
            let host = target_addr_str
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(target_addr_str);
            match crate::dns_cache::resolve_host_cached(host).await {
                None => {
                    error!(
                        "DNS resolution failed (timeout/negative cache) for {}",
                        mask_target(target_addr_str)
                    );
                    debug!("DNS resolution failed (plaintext): {}", target_addr_str);
                    crate::metrics::metrics()
                        .hs_dns
                        .observe(dns_start.elapsed().as_secs_f64());
                    return Err((
                        ERR_DNS_FAIL,
                        HydraError::ConnectionError(format!(
                            "DNS resolution failed for {}",
                            mask_target(target_addr_str)
                        )),
                    ));
                }
                Some(addrs) => {
                    crate::metrics::metrics()
                        .hs_dns
                        .observe(dns_start.elapsed().as_secs_f64());
                    let ordered = order_candidates(addrs);
                    if ordered.is_empty() {
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
                    ordered
                }
            }
        };

        // ── SSRF 目标过滤（遗留 P1-3）：逐候选复查（每个候选都可能被连接），
        // 命中即剔除；全部命中才拒绝（部分合法候选仍可服务）。默认拒绝；
        // HYDRA_ALLOW_PRIVATE_TARGETS=1 放开（测试基线依赖 127.0.0.1 回显服务器）。
        let candidates: Vec<SocketAddr> = if private_targets_allowed() {
            candidates
        } else {
            let mut allowed = Vec::with_capacity(candidates.len());
            let mut first_block: Option<&'static str> = None;
            for addr in candidates {
                match classify_blocked_ip(addr.ip()) {
                    Some(reason) => {
                        if first_block.is_none() {
                            first_block = Some(reason);
                        }
                    }
                    None => allowed.push(addr),
                }
            }
            if allowed.is_empty() {
                let reason = first_block.unwrap_or("private/reserved");
                // 脱敏日志：只记短哈希，不落目标明文
                warn!(
                    "Blocked SSRF target (private/reserved: {}): {}",
                    reason,
                    mask_target(target_addr_str)
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
            allowed
        };

        info!(
            "Connecting to target: {} ({} candidate(s), 15s total timeout)",
            mask_target(target_addr_str),
            candidates.len()
        );

        let connect_start = std::time::Instant::now();

        // 逐候选建连（v4 优先）：15s 总预算摊给全部候选，单候选失败即时换下一个
        // ——双栈节点单族路由故障不再致命；中间失败 debug 级（v4-only 节点的
        // v6 候选秒败不再刷 error，降噪），仅最终失败 error 级。
        const CONNECT_TOTAL: std::time::Duration = std::time::Duration::from_secs(15);
        const MIN_ATTEMPT: std::time::Duration = std::time::Duration::from_millis(500);
        let mut last_err: Option<HydraError> = None;
        for candidate in &candidates {
            let remaining = CONNECT_TOTAL.saturating_sub(connect_start.elapsed());
            if remaining < MIN_ATTEMPT {
                break; // 预算耗尽：不再尝试（避免超时叠加突破客户端 20s 预算）
            }
            debug!(
                "Trying candidate: {} (budget {}ms)",
                mask_target(&candidate.to_string()),
                remaining.as_millis()
            );
            match tokio::time::timeout(remaining, TcpStream::connect(candidate)).await {
                Ok(Ok(stream)) => {
                    // 禁 Nagle：目标侧交互式流量延迟敏感（审查 R-11）
                    let _ = stream.set_nodelay(true);
                    // Metrics v2：目标建连延迟直方图
                    crate::metrics::metrics().hs_target.observe(
                        connect_start.elapsed().as_secs_f64(),
                    );
                    info!(
                        "Connected to target: {} (took {}ms)",
                        mask_target(&candidate.to_string()),
                        connect_start.elapsed().as_millis()
                    );
                    return Ok(stream);
                }
                Ok(Err(e)) => {
                    debug!(
                        "Candidate unreachable: {}: {}",
                        mask_target(&candidate.to_string()),
                        e
                    );
                    last_err = Some(HydraError::TargetUnreachable(format!(
                        "Failed to connect to {}: {}",
                        mask_target(&candidate.to_string()),
                        e
                    )));
                }
                Err(_) => {
                    debug!("Candidate timeout: {}", mask_target(&candidate.to_string()));
                    last_err = Some(HydraError::TargetUnreachable(format!(
                        "Timeout connecting to {}",
                        mask_target(&candidate.to_string())
                    )));
                }
            }
        }

        let err = last_err.unwrap_or_else(|| {
            HydraError::TargetUnreachable(format!(
                "Timeout connecting to {}",
                mask_target(target_addr_str)
            ))
        });
        error!(
            "Failed to reach target {} ({} candidate(s), took {}ms)",
            mask_target(target_addr_str),
            candidates.len(),
            connect_start.elapsed().as_millis()
        );
        Err((ERR_TARGET_CONNECT, err))
    }
}

/// DNS 解析结果整理为建连候选序列：IPv4 优先（稳定排序，同族内保留解析器
/// 顺序）+ 全量去重（HashSet retain 保序去重——`dedup()` 只删相邻重复，
/// 解析器可能返回非相邻重复）。v6-only 目标保留 v6 候选（无 v4 时仍可达）；
/// v4 优先使 v4-only VPS 不再先撞 v6（配合 [`crate::dns_aaaa`] 的 DNS AAAA
/// 本地过滤，双保险消除 ENETUNREACH 噪音）。
fn order_candidates(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by_key(|a| !a.is_ipv4());
    let mut seen = std::collections::HashSet::new();
    addrs.retain(|a| seen.insert(*a));
    addrs
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
        // 07-P2-1：::/96 IPv4 兼容段与 ::ffff:0:0/96 段的内嵌 IPv4 同样复查
        assert_eq!(
            classify_blocked_ip("::127.0.0.1".parse().unwrap()),
            Some("loopback"),
            "::/96 内嵌回环必须被拦下"
        );
        assert_eq!(
            classify_blocked_ip("::10.0.0.1".parse().unwrap()),
            Some("RFC1918 private"),
            "::/96 内嵌私网必须被拦下"
        );
        assert_eq!(
            classify_blocked_ip("::ffff:0:7f00:1".parse().unwrap()),
            Some("loopback"),
            "::ffff:0:0/96 内嵌回环必须被拦下"
        );
        // ::/96 与 ::ffff:0:0/96 的公网内嵌地址不拦
        assert_eq!(classify_blocked_ip("::8.8.8.8".parse().unwrap()), None);
        assert_eq!(
            classify_blocked_ip("::ffff:0:808:808".parse().unwrap()),
            None
        );
        // 未指定地址 :: 不属于内嵌 IPv4（仍由 is_unspecified 分支拦截）
        assert_eq!(
            classify_blocked_ip("::".parse().unwrap()),
            Some("unspecified ::")
        );
        // 内嵌公网 IPv4 不拦
        assert_eq!(classify_blocked_ip("::ffff:8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn new_segments_blocked() {
        // 审查 N-06 补段：CGNAT / 基准测试 / 组播 / 保留段（含广播）
        assert_eq!(
            classify_blocked_ip("100.64.0.1".parse().unwrap()),
            Some("CGNAT 100.64.0.0/10")
        );
        assert_eq!(
            classify_blocked_ip("100.127.255.254".parse().unwrap()),
            Some("CGNAT 100.64.0.0/10")
        );
        // 100.64/10 边界外不误伤（100.128.0.0 属公网段）
        assert_eq!(classify_blocked_ip("100.128.0.1".parse().unwrap()), None);
        assert_eq!(classify_blocked_ip("100.63.255.254".parse().unwrap()), None);
        assert_eq!(
            classify_blocked_ip("198.18.0.1".parse().unwrap()),
            Some("benchmarking 198.18.0.0/15")
        );
        assert_eq!(
            classify_blocked_ip("198.19.255.255".parse().unwrap()),
            Some("benchmarking 198.18.0.0/15")
        );
        assert_eq!(classify_blocked_ip("198.20.0.1".parse().unwrap()), None);
        assert_eq!(
            classify_blocked_ip("224.0.0.1".parse().unwrap()),
            Some("multicast 224.0.0.0/4")
        );
        assert_eq!(
            classify_blocked_ip("239.255.255.250".parse().unwrap()),
            Some("multicast 224.0.0.0/4")
        );
        assert_eq!(
            classify_blocked_ip("240.0.0.1".parse().unwrap()),
            Some("reserved 240.0.0.0/4")
        );
        assert_eq!(
            classify_blocked_ip("255.255.255.255".parse().unwrap()),
            Some("reserved 240.0.0.0/4")
        );
        // 组播/保留段边界外不误伤
        assert_eq!(
            classify_blocked_ip("223.255.255.254".parse().unwrap()),
            None
        );
    }

    #[test]
    fn documentation_segments_blocked() {
        // 09-P3 补段：TEST-NET-1/2/3 + 192.0.0.0/24
        assert_eq!(
            classify_blocked_ip("192.0.2.1".parse().unwrap()),
            Some("documentation TEST-NET-1 192.0.2.0/24")
        );
        assert_eq!(
            classify_blocked_ip("198.51.100.7".parse().unwrap()),
            Some("documentation TEST-NET-2 198.51.100.0/24")
        );
        assert_eq!(
            classify_blocked_ip("203.0.113.9".parse().unwrap()),
            Some("documentation TEST-NET-3 203.0.113.0/24")
        );
        assert_eq!(
            classify_blocked_ip("192.0.0.1".parse().unwrap()),
            Some("special 192.0.0.0/24")
        );
        // 段外不误伤（198.51.101.x 与 203.0.114.x 属公网）
        assert_eq!(classify_blocked_ip("198.51.101.1".parse().unwrap()), None);
        assert_eq!(classify_blocked_ip("203.0.114.1".parse().unwrap()), None);
        // 09-P2-5 补段：IPv6 组播与 2001:db8（此前仅 UDP 镜像侧有）
        assert_eq!(
            classify_blocked_ip("ff02::1".parse().unwrap()),
            Some("IPv6 multicast ff00::/8")
        );
        assert_eq!(
            classify_blocked_ip("2001:db8::1".parse().unwrap()),
            Some("documentation 2001:db8::/32")
        );
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

    #[test]
    fn candidates_v4_first_stable_and_deduped() {
        let parse = |s: &str| s.parse::<SocketAddr>().unwrap();
        // 解析器典型输出（v6 混排在前）：v4 提前，同族内顺序保持
        let ordered = order_candidates(vec![
            parse("[2001:4860:4860::8888]:443"),
            parse("8.8.8.8:443"),
            parse("[2606:4700::1111]:443"),
            parse("8.8.4.4:443"),
        ]);
        assert_eq!(
            ordered,
            vec![
                parse("8.8.8.8:443"),
                parse("8.8.4.4:443"),
                parse("[2001:4860:4860::8888]:443"),
                parse("[2606:4700::1111]:443"),
            ]
        );
        // v6-only 目标：候选保留（无 v4 时仍可达）
        let only_v6 = order_candidates(vec![parse("[2001:db8::1]:443")]);
        assert_eq!(only_v6, vec![parse("[2001:db8::1]:443")]);
        // 去重（解析器可能返回重复地址，含**非相邻**重复——dedup 只删相邻，
        // 必须 HashSet 保序去重）
        let dup = order_candidates(vec![
            parse("8.8.8.8:443"),
            parse("8.8.4.4:443"),
            parse("8.8.8.8:443"),
            parse("[2001:db8::1]:443"),
            parse("8.8.8.8:443"),
        ]);
        assert_eq!(
            dup,
            vec![
                parse("8.8.8.8:443"),
                parse("8.8.4.4:443"),
                parse("[2001:db8::1]:443"),
            ]
        );
        // 空列表安全
        assert!(order_candidates(vec![]).is_empty());
    }
}
