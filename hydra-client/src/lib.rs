pub mod nat;
pub mod proxy;
pub mod routing;
pub mod scheduler;
pub mod share_link;
pub mod speedtest;
pub mod subscription;
pub mod tcp_transport;
pub mod traffic;
pub mod transport;
// TUN 透明代理模式（feature = "tun"，见 tun.rs 模块文档）
#[cfg(feature = "tun")]
pub mod tun;

pub use nat::*;
pub use proxy::*;
pub use routing::*;
pub use scheduler::*;
pub use share_link::*;
pub use speedtest::*;
pub use subscription::*;
pub use tcp_transport::*;
pub use traffic::*;
#[cfg(feature = "tun")]
pub use tun::*;

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";

/// 从 HYDRA_AUTH_KEY 环境变量解析节点预共享认证密钥
pub fn auth_key_from_env() -> Result<Vec<u8>, String> {
    let hex_str = std::env::var("HYDRA_AUTH_KEY").map_err(|_| {
        "未设置 HYDRA_AUTH_KEY 环境变量（节点预共享密钥，hex 编码，解码后恰好 32 字节）".to_string()
    })?;
    auth_key_from_hex(&hex_str)
}

/// 从 hex 字符串解析认证密钥（必须恰好 32 字节——snow NNpsk2 的 PSK 长度约束，
/// 提前 fail-fast 而非让每条连接在握手期静默失败）
pub fn auth_key_from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let key = hydra_protocol::hex_decode(hex_str)?;
    if key.len() != 32 {
        return Err(format!(
            "认证密钥长度非法：解码后 {} 字节（必须恰好 32 字节，即 64 个 hex 字符；生成：openssl rand -hex 32）",
            key.len()
        ));
    }
    Ok(key)
}

/// 从 HYDRA_NODE_CERT 环境变量读取节点证书文件
pub fn node_certs_from_env() -> Result<Vec<Vec<u8>>, String> {
    let path = std::env::var("HYDRA_NODE_CERT").map_err(|_| {
        "未设置 HYDRA_NODE_CERT 环境变量（指向节点生成的 hydra-node-cert.der 证书文件，用于防止中间人）"
            .to_string()
    })?;
    let der = std::fs::read(&path).map_err(|e| format!("读取节点证书 {} 失败: {}", path, e))?;
    Ok(vec![der])
}

// ── TUN 公共入口（feature = "tun"）──────────────────────────────────────────
// 此前 CLI 专用的 TUN 接线（配置构造 / 环路检测 / 停机令牌）全部私有在 src/main.rs，
// GUI（hydra-client-gui，与代理同进程）无法复用。此处抽出轻量 pub 入口，
// CLI 行为不变（main.rs 私有版本保留），向后兼容。

/// GUI 场景的 TUN 配置构造：显式参数（非 env），豁免清单 = 节点 IP + 系统 DNS。
/// - `addr`：形如 "10.7.0.1/30"（可省略前缀，默认 /30）；None = 全默认
/// - `ports`：逗号分隔拦截端口列表；None = 默认 80,443,8080,8443
/// - 解析失败返回 Err（GUI 先行校验后仍需兜底，与 CLI 的「告警+回落默认」不同：
///   GUI 用户输入场景应显式报错而非静默换值）
#[cfg(feature = "tun")]
pub fn tun_config_from_settings(
    addr: Option<&str>,
    ports: Option<&str>,
    nodes: &[std::net::SocketAddr],
) -> std::result::Result<crate::tun::TunConfig, String> {
    use std::net::Ipv4Addr;
    let mut cfg = crate::tun::TunConfig::default();
    if let Some(s) = addr.map(str::trim).filter(|s| !s.is_empty()) {
        match s.split_once('/') {
            Some((ip, prefix)) => {
                let ip: Ipv4Addr = ip
                    .trim()
                    .parse()
                    .map_err(|e| format!("TUN 地址非法（应为形如 10.7.0.1/30）: {e}"))?;
                let prefix: u8 = prefix
                    .trim()
                    .parse()
                    .map_err(|e| format!("TUN 前缀长度非法: {e}"))?;
                // 审查 06-P2-9 同源约束：prefix>32 会使掩码计算下溢
                if prefix > 32 {
                    return Err(format!("TUN 前缀长度 {prefix} 非法（须 ≤32）"));
                }
                cfg.addr = ip;
                cfg.prefix = prefix;
            }
            None => {
                cfg.addr = s
                    .parse()
                    .map_err(|e| format!("TUN 地址非法（应为形如 10.7.0.1/30）: {e}"))?;
            }
        }
    }
    if let Some(s) = ports.map(str::trim).filter(|s| !s.is_empty()) {
        let list: Vec<u16> = s
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
        if list.is_empty() {
            return Err(format!("TUN 端口列表非法（应为逗号分隔端口，如 80,443,8080,8443）: {s}"));
        }
        cfg.listen_ports = list;
    }
    // 防环路关键：节点 IP 豁免（IPv4 /32；IPv6 节点进 v6 豁免清单），与 CLI 同构
    for n in nodes {
        match n.ip() {
            std::net::IpAddr::V4(ip) => cfg.exclude_routes.push(ip),
            std::net::IpAddr::V6(ip) => cfg.exclude_routes_v6.push(ip),
        }
    }
    // 系统 DNS 豁免（best-effort；v1 无 DNS 劫持，DNS 明文直出物理网卡）
    for dns in crate::tun::detect_dns_servers() {
        cfg.exclude_routes.push(dns);
    }
    Ok(cfg)
}

/// 为子进程命令附加 Windows `CREATE_NO_WINDOW (0x0800_0000)` 标志：
/// 后台调用 reg/route/netsh/ip 等系统命令时不再弹出控制台窗口。
/// 非 Windows 平台为 no-op（跨平台统一走本封装，调用方无需 cfg 门控）。
pub fn hide_console_window(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // 0x0800_0000 = CREATE_NO_WINDOW：不为子进程创建控制台窗口
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

/// Windows 系统代理是否已启用（HKCU Internet Settings ProxyEnable=0x1）。
/// TUN 全流量接管与系统代理叠加会形成环路，GUI 据此展示与 CLI 一致的告警。
/// 审查修复：精确比较 REG_DWORD 数值——此前 `contains("0x1")` 会把
/// "0x10"、"0x1f" 等值误判为开启（项目 winreg 依赖仅在 GUI crate，
/// 本 crate 保持 reg 子进程读取，但按行取末列做全等比较）。
#[cfg(all(windows, feature = "tun"))]
pub fn windows_system_proxy_enabled() -> bool {
    // CREATE_NO_WINDOW：避免 reg query 弹控制台窗口（GUI 曾因渲染路径每帧调用而狂闪）
    let mut cmd = std::process::Command::new("reg");
    cmd.args([
        "query",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v",
        "ProxyEnable",
    ]);
    crate::hide_console_window(&mut cmd)
        .output()
        .map(|o| {
            // reg query 输出形如 `    ProxyEnable    REG_DWORD    0x1`，
            // 取每行最后一个空白分隔字段与 "0x1" 全等比较
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|line| line.split_whitespace().last() == Some("0x1"))
        })
        .unwrap_or(false)
}

/// TUN 任务停机令牌类型别名（调用方无需直接依赖 tokio_util）
#[cfg(feature = "tun")]
pub type ShutdownToken = tokio_util::sync::CancellationToken;

/// TUN 任务停机令牌（tokio_util CancellationToken 组装点，此前为 main.rs 私有）。
/// GUI 代理线程用它在「停止代理」时同步取消 TUN 栈任务（RouteGuard Drop 清理路由）。
#[cfg(feature = "tun")]
pub fn new_tun_shutdown_token() -> tokio_util::sync::CancellationToken {
    tokio_util::sync::CancellationToken::new()
}

/// 从逗号分隔的证书文件路径列表读取多节点证书（`HYDRA_NODE_CERTS`）。
/// 顺序必须与节点地址顺序一一对应（仅用于 pin 模式信任根；Noise 指纹取对端
/// 叶证书，配对错误不再导致握手失败——审查 R-02 的根治补全）。
pub fn node_certs_from_paths(paths: &str) -> Result<Vec<Vec<u8>>, String> {
    paths
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| std::fs::read(p).map_err(|e| format!("读取节点证书 {} 失败: {}", p, e)))
        .collect()
}

#[cfg(test)]
mod tun_settings_tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn tun_settings_defaults() {
        // 全 None → 库默认（10.7.0.1/30 + 80,443,8080,8443）
        let cfg = tun_config_from_settings(None, None, &[]).unwrap();
        assert_eq!(cfg.addr, std::net::Ipv4Addr::new(10, 7, 0, 1));
        assert_eq!(cfg.prefix, 30);
        assert_eq!(cfg.listen_ports, vec![80, 443, 8080, 8443]);
        // 空串等价 None（GUI 未填写场景）
        let cfg = tun_config_from_settings(Some("  "), Some("  "), &[]).unwrap();
        assert_eq!(cfg.prefix, 30);
        assert_eq!(cfg.listen_ports, vec![80, 443, 8080, 8443]);
    }

    #[test]
    fn tun_settings_parse_addr_ports() {
        let cfg = tun_config_from_settings(Some("10.9.9.1/24"), Some("80, 443"), &[]).unwrap();
        assert_eq!(cfg.addr, std::net::Ipv4Addr::new(10, 9, 9, 1));
        assert_eq!(cfg.prefix, 24);
        assert_eq!(cfg.listen_ports, vec![80, 443]);
        // 裸 IP（无前缀）→ 默认 /30
        let cfg = tun_config_from_settings(Some("10.9.9.1"), None, &[]).unwrap();
        assert_eq!(cfg.prefix, 30);
    }

    #[test]
    fn tun_settings_rejects_bad_input() {
        assert!(tun_config_from_settings(Some("10.7.0.1/33"), None, &[]).is_err());
        assert!(tun_config_from_settings(Some("no-host/30"), None, &[]).is_err());
        assert!(tun_config_from_settings(None, Some("http,abc"), &[]).is_err());
    }

    #[test]
    fn tun_settings_excludes_node_ips() {
        let nodes = vec![
            "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            "[::1]:443".parse::<SocketAddr>().unwrap(),
        ];
        let cfg = tun_config_from_settings(None, None, &nodes).unwrap();
        assert!(cfg.exclude_routes.contains(&std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(cfg.exclude_routes_v6.len(), 1);
    }
}
