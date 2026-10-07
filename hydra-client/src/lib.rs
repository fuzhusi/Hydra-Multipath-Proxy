//! Hydra 桌面客户端库（Windows/Linux/macOS CLI + GUI 共用入口）。
//!
//! v0.3.0 起，平台无关的核心逻辑抽取至 [`hydra-core`]（docs/design/
//! 移动端Android方案-v2.md §3，Android uniffi 共用同一核心）。本 crate 保留：
//! - 全量 re-export（GUI/CLI 既有 `hydra_client::…` 引用路径不变）
//! - 桌面专有封装：env 凭据读取、TUN 设备/系统路由（tun.rs）、Windows 系统代理
//!   检测、CREATE_NO_WINDOW 等
//! - `tun_config_from_settings` 等 TUN 配置构造（依赖 tun.rs 类型，故留桌面）

pub use hydra_core::{
    auth_key_from_hex, node_certs_from_paths,
    // 内容级 re-export（各模块 pub use 于 core::lib 已展开为平铺项）
    channel::*, connections::*, nat::*, proxy::*, routing::*, scheduler::*, share_link::*,
    speedtest::*, subscription::*, tcp_transport::*, traffic::*, udp_relay::*,
};
// 模块路径同样保留（`hydra_client::proxy::ProxyServer` 等既有引用）
pub use hydra_core::{channel, connections, nat, proxy, routing, scheduler, share_link, speedtest,
    subscription, tcp_transport, traffic, transport, udp_relay};

// TUN 透明代理模式（feature = "tun"，见 tun.rs 模块文档；Android 不复用本模块，
// 其 tun_core 为按评审 R1-R4 增强的独立实现）
#[cfg(feature = "tun")]
pub mod tun;

#[cfg(feature = "tun")]
pub use tun::*;

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub use hydra_core::transport::DEFAULT_SNI;

/// 从 HYDRA_AUTH_KEY 环境变量解析节点预共享认证密钥
pub fn auth_key_from_env() -> Result<Vec<u8>, String> {
    let hex_str = std::env::var("HYDRA_AUTH_KEY").map_err(|_| {
        "未设置 HYDRA_AUTH_KEY 环境变量（节点预共享密钥，hex 编码，解码后恰好 32 字节）".to_string()
    })?;
    auth_key_from_hex(&hex_str)
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
    // UDP 接管/DNS 直连开关（09 交付，与 CLI 同构）：HYDRA_TUN_UDP=0 关 UDP 接管；
    // HYDRA_TUN_DNS_DIRECT=1 恢复 DNS 直连（默认经隧道）
    if let Ok(v) = std::env::var("HYDRA_TUN_UDP") {
        if v.trim() == "0" {
            cfg.udp_relay = false;
        }
    }
    if let Ok(v) = std::env::var("HYDRA_TUN_DNS_DIRECT") {
        if v.trim() == "1" {
            cfg.dns_via_proxy = false;
        }
    }
    // 系统 DNS 豁免：DNS 经隧道开启时**不再**自动豁免——公网 DNS 查询随 UDP
    // 隧道经节点解析（加密，TUN 方案 v2 方向）；DNS 直连模式（v1 行为或显式
    // HYDRA_TUN_DNS_DIRECT=1）照旧豁免。v4+v6 都在覆盖内。
    if !cfg.udp_relay || !cfg.dns_via_proxy {
        for dns in crate::tun::detect_dns_servers() {
            cfg.exclude_routes.push(dns);
        }
        for dns in crate::tun::detect_dns_servers_v6() {
            cfg.exclude_routes_v6.push(dns);
        }
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

// ── 双实例互斥（09-P3-5）────────────────────────────────────────────────────

/// 双实例互斥守卫：持有即代表本进程是唯一实例（守卫 drop / 进程退出自动释放）。
/// 实现为**绑定固定回环端口**的进程锁——内核保证端口独占，比锁文件可靠
/// （崩溃残留的锁文件会永久阻塞下次启动，端口随进程死自动归还）。
pub struct InstanceGuard {
    _listener: std::net::TcpListener,
}

/// CLI TUN 模式互斥端口：两个 TUN 实例会争抢同一 TUN 网卡与 /1 接管路由
/// （第二实例路由失败半途退出虽安全，但期间路由可能指向错误适配器）。
pub const INSTANCE_PORT_CLI_TUN: u16 = 52810;
/// GUI 互斥端口：双 GUI 实例会并发写配置（虽已 pid 唯一化）且互相抢系统代理
/// 开关状态，单实例语义更安全。
pub const INSTANCE_PORT_GUI: u16 = 52811;

/// 尝试取得实例互斥。已有一实例在运行 → Err（携带用户可读信息）；
/// 其余绑定错误原样透传。守卫须由调用方保存到 main 作用域直至退出。
pub fn acquire_instance_guard(port: u16) -> Result<InstanceGuard, String> {
    std::net::TcpListener::bind(("127.0.0.1", port))
        .map(|listener| InstanceGuard { _listener: listener })
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                format!("已有 Hydra 实例在运行（互斥端口 {port} 被占用）——请先退出已有实例；\
                         若确认没有，可能是其他程序占用了该端口")
            } else {
                format!("实例互斥端口 {port} 绑定失败: {e}")
            }
        })
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
