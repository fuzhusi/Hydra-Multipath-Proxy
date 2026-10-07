//! TUN 透明代理模式（docs/design/TUN模式方案.md，v1）。
//!
//! 职责：
//! 1. [`TunConfig`] + [`compute_routes`]：纯函数计算「路由豁免清单」——
//!    `0.0.0.0/1` + `128.0.0.0/1` → TUN，节点 IP / DNS / TUN 网段豁免回物理网关，
//!    以及一一对应的幂等清理命令（[`RoutePlan`]）。
//! 2. [`RouteExecutor`]：路由命令执行抽象（真实 `route`/`ip route` 命令 / dry-run），
//!    测试用 fake executor 断言命令清单，不真跑。
//! 3. [`PacketTransport`] + [`run_stack`]：smoltcp 用户态 TCP/IP 栈主循环。
//!    TUN 设备收发与「栈侧」解耦为 trait，测试可用通道在单进程内对接两个
//!    smoltcp Interface 做回环验证，无需真实 TUN 设备。
//! 4. [`run_tun`]：真实设备接线（tun2 → Wintun/TUN）+ 路由应用 + drop guard 清理。
//!
//! v1 完整版边界（如实声明）：
//! - **仅 TCP 转发**：UDP（含 QUIC/HTTP3）不代理——IPv4 UDP 回 **ICMPv4 port
//!   unreachable**（type 3 / code 3，含正确校验和），应用立即失败回落 TCP；
//!   非 TCP 的 IPv6 包同理回 ICMPv6 destination unreachable。
//! - **IPv6 正向路径**：smoltcp 启用 proto-ipv6，v6 TCP 由栈直接代理。注意
//!   smoltcp 0.11 的 any-ip 仅作用于 IPv4（iface/interface/ipv6.rs 的入站过滤
//!   只认接口自身地址），因此对 v6 采用**动态 AnyIP**：入站 v6 TCP 包的目的
//!   地址临时挂为接口 /128 地址（有界池 + 活跃流保护，见 [`ensure_v6_dst`]）。
//!   `ipv6_enabled` 默认 **true**（栈能正转，接管才有意义）；关闭时 v6 走
//!   旧快速失败路径（SYN 回 RST、其余 ICMPv6 不可达），应用回落 IPv4。
//! - **无 DNS 劫持 / fake-IP**：DNS 服务器走豁免路由直出物理网卡。
//! - **smoltcp 无通配监听**：只能按端口 LISTEN，v1 拦截常用 TCP 端口列表
//!   （默认 80/443/8080/8443，`HYDRA_TUN_PORTS` 覆盖）。未在列表内的端口
//!   smoltcp 会回 RST，应用表现为连接被拒——v1 已知限制。
//! - **无域名分流**：TUN 拿不到域名，全部流量经节点（CN 分流退化为全走节点）。
//! - **v6 目标字符串格式**：形如 `[2001:db8::1]:443`（`SocketAddr` 标准形式，
//!   节点侧 `parse::<SocketAddr>` 可直解）；v4 仍为 `ip:port`。
//!
//! 真实设备路径（Wintun 全链路、路由生效、退出清理、真机 v6 接管的 netsh +
//! 管理员验证）需管理员运行，**人工验证**，见 README 部署指南指引。

use hydra_protocol::{mask_target, HydraError, Result};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// ── 配置 ─────────────────────────────────────────────────────────────────────

/// TUN 模式配置
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// TUN 虚拟网卡 IPv4 地址（默认 10.7.0.1，HYDRA_TUN_ADDR 可覆盖）
    pub addr: Ipv4Addr,
    /// TUN 网段前缀长度（默认 /30）
    pub prefix: u8,
    /// TUN MTU（方案定为 1500：65535 对用户态栈无意义且浪费内存）
    pub mtu: u16,
    /// 路由豁免 IP（/32 回物理网关）：节点 IP、系统 DNS 等，防代理环路
    pub exclude_routes: Vec<Ipv4Addr>,
    /// IPv6 豁免 IP（/128 回物理网关 v6）：节点 IPv6 地址等（0-4 IPv6 防泄漏）
    pub exclude_routes_v6: Vec<Ipv6Addr>,
    /// TUN 虚拟网卡 IPv6 网关占位地址（v6 接管路由 `via` 指向它；
    /// HYDRA_TUN_ADDR6 可覆盖。默认 ULA 段 fd07::1，与 v4 的 10.7.0.1 对称）
    pub addr6: Ipv6Addr,
    /// IPv6 接管开关（v1 完整版默认 **true**）：栈已启用 proto-ipv6，v6 TCP 走
    /// 正向代理路径（动态 AnyIP，见 [`ensure_v6_dst`]）；`HYDRA_TUN_IPV6=0` 可关。
    /// 关闭时 v6 包全部快速失败（TCP SYN 回 RST、其余回 ICMPv6 不可达），
    /// 应用回落 IPv4；节点 IPv6 豁免照旧生效。
    pub ipv6_enabled: bool,
    /// 并发流上限（超限对新流回 RST，防资源耗尽）
    pub max_flows: usize,
    /// smoltcp LISTEN 端口列表（smoltcp 无通配监听，v1 已知限制，见模块注释）
    pub listen_ports: Vec<u16>,
    /// UDP-over-proxy 接管开关（09 交付：默认 **true**）——公网目标的 UDP
    /// （含 QUIC/HTTP3/DNS）经节点 UDP 中继转发（加密隧道）；私网/组播/广播
    /// 目标照旧不入隧道。关闭（`HYDRA_TUN_UDP=0`）时恢复 v1 行为：公网 UDP
    /// 代答 ICMP port unreachable 引导应用回落 TCP。
    pub udp_relay: bool,
    /// 系统 DNS 经隧道开关（默认 **true**）：UDP 接管生效时，探测到的公网系统
    /// DNS **不再**自动豁免出物理网卡，DNS 查询随隧道经节点解析（加密、无明文
    /// 泄漏——TUN 方案 v2 方向的实现）。`HYDRA_TUN_DNS_DIRECT=1` 恢复 v1 直连
    /// 行为；用户显式指定的 `HYDRA_TUN_DNS` 恒豁免（可能是内网 resolver）。
    pub dns_via_proxy: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::new(10, 7, 0, 1),
            prefix: 30,
            mtu: 1500,
            exclude_routes: Vec::new(),
            exclude_routes_v6: Vec::new(),
            addr6: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
            // v1 完整版：proto-ipv6 栈 + 动态 AnyIP 正向路径就绪，默认开启
            ipv6_enabled: true,
            max_flows: 512,
            // 常用明文/加密 Web 端口；其余端口需 HYDRA_TUN_PORTS 扩展
            listen_ports: vec![80, 443, 8080, 8443],
            udp_relay: true,
            dns_via_proxy: true,
        }
    }
}

impl TunConfig {
    /// TUN 网段的网络地址（如 10.7.0.1/30 → 10.7.0.0）
    pub fn network(&self) -> Ipv4Addr {
        let mask = prefix_to_mask(self.prefix);
        Ipv4Addr::new(
            self.addr.octets()[0] & mask[0],
            self.addr.octets()[1] & mask[1],
            self.addr.octets()[2] & mask[2],
            self.addr.octets()[3] & mask[3],
        )
    }

    /// 空闲流超时（300s，方案 §2）
    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
}

/// 前缀长度 → 掩码
fn prefix_to_mask(prefix: u8) -> [u8; 4] {
    // 审查 06-P2-9：prefix>32 时 `32 - prefix` 下溢——debug 构建 panic（启动 TUN
    // 即崩，而此时设备已建）、release 回绕成错误掩码。做双保险：钳制到 ≤32。
    let shift = 32u32.saturating_sub(prefix.min(32) as u32);
    let v = if prefix == 0 { 0 } else { !0u32 << shift };
    v.to_be_bytes()
}

// ── 路由豁免清单（纯函数，必测）──────────────────────────────────────────────

/// 路由命令动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Add,
    Delete,
}

/// 一条结构化路由命令：目标网段 + 网关（豁免/接管）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCmd {
    pub dest: Ipv4Addr,
    pub prefix: u8,
    /// 下一跳网关（Windows `route add` 必填；TUN 网段用 TUN 自身地址做网关）
    pub gateway: Ipv4Addr,
}

impl RouteCmd {
    /// Windows `route add/delete <ip> mask <mask> <gw> metric <n>` 参数
    pub fn windows_args(&self, action: RouteAction) -> Vec<String> {
        let mut args = vec![
            match action {
                RouteAction::Add => "add".to_string(),
                RouteAction::Delete => "delete".to_string(),
            },
            self.dest.to_string(),
            "mask".to_string(),
            prefix_to_mask(self.prefix).map(|o| o.to_string()).join("."),
            self.gateway.to_string(),
        ];
        if action == RouteAction::Add {
            // metric 1：比物理默认路由更精确/更优即生效（接管两条 /1）
            args.push("metric".to_string());
            args.push("1".to_string());
        }
        args
    }

    /// Linux `ip route add/delete <dest/prefix> via <gw>` 参数
    pub fn linux_args(&self, action: RouteAction) -> Vec<String> {
        vec![
            match action {
                RouteAction::Add => "add".to_string(),
                RouteAction::Delete => "delete".to_string(),
            },
            format!("{}/{}", self.dest, self.prefix),
            "via".to_string(),
            self.gateway.to_string(),
        ]
    }
}

/// 路由方案：添加清单 + 一一对应的幂等删除清单
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutePlan {
    pub add: Vec<RouteCmd>,
    /// 与 `add` 同序的删除命令（退出/崩溃后幂等清理用）
    pub remove: Vec<RouteCmd>,
}

/// 计算路由豁免清单（纯函数）。
///
/// - `0.0.0.0/1`、`128.0.0.0/1` → TUN（比默认路由 /0 更精确即接管全流量）
/// - TUN 自身网段 → 经 TUN 地址（直连，Windows route 需显式网关指向 TUN 地址）
/// - 每个 exclude IP /32 → 物理网关（None 时跳过豁免项——没有物理网关就无法
///   生成豁免命令，调用方应先 [`detect_physical_gateway`] 或要求 `HYDRA_TUN_GW`）
pub fn compute_routes(tun: &TunConfig, physical_gw: Option<Ipv4Addr>) -> RoutePlan {
    // 审查 06-P2-10：TUN 网段直连路由仅 Windows 需要——Linux 内核在配置 TUN
    // 地址后已自动生成 connected route，显式 `via <本机TUN地址>` 会被内核以
    // EINVAL（Nexthop has invalid gateway）拒绝；而 apply_routes 部分失败即整体
    // 回滚，这条必然失败的命令会让 Linux 上 TUN 启动 100% 失败。
    compute_routes_for(tun, physical_gw, cfg!(windows))
}

/// `include_subnet_direct` 显式参数版（供测试确定性地构造含/不含网段直连的方案）
pub fn compute_routes_for(
    tun: &TunConfig,
    physical_gw: Option<Ipv4Addr>,
    include_subnet_direct: bool,
) -> RoutePlan {
    let mut add = Vec::new();
    // 1. 接管路由：两条 /1 覆盖整个 IPv4 空间且比 /0 更精确
    add.push(RouteCmd {
        dest: Ipv4Addr::new(0, 0, 0, 0),
        prefix: 1,
        gateway: tun.addr,
    });
    add.push(RouteCmd {
        dest: Ipv4Addr::new(128, 0, 0, 0),
        prefix: 1,
        gateway: tun.addr,
    });
    // 2. TUN 网段直连（保证 TUN 子网内部通信不绕行；仅 Windows，见 compute_routes）
    if include_subnet_direct {
        add.push(RouteCmd {
            dest: tun.network(),
            prefix: tun.prefix,
            gateway: tun.addr,
        });
    }
    // 3. 豁免清单：/32 回物理网关（节点 IP / DNS —— 防环路关键）
    if let Some(gw) = physical_gw {
        for ip in &tun.exclude_routes {
            add.push(RouteCmd {
                dest: *ip,
                prefix: 32,
                gateway: gw,
            });
        }
        // 09-P2-1：私网段豁免——TUN /1 接管覆盖 RFC1918/CGNAT，而这些目标的
        // 流量进 TUN 后会被节点的 SSRF 过滤 fail-closed 拒绝（对应用表现为
        // "能上外网但访问不了路由器/NAS 等内网设备"且无日志解释）。按
        // "与无 VPN 时一致"的语义豁免回物理网关（TUN 自身网段 /30 更精确，
        // 不受影响）。节点本就不接受私网目标，豁免无功能损失。
        for (dest, prefix) in PRIVATE_EXCLUDE_V4 {
            add.push(RouteCmd { dest, prefix, gateway: gw });
        }
    } else if !tun.exclude_routes.is_empty() {
        warn!(
            "物理网关未知，{} 条豁免路由未能生成——代理到节点的流量可能形成环路！\
             请设置 HYDRA_TUN_GW 或确认默认网关可解析",
            tun.exclude_routes.len()
        );
    }
    let remove = add.to_vec();
    RoutePlan { add, remove }
}

/// 私网段豁免路由（09-P2-1）：RFC1918 全部三段 + CGNAT 100.64/10
const PRIVATE_EXCLUDE_V4: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

// ── IPv6 路由方案（0-4 防泄漏：与 v4 对称的接管/豁免清单）────────────────────

/// 一条结构化 IPv6 路由命令（与 v4 [`RouteCmd`] 对称）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCmdV6 {
    pub dest: Ipv6Addr,
    pub prefix: u8,
    /// 下一跳网关（接管路由 = TUN 自身 v6 地址；豁免路由 = 物理网关 v6）
    pub gateway: Ipv6Addr,
}

impl RouteCmdV6 {
    /// Linux `ip -6 route add/delete <dest/prefix> via <gw>` 参数
    pub fn linux_args(&self, action: RouteAction) -> Vec<String> {
        vec![
            "-6".to_string(),
            "route".to_string(),
            match action {
                RouteAction::Add => "add".to_string(),
                RouteAction::Delete => "delete".to_string(),
            },
            format!("{}/{}", self.dest, self.prefix),
            "via".to_string(),
            self.gateway.to_string(),
        ]
    }

    /// Windows `netsh interface ipv6 add/delete route <pfx>/<len> interface=<if>`
    /// 参数（Windows `route` 命令不支持 IPv6，只能走 netsh，且必须给接口名——
    /// 取 `HYDRA_TUN_IF`；未设置返回 None，由执行器按"失败告警"路径处理）
    pub fn windows_args(&self, action: RouteAction, ifname: &str) -> Vec<String> {
        vec![
            "interface".to_string(),
            "ipv6".to_string(),
            match action {
                RouteAction::Add => "add".to_string(),
                RouteAction::Delete => "delete".to_string(),
            },
            "route".to_string(),
            format!("{}/{}", self.dest, self.prefix),
            "interface=".to_string() + ifname,
        ]
    }
}

/// IPv6 路由方案：添加清单 + 一一对应的幂等删除清单（可为空 = 未启用/无网关）
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutePlanV6 {
    pub add: Vec<RouteCmdV6>,
    /// 与 `add` 同序的删除命令（退出/崩溃后幂等清理用）
    pub remove: Vec<RouteCmdV6>,
}

/// 计算 IPv6 路由方案（纯函数，与 [`compute_routes`] 对称）。
///
/// - `ipv6_enabled == false` → 返回空方案（不生成任何命令）。默认 **true**
///   （09 补正：`TunConfig::default` 为 true，`HYDRA_TUN_IPV6=0` 显式关闭；
///   本注释此前误写"默认 false"，与实现相反）；
/// - 接管：`::/1` + `8000::/1` → TUN（比 v6 默认路由 /0 更精确即接管全 v6 空间）；
/// - 豁免：每个 exclude v6 IP /128 → 物理网关 v6（None 时跳过豁免项并告警——
///   与 v4 同语义：没有网关就无法生成豁免命令）；
/// - **try-and-warn 语义在执行侧**（[`apply_routes_v6_try`]）：本函数只产出方案。
pub fn compute_routes_v6(tun: &TunConfig, physical_gw6: Option<Ipv6Addr>) -> RoutePlanV6 {
    let mut add: Vec<RouteCmdV6> = Vec::new();
    if tun.ipv6_enabled {
        // 接管：两条 /1 覆盖整个 IPv6 空间（::/1 与 8000::/1 各半）
        add.push(RouteCmdV6 {
            dest: Ipv6Addr::UNSPECIFIED,
            prefix: 1,
            gateway: tun.addr6,
        });
        add.push(RouteCmdV6 {
            dest: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
            prefix: 1,
            gateway: tun.addr6,
        });
        // 豁免：节点 IPv6 地址 /128 回物理网关 v6
        if let Some(gw) = physical_gw6 {
            for ip in &tun.exclude_routes_v6 {
                add.push(RouteCmdV6 {
                    dest: *ip,
                    prefix: 128,
                    gateway: gw,
                });
            }
            // 09-P2-1：ULA fc00::/7 豁免（与 v4 RFC1918 对称；fe80::/10 链路
            // 本地由内核直连处理，无需显式路由）
            add.push(RouteCmdV6 {
                dest: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                prefix: 7,
                gateway: gw,
            });
        } else if !tun.exclude_routes_v6.is_empty() {
            warn!(
                "物理网关（IPv6）未知，{} 条 v6 豁免路由未能生成——代理到 v6 节点的流量可能环路",
                tun.exclude_routes_v6.len()
            );
        }
    }
    let remove = add.to_vec();
    RoutePlanV6 { add, remove }
}

// ── 路由命令执行（可注入 dry-run）────────────────────────────────────────────

/// 路由命令执行器抽象（测试注入 fake，不真跑系统命令）
pub trait RouteExecutor: Send + Sync {
    fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()>;

    /// IPv6 路由命令执行（与 v4 `run` 分离：v6 失败走 try-and-warn，不阻断启动）
    fn run6(&self, action: RouteAction, cmd: &RouteCmdV6) -> std::io::Result<()>;
}

/// 真实执行器：Windows `route` / Linux `ip route`（需管理员/root）
pub struct SystemRouteExecutor;

impl RouteExecutor for SystemRouteExecutor {
    fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            let args = cmd.windows_args(action);
            debug!("route {}", args.join(" "));
            // CREATE_NO_WINDOW：TUN 路由操作不弹控制台窗口
            let mut c = std::process::Command::new("route");
            c.args(&args);
            let out = crate::hide_console_window(&mut c).output()?;
            if !out.status.success() {
                return Err(std::io::Error::other(format!(
                    "route {} 失败: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        #[cfg(unix)]
        {
            let args = cmd.linux_args(action);
            debug!("ip route {}", args.join(" "));
            let out = std::process::Command::new("ip")
                .args(["route"])
                .args(&args)
                .output()?;
            if !out.status.success() {
                return Err(std::io::Error::other(format!(
                    "ip route {} 失败: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (action, cmd);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN 路由配置不支持当前平台",
            ))
        }
    }

    fn run6(&self, action: RouteAction, cmd: &RouteCmdV6) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            // Windows 的 `route` 命令不支持 IPv6，只能 netsh + 接口名；
            // 接口名取 HYDRA_TUN_IF（Wintun 适配器名），未设置则按失败处理
            // （调用方告警"IPv6 未接管"，不阻断启动）。
            let ifname = std::env::var("HYDRA_TUN_IF").unwrap_or_default();
            if ifname.trim().is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Windows 下 IPv6 接管需设置 HYDRA_TUN_IF（TUN 适配器名，netsh 需要）",
                ));
            }
            let args = cmd.windows_args(action, ifname.trim());
            debug!("netsh {}", args.join(" "));
            // CREATE_NO_WINDOW：netsh IPv6 路由操作不弹控制台窗口
            let mut c = std::process::Command::new("netsh");
            c.args(&args);
            let out = crate::hide_console_window(&mut c).output()?;
            if !out.status.success() {
                return Err(std::io::Error::other(format!(
                    "netsh {} 失败: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        #[cfg(unix)]
        {
            let args = cmd.linux_args(action);
            debug!("ip {}", args.join(" "));
            let out = std::process::Command::new("ip").args(&args).output()?;
            if !out.status.success() {
                return Err(std::io::Error::other(format!(
                    "ip {} 失败: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = (action, cmd);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN IPv6 路由配置不支持当前平台",
            ))
        }
    }
}

/// dry-run 执行器：记录命令清单（单测断言用），不真跑
#[derive(Default)]
pub struct DryRunExecutor {
    pub commands: Mutex<Vec<String>>,
}

impl RouteExecutor for DryRunExecutor {
    fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()> {
        let line = format!(
            "{:?} {}/{} via {}",
            action, cmd.dest, cmd.prefix, cmd.gateway
        );
        self.commands.lock().unwrap().push(line);
        Ok(())
    }

    fn run6(&self, action: RouteAction, cmd: &RouteCmdV6) -> std::io::Result<()> {
        let line = format!(
            "v6 {:?} {}/{} via {}",
            action, cmd.dest, cmd.prefix, cmd.gateway
        );
        self.commands.lock().unwrap().push(line);
        Ok(())
    }
}

/// 应用添加清单（全部成功才算成功；任一条失败立即对已成功部分执行幂等删除
/// 回滚——半接管状态（/1 已生效但无人读设备）会让整机流量进黑洞且进程退出后
/// 残留，比不接管更糟）
pub fn apply_routes(exec: &dyn RouteExecutor, plan: &RoutePlan) -> std::io::Result<()> {
    for (i, cmd) in plan.add.iter().enumerate() {
        if let Err(e) = exec.run(RouteAction::Add, cmd) {
            // 回滚已成功添加的前缀（best-effort；残留由下次启动幂等清理兜底）
            for prev in &plan.add[..i] {
                if let Err(e2) = exec.run(RouteAction::Delete, prev) {
                    warn!("回滚路由 {}/{} 失败: {}", prev.dest, prev.prefix, e2);
                }
            }
            return Err(e);
        }
    }
    Ok(())
}

/// 退出/任务结束时的幂等清理（best-effort，逐条删除并记录失败）。
///
/// P3-7 修复：**/1 接管路由最先删除**（危害最大者先行）——Windows
/// CTRL_CLOSE_EVENT 只有约 5s 宽限，串行 spawn `route delete`（每条数十至百余
/// ms）+ `netsh` v6（数百 ms）可能超时被强杀；把两条 /1 放最前保证即使中途被
/// 杀，最致命的「整机流量进 TUN」路由必已摘除，残留的只是无害豁免项。
/// v6 计划由 [`cleanup_routes_v6`] 同语义处理。
pub fn cleanup_routes(exec: &dyn RouteExecutor, plan: &RoutePlan) {
    for cmd in takeover_first(&plan.remove) {
        if let Err(e) = exec.run(RouteAction::Delete, cmd) {
            // 忽略单条失败（残留路由由下次启动幂等清理兜底，方案 §2/§5）
            warn!("清理路由 {}/{} 失败: {}", cmd.dest, cmd.prefix, e);
        }
    }
}

/// 排序：前缀 ≤1（即 /1 与 /0 级接管路由）排最前，其余保持原相对顺序（稳定）
fn takeover_first<T>(cmds: &[T]) -> impl Iterator<Item = &T>
where
    T: AsTakeover,
{
    let mut idx: Vec<usize> = (0..cmds.len()).collect();
    idx.sort_by_key(|&i| !cmds[i].is_takeover());
    idx.into_iter().map(move |i| &cmds[i])
}

/// 接管路由判定（前缀 ≤1 = 覆盖半边地址空间的接管项，清理时优先）
trait AsTakeover {
    fn is_takeover(&self) -> bool;
}
impl AsTakeover for RouteCmd {
    fn is_takeover(&self) -> bool {
        self.prefix <= 1
    }
}
impl AsTakeover for RouteCmdV6 {
    fn is_takeover(&self) -> bool {
        self.prefix <= 1
    }
}

/// IPv6 路由 try-and-warn 应用（0-4 语义核心）：逐条添加，**任一条失败只告警、
/// 绝不回滚、绝不阻断启动**。理由：v6 接管是"防泄漏增益"而非"可用性前提"——
/// 若因 v6 命令失败放弃整个 TUN 启动，v4 防泄漏一并丢失；若像 v4 一样回滚，
/// 泄漏面反而更大。失败时调用方（run_tun）会追加"IPv6 未接管，存在泄漏"告警。
/// 返回失败条数（0 = 全部成功）。
pub fn apply_routes_v6_try(exec: &dyn RouteExecutor, plan: &RoutePlanV6) -> usize {
    let mut failed = 0;
    for cmd in &plan.add {
        if let Err(e) = exec.run6(RouteAction::Add, cmd) {
            failed += 1;
            warn!(
                "IPv6 接管路由 {}/{} 添加失败（忽略，仅告警）: {}",
                cmd.dest, cmd.prefix, e
            );
        }
    }
    failed
}

/// IPv6 路由幂等清理（best-effort，与 v4 cleanup_routes 对称）。
/// P3-7 同语义：::/1 + 8000::/1 接管路由最先删；豁免 /128 残留无害。
pub fn cleanup_routes_v6(exec: &dyn RouteExecutor, plan: &RoutePlanV6) {
    for cmd in takeover_first(&plan.remove) {
        if let Err(e) = exec.run6(RouteAction::Delete, cmd) {
            warn!("清理 IPv6 路由 {}/{} 失败: {}", cmd.dest, cmd.prefix, e);
        }
    }
}

/// drop guard：任务任何路径退出（含 panic 展开）都执行幂等删除
/// （v4 计划必清；v6 计划可选——None 表示未启用 IPv6 接管）
pub struct RouteGuard {
    exec: Arc<dyn RouteExecutor>,
    plan: RoutePlan,
    plan6: Option<RoutePlanV6>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.exec.as_ref(), &self.plan);
        if let Some(p6) = &self.plan6 {
            cleanup_routes_v6(self.exec.as_ref(), p6);
        }
    }
}

// ── 物理网关 / DNS 探测（best-effort）───────────────────────────────────────

/// 探测物理网卡默认网关。优先 `HYDRA_TUN_GW` 环境变量；否则：
/// Windows 解析 `route print -4 0.0.0.0`，Linux 解析 `/proc/net/route`。
/// 失败返回 None（调用方据此报错或跳过豁免项）。
pub fn detect_physical_gateway() -> Option<Ipv4Addr> {
    if let Ok(s) = std::env::var("HYDRA_TUN_GW") {
        if let Ok(ip) = s.trim().parse() {
            return Some(ip);
        }
    }
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW：网关探测不弹控制台窗口
        let mut c = std::process::Command::new("route");
        c.args(["print", "-4", "0.0.0.0"]);
        if let Ok(out) = crate::hide_console_window(&mut c).output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let toks: Vec<&str> = line.split_whitespace().collect();
                // 路由表行格式：0.0.0.0  0.0.0.0  <网关>  <接口>  <metric>
                if toks.len() >= 3 && toks[0] == "0.0.0.0" && toks[1] == "0.0.0.0" {
                    if let Ok(ip) = toks[2].parse::<Ipv4Addr>() {
                        if ip != Ipv4Addr::UNSPECIFIED {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    #[cfg(unix)]
    {
        // /proc/net/route：Iface Destination Gateway Flags ...（十六进制，CPU 字节序）
        if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() > 2 && cols[1] == "00000000" {
                    if let Ok(raw) = u32::from_str_radix(cols[2], 16) {
                        let b = raw.to_le_bytes();
                        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                        if ip != Ipv4Addr::UNSPECIFIED {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    None
}

/// best-effort 探测物理网关的 IPv6 地址（v6 豁免路由用）。
/// `HYDRA_TUN_GW6` 优先；Windows 解析 `route print -6` 的 `::/0` 行，
/// Linux 解析 `ip -6 route show default`。失败返回 None（豁免项跳过，仅告警）。
pub fn detect_physical_gateway_v6() -> Option<Ipv6Addr> {
    if let Ok(s) = std::env::var("HYDRA_TUN_GW6") {
        if let Ok(ip) = s.trim().parse::<Ipv6Addr>() {
            if !ip.is_unspecified() {
                return Some(ip);
            }
        }
    }
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW：IPv6 网关探测不弹控制台窗口
        let mut c = std::process::Command::new("route");
        c.args(["print", "-6"]);
        if let Ok(out) = crate::hide_console_window(&mut c).output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let toks: Vec<&str> = line.split_whitespace().collect();
                // ::/0 行形如 `::/0  <gateway>  ...`；网关列是能解析的 v6 且非 ::
                if toks.first() == Some(&"::/0") {
                    for tok in toks.iter().skip(1) {
                        if let Ok(ip) = tok.parse::<Ipv6Addr>() {
                            if !ip.is_unspecified() {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for tok in text.split_whitespace() {
                // 形如 `default via  fe80::1 dev eth0`（部分 iproute2 无空格差异）。
                // parse 返回 Result（非 Option）——CI Linux 编译错误修复
                if let Ok(ip) = tok.trim_start_matches("via").parse::<Ipv6Addr>() {
                    if !ip.is_unspecified() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// best-effort 探测系统 DNS 服务器（豁免路由用：DNS 明文直出物理网卡，方案 §1 非目标）。
/// `HYDRA_TUN_DNS`（逗号分隔，v4/v6 均可）优先；Windows 解析注册表
/// NameServer/DhcpNameServer 行，Linux 解析 /etc/resolv.conf。
///
/// 09-P3-7 修复：只取 **NameServer 行**并按 v4/v6 分桶——此前对 reg query 全量
/// 输出"凡能解析成 IPv4 的 token 都收"，DhcpIPAddress/第三方虚拟适配器地址等
/// 非 DNS 值也被收进豁免清单（各生成一条 /32 豁免路由，可能覆盖同网段
/// on-link 路由）；v6 DNS（如 2001:4860:4860::8888）此前完全缺失——v6 DNS
/// over UDP 被 TUN 代答回不可达（纯 v6 网络断网观感），over TCP 却被代理。
pub fn detect_dns_servers() -> Vec<Ipv4Addr> {
    detect_dns_all().0
}

/// 系统 IPv6 DNS 服务器（09-P2-4：与 v4 对称进入 v6 豁免清单）
pub fn detect_dns_servers_v6() -> Vec<Ipv6Addr> {
    detect_dns_all().1
}

/// v4/v6 DNS 探测合一（`HYDRA_TUN_DNS` > Windows 注册表 > /etc/resolv.conf）
fn detect_dns_all() -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4_out = Vec::new();
    let mut v6_out = Vec::new();
    let push = |tok: &str, v4: &mut Vec<Ipv4Addr>, v6: &mut Vec<Ipv6Addr>| {
        match tok.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                if !v4.contains(&ip) {
                    v4.push(ip);
                }
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                if !v6.contains(&ip) {
                    v6.push(ip);
                }
            }
            Err(_) => {}
        }
    };
    if let Ok(s) = std::env::var("HYDRA_TUN_DNS") {
        let mut any = false;
        for p in s.split(',') {
            let before_v4 = v4_out.len();
            let before_v6 = v6_out.len();
            push(p.trim(), &mut v4_out, &mut v6_out);
            if v4_out.len() != before_v4 || v6_out.len() != before_v6 {
                any = true;
            }
        }
        if any {
            return (v4_out, v6_out);
        }
    }
    #[cfg(windows)]
    {
        // reg query 递归导出各接口 DNS；仅取含 "NameServer" 的行（静态 NameServer
        // 与 DhcpNameServer），行内按空白/逗号切分 token 后逐个尝试解析
        // CREATE_NO_WINDOW：DNS 探测不弹控制台窗口
        let mut c = std::process::Command::new("reg");
        c.args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            "/s",
        ]);
        if let Ok(outp) = crate::hide_console_window(&mut c).output() {
            let text = String::from_utf8_lossy(&outp.stdout);
            for line in text.lines() {
                if !line.contains("NameServer") {
                    continue;
                }
                for tok in line.split([' ', '\t', ',']) {
                    push(tok.trim(), &mut v4_out, &mut v6_out);
                }
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if it.next() == Some("nameserver") {
                    if let Some(tok) = it.next() {
                        push(tok, &mut v4_out, &mut v6_out);
                    }
                }
            }
        }
    }
    (v4_out, v6_out)
}

// ── 代理通道开启器（实现见 hydra_core::proxy::ProxyServer::tun_channel_opener）──
// trait 抽象平台无关，已下沉 hydra-core::channel（Android tun_core 复用同一接口）；
// 此处 re-export 维持本模块既有引用路径 `tun::ChannelOpener` 等不变。
pub use hydra_core::channel::{ChannelOpener, OpenFuture, ProxyDuplex};

// ── TUN 包传输抽象（设备与栈解耦；测试用通道对接两个 smoltcp Interface）──────

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// TUN 设备包传输：recv 收一个裸 IP 包（包边界），send 发一个裸 IP 包
pub trait PacketTransport: Send + Sync + 'static {
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFut<'a, std::io::Result<usize>>;
    fn send<'a>(&'a self, buf: &'a [u8]) -> BoxFut<'a, std::io::Result<()>>;
}

/// tun2 真实设备适配（Windows: Wintun，需 wintun.dll 随包；Linux: /dev/net/tun）
pub struct Tun2Transport {
    dev: Arc<tun2::AsyncDevice>,
}

impl Tun2Transport {
    pub fn new(dev: tun2::AsyncDevice) -> Self {
        Self { dev: Arc::new(dev) }
    }
}

impl PacketTransport for Tun2Transport {
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFut<'a, std::io::Result<usize>> {
        Box::pin(async move {
            self.dev
                .recv(buf)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }

    fn send<'a>(&'a self, buf: &'a [u8]) -> BoxFut<'a, std::io::Result<()>> {
        Box::pin(async move {
            self.dev
                .send(buf)
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }
}

// ── smoltcp 栈侧 ─────────────────────────────────────────────────────────────

/// 进程内单调时钟 → smoltcp Instant（smoltcp 时间以毫秒计，无 from_std）
fn smol_now() -> SmolInstant {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

/// 通道化 smoltcp Device：入站队列由主循环投喂，出站队列由主循环排空写回 TUN。
/// （队列指针在 Device 与主循环间共享，Send/Sync 安全。）
struct ChanDevice {
    inbound: SharedQueue,
    outbound: SharedQueue,
    mtu: usize,
}

/// 共享队列类型别名（clippy type_complexity：Arc<Mutex<VecDeque<Vec<u8>>>> 三处复用）
type SharedQueue = Arc<Mutex<VecDeque<Vec<u8>>>>;

impl ChanDevice {
    fn new(mtu: usize) -> (Self, SharedQueue, SharedQueue) {
        let inbound = Arc::new(Mutex::new(VecDeque::new()));
        let outbound = Arc::new(Mutex::new(VecDeque::new()));
        let dev = Self {
            inbound: inbound.clone(),
            outbound: outbound.clone(),
            mtu,
        };
        (dev, inbound, outbound)
    }

    fn push_inbound(&self, pkt: &[u8]) {
        self.inbound.lock().unwrap().push_back(pkt.to_vec());
    }

    fn drain_outbound(&self) -> Vec<Vec<u8>> {
        self.outbound.lock().unwrap().drain(..).collect()
    }
}

impl Device for ChanDevice {
    type RxToken<'a> = ChanRx;
    type TxToken<'a> = ChanTx;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.inbound.lock().unwrap().pop_front()?;
        Some((
            ChanRx(Some(frame)),
            ChanTx {
                queue: self.outbound.clone(),
            },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChanTx {
            queue: self.outbound.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct ChanRx(Option<Vec<u8>>);

impl RxToken for ChanRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        let mut buf = self.0.take().unwrap_or_default();
        f(&mut buf)
    }
}

struct ChanTx {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl TxToken for ChanTx {
    fn consume<V, F: FnOnce(&mut [u8]) -> V>(self, len: usize, f: F) -> V {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.queue.lock().unwrap().push_back(buf);
        res
    }
}

/// 构建栈 Interface：IP medium、TUN 地址、默认路由（TUN 上一切目标都是 on-link）。
/// `ipv6_enabled` 时额外配置 IPv6 地址（链接本地 fe80::1/10 + 全局 addr6/64）
/// 与 v6 默认路由，使 proto-ipv6 栈可处理 v6 TCP（入站接受 + 出站源地址选择）。
fn build_interface(cfg: &TunConfig, device: &mut ChanDevice) -> Result<Interface> {
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    // 随机邻居缓存容量等默认即可；IP medium 不需要硬件地址
    iface_cfg.random_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9ABC_DEF0);
    let now = smol_now();
    let mut iface = Interface::new(iface_cfg, device, now);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address(cfg.addr.octets())),
                cfg.prefix,
            ))
            .expect("IP 地址表已满");
        if cfg.ipv6_enabled {
            // 链接本地地址（必需）：smoltcp 出站源地址选择（RFC 6724）需要
            // 至少一个 v6 地址；/10 是 fe80::/10 的标准前缀长度
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    10,
                ))
                .expect("IP 地址表已满");
            // 全局占位地址（ULA fd07::1/64）：与 v4 的 10.7.0.1 对称，
            // v6 接管路由 via 指向它；动态 AnyIP 地址见 ensure_v6_dst
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv6(smoltcp::wire::Ipv6Address(cfg.addr6.octets())),
                    64,
                ))
                .expect("IP 地址表已满");
        }
    });
    // 默认路由（TUN 是 IP 层端点，网关占位为 TUN 自身地址；仅用于路由查找存在性）
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address(cfg.addr.octets()))
        .map_err(|_| HydraError::ConnectionError("smoltcp 路由表已满".into()))?;
    if cfg.ipv6_enabled {
        // v6 默认路由：SYN-ACK 等出站包对任意客户端 v6 地址的路由查找需要它
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address(cfg.addr6.octets()))
            .map_err(|_| HydraError::ConnectionError("smoltcp v6 路由表已满".into()))?;
    }
    // 关键：any-ip 模式（**仅 IPv4 生效**——smoltcp 0.11 对 v6 无 any-ip，
    // v6 由动态 AnyIP [`ensure_v6_dst`] 处理）。TUN 收到的包目标地址是
    // 「应用想访问的任意远端」，不是 TUN 接口自身地址；不开 any-ip 会被
    // smoltcp 当作非本机包丢弃。
    iface.set_any_ip(true);
    Ok(iface)
}

const TCP_BUF: usize = 64 * 1024;
/// 代理 → 栈 单条流的下行通道深度（背压用）
const FLOW_CHAN: usize = 64;
/// 栈 → 代理 单条流的上行通道深度（16KB 块 ×8 = 128KB 缓冲；满即停 recv，
/// 让 smoltcp 接收窗口归零形成真实 TCP 背压）
const FLOW_UP_CHAN: usize = 8;
/// 上行单次写入超时（06-P1-8）：节点链路假死/窗口耗尽时写任务有限期退出并
/// 回报错误中止该流，绝不拖累其他流
const UP_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 建连超时（open_target 内部已有节点级超时，这里兜底总时限）
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// 未完成 TCP 握手的流的建立超时（审查 06-P2-8）：握手从未完成（扫描 SYN 等）
/// 的僵尸流用更短窗口回收，不再等 300s 空闲超时
const FLOW_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// 流消息：代理侧任务 → 栈主循环
enum FlowMsg {
    /// 通道已建成（主循环随后派生下行读取任务）
    Link(ProxyDuplex),
    /// 通道开启失败（TargetUnreachable 等）→ 回 RST
    LinkErr,
    /// 代理侧读到的下行数据
    Data(Vec<u8>),
    /// 上行写任务故障（写错误/写超时）→ 回 RST 中止该流
    UpErr,
}

/// 一条活动流
struct Flow {
    target: String,
    up_rx: mpsc::Receiver<FlowMsg>,
    up_task: tokio::task::JoinHandle<()>,
    /// 代理下行读取任务（读取 duplex.reader → Data 消息）
    reader_task: Option<tokio::task::JoinHandle<()>>,
    /// 通道开启任务持有的发送端（派生下行读取任务时需要）
    flow_tx: mpsc::Sender<FlowMsg>,
    /// 代理链路上行发送端（栈 → 代理；写任务独立派生，主循环只做非阻塞投递）
    up_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// 上行写任务（own duplex.writer：write_all 阻塞不再发生在栈主循环）
    writer_task: Option<tokio::task::JoinHandle<()>>,
    /// socket 发不下的积压（socket 缓冲满时暂存，防字节流损坏）
    pending: VecDeque<Vec<u8>>,
    last_active: Instant,
    /// 06-P2-8：真实上游建链是否已派生（Established 后才派生，扫描 SYN 不触发建链）
    opened: bool,
    /// 接受时刻（建立超时回收用）
    accepted_at: Instant,
}

/// 派生上游建链任务（open_target → FlowMsg::Link/LinkErr）。
/// 06-P2-8：从 accept 分支拆出，改由"待建立流"循环在流进入 Established 后调用。
fn spawn_up_task(
    opener: ChannelOpener,
    target: String,
    tx: mpsc::Sender<FlowMsg>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let open_fut = opener(target.clone());
        match tokio::time::timeout(OPEN_TIMEOUT, open_fut).await {
            Ok(Ok(duplex)) => {
                let _ = tx.send(FlowMsg::Link(duplex)).await;
                // 通道已交付主循环；up 任务结束（下行读取由 reader 任务负责）
            }
            Ok(Err(e)) => {
                warn!("TUN 流开通道失败（{target}）: {} → 回 RST", e);
                let _ = tx.send(FlowMsg::LinkErr).await;
            }
            Err(_) => {
                warn!("TUN 流开通道超时（{target}）→ 回 RST");
                let _ = tx.send(FlowMsg::LinkErr).await;
            }
        }
    })
}

// ── IPv6 快速失败 / 动态 AnyIP（v1 完整版）───────────────────────────────────
// 栈已启用 proto-ipv6：`ipv6_enabled = true` 时 v6 TCP 走正向路径——smoltcp 0.11
// 的 any-ip 仅对 IPv4 生效（iface/interface/ipv6.rs 入站过滤只认接口自身地址），
// 因此在投喂前把包的目的地址临时挂为接口 /128 地址（[`ensure_v6_dst`] 有界池 +
// 活跃流保护），栈即可接受并代理该连接。
// `ipv6_enabled = false` 或 v6 非 TCP 包（UDP/ICMPv6 等）仍手工组包快速失败：
// TCP SYN 回 RST，其余回 ICMPv6 destination unreachable——应用立即回落 IPv4，
// 而非等待超时。无对应栈处理能力，全部手工组包（IPv6 头 40B）。

/// 判断包是否为 IPv6（首字节高 4 位版本号 == 6，且至少有完整 40B 头）
fn is_ipv6_packet(pkt: &[u8]) -> bool {
    pkt.len() >= 40 && pkt[0] >> 4 == 6
}

/// RFC 1071 校验和（16 位反码求和；输入网络字节序，输出网络字节序）
fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv6 伪首部（上层校验和计算用）：src + dst + 4B 上层长度 + next header
fn ipv6_pseudo_header(src: &[u8; 16], dst: &[u8; 16], upper_len: u32, next_header: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(src);
    v.extend_from_slice(dst);
    v.extend_from_slice(&upper_len.to_be_bytes());
    v.push(0); // 3B 保留
    v.push(0);
    v.push(0);
    v.push(next_header);
    v
}

/// 40B IPv6 头：版本 6 + payload_len + next_header + hop limit 64 + 地址
fn build_ipv6_header(src: &[u8; 16], dst: &[u8; 16], payload_len: u16, next_header: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    v.push(0x60); // 版本 6 + 流类别/流标签 0
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&payload_len.to_be_bytes());
    v.push(next_header);
    v.push(64); // hop limit
    v.extend_from_slice(src);
    v.extend_from_slice(dst);
    v
}

/// 对 IPv6 TCP SYN 构造 RST（40B IPv6 头 + 20B TCP 头）：
/// 地址/端口对调，ack = 对端 seq + 1（SYN 占一个序号），flags = RST|ACK，
/// 应用侧立即收到 ECONNRESET 快速回落 IPv4。非 SYN（已建立流的 ACK/DATA 等）
/// 返回 None——对既有流代答只会制造噪声。
fn build_tcp_rst_v6(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 60 || pkt[6] != 6 {
        return None; // 需完整 40B IPv6 头 + 20B TCP 头，且 next header = TCP
    }
    let tcp_off = 40;
    let data_off = ((pkt[tcp_off + 12] >> 4) as usize) * 4;
    if data_off < 20 || pkt.len() < tcp_off + data_off {
        return None;
    }
    let flags = pkt[tcp_off + 13];
    // 只应答首包 SYN（无 ACK）；SYN-ACK/ACK/FIN 等不代答
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    let sport = u16::from_be_bytes([pkt[tcp_off], pkt[tcp_off + 1]]); // 对端源端口
    let dport = u16::from_be_bytes([pkt[tcp_off + 2], pkt[tcp_off + 3]]); // 对端目的端口
    let seq = u32::from_be_bytes([
        pkt[tcp_off + 4],
        pkt[tcp_off + 5],
        pkt[tcp_off + 6],
        pkt[tcp_off + 7],
    ]);
    let ack = u32::from_be_bytes([
        pkt[tcp_off + 8],
        pkt[tcp_off + 9],
        pkt[tcp_off + 10],
        pkt[tcp_off + 11],
    ]);

    // RST 包 TCP 头（校验和先置 0）
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&dport.to_be_bytes()); // 我方源端口 = 原目的端口
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes()); // 我方 seq = 对端 ack
    tcp.extend_from_slice(&(seq.wrapping_add(1)).to_be_bytes()); // ack = 对端 seq + 1
    tcp.push(0x50); // 数据偏移 5（20B）
    tcp.push(0x14); // RST | ACK
    tcp.extend_from_slice(&0u16.to_be_bytes()); // window 0
    tcp.extend_from_slice(&[0, 0]); // 校验和占位
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    let ck = checksum16(&[ipv6_pseudo_header(&dst, &src, 20, 6), tcp.clone()].concat());
    tcp[16..18].copy_from_slice(&ck.to_be_bytes());

    let mut out = build_ipv6_header(&dst, &src, 20, 6);
    out.extend_from_slice(&tcp);
    Some(out)
}

/// 构造 ICMPv6 destination unreachable（type 1 / code 0）应答：引用原包前缀
/// （截到总长 ≤ 1280B，即 IPv6 最小 MTU），让 UDP/ICMP 等非 TCP 的 v6 请求
/// 立即收到不可达错误而非等待超时。
fn build_icmpv6_unreachable_v6(pkt: &[u8]) -> Vec<u8> {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    // 引用载荷截断：40B 头 + 8B ICMP 头 + 引用 ≤ 1280
    let quoted = &pkt[..pkt.len().min(1280 - 40 - 8)];
    let icmp_len = 8 + quoted.len();
    let mut icmp = Vec::with_capacity(icmp_len);
    icmp.push(1); // type = destination unreachable
    icmp.push(0); // code = 0（无路由到达目标）
    icmp.extend_from_slice(&[0, 0]); // 校验和占位
    icmp.extend_from_slice(&[0, 0, 0, 0]); // 4B 保留
    icmp.extend_from_slice(quoted);
    let ck = checksum16(
        &[
            ipv6_pseudo_header(&dst, &src, icmp_len as u32, 58),
            icmp.clone(),
        ]
        .concat(),
    );
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    let mut out = build_ipv6_header(&dst, &src, icmp_len as u16, 58);
    out.extend_from_slice(&icmp);
    out
}

// ── IPv4 UDP → ICMPv4 port unreachable（v1 完整版）──────────────────────────

/// 判断包是否为「应代答的 IPv4 UDP 包」：完整 IPv4 头（IHL≥5）、协议号 17（UDP）、
/// 非分片（分片偏移 0 且不分片才答首个分片；后续分片一律静默丢弃——对分片代答
/// 会让应用收到重复/错序 ICMP）。返回 None 表示包应正常投喂栈。
/// IPv4 UDP 包的目的地址是否为私网（RFC1918/CGNAT/回环/链路本地/保留段）。
/// 09-P3-7：此类目的不代答 ICMP 差错（详见 run_stack 分发处注释）。
fn is_private_udp_v4_dst(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    dst.is_loopback()
        || dst.is_link_local()
        || dst.is_private()
        || dst.octets()[0] == 0
        || (dst.octets()[0] == 100 && (64..=127).contains(&dst.octets()[1]))
        || dst.octets()[0] & 0xf0 == 0xe0
        || dst.octets()[0] & 0xf0 == 0xf0
}

fn is_unproxyable_udp_v4(pkt: &[u8]) -> bool {    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return false;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x1fff != 0 {
        return false; // 非首片：静默丢弃（不答）
    }
    // RFC 1122 §3.2.2：广播/组播目的、未指定源不回 ICMP 差错
    // （DHCP Discover 255.255.255.255、mDNS 224.0.0.251 等场景回包是协议违规）
    let dst = &pkt[16..20];
    if dst == [255, 255, 255, 255] || dst[0] & 0xf0 == 0xe0 {
        return false;
    }
    if pkt[12..16] == [0, 0, 0, 0] {
        return false;
    }
    pkt[9] == 17 // protocol = UDP
}

/// 20B IPv4 头（校验和先置 0，由调用方补算）：version 4 / IHL 5、proto、TTL 64
fn build_ipv4_header(
    src: &[u8; 4],
    dst: &[u8; 4],
    total_len: u16,
    protocol: u8,
    identification: u16,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.push(0x45); // version 4 + IHL 5
    v.push(0); // TOS
    v.extend_from_slice(&total_len.to_be_bytes());
    v.extend_from_slice(&identification.to_be_bytes());
    v.extend_from_slice(&[0, 0]); // flags=0 + 分片偏移 0
    v.push(64); // TTL
    v.push(protocol);
    v.extend_from_slice(&[0, 0]); // 头校验和占位
    v.extend_from_slice(src);
    v.extend_from_slice(dst);
    v
}

/// 构造 ICMPv4 destination unreachable（type 3 / **code 3 = port unreachable**）
/// 应答：引用「原 IP 头 + 载荷前 8B」（RFC 792 要求，应用靠引用内嵌 UDP 头的
/// 端口字段匹配到对应 socket 立即收到 ECONNREFUSED，QUIC/HTTP3 应用据此快速
/// 回落 TCP），不再是静默丢弃后的漫长超时。
fn build_icmpv4_port_unreachable(pkt: &[u8]) -> Option<Vec<u8>> {
    if !is_unproxyable_udp_v4(pkt) {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    let ident = u16::from_be_bytes([pkt[4], pkt[5]]);

    // ICMP 载荷：type 3 / code 3 / 校验和占位 2B / unused 4B / 引用原 IP 头 + 8B 载荷
    let quoted_len = (ihl + 8).min(pkt.len());
    let icmp_len = 8 + quoted_len;
    let mut icmp = Vec::with_capacity(icmp_len);
    icmp.push(3); // type = destination unreachable
    icmp.push(3); // code = port unreachable
    icmp.extend_from_slice(&[0, 0]); // 校验和占位
    icmp.extend_from_slice(&[0, 0, 0, 0]); // unused
    icmp.extend_from_slice(&pkt[..quoted_len]);
    // 校验和：RFC 792 明确 ICMPv4 校验和**只覆盖 ICMP 段自身、不含 IPv4 伪首部**
    //（与 v6 的伪首部式校验不同，RFC 4443 才要求伪首部）。任务书写的「含 IPv4
    // 伪首部」按标准修正为不含——含伪首部对 ICMPv4 是错误校验和，宿主栈会整包
    // 丢弃（IPv4 伪首部前 12B 恰好不含 0xFFFF 取反语义，两种算法结果必然不同）。
    let ck = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    // 外层 IPv4 头：源 = 原目的（TUN 侧代答者），目的 = 原源
    let total_len = (20 + icmp_len) as u16;
    let mut out = build_ipv4_header(&dst, &src, total_len, 1, ident);
    let ck = checksum16(&out); // IPv4 头校验和只覆盖头自身（RFC 1071）
    out[10..12].copy_from_slice(&ck.to_be_bytes());
    out.extend_from_slice(&icmp);
    Some(out)
}

// ── IPv6 动态 AnyIP（smoltcp 0.11 any-ip 仅 v4，v6 用显式地址接受）──────────

/// 动态 AnyIP 地址池容量：smoltcp 接口地址表共 8 槽，静态占用 3 槽
/// （v4 /30 + 链路本地 fe80::1/10 + 全局 addr6/64），余 5 槽轮转
const V6_DYNAMIC_SLOTS: usize = smoltcp::config::IFACE_MAX_ADDR_COUNT - 3;

/// 把入站 v6 TCP 包的目的地址临时挂为接口 /128 地址（动态 AnyIP），使 smoltcp
/// 的入站地址过滤放行（其 v6 路径不认 any-ip，见模块注释）。有界池轮转：
/// 超出 [`V6_DYNAMIC_SLOTS`] 时淘汰最旧的**非活跃流**目的地址（活跃流受保护，
/// 防止其在途包被过滤丢弃）；全部活跃时放弃添加（该包静默丢弃，TCP 重传兜底）。
fn ensure_v6_dst(
    iface: &mut Interface,
    addr: std::net::Ipv6Addr,
    pool: &mut VecDeque<std::net::Ipv6Addr>,
    protected: &std::collections::HashSet<std::net::Ipv6Addr>,
) {
    if iface.has_ip_addr(IpAddress::Ipv6(smoltcp::wire::Ipv6Address(addr.octets()))) {
        return; // 已挂（含静态地址命中）
    }
    while pool.len() >= V6_DYNAMIC_SLOTS {
        match pool.pop_front() {
            Some(v) if protected.contains(&v) => {
                // 活跃流地址不可淘汰：挪回队尾，若池内全是活跃地址则放弃
                pool.push_back(v);
                if pool.iter().all(|a| protected.contains(a)) {
                    debug!("v6 动态地址池满且全部活跃，放弃挂载 {addr}");
                    return;
                }
                continue;
            }
            Some(v) => {
                let target = IpAddress::Ipv6(smoltcp::wire::Ipv6Address(v.octets()));
                iface.update_ip_addrs(|addrs| {
                    addrs.retain(|c| c.address() != target);
                });
                break;
            }
            None => break,
        }
    }
    iface.update_ip_addrs(|addrs| {
        // 审查批次 P3-9：push 失败（静态地址挤占）时不入池——池认为已挂载而
        // 接口实际没有会造成「每包重试 + 误淘汰他人」的失同步抖动
        if addrs.push(IpCidr::new(
            IpAddress::Ipv6(smoltcp::wire::Ipv6Address(addr.octets())),
            128,
        ))
        .is_err()
        {
            debug!("v6 动态地址挂载失败（地址表满），{addr} 不入池");
            return;
        }
        pool.push_back(addr);
    });
}

// ── UDP-over-proxy 接管（09 交付：TUN 方案 v2 方向落地）────────────────────

use hydra_core::udp_relay::{NodeUdpChannel, UdpChannelFactory, UdpRx};

/// 中继通道任务命令：分发循环把公网 UDP 包转交此通道（带完整流上下文）
enum UdpCmd {
    Send {
        /// 流键（客户端四元组的 src|dst，参与 keyed 会话映射）
        flow: String,
        /// 节点侧目标（= 客户端包的目的地）
        dst: SocketAddr,
        /// 客户端包的源地址（回包注入 TUN 时的目的地）
        src: SocketAddr,
        data: Vec<u8>,
    },
}

/// 每流的记录：sid → (流目的地址, 客户端源地址)。回包构造：
/// src = 流目的地址（应用看到的"远端"），dst = 客户端源地址。
#[derive(Default)]
struct UdpFlowTable {
    by_sid: HashMap<u16, (SocketAddr, SocketAddr)>,
    last_seen: HashMap<u16, std::time::Instant>,
}

impl UdpFlowTable {
    const IDLE_SECS: u64 = 150;

    fn touch(&mut self, sid: u16, dst: SocketAddr, src: SocketAddr) {
        self.by_sid.insert(sid, (dst, src));
        self.last_seen.insert(sid, std::time::Instant::now());
    }

    fn remove(&mut self, sid: u16) {
        self.by_sid.remove(&sid);
        self.last_seen.remove(&sid);
    }

    /// 周期清理空闲流（无回包也无上行超时——节点侧 60s 空闲回收先行，
    /// 此处兜底防 sid 表泄漏；未及时收到 Closed 帧的场景）
    fn sweep_idle(&mut self) {
        let now = std::time::Instant::now();
        let expired: Vec<u16> = self
            .last_seen
            .iter()
            .filter(|(_, t)| now.duration_since(**t).as_secs() > Self::IDLE_SECS)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in expired {
            self.remove(sid);
        }
    }
}

/// UDP 中继通道任务：持有到节点的 UdpChannel，双向泵——
/// 上行：分发循环经 `cmd_rx` 投递公网 UDP 包 → keyed 会话发送；
/// 下行：节点回包按 sid 反解 → 构造 UDP/IP 包注入 TUN（回给应用 socket）。
/// 通道断开自动重连（指数退避封顶 10s）；每次重连按当前最优节点建连。
async fn udp_relay_task(
    factory: UdpChannelFactory,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<UdpCmd>,
    transport: Arc<dyn PacketTransport>,
    shutdown: CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        // 1. 建连（按当前最优节点）
        let mut ch: NodeUdpChannel = match (factory)().await {
            Ok(c) => {
                backoff = Duration::from_secs(1);
                info!("TUN UDP 中继通道已建立（加密隧道）");
                c
            }
            Err(e) => {
                warn!("TUN UDP 中继建连失败（{}s 后重试）: {}", backoff.as_secs(), e);
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }
        };

        // 2. 双向泵
        let mut flows = UdpFlowTable::default();
        let mut janitor = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = janitor.tick() => flows.sweep_idle(),
                cmd = cmd_rx.recv() => match cmd {
                    Some(UdpCmd::Send { flow, dst, src, data }) => {
                        let dst_str = sock_to_target(dst);
                        match ch.send_to_ext(&flow, &dst_str, &data).await {
                            Ok(sid) => flows.touch(sid, dst, src),
                            Err(e) => {
                                debug!("TUN UDP 中继上行写失败（通道重建）: {e}");
                                break; // 重建通道；本包丢弃（UDP 语义）
                            }
                        }
                    }
                    None => return, // 分发循环已退出
                },
                rx = ch.recv_from_ext() => match rx {
                    Ok(UdpRx::Data { sid, target, datagram }) => {
                        // 回包源/目的取**流表权威数据**（发送时记录的四元组），
                        // 不信任线上回显的 target 字段
                        let Some(&(flow_dst, client_src)) = flows.by_sid.get(&sid) else {
                            debug!("TUN UDP 下行 sid 无流映射（迟到帧），丢弃: {}", mask_target(&target));
                            continue;
                        };
                        let reply = match (flow_dst, client_src) {
                            (SocketAddr::V4(s), SocketAddr::V4(d)) => Some(build_udp_reply_v4(
                                *s.ip(), *d.ip(), s.port(), d.port(), &datagram,
                            )),
                            (SocketAddr::V6(s), SocketAddr::V6(d)) => Some(build_udp_reply_v6(
                                *s.ip(), *d.ip(), s.port(), d.port(), &datagram,
                            )),
                            _ => None, // v4/v6 混线（不应发生）：丢弃
                        };
                        if let Some(pkt) = reply {
                            if let Err(e) = transport.send(&pkt).await {
                                error!("TUN UDP 回包注入失败: {e}");
                            }
                        }
                    }
                    Ok(UdpRx::Closed { sid }) => flows.remove(sid),
                    Err(e) => {
                        debug!("TUN UDP 中继下行读失败（通道重建）: {e}");
                        break;
                    }
                },
            }
        }
        // 3. 断线退避后重连（flows 随通道作废：sid 空间在新通道重新分配）
        drop(ch);
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

/// SocketAddr → UDP 中继目标串（v6 带方括号："1.2.3.4:53" / "[::1]:53"）
fn sock_to_target(a: SocketAddr) -> String {
    match a {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// v4 UDP 首片可解析性：长度/协议/分片检查（供分发判定）。
/// 返回 Some((src, dst, payload 起始, payload 长度))；不可解析 → None。
fn parse_udp_v4(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, usize, usize)> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x3fff != 0 {
        return None; // 有分片（offset 或 MF）：不代理（罕见，MTU 内流量不分片）
    }
    // 以 IP 总长字段为准（剥离链路层填充尾巴）
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let udp_len = usize::from(u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]));
    let payload_len = udp_len.saturating_sub(8);
    if udp_len < 8 || pkt.len() < ihl + udp_len || total < ihl + udp_len {
        return None;
    }
    let src = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
        u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
    );
    let dst = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
        u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
    );
    Some((src, dst, ihl + 8, payload_len))
}

/// v6 UDP 可解析性（无扩展头直载）：返回 Some((src, dst, payload 起始, 长度))。
fn parse_udp_v6(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, usize, usize)> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 || pkt[6] != 17 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if payload_len < 8 || pkt.len() < 40 + payload_len {
        return None;
    }
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&pkt[8..24]);
    d.copy_from_slice(&pkt[24..40]);
    let src = SocketAddr::new(
        std::net::IpAddr::V6(Ipv6Addr::from(s)),
        u16::from_be_bytes([pkt[40], pkt[41]]),
    );
    let dst = SocketAddr::new(
        std::net::IpAddr::V6(Ipv6Addr::from(d)),
        u16::from_be_bytes([pkt[42], pkt[43]]),
    );
    Some((src, dst, 48, payload_len - 8))
}

/// 构造回包：UDP/IP 完整帧，src = 流目的地址（应用看到的远端），dst = 客户端源。
/// v4：UDP 校验和按 RFC 768 伪首部计算（0 视为无校验和，但我们给出真实值，
/// 与主流栈一致，避免个别应用/中间盒对 0 校验和的兼容性问题）。
fn build_udp_reply_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    let total_be = (total as u16).to_be_bytes();
    pkt[2..4].copy_from_slice(&total_be);
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 17; // proto UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let csum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    // UDP 头
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // 伪首部校验和
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let uc = checksum16(&pseudo);
    pkt[26..28].copy_from_slice(&uc.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// v6 版回包（校验和必需，RFC 2460）。
fn build_udp_reply_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&sport.to_be_bytes());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // 校验和覆盖伪首部 + UDP 头 + 载荷（RFC 2460；checksum16 顺序无关）
    let pseudo = ipv6_pseudo_header(&src.octets(), &dst.octets(), udp_len as u32, 17);
    let mut covered = pseudo;
    covered.extend_from_slice(&pkt[40..]);
    let uc = checksum16(&covered);
    pkt[46..48].copy_from_slice(&uc.to_be_bytes());
    pkt[48..].copy_from_slice(payload);
    pkt
}

/// `HYDRA_ALLOW_PRIVATE_TARGETS=1` 放开私网目标（与节点侧同款 OnceLock 语义）：
/// 自建 LAN 节点场景下节点侧已放开，客户端 TUN 的 UDP 分发应同样放行——
/// 单边硬拦会让"LAN 节点 + TUN"的私网访问无解（09 之前 TCP 路径即如此：
/// 包进 TUN 被节点拒；UDP 接管后客户端同样尊重该开关）。
fn private_targets_allowed() -> bool {
    static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ALLOW.get_or_init(|| {
        matches!(std::env::var("HYDRA_ALLOW_PRIVATE_TARGETS"), Ok(v) if v == "1")
    })
}

/// 分发入口（run_stack 调用）：解析 + 私网/组播过滤 + 转交中继任务。
/// 返回 true = 已接管（转发中）；false = 未接管（调用方按旧行为处理）。
fn try_forward_udp(
    pkt: &[u8],
    cmd_tx: &tokio::sync::mpsc::UnboundedSender<UdpCmd>,
) -> bool {
    let parsed = parse_udp_v4(pkt).or_else(|| parse_udp_v6(pkt));
    let Some((src, dst, off, len)) = parsed else {
        return false;
    };
    // 目的地过滤：与路由豁免语义一致——私网/回环/链路本地/ULA/组播/广播不入
    // 隧道；HYDRA_ALLOW_PRIVATE_TARGETS=1 时放开私网类（组播/广播/未指定仍拦）
    let allow_private = private_targets_allowed();
    let excluded = match dst.ip() {
        std::net::IpAddr::V4(v4) => {
            let private_like = v4.is_loopback() || v4.is_link_local() || v4.is_private()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]));
            if allow_private {
                v4.is_broadcast() || v4.is_multicast()
            } else {
                private_like || v4.is_broadcast() || v4.is_multicast()
            }
        }
        std::net::IpAddr::V6(v6) => {
            let private_like = v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00;
            if allow_private {
                v6.is_multicast()
            } else {
                private_like || v6.is_multicast()
            }
        }
    };
    if excluded {
        return false;
    }
    let flow = format!("{src}|{dst}");
    cmd_tx
        .send(UdpCmd::Send {
            flow,
            dst,
            src,
            data: pkt[off..off + len].to_vec(),
        })
        .is_ok()
}

/// 栈主循环（与真实 TUN 设备解耦：任何 [`PacketTransport`] 都可驱动，
/// 测试用通道对接两个 smoltcp Interface 做回环验证）。
/// `udp_factory` = Some 时公网 UDP 经节点中继接管（09 交付）；None/关闭时
/// 保持 v1 行为（公网 UDP 代答 ICMP 不可达回落 TCP）。
pub async fn run_stack<T: PacketTransport>(
    transport: Arc<T>,
    cfg: TunConfig,
    opener: ChannelOpener,
    udp_factory: Option<UdpChannelFactory>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (mut device, _in_q, _out_q) = ChanDevice::new(cfg.mtu as usize);
    let mut iface = build_interface(&cfg, &mut device)?;
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);

    // 监听 socket（smoltcp 无通配监听：按端口列表 LISTEN，v1 已知限制）
    let mut listeners: Vec<SocketHandle> = Vec::new();
    for &port in &cfg.listen_ports {
        listeners.push(add_listener(&mut sockets, port));
    }
    info!(
        "TUN 栈就绪：addr={}/{} mtu={} 监听端口={:?} 流上限={}",
        cfg.addr, cfg.prefix, cfg.mtu, cfg.listen_ports, cfg.max_flows
    );

    let mut flows: HashMap<SocketHandle, Flow> = HashMap::new();
    let mut buf = vec![0u8; cfg.mtu as usize + 4];
    // 07-P1-2：IPv6 快速失败首见告警只发一次（避免每包刷日志）
    let mut warned_v6 = false;
    // 09-P2-1 栈侧兜底：私网 TCP 目标告警只发一次
    let mut warned_private = false;
    // v6 动态 AnyIP 地址池（静态 3 槽之外轮转，见 ensure_v6_dst）
    let mut v6_pool: VecDeque<std::net::Ipv6Addr> = VecDeque::new();
    // 栈中转缓冲：一次分配、整个主循环复用（06-P3-8：此前 step() 每 tick
    // 分配 16KB 再丢弃，持续产生无效内存带宽；09-P3-8 复核发现分配仍在
    // 循环内，本次真正提到循环外）
    let mut stack_buf = vec![0u8; 16 * 1024];

    // ── UDP-over-proxy 接管（09 交付）──
    // 公网 UDP（DNS/QUIC/HTTP3/P2P）→ 节点中继（加密隧道）。开关关闭或未提供
    // 工厂时保持 v1 行为（公网 UDP 代答 ICMP 不可达回落 TCP）。
    let udp_tx = if cfg.udp_relay {
        match udp_factory {
            Some(factory) => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<UdpCmd>();
                tokio::spawn(udp_relay_task(
                    factory,
                    rx,
                    transport.clone(),
                    shutdown.clone(),
                ));
                info!(
                    "TUN UDP-over-proxy 已接管：公网 UDP（DNS/QUIC）经节点加密中继\
                     ；DNS {}（HYDRA_TUN_DNS_DIRECT=1 可恢复直连）",
                    if cfg.dns_via_proxy { "经隧道" } else { "直连" }
                );
                Some(tx)
            }
            None => {
                warn!("TUN UDP 接管未启用（未提供 UDP 通道工厂）：公网 UDP 回落 TCP（v1 行为）");
                None
            }
        }
    } else {
        info!("TUN UDP 接管已关闭（HYDRA_TUN_UDP=0）：公网 UDP 代答 ICMP 不可达回落 TCP");
        None
    };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("TUN 栈收到停机信号");
                break;
            }
            r = transport.recv(&mut buf) => match r {
                Ok(0) => {
                    info!("TUN 设备关闭");
                    break;
                }
                Ok(n) => {
                    let pkt = &buf[..n];
                    if is_ipv6_packet(pkt) {
                        // 09-P2-3：组播目的/未指定源豁免（上轮 v4 修复的同源遗漏
                        // 在 v6 侧补齐）——对 ff02::fb（mDNS）等回差错违反
                        // RFC 4443 §2.4(e)，组播目的的 SYN 走正向路径还会白占
                        // AnyIP 池与流槽，一律静默丢弃
                        let v6_drop = pkt.len() >= 40 && {
                            let src = std::net::Ipv6Addr::new(
                                u16::from_be_bytes([pkt[8], pkt[9]]),
                                u16::from_be_bytes([pkt[10], pkt[11]]),
                                u16::from_be_bytes([pkt[12], pkt[13]]),
                                u16::from_be_bytes([pkt[14], pkt[15]]),
                                u16::from_be_bytes([pkt[16], pkt[17]]),
                                u16::from_be_bytes([pkt[18], pkt[19]]),
                                u16::from_be_bytes([pkt[20], pkt[21]]),
                                u16::from_be_bytes([pkt[22], pkt[23]]),
                            );
                            let dst = std::net::Ipv6Addr::new(
                                u16::from_be_bytes([pkt[24], pkt[25]]),
                                u16::from_be_bytes([pkt[26], pkt[27]]),
                                u16::from_be_bytes([pkt[28], pkt[29]]),
                                u16::from_be_bytes([pkt[30], pkt[31]]),
                                u16::from_be_bytes([pkt[32], pkt[33]]),
                                u16::from_be_bytes([pkt[34], pkt[35]]),
                                u16::from_be_bytes([pkt[36], pkt[37]]),
                                u16::from_be_bytes([pkt[38], pkt[39]]),
                            );
                            src.is_unspecified() || src.is_multicast() || dst.is_multicast()
                        };
                        if v6_drop {
                            debug!("TUN 丢弃组播/未指定源 IPv6 包");
                        }
                        // v6 分发：TCP 且已启用接管 → 正向路径投喂栈（动态 AnyIP）；
                        // 否则快速失败代答（SYN→RST / 其余→ICMPv6 不可达），应用回落 IPv4
                        let v6_tcp = pkt.len() >= 41 && pkt[6] == 6; // 无扩展头直载 TCP
                        if !v6_drop && cfg.ipv6_enabled && v6_tcp {
                            if !warned_v6 {
                                info!(
                                    "TUN IPv6 正向路径就绪：v6 TCP 经动态 AnyIP 代理，\
                                     非 TCP 回 ICMPv6 不可达供应用回落 IPv4"
                                );
                                warned_v6 = true;
                            }
                            // 活跃 v6 目的地址集合（动态地址淘汰保护）。
                            // 审查修复：保护来源从 flows 改为整个 SocketSet——accept
                            // 循环在 poll 之后执行，SYN 已被投喂但 Flow 尚未登记的
                            // 一轮里，仅按 flows 保护会漏掉握手期连接，池满时其
                            // 地址被误淘汰（重传才恢复）。遍历 SocketSet 覆盖
                            // SynReceived/Established/CloseWait 全部状态；监听
                            // socket 的 local 地址未指定，被 filter_map 自然过滤。
                            let protected: std::collections::HashSet<std::net::Ipv6Addr> =
                                sockets
                                    .iter()
                                    .filter_map(|(_h, socket)| match socket {
                                        smoltcp::socket::Socket::Tcp(s) => s.local_endpoint(),
                                    })
                                    .filter_map(|ep| match ep.addr {
                                        IpAddress::Ipv6(a) => {
                                            Some(std::net::Ipv6Addr::from(a.0))
                                        }
                                        _ => None,
                                    })
                                    .collect();
                            let mut dst = [0u8; 16];
                            dst.copy_from_slice(&pkt[24..40]);
                            ensure_v6_dst(
                                &mut iface,
                                std::net::Ipv6Addr::from(dst),
                                &mut v6_pool,
                                &protected,
                            );
                            device.push_inbound(pkt);
                            } else if !v6_drop {
                                if !warned_v6 {
                                warn!(
                                    "TUN 收到 IPv6 包：{}，代答快速失败\
                                     （SYN→RST，其余→ICMPv6 不可达）供应用回落 IPv4",
                                    if cfg.ipv6_enabled { "非 TCP 包" } else { "v6 接管已关闭" }
                                );
                                warned_v6 = true;
                            }
                            if let Some(rst) = build_tcp_rst_v6(pkt) {
                                if let Err(e) = transport.send(&rst).await {
                                    error!("TUN 写 IPv6 RST 失败: {}", e);
                                }
                            } else if pkt.len() > 6 && pkt[6] == 58 {
                                // 入站 ICMPv6：RFC 4443 §2.4(e) 禁止对差错报文再回
                                // 差错（防差错风暴/反射），静默丢弃；ping 不通属设
                                // 计内（无 v6 转发能力，回不可达反而让 ping 失真）
                                debug!("TUN 丢弃入站 IPv6 ICMPv6 包（无 v6 转发能力）");
                            } else if pkt.len() > 6
                                && matches!(pkt[6], 0 | 43 | 44 | 51 | 60)
                            {
                                // IPv6 扩展头承载的 TCP（HBH/路由/分片/IPsec）：
                                // 无法安全解析端口——静默丢弃而非回不可达（让应用
                                // 快速失败即可，审查批次 C P3-8 同源场景）
                                debug!("TUN 丢弃带扩展头的 IPv6 包（无 v6 转发能力）");
                            } else if let Some(tx) = udp_tx.as_ref().filter(|_| !v6_drop).filter(|_| parse_udp_v6(pkt).is_some()) {
                                // 09 交付：v6 公网 UDP 经节点中继（与 v4 对称）
                                try_forward_udp(pkt, tx);
                            } else {
                                let icmp = build_icmpv6_unreachable_v6(pkt);
                                if let Err(e) = transport.send(&icmp).await {
                                    error!("TUN 写 ICMPv6 不可达失败: {}", e);
                                }
                            }
                        }
                    } else if parse_udp_v4(pkt).is_some() {
                        // IPv4 UDP（09 交付统一分发）：可解析 UDP 全部在此处理——
                        // ① UDP 接管开启：公网目标（或 HYDRA_ALLOW_PRIVATE_TARGETS
                        //    放开的私网目标）经节点中继（加密隧道）；
                        // ② 广播/组播/未指定源/未放开私网：静默丢弃（RFC 1122 不回
                        //    差错；私网是豁免路由缺失的降级场景）；
                        // ③ 接管关闭（v1 行为）：公网 UDP 代答 ICMP port unreachable
                        //    引导应用回落 TCP。
                        let (src, dst, _off, _len) = parse_udp_v4(pkt).unwrap();
                        let private = is_private_udp_v4_dst(pkt);
                        let allow_private = private_targets_allowed();
                        let no_relay = dst.ip().is_multicast()
                            || matches!(dst, SocketAddr::V4(v4) if v4.ip().is_broadcast())
                            || src.ip().is_unspecified()
                            || (private && !allow_private);
                        if let Some(tx) = udp_tx.as_ref().filter(|_| !no_relay) {
                            try_forward_udp(pkt, tx);
                        } else if no_relay {
                            debug!(
                                "TUN 丢弃 UDP 包（广播/组播/未指定源/私网未放开）: dst={}",
                                dst
                            );
                        } else if let Some(icmp) = build_icmpv4_port_unreachable(pkt) {
                            if let Err(e) = transport.send(&icmp).await {
                                error!("TUN 写 ICMPv4 不可达失败: {}", e);
                            }
                        } else {
                            device.push_inbound(pkt); // 判定与构造不一致的防御兜底
                        }
                    } else {
                        // IPv4 其余协议：逐项过滤后投喂 smoltcp（09 审查）
                        handle_v4_else(pkt, &cfg, &mut device, &mut warned_private);
                    }
                }
                Err(e) => {
                    error!("TUN 读包失败: {}（100ms 后重试）", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            // 周期 tick：驱动超时/重传/无包时的 poll
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }

        // 栈中转缓冲已提升到循环外复用（06-P3-8 / 09-P3-8）
        step(
            &cfg,
            &mut iface,
            &mut device,
            &mut sockets,
            &mut listeners,
            &mut flows,
            &opener,
            &mut stack_buf,
        )
        .await?;

        for frame in device.drain_outbound() {
            if let Err(e) = transport.send(&frame).await {
                error!("TUN 写包失败: {}", e);
            }
        }
    }

    // 收尾：中止所有流任务（路由清理由 run_tun 的 RouteGuard 负责）
    for (_, mut f) in flows.drain() {
        f.up_task.abort();
        if let Some(t) = f.reader_task.take() {
            t.abort();
        }
        if let Some(t) = f.writer_task.take() {
            t.abort();
        }
    }
    Ok(())
}

/// IPv4 非 UDP（非代答路径）包的过滤与投喂（09 审查 T-2/分片/私网兜底）。
///
/// - **ICMP 全部静默丢弃**（09-P2-2）：smoltcp（未启用 socket-icmp）对
///   EchoRequest 无条件自动回 EchoReply，且 any-ip 放行一切单播目的——
///   此前任意 IPv4 地址的 ping 都被本地栈以被 ping 的 IP 为源伪造应答，
///   连通性探测/故障切换/captive-portal 判定全部失真。丢弃后与 v6
///   "ping 不通属设计内"语义对称。
/// - **分片包全部静默丢弃**（09-P3-1）：未启用 proto-ipv4-fragmentation 时
///   smoltcp 不检查分片，非首片载荷会被按传输层头解析（仅靠校验和兜底，
///   理论可伪造）；MF 位此前也未判。MTU 1500 + MSS 钳制下分片本就罕见。
/// - **私网 TCP 目标告警兜底**（09-P2-1）：正常路径下私网段已被豁免路由
///   引回物理网关；仅当物理网关未知、豁免未生成时包才会到达此处——
///   丢弃并一次性告警（节点会 SSRF 拒绝私网目标，盲转发注定失败且无诊断）。
/// - 其余（TCP 到公网目标等）原样投喂栈。
fn handle_v4_else(
    pkt: &[u8],
    cfg: &TunConfig,
    device: &mut ChanDevice,
    warned_private: &mut bool,
) {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        // 非 IPv4（ARP 等非 IP 帧）：原样投喂由栈自行处理
        device.push_inbound(pkt);
        return;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if pkt[0] & 0x0f < 5 || pkt.len() < ihl {
        device.push_inbound(pkt); // 畸形头交由 smoltcp checked parse 丢弃
        return;
    }
    let proto = pkt[9];
    let (flags_frag_lo, frag_hi) = (pkt[6], pkt[7]);
    let frag_offset = (u16::from(flags_frag_lo & 0x1f) << 8) | u16::from(frag_hi);
    let has_more = flags_frag_lo & 0x20 != 0;
    if proto == 1 {
        // ICMP：不再投喂（防 any-ip 伪造 Echo Reply，见函数文档）
        debug!("TUN 丢弃入站 ICMPv4 包（防本地栈伪造回显）");
        return;
    }
    if frag_offset != 0 || has_more {
        debug!("TUN 丢弃 IPv4 分片包（无重组能力，防非首片被误解析）");
        return;
    }
    if proto == 6 && pkt.len() >= 24 {
        // 私网 TCP 目标兜底（排除 TUN 自身网段：发往 TUN 地址的流量合法）
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let mask = match cfg.prefix {
            0 => 0u32,
            p => u32::MAX << (32 - p.min(32)),
        };
        let dst_u32 = u32::from(dst);
        let net_u32 = u32::from(cfg.network());
        let private = dst.is_loopback()
            || dst.is_link_local()
            || dst.is_private()
            || dst.octets()[0] == 0
            || (dst.octets()[0] == 100 && (64..=127).contains(&dst.octets()[1]));
        let tun_subnet_hit = cfg.prefix > 0 && (dst_u32 & mask) == (net_u32 & mask);
        if private && !tun_subnet_hit {
            if !*warned_private {
                *warned_private = true;
                warn!(
                    "TUN 收到发往私网目标的 TCP 包（如 {}）但未生成豁免路由\
                     （物理网关未知？）：私网目标不经代理（节点会拒绝），已丢弃。\
                     请设置 HYDRA_TUN_GW 或确认默认网关可解析，私网访问即可直连",
                    dst
                );
            }
            return;
        }
    }
    device.push_inbound(pkt);
}

/// 添加一个监听 socket
fn add_listener(sockets: &mut SocketSet<'_>, port: u16) -> SocketHandle {
    let rx = SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = SocketBuffer::new(vec![0u8; TCP_BUF]);
    let mut sock = TcpSocket::new(rx, tx);
    // listen(port)：接受任意本地地址上目标端口为 port 的连接
    if let Err(e) = sock.listen(port) {
        error!("监听端口 {port} 失败: {e:?}");
    }
    sockets.add(sock)
}

/// 一轮栈步进：接受新流 → 泵下行 → poll → 泵上行/关闭/超时
#[allow(clippy::too_many_arguments)]
async fn step(
    cfg: &TunConfig,
    iface: &mut Interface,
    device: &mut ChanDevice,
    sockets: &mut SocketSet<'_>,
    listeners: &mut Vec<SocketHandle>,
    flows: &mut HashMap<SocketHandle, Flow>,
    opener: &ChannelOpener,
    // 06-P3-8：栈中转缓冲由调用方一次分配传入，step 每 tick 不再重新分配
    stack_buf: &mut [u8],
) -> Result<()> {
    // 1. 接受：监听 socket 一旦收到 SYN 就不再是 Listen 状态——它本身就是这条连接
    // （手工索引：port 0/None 分支会从 listeners 移除条目，此时不递增）
    let mut i = 0;
    while i < listeners.len() {
        let h = listeners[i];
        if matches!(sockets.get::<TcpSocket>(h).state(), State::Listen) {
            i += 1;
            continue;
        }
        // 审查 06-P2-8：仍然立即接受（占住流槽、补挂新监听，保证并发 SYN 不被
        // 丢弃），但**推迟真实上游建链**——up 任务（open_target → 节点 TCP+TLS+
        // Noise 握手）改到流进入 Established 后才派生（见下方"待建立流"循环）。
        // 此前 SynReceived 即建链：端口扫描的每个 SYN 都会兑换一条经节点的真实
        // 出站连接（出口流量放大器）；从未握成手的僵尸流由 30s 建立超时回收，
        // 不再等 300s 空闲超时。
        // 提取目标（TUN 视角：本地端点 = 应用想连的真实目的地）
        // v6 目标用 `[addr]:port`（SocketAddr 标准形式，节点侧 parse 可直解）
        // 注意：必须在 abort() 之前取端点——abort 后 local_endpoint 必为 None
        let endpoint = sockets.get::<TcpSocket>(h).local_endpoint();
        let (dst_ip, dst_port) = match endpoint {
            Some(ep) => (ep.addr, ep.port),
            None => {
                let port = sockets.get::<TcpSocket>(h).local_endpoint().map(|e| e.port);
                warn!("接受的连接缺少本地端点，回 RST（port={port:?}）");
                sockets.get_mut::<TcpSocket>(h).abort();
                // 先移除 socket 再处理监听：此前只 abort 不 remove，句柄遗弃在
                // SocketSet 中永不释放（每 socket 128KB 缓冲泄漏）
                sockets.remove(h);
                // 端点缺失 → 无端口可补挂：只移除不补挂（补挂 port 0 的 listen
                // 不匹配任何真实连接，只会形成死监听占住槽位）
                error!("接受的连接缺少本地端点（port={port:?}），移除该监听槽位且不补挂");
                listeners.remove(i);
                continue;
            }
        };
        let target = match dst_ip {
            IpAddress::Ipv4(a) => format!("{}:{}", a, dst_port),
            IpAddress::Ipv6(a) => format!("[{}]:{}", a, dst_port),
        };
        let port = dst_port;
        if flows.len() >= cfg.max_flows {
            // 超限：abort 发 RST 给应用（防资源耗尽，方案 §2）
            warn!("流数已达上限 {}，对新流回 RST", cfg.max_flows);
            sockets.get_mut::<TcpSocket>(h).abort();
            // 同上：先 remove 再补挂，防句柄遗弃泄漏
            sockets.remove(h);
            listeners[i] = add_listener(sockets, port);
            i += 1;
            continue;
        }
        // 生成流：up 任务负责开代理通道；Link 之后派生下行读取任务。
        // 06-P2-8：up 任务推迟到 Established 才派生（见 accepted_at/opened 字段
        // 与下方"待建立流"循环）——此处只登记通道与流槽。
        let (tx, rx) = mpsc::channel(FLOW_CHAN);
        let flow_tx = tx.clone();
        debug!("TUN 新流: {target}");
        flows.insert(
            h,
            Flow {
                target,
                up_rx: rx,
                up_task: tokio::spawn(async {}), // 占位：Established 后替换为真实 up 任务
                reader_task: None,
                flow_tx,
                up_tx: None,
                writer_task: None,
                pending: VecDeque::new(),
                last_active: Instant::now(),
                opened: false,
                accepted_at: Instant::now(),
            },
        );
        // 补一个新监听 socket 接下一个连接
        listeners[i] = add_listener(sockets, port);
        i += 1;
    }

    // 1.5 待建立流（审查 06-P2-8）：流进入 Established 后才派生真实上游建链；
    // 握手死掉 / 建立超时（30s）的流回 RST 回收——扫描 SYN 不再兑换成经节点的
    // 真实出站连接，僵尸流也不再等 300s 空闲超时。
    let mut to_remove: Vec<SocketHandle> = Vec::new();
    let mut to_open: Vec<SocketHandle> = Vec::new();
    for (&h, flow) in flows.iter_mut() {
        if flow.opened {
            continue;
        }
        let st = sockets.get::<TcpSocket>(h).state();
        // P3-8 修复：Established 与 **CloseWait** 都派生建链——应用把最后
        // ACK+数据+FIN 打包同批到达时（小请求 + delayed ACK 可出现），smoltcp
        // 同一次 poll 内完成 Established→CloseWait 迁移；旧逻辑只见 CloseWait
        // 不派生 opener，该已收到完整请求的流挂满 30s 后被 RST、数据零转发。
        // CloseWait 说明请求字节已到（may_recv 语义），照常建链转发。
        if st == State::Established || st == State::CloseWait {
            flow.opened = true;
            to_open.push(h);
        } else if matches!(st, State::Closed | State::TimeWait)
            || flow.accepted_at.elapsed() > FLOW_ESTABLISH_TIMEOUT
        {
            debug!(
                "TUN 流握手未完成即终结（state={st:?}），回收: {}",
                flow.target
            );
            sockets.get_mut::<TcpSocket>(h).abort();
            to_remove.push(h);
        }
    }
    for h in to_open {
        if let Some(flow) = flows.get_mut(&h) {
            flow.up_task = spawn_up_task(opener.clone(), flow.target.clone(), flow.flow_tx.clone());
        }
    }

    // 2. 泵代理下行数据入栈（socket 缓冲满则积压在 pending）
    for (&h, flow) in flows.iter_mut() {
        while let Ok(msg) = flow.up_rx.try_recv() {
            match msg {
                FlowMsg::Link(d) => {
                    // 拆出读写端：读端交给下行读取任务，写端交给独立上行写任务
                    // （06-P1-8：write_all 阻塞被移出栈主循环，慢流不再队头阻塞）
                    let ProxyDuplex { reader, writer } = d;
                    let tx = flow.flow_tx.clone();
                    let mut reader = reader;
                    flow.reader_task = Some(tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            match reader.read(&mut buf).await {
                                Ok(0) => break, // 代理侧 EOF（响应完整结束）
                                Ok(n) => {
                                    if tx.send(FlowMsg::Data(buf[..n].to_vec())).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break, // 代理链路故障 → EOF 语义（FIN）
                            }
                        }
                        // 任务结束 → 主循环检测 is_finished 后关写侧（发 FIN 给应用）
                    }));
                    // 上行写任务：own 写端 + 独立通道；写错误/写超时经 UpErr 回报
                    // 主循环中止该流，自身永不拖慢其他流
                    let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(FLOW_UP_CHAN);
                    let err_tx = flow.flow_tx.clone();
                    let mut writer = writer;
                    let target2 = flow.target.clone();
                    flow.writer_task = Some(tokio::spawn(async move {
                        loop {
                            match up_rx.recv().await {
                                Some(chunk) => {
                                    let wr = tokio::time::timeout(
                                        UP_WRITE_TIMEOUT,
                                        writer.write_all(&chunk),
                                    )
                                    .await;
                                    match wr {
                                        Ok(Ok(())) => {}
                                        Ok(Err(e)) => {
                                            warn!("TUN 流上行写失败（{target2}）: {e} → 回 RST");
                                            let _ = err_tx.send(FlowMsg::UpErr).await;
                                            return;
                                        }
                                        Err(_) => {
                                            // 写超时：链路假死/窗口耗尽，弃流保栈
                                            warn!("TUN 流上行写超时（{target2}，{UP_WRITE_TIMEOUT:?}）→ 回 RST");
                                            let _ = err_tx.send(FlowMsg::UpErr).await;
                                            return;
                                        }
                                    }
                                }
                                // 通道关闭 = 流已被主循环移除清理
                                None => return,
                            }
                        }
                    }));
                    flow.up_tx = Some(up_tx);
                }
                FlowMsg::LinkErr => {
                    sockets.get_mut::<TcpSocket>(h).abort();
                    to_remove.push(h);
                    break;
                }
                FlowMsg::UpErr => {
                    // 上行写任务故障：中止该流（RST 应用），其余流不受影响
                    warn!("TUN 流上行故障（{}）→ 回 RST", flow.target);
                    sockets.get_mut::<TcpSocket>(h).abort();
                    to_remove.push(h);
                    break;
                }
                FlowMsg::Data(v) => {
                    flow.last_active = Instant::now();
                    flow.pending.push_back(v);
                }
            }
        }
        // 尽量把积压写进 socket 发送缓冲
        while let Some(front_len) = flow.pending.front().map(|v| v.len()) {
            let sock = sockets.get_mut::<TcpSocket>(h);
            if !sock.may_send() {
                break;
            }
            // 06-P3-8：不再整块 clone——直接借 front 切片喂 socket（send_slice 只读）；
            // 仅部分写入的罕见路径才为剩余字节做一次 to_vec
            let n = {
                let front = flow.pending.front().unwrap();
                sock.send_slice(front).unwrap_or(0)
            };
            if n == 0 {
                break;
            }
            if n < front_len {
                let rest = flow.pending.front().unwrap()[n..].to_vec();
                flow.pending.pop_front();
                flow.pending.push_front(rest);
            } else {
                flow.pending.pop_front();
            }
        }
    }

    // 3. poll 栈（处理收到的包 + 生成 SYN-ACK/ACK/数据/FIN/RST）
    let now = smol_now();
    iface.poll(now, device, sockets);

    // 4. 栈 → 代理上行 + 关闭/超时管理
    // 06-P1-8 修复：上行投递改为非阻塞 try_send——单流链路卡死最多占满自己的
    // 上行通道（此后停 recv，靠 smoltcp 接收窗口归零背压），绝不阻塞主循环，
    // 其他流照常推进
    // 06-P3-8：此处原每 tick `vec![0u8; 16*1024]`——已改为调用方一次分配复用
    for (&h, flow) in flows.iter_mut() {
        let sock = sockets.get_mut::<TcpSocket>(h);
        // P3-8 配套：**不再**对 CloseWait 立即 close()（关写侧发 FIN）——主动
        // 半关闭的应用（发完请求 + FIN 后等待响应，FinWait2）会被这个立即 FIN
        // 直接拆线，响应永远收不到。写侧收敛统一交给下方「代理 reader EOF 且
        // pending 清空 → close()」路径；open 失败走 LinkErr→abort、链路挂死走
        // 空闲超时 abort，不存在写侧永不关闭的泄漏路径。
        // 通道未就绪（up_tx == None）时不 recv：数据留在 smoltcp rx 缓冲，
        // 接收窗口归零形成真实背压，对端会重传——此前先 recv 再丢弃是错的
        // （smoltcp 取走数据即推进 ACK，对端绝不会重传，窗口期字节被静默吞掉，
        // TLS ClientHello 丢失导致连接永久挂死）
        if sock.may_recv() {
            if let Some(up_tx) = &flow.up_tx {
                // 【取数顺序关键】先确认通道确有余量，再从 socket 取一块：
                // 每块只占一个槽位，且本上行通道的唯一发送方就是主循环自身，
                // capacity 检查到 try_send 之间无竞态——try_send 的 Full 分支
                // 理论不可达（防御性保留）。通道满 = 写端被慢链路拖住 → 本流
                // 停止 recv（数据留 socket，TCP 窗口背压），主循环继续服务其他流。
                while up_tx.capacity() > 0 && sock.may_recv() {
                    // 0.11 的 recv_slice 返回 Result<usize, RecvError>
                    let n = sock.recv_slice(stack_buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    match up_tx.try_send(stack_buf[..n].to_vec()) {
                        Ok(()) => {
                            flow.last_active = Instant::now();
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => break, // 防御性兜底
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // 写任务已死（UpErr 已回报）：中止该流
                            sock.abort();
                            to_remove.push(h);
                            break;
                        }
                    }
                }
            }
        }
        // 代理下行读取任务结束 = 代理侧 EOF/故障 → 关写侧（发 FIN 给应用）
        if flow
            .reader_task
            .as_ref()
            .map(|t| t.is_finished())
            .unwrap_or(false)
            && flow.pending.is_empty()
        {
            sock.close();
        }
        if !sock.is_open() && matches!(sock.state(), State::Closed | State::TimeWait) {
            to_remove.push(h);
        }
        if flow.last_active.elapsed() > TunConfig::IDLE_TIMEOUT {
            info!("TUN 流空闲超时（{}），中止", flow.target);
            sock.abort();
            to_remove.push(h);
        }
    }

    // 5. 清理（socket 移除 + 相关任务收敛）
    for h in to_remove {
        if let Some(mut f) = flows.remove(&h) {
            debug!("TUN 流关闭: {}", f.target);
            f.up_task.abort();
            if let Some(t) = f.reader_task.take() {
                t.abort();
            }
            if let Some(t) = f.writer_task.take() {
                t.abort();
            }
            sockets.remove(h);
        }
    }
    Ok(())
}

// ── 真实 TUN 设备接线 ────────────────────────────────────────────────────────

/// TUN 模式入口：创建设备 → 应用路由（带 drop guard）→ 跑栈主循环。
/// 设备创建失败（Windows 无 wintun.dll / 非管理员；Linux 无 /dev/net/tun 或无
/// CAP_NET_ADMIN）→ 明确报错。
pub async fn run_tun(
    cfg: TunConfig,
    opener: ChannelOpener,
    udp_factory: Option<UdpChannelFactory>,
    shutdown: CancellationToken,
) -> Result<()> {
    // 1. 物理 gw 探测 + 路由方案（豁免失败只是告警，见 compute_routes）
    let gw = detect_physical_gateway();
    let plan = compute_routes(&cfg, gw);
    info!(
        // 07-P2-3：不再做平台相关的硬编码减法（`len() - 3` 在 Linux + 物理网关
        // 探测失败时 usize 下溢 panic）——直接输出总数与豁免数，与平台解耦
        "TUN 路由方案：{} 条添加（豁免 {} 条），物理网关={}",
        plan.add.len(),
        cfg.exclude_routes.len(),
        gw.map(|i| i.to_string()).unwrap_or_else(|| "未知".into())
    );

    // 2. 创建 TUN 设备（先于路由：路由指向 TUN 地址，设备必须先存在）
    let mut tcfg = tun2::Configuration::default();
    tcfg.address(cfg.addr)
        .netmask(prefix_to_mask(cfg.prefix).map(|o| o.to_string()).join("."))
        .mtu(cfg.mtu)
        .up();
    // Windows：wintun.dll（与 exe 同架构）需放在 exe 目录或 PATH；非管理员创建会失败
    let dev = tun2::create_as_async(&tcfg).map_err(|e| {
        HydraError::ConnectionError(format!(
            "TUN 设备创建失败: {e}（Windows 需管理员运行且 wintun.dll 可用；Linux 需 root/CAP_NET_ADMIN）"
        ))
    })?;
    info!(
        "✓ TUN 设备已创建（addr={} prefix={} mtu={}）",
        cfg.addr, cfg.prefix, cfg.mtu
    );

    // 3. 应用路由 + drop guard（任务结束/崩溃展开时幂等清理）
    let exec: Arc<dyn RouteExecutor> = Arc::new(SystemRouteExecutor);
    if let Err(e) = apply_routes(exec.as_ref(), &plan) {
        error!("路由配置失败: {e}——已回滚本次已添加的路由，放弃启动 TUN（无残留）");
        return Err(HydraError::ConnectionError(format!(
            "TUN 路由配置失败: {e}"
        )));
    }
    // 3b. IPv6 对称接管（try-and-warn，见 apply_routes_v6_try）：
    // 失败/关闭均不阻断启动，但必须明确告警泄漏面（0-4 防泄漏要求）。
    let gw6 = detect_physical_gateway_v6();
    let plan6 = compute_routes_v6(&cfg, gw6);
    if !cfg.ipv6_enabled {
        // 显式关闭（HYDRA_TUN_IPV6=0）：v6 走原路径不经代理——如实告警泄漏面
        warn!(
            "IPv6 接管已显式关闭（HYDRA_TUN_IPV6=0）——\
             系统 IPv6 流量不经代理直接出网，存在泄漏；v6 包将被快速失败代答"
        );
    } else if plan6.add.is_empty() {
        warn!("IPv6 接管未生成任何路由（无方案）——存在 IPv6 泄漏风险");
    } else {
        // v1 完整版：proto-ipv6 栈 + 动态 AnyIP 正向路径——v6 TCP 真实经节点代理；
        // v6 UDP/ICMP 等非 TCP 包仍回 ICMPv6 不可达（应用回落 IPv4）
        info!(
            "IPv6 接管已开启：v6 TCP 经用户态栈代理转发（动态 AnyIP），\
             v6 非 TCP（UDP 等）回 ICMPv6 不可达供应用回落 IPv4"
        );
        let failed = apply_routes_v6_try(exec.as_ref(), &plan6);
        if failed > 0 {
            warn!(
                "IPv6 接管 {} / {} 条路由失败——未接管部分存在 IPv6 泄漏；\
                 v4 接管不受影响，继续启动",
                failed,
                plan6.add.len()
            );
        } else {
            info!(
                "✓ IPv6 接管路由已添加（::/1 + 8000::/1，豁免 {} 条）",
                plan6.add.len() - 2
            );
        }
    }
    let _guard = RouteGuard {
        exec,
        plan,
        plan6: cfg.ipv6_enabled.then_some(plan6),
    };

    // 4. 栈主循环
    let transport = Arc::new(Tun2Transport::new(dev));
    let res = run_stack(transport, cfg, opener, udp_factory, shutdown).await;
    info!("TUN 模式退出，路由已清理");
    res
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tun() -> TunConfig {
        TunConfig {
            exclude_routes: vec![
                Ipv4Addr::new(203, 0, 113, 7), // 节点 IP
                Ipv4Addr::new(8, 8, 8, 8),     // DNS
            ],
            ..Default::default()
        }
    }

    /// 07-P1-2 起步、v1 完整版扩充：IPv6 快速失败代答组包正确性 +
    /// 动态 AnyIP 正向路径（回环集成见下方 v6 用例）
    mod v6_blackhole {
        use super::*;

        /// 构造一个 IPv6 + TCP SYN 包（应用 → 远端 2001:db8::1:443）
        fn sample_syn() -> Vec<u8> {
            let mut p = Vec::new();
            p.push(0x60);
            p.extend_from_slice(&[0, 0, 0]);
            p.extend_from_slice(&20u16.to_be_bytes());
            p.push(6); // next header = TCP
            p.push(64);
            p.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]); // src
            p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // dst
            p.extend_from_slice(&54321u16.to_be_bytes()); // sport
            p.extend_from_slice(&443u16.to_be_bytes()); // dport
            p.extend_from_slice(&1000u32.to_be_bytes()); // seq
            p.extend_from_slice(&0u32.to_be_bytes()); // ack
            p.push(0x50);
            p.push(0x02); // SYN
            p.extend_from_slice(&0u16.to_be_bytes());
            p.extend_from_slice(&[0, 0]);
            p.extend_from_slice(&[0, 0]);
            p
        }

        #[test]
        fn ipv6识别() {
            assert!(is_ipv6_packet(&sample_syn()));
            let mut v4 = vec![
                0x45, 0, 0, 60, 0, 0, 0, 0, 64, 6, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2, 0, 0, 0, 0,
            ];
            v4.resize(40, 0);
            assert!(!is_ipv6_packet(&v4));
            assert!(!is_ipv6_packet(&[0x60, 0x00])); // 长度不足
        }

        #[test]
        fn syn回rst_地址端口对调_ack为seq加一() {
            let syn = sample_syn();
            let rst = build_tcp_rst_v6(&syn).expect("SYN 应构造出 RST");
            assert_eq!(rst.len(), 60);
            // IPv6 头：版本 6、方向对调
            assert_eq!(rst[0] >> 4, 6);
            assert_eq!(&rst[8..24], &syn[24..40], "RST 源 = 原 SYN 目的");
            assert_eq!(&rst[24..40], &syn[8..24], "RST 目的 = 原 SYN 源");
            // TCP 头：端口对调、ack = seq+1、RST|ACK
            assert_eq!(&rst[40..42], &syn[42..44], "源端口 = 原 SYN 目的端口");
            assert_eq!(&rst[42..44], &syn[40..42], "目的端口 = 原 SYN 源端口");
            assert_eq!(
                rst[51], 0xE9,
                "ack 低字节 = seq+1（seq=1000=0x3E8 → ack=0x3E9）"
            );
            assert_eq!(rst[53], 0x14, "flags = RST|ACK");
            // 校验和自洽：置 0 后按伪首部复算应等于包内值
            let mut tcp = rst[40..].to_vec();
            let ck_in_pkt = u16::from_be_bytes([tcp[16], tcp[17]]);
            tcp[16] = 0;
            tcp[17] = 0;
            let ck_recalc = checksum16(
                &[
                    ipv6_pseudo_header(
                        &rst[8..24].try_into().unwrap(),
                        &rst[24..40].try_into().unwrap(),
                        20,
                        6,
                    ),
                    tcp,
                ]
                .concat(),
            );
            assert_eq!(ck_in_pkt, ck_recalc, "RST 校验和应自洽");
        }

        #[test]
        fn 非syn不回rst() {
            let mut syn = sample_syn();
            syn[53] = 0x10; // ACK（无 SYN）
            assert!(build_tcp_rst_v6(&syn).is_none(), "纯 ACK 不应代答 RST");
            syn[53] = 0x12; // SYN|ACK
            assert!(build_tcp_rst_v6(&syn).is_none(), "SYN-ACK 不应代答 RST");
            syn[6] = 17; // next header = UDP
            assert!(build_tcp_rst_v6(&syn).is_none(), "非 TCP 不应代答 RST");
        }

        #[test]
        fn 其余回icmpv6不可达_引用原包() {
            let syn = sample_syn();
            let icmp = build_icmpv6_unreachable_v6(&syn);
            // 40B 头 + 8B ICMP 头 + 引用整包（60B < 1232 截断限）
            assert_eq!(icmp.len(), 40 + 8 + syn.len());
            assert_eq!(icmp[40], 1, "type = destination unreachable");
            assert_eq!(icmp[41], 0, "code = 0");
            assert_eq!(&icmp[48..], &syn[..], "应引用原包全文（未达截断限时）");
            assert_eq!(&icmp[8..24], &syn[24..40], "ICMPv6 源 = 原目的");
            // 校验和自洽
            let mut body = icmp[40..].to_vec();
            let ck_in_pkt = u16::from_be_bytes([body[2], body[3]]);
            body[2] = 0;
            body[3] = 0;
            let ck_recalc = checksum16(
                &[
                    ipv6_pseudo_header(
                        &icmp[8..24].try_into().unwrap(),
                        &icmp[24..40].try_into().unwrap(),
                        (icmp.len() - 40) as u32,
                        58,
                    ),
                    body,
                ]
                .concat(),
            );
            assert_eq!(ck_in_pkt, ck_recalc, "ICMPv6 校验和应自洽");
        }

        // ── v1 完整版：IPv4 UDP 代答 ICMPv4 port unreachable ────────────────

        /// 构造一个 IPv4 UDP 包（应用 → 远端 1.2.3.4:443，UDP 8B 头）
        fn sample_udp_v4() -> Vec<u8> {
            let mut p = vec![0x45, 0, 28, 0x12, 0x34, 0, 0, 0, 64, 17, 0, 0]; // 头校验和置 0
            p.extend_from_slice(&[192, 168, 1, 100]); // src
            p.extend_from_slice(&[1, 2, 3, 4]); // dst
            p.extend_from_slice(&54321u16.to_be_bytes()); // sport
            p.extend_from_slice(&443u16.to_be_bytes()); // dport
            p.extend_from_slice(&8u16.to_be_bytes()); // UDP 长度
            p.extend_from_slice(&[0, 0]); // UDP 校验和 0
            p
        }

        #[test]
        fn ipv4_udp判定_tcp与非首片不代答() {
            assert!(is_unproxyable_udp_v4(&sample_udp_v4()));
            // TCP（协议号 6）不代答
            let mut tcp = sample_udp_v4();
            tcp[9] = 6;
            assert!(!is_unproxyable_udp_v4(&tcp));
            // 非首片（分片偏移 ≠ 0）不代答（对分片代答会制造重复 ICMP）
            let mut frag = sample_udp_v4();
            frag[6] = 0x00;
            frag[7] = 0x08; // 偏移 1（8 字节单位）
            assert!(!is_unproxyable_udp_v4(&frag));
            // 非 IPv4 不代答
            assert!(!is_unproxyable_udp_v4(&[0x60, 0, 0, 0, 0, 0, 0, 0]));
        }

        #[test]
        fn icmpv4_port_unreachable_格式与校验和() {
            let udp = sample_udp_v4();
            let icmp = build_icmpv4_port_unreachable(&udp).expect("UDP 包应构造出 ICMP");
            // 20B IPv4 头 + 8B ICMP 头 + 引用（原 IP 头 20B + 8B 载荷）
            assert_eq!(icmp.len(), 20 + 8 + 28);
            // 外层头方向对调、协议 = ICMP(1)
            assert_eq!(&icmp[12..16], &udp[16..20], "ICMP 源 = 原 UDP 目的");
            assert_eq!(&icmp[16..20], &udp[12..16], "ICMP 目的 = 原 UDP 源");
            assert_eq!(icmp[9], 1, "protocol = ICMP");
            // type 3 / code 3
            assert_eq!(icmp[20], 3);
            assert_eq!(icmp[21], 3);
            // 引用 = 原 IP 头 + 前 8B 载荷（RFC 792）
            assert_eq!(&icmp[28..48], &udp[..20]);
            assert_eq!(&icmp[48..56], &udp[20..28]);
            // ICMP 校验和自洽（RFC 792：只覆盖 ICMP 段，不含伪首部）
            let ck_in = u16::from_be_bytes([icmp[22], icmp[23]]);
            let mut body = icmp[20..].to_vec();
            body[2] = 0;
            body[3] = 0;
            assert_eq!(ck_in, checksum16(&body), "ICMPv4 校验和应自洽");
            // IPv4 头校验和自洽（RFC 1071：只覆盖头自身）
            let ck_in = u16::from_be_bytes([icmp[10], icmp[11]]);
            let mut hdr = icmp[..20].to_vec();
            hdr[10] = 0;
            hdr[11] = 0;
            assert_eq!(ck_in, checksum16(&hdr), "IPv4 头校验和应自洽");
        }

        #[test]
        fn icmpv4_非udp包返回none() {
            assert!(build_icmpv4_port_unreachable(&sample_udp_v4()[..15]).is_none());
            let mut tcp = sample_udp_v4();
            tcp[9] = 6;
            assert!(build_icmpv4_port_unreachable(&tcp).is_none());
        }

        // ── v1 完整版：动态 AnyIP（ensure_v6_dst）────────────────────────────

        /// 干净栈接口（ipv6_enabled 默认配置：v4 + fe80::1/10 + fd07::1/64 三静态地址）
        fn fresh_iface() -> (Interface, ChanDevice) {
            let cfg = TunConfig::default();
            let (mut dev, _in_q, _out_q) = ChanDevice::new(1500);
            let iface = build_interface(&cfg, &mut dev).unwrap();
            (iface, dev)
        }

        #[test]
        fn 动态anyip_挂载_池满淘汰_活跃保护() {
            let (mut iface, _dev) = fresh_iface();
            let mut pool = VecDeque::new();
            let empty = std::collections::HashSet::new();

            // 前 V6_DYNAMIC_SLOTS 个目的地址全部挂载成功
            let addrs: Vec<std::net::Ipv6Addr> = (1..=V6_DYNAMIC_SLOTS as u16 + 2)
                .map(|i| {
                    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)
                })
                .collect();
            for a in &addrs[..V6_DYNAMIC_SLOTS] {
                ensure_v6_dst(&mut iface, *a, &mut pool, &empty);
                assert!(pool.contains(a));
            }
            // 第 7 个：池满 → 淘汰最旧非活跃（addrs[0]），新地址挂载成功
            ensure_v6_dst(&mut iface, addrs[V6_DYNAMIC_SLOTS], &mut pool, &empty);
            assert!(pool.contains(&addrs[V6_DYNAMIC_SLOTS]));
            assert!(
                !pool.contains(&addrs[0]),
                "最旧非活跃地址应被淘汰"
            );
            assert!(
                !iface.has_ip_addr(IpAddress::Ipv6(smoltcp::wire::Ipv6Address(addrs[0].octets()))),
                "被淘汰地址应从接口摘除"
            );
            assert!(pool.len() <= V6_DYNAMIC_SLOTS, "池容量应有界");

            // 活跃保护：剩余地址全部受保护时，新地址放弃挂载、既有地址保留
            let protected: std::collections::HashSet<_> = pool.iter().copied().collect();
            let newcomer = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 1);
            ensure_v6_dst(&mut iface, newcomer, &mut pool, &protected);
            assert!(!pool.contains(&newcomer), "全部活跃时不应挤占");
            for a in &protected {
                assert!(pool.contains(a), "受保护地址不应被淘汰: {a}");
            }

            // 重复挂载幂等（含静态地址命中：fd07::1 是接口静态地址）
            let before = pool.len();
            ensure_v6_dst(&mut iface, addrs[1], &mut pool, &empty);
            assert_eq!(pool.len(), before, "重复挂载不应重复入池");
        }
    }

    #[test]
    fn compute_routes_含豁免清单完备() {
        let gw = Some(Ipv4Addr::new(192, 168, 1, 1));
        // 显式含网段直连版（平台无关；生产入口按 cfg!(windows) 决定，见 compute_routes）
        let plan = compute_routes_for(&tun(), gw, true);
        // 添加清单：/1 x2 + TUN 网段 + 2 豁免 + 4 私网段豁免（09-P2-1）
        assert_eq!(plan.add.len(), 9);
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 1,
            gateway: Ipv4Addr::new(10, 7, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(128, 0, 0, 0),
            prefix: 1,
            gateway: Ipv4Addr::new(10, 7, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(10, 7, 0, 0),
            prefix: 30,
            gateway: Ipv4Addr::new(10, 7, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(203, 0, 113, 7),
            prefix: 32,
            // gw 静态为 Some：直接写字面量（clippy unnecessary_literal_unwrap）
            gateway: Ipv4Addr::new(192, 168, 1, 1),
        }));
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(8, 8, 8, 8),
            prefix: 32,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
        }));
    }

    #[test]
    fn compute_routes_删除与添加一一对应() {
        let plan = compute_routes(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(plan.add.len(), plan.remove.len());
        for (a, r) in plan.add.iter().zip(plan.remove.iter()) {
            // 同一网段同一网关，动作相反（幂等清理配对）
            assert_eq!(a.dest, r.dest);
            assert_eq!(a.prefix, r.prefix);
            assert_eq!(a.gateway, r.gateway);
        }
    }

    #[test]
    fn compute_routes_无物理网关时跳过豁免并保留接管() {
        let plan = compute_routes_for(&tun(), None, true);
        // 仅 /1 x2 + TUN 网段；豁免项不生成（避免生成错误路由）
        assert_eq!(plan.add.len(), 3);
        assert!(plan.remove.len() == 3);
    }

    /// 审查 06-P2-10：Linux 不生成 TUN 网段直连路由（内核 connected route 已覆盖，
    /// 显式 via 本机地址会 EINVAL 且连累整体回滚）
    #[test]
    fn compute_routes_linux不含网段直连() {
        let plan = compute_routes_for(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)), false);
        // /1 x2 + 2 豁免 + 4 私网段豁免（09-P2-1）= 8；无 10.7.0.0/30
        assert_eq!(plan.add.len(), 8);
        assert!(!plan
            .add
            .iter()
            .any(|c| c.prefix == 30 && c.dest == Ipv4Addr::new(10, 7, 0, 0)));
        assert_eq!(plan.remove.len(), 8);
        // 私网豁免段在场
        assert!(plan
            .add
            .iter()
            .any(|c| c.prefix == 8 && c.dest == Ipv4Addr::new(10, 0, 0, 0)));
    }

    /// 审查 06-P2-9：prefix>32 不再下溢（钳制到 32 的掩码）
    #[test]
    fn prefix_to_mask_prefix超界被钳制() {
        assert_eq!(prefix_to_mask(32), [255, 255, 255, 255]);
        assert_eq!(
            prefix_to_mask(33),
            [255, 255, 255, 255],
            "prefix>32 应钳制而非下溢"
        );
        assert_eq!(prefix_to_mask(255), [255, 255, 255, 255]);
        assert_eq!(prefix_to_mask(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_mask(30), [255, 255, 255, 252]);
    }

    // ── 0-4 IPv6 对称接管单测 ────────────────────────────────────────────────

    fn tun_v6() -> TunConfig {
        TunConfig {
            exclude_routes_v6: vec![
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7), // 节点 IPv6 地址
            ],
            // 07-P1-2 时默认关闭；本组用例验证"接管开启"的方案生成，显式打开
            //（v1 完整版默认已为 true，显式写出以隔离默认值变动）
            ipv6_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn compute_routes_v6_接管与豁免完备() {
        let gw6 = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let plan = compute_routes_v6(&tun_v6(), gw6);
        // ::/1 + 8000::/1 接管 + 1 条节点 v6 豁免 /128 + ULA fc00::/7 豁免（09-P2-1）
        assert_eq!(plan.add.len(), 4);
        assert!(plan.add.contains(&RouteCmdV6 {
            dest: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            prefix: 7,
            gateway: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmdV6 {
            dest: Ipv6Addr::UNSPECIFIED,
            prefix: 1,
            gateway: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmdV6 {
            dest: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
            prefix: 1,
            gateway: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
        }));
        assert!(plan.add.contains(&RouteCmdV6 {
            dest: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7),
            prefix: 128,
            // gw6 静态为 Some：直接写字面量
            gateway: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        }));
        // 删除与添加一一对应（幂等清理配对）
        assert_eq!(plan.add.len(), plan.remove.len());
    }

    #[test]
    fn compute_routes_v6_无v6网关时跳过豁免保留接管() {
        let plan = compute_routes_v6(&tun_v6(), None);
        assert_eq!(plan.add.len(), 2);
        assert_eq!(plan.remove.len(), 2);
    }

    #[test]
    fn compute_routes_v6_开关关闭时产出空方案() {
        let mut cfg = tun_v6();
        cfg.ipv6_enabled = false;
        let plan = compute_routes_v6(&cfg, Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(plan.add.is_empty());
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn v6_路由命令平台参数格式() {
        let cmd = RouteCmdV6 {
            dest: Ipv6Addr::UNSPECIFIED,
            prefix: 1,
            gateway: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
        };
        assert_eq!(
            cmd.linux_args(RouteAction::Add),
            vec!["-6", "route", "add", "::/1", "via", "fd07::1"]
        );
        assert_eq!(
            cmd.linux_args(RouteAction::Delete),
            vec!["-6", "route", "delete", "::/1", "via", "fd07::1"]
        );
        assert_eq!(
            cmd.windows_args(RouteAction::Add, "Hydra"),
            vec![
                "interface",
                "ipv6",
                "add",
                "route",
                "::/1",
                "interface=Hydra"
            ]
        );
    }

    #[test]
    fn apply_routes_v6_try_失败不回滚不阻断只计数() {
        let plan = compute_routes_v6(&tun_v6(), Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        // 第 1 条（::/1）成功，之后全部失败
        let exec = FailAfterExecutor {
            ok: 1,
            calls: Mutex::new(Vec::new()),
        };
        let failed = apply_routes_v6_try(&exec, &plan);
        assert_eq!(
            failed,
            3,
            "::/1 之后的 3 条（8000::/1、节点 /128、ULA /7）应失败: {calls:?}",
            calls = exec.calls.lock().unwrap()
        );
        // try-and-warn：失败条目不产生任何 Delete（不回滚），已成功的保留
        let calls = exec.calls.lock().unwrap();
        let deletes: Vec<&String> = calls.iter().filter(|c| c.contains("Delete")).collect();
        assert!(deletes.is_empty(), "v6 接管失败不应回滚: {deletes:?}");
    }

    #[test]
    fn apply_routes_v6_try_全部成功返回零() {
        let plan = compute_routes_v6(&tun_v6(), Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        let exec = FailAfterExecutor {
            ok: usize::MAX,
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(apply_routes_v6_try(&exec, &plan), 0);
        assert_eq!(exec.calls.lock().unwrap().len(), 4);
    }

    #[test]
    fn cleanup_routes_v6_幂等删除配对() {
        let exec = DryRunExecutor::default();
        let plan = compute_routes_v6(&tun_v6(), Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(apply_routes_v6_try(&exec, &plan), 0);
        cleanup_routes_v6(&exec, &plan);
        let cmds = exec.commands.lock().unwrap();
        assert_eq!(cmds.len(), 8);
        assert!(cmds[4].starts_with("v6 Delete ::/1"));
    }

    #[test]
    fn 路由命令平台参数格式() {
        let cmd = RouteCmd {
            dest: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 1,
            gateway: Ipv4Addr::new(10, 7, 0, 1),
        };
        assert_eq!(
            cmd.windows_args(RouteAction::Add),
            vec![
                "add",
                "0.0.0.0",
                "mask",
                "128.0.0.0",
                "10.7.0.1",
                "metric",
                "1"
            ]
        );
        assert_eq!(
            cmd.windows_args(RouteAction::Delete),
            vec!["delete", "0.0.0.0", "mask", "128.0.0.0", "10.7.0.1"]
        );
        assert_eq!(
            cmd.linux_args(RouteAction::Add),
            vec!["add", "0.0.0.0/1", "via", "10.7.0.1"]
        );
    }

    #[test]
    fn dry_run执行器记录命令且不真跑() {
        let exec = DryRunExecutor::default();
        let plan = compute_routes_for(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)), true);
        apply_routes(&exec, &plan).unwrap();
        assert_eq!(exec.commands.lock().unwrap().len(), 9);
        cleanup_routes(&exec, &plan);
        assert_eq!(exec.commands.lock().unwrap().len(), 18);
        assert!(exec.commands.lock().unwrap()[0].starts_with("Add 0.0.0.0/1"));
        assert!(exec.commands.lock().unwrap()[9].starts_with("Delete 0.0.0.0/1"));
    }

    /// 注入式执行器：前 `ok` 条 Add 成功，之后全部失败；记录所有命令
    struct FailAfterExecutor {
        ok: usize,
        calls: Mutex<Vec<String>>,
    }

    impl RouteExecutor for FailAfterExecutor {
        fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()> {
            let line = format!("{:?} {}/{}", action, cmd.dest, cmd.prefix);
            let adds = self
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("Add"))
                .count();
            if action == RouteAction::Add && adds >= self.ok {
                return Err(std::io::Error::other("注入失败"));
            }
            self.calls.lock().unwrap().push(line);
            Ok(())
        }

        fn run6(&self, action: RouteAction, cmd: &RouteCmdV6) -> std::io::Result<()> {
            let line = format!("v6 {:?} {}/{}", action, cmd.dest, cmd.prefix);
            let adds = self
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("v6 Add"))
                .count();
            if action == RouteAction::Add && adds >= self.ok {
                return Err(std::io::Error::other("注入失败"));
            }
            self.calls.lock().unwrap().push(line);
            Ok(())
        }
    }

    #[test]
    fn apply_routes_部分失败回滚已成功部分() {
        let plan = compute_routes_for(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)), true);
        // 前 3 条（两条 /1 接管 + TUN 网段）成功，第 4 条（豁免路由，最易失败）失败
        let exec = FailAfterExecutor {
            ok: 3,
            calls: Mutex::new(Vec::new()),
        };
        assert!(apply_routes(&exec, &plan).is_err());
        let calls = exec.calls.lock().unwrap();
        // 已成功的 3 条必须全部回滚（Delete x3），否则半接管黑洞残留
        let deletes: Vec<&String> = calls.iter().filter(|c| c.starts_with("Delete")).collect();
        assert_eq!(deletes.len(), 3, "已添加的 3 条路由应全部回滚: {calls:?}");
        assert!(deletes[0].contains("0.0.0.0/1"));
        assert!(deletes[1].contains("128.0.0.0/1"));
        assert!(deletes[2].contains("10.7.0.0/30"));
    }

    #[test]
    fn apply_routes_全部成功不产生删除() {
        let plan = compute_routes_for(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)), true);
        let exec = FailAfterExecutor {
            ok: usize::MAX,
            calls: Mutex::new(Vec::new()),
        };
        assert!(apply_routes(&exec, &plan).is_ok());
        assert_eq!(exec.calls.lock().unwrap().len(), 9);
        assert!(exec
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|c| c.starts_with("Add")));
    }

    // ── smoltcp 回环集成：单进程两个 Interface 对接（无真实 TUN 设备）────────

    use smoltcp::iface::SocketSet as ClientSocketSet;
    use smoltcp::socket::tcp::Socket as ClientTcpSocket;

    /// 测试传输：栈侧 recv 从通道收包（由「客户端栈」注入），send 丢入回传通道
    struct TestTransport {
        inbound: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl PacketTransport for TestTransport {
        fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFut<'a, std::io::Result<usize>> {
            Box::pin(async move {
                let pkt = self
                    .inbound
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| std::io::Error::other("closed"))?;
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            })
        }
        fn send<'a>(&'a self, buf: &'a [u8]) -> BoxFut<'a, std::io::Result<()>> {
            Box::pin(async move {
                let _ = self.outbound.send(buf.to_vec());
                Ok(())
            })
        }
    }

    /// 客户端（应用侧）栈设备：与 ChanDevice 同构
    struct ClientDev {
        inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
        outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl Device for ClientDev {
        type RxToken<'a> = ChanRx;
        type TxToken<'a> = ChanTx;
        fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.inbound.lock().unwrap().pop_front()?;
            Some((
                ChanRx(Some(frame)),
                ChanTx {
                    queue: self.outbound.clone(),
                },
            ))
        }
        fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(ChanTx {
                queue: self.outbound.clone(),
            })
        }
        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = 1500;
            caps
        }
    }

    /// 目标通道调用参数记录（mock opener）
    type RecordedTargets = Arc<Mutex<Vec<String>>>;

    /// mock opener：建一条 duplex——一半交给测试侧（写"pong"/读"ping"），
    /// 另一半打包成 ProxyDuplex 交给栈。
    fn mock_opener(
        recorded: RecordedTargets,
    ) -> (ChannelOpener, mpsc::Receiver<tokio::io::DuplexStream>) {
        let (tx, rx) = mpsc::channel(8);
        let opener: ChannelOpener = Arc::new(move |target: String| {
            recorded.lock().unwrap().push(target);
            let tx = tx.clone();
            Box::pin(async move {
                let (test_side, stack_side) = tokio::io::duplex(64 * 1024);
                let _ = tx.send(test_side).await;
                let (r, w) = tokio::io::split(stack_side);
                Ok(ProxyDuplex {
                    reader: Box::new(r),
                    writer: Box::new(w),
                })
            }) as OpenFuture
        });
        (opener, rx)
    }

    fn client_iface(dev: &mut ClientDev) -> (Interface, ClientSocketSet<'static>, SocketHandle) {
        let cfg = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(cfg, dev, smol_now());
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address([10, 7, 0, 2])), 30))
                .unwrap();
            // v6 测试路径需要客户端栈也有 v6 地址与默认路由（与栈侧对称）
            a.push(IpCidr::new(
                IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
                64,
            ))
            .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address([10, 7, 0, 1]))
            .unwrap();
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
            .unwrap();
        let mut sockets = ClientSocketSet::new(vec![]);
        let rx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let tx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let h = sockets.add(ClientTcpSocket::new(rx, tx));
        (iface, sockets, h)
    }

    /// tokio 测试：客户端 socket 连 93.184.216.34:443 → 断言 opener 收到该参数，
    /// 数据双向透传（"ping" 出、"pong" 回）。
    #[tokio::test(flavor = "multi_thread")]
    async fn 栈回环_建连_目标参数_双向透传() {
        let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
        let (opener, mut dup_rx) = mock_opener(recorded.clone());

        // 栈侧 transport 通道：client 出包 → stack inbound；stack 出包 → client inbound
        let (to_stack_tx, to_stack_rx) = mpsc::unbounded_channel();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(to_stack_rx),
            outbound: to_client_tx,
        });

        // 远端模拟任务：拿到 duplex 测试侧后立即写 "pong"（multi_thread 下独立任务推进）
        tokio::spawn(async move {
            if let Some(mut side) = dup_rx.recv().await {
                use tokio::io::AsyncWriteExt;
                let _ = side.write_all(b"pong").await;
                let _ = side.flush().await;
                // 保持存活 10s，模拟远端连接保持
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let cfg = TunConfig::default();
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let _stack_task =
            tokio::spawn(async move { run_stack(transport, cfg, opener, None, shutdown2).await });

        // 客户端栈（模拟 TUN 后面的应用）
        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev {
            inbound: cin.clone(),
            outbound: cout.clone(),
        };
        let (mut ciface, mut csockets, _ch) = client_iface(&mut cdev);

        let rx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let tx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let mut csock_data = ClientTcpSocket::new(rx, tx);
        csock_data
            .connect(
                ciface.context(),
                (IpAddress::Ipv4(Ipv4Address([93, 184, 216, 34])), 443),
                (Ipv4Address([10, 7, 0, 2]), 40001),
            )
            .unwrap();
        let ch_data = csockets.add(csock_data);

        // 单循环驱动：桥接两个栈 + 客户端 poll + opener 结果非阻塞收取 +
        // 测试侧写 "pong"（模拟远端响应）+ 收 "pong" 断言透传
        let mut sent = false;
        let mut got_pong = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !got_pong {
            // stack 出包 → client 入队
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            // client 出包 → stack 入队
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);

            // 连接建立后发 "ping"（opener 参数断言用 recorded，远端任务负责写 pong）
            {
                let sock = csockets.get_mut::<ClientTcpSocket>(ch_data);
                if !sent && sock.may_send() && sock.state() == State::Established {
                    let _ = sock.send_slice(b"ping");
                    sent = true;
                }
            }
            // 测试侧 "pong" 由远端模拟任务负责写入
            // 客户端收数据
            {
                let sock = csockets.get_mut::<ClientTcpSocket>(ch_data);
                let mut buf = [0u8; 16];
                if let Ok(n) = sock.recv_slice(&mut buf) {
                    if buf[..n].windows(4).any(|w| w == b"pong") {
                        got_pong = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let opened_target = recorded.lock().unwrap().last().cloned();
        assert_eq!(
            opened_target.as_deref(),
            Some("93.184.216.34:443"),
            "ChannelOpener 收到的目标参数错误（recorded={:?}）",
            recorded.lock().unwrap()
        );
        assert!(got_pong, "回环未收到 'pong'（数据透传失败，sent={sent}）");
    }

    /// 流上限：max_flows=1 时第二条连接被回 RST，opener 只被调用一次
    #[tokio::test(flavor = "multi_thread")]
    async fn 流上限_超限回rst() {
        let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
        let (opener, _dup_rx) = mock_opener(recorded.clone());

        let (to_stack_tx, to_stack_rx) = mpsc::unbounded_channel();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(to_stack_rx),
            outbound: to_client_tx,
        });

        let cfg = TunConfig {
            max_flows: 1,
            ..TunConfig::default()
        };
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let stack_task =
            tokio::spawn(async move { run_stack(transport, cfg, opener, None, shutdown2).await });

        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev {
            inbound: cin.clone(),
            outbound: cout.clone(),
        };
        let (mut ciface, mut csockets, _) = client_iface(&mut cdev);

        let mk = |ciface: &mut Interface| {
            let mut s = ClientTcpSocket::new(
                SocketBuffer::new(vec![0u8; 4096]),
                SocketBuffer::new(vec![0u8; 4096]),
            );
            s.connect(
                ciface.context(),
                (IpAddress::Ipv4(Ipv4Address([1, 2, 3, 4])), 443),
                (
                    Ipv4Address([10, 7, 0, 2]),
                    40000 + (rand::random::<u16>() % 1000),
                ),
            )
            .unwrap();
            s
        };
        let h1 = csockets.add(mk(&mut ciface));
        let h2 = csockets.add(mk(&mut ciface));

        let deadline = Instant::now() + Duration::from_secs(15);
        let mut s1_state = State::SynSent;
        let mut s2_state = State::SynSent;
        while Instant::now() < deadline {
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);
            s1_state = csockets.get_mut::<ClientTcpSocket>(h1).state();
            s2_state = csockets.get_mut::<ClientTcpSocket>(h2).state();
            if s1_state == State::Established && s2_state != State::SynReceived {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // 稳定期：RST 相对客户端的 ESTABLISHED 视角在网络中滞后，
        // 继续驱动客户端直至 RST 落地（s2 离开 Established）或超时
        let settle = Instant::now() + Duration::from_secs(5);
        while Instant::now() < settle && s2_state == State::Established {
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);
            s2_state = csockets.get_mut::<ClientTcpSocket>(h2).state();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), stack_task).await;

        assert_eq!(recorded.lock().unwrap().len(), 1, "opener 应只被调用一次");
        assert_eq!(s1_state, State::Established, "第一条流应正常建立");
        // 第二条流：收到 RST（Closed）或至少无法进入 Established/SynReceived 停留
        assert_ne!(s2_state, State::Established, "第二条流不应建立");
    }

    /// 06-P1-8 回归（慢流不阻塞快流）：流 A 的上行写端永远 Pending（模拟节点
    /// 链路假死/窗口耗尽），流 B 在短超时内仍必须完成 ping/pong。
    /// 修复前：step() 第 4 步的 `write_all().await` 在主循环内永久阻塞，
    /// 流 B 的 SYN 都不会被处理——本测试即红。
    #[tokio::test(flavor = "multi_thread")]
    async fn 栈回环_慢流不阻塞快流() {
        use std::task::{Context, Poll};

        /// 永远 Pending 的写端（链路假死模拟）
        struct StuckWriter;
        impl tokio::io::AsyncWrite for StuckWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        /// 永远 Pending 的读端（慢流下行也不推进，聚焦上行阻塞场景）
        struct NeverReader;
        impl tokio::io::AsyncRead for NeverReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }

        // opener：9.9.9.9 = 慢流（假死链路）；其余 = 正常 duplex 交付测试侧
        let (fast_tx, mut fast_rx) = mpsc::channel::<tokio::io::DuplexStream>(8);
        let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
        let opener: ChannelOpener = {
            let recorded = recorded.clone();
            Arc::new(move |target: String| {
                recorded.lock().unwrap().push(target.clone());
                let fast_tx = fast_tx.clone();
                Box::pin(async move {
                    if target.starts_with("9.9.9.9") {
                        Ok(ProxyDuplex {
                            reader: Box::new(NeverReader),
                            writer: Box::new(StuckWriter),
                        })
                    } else {
                        let (test_side, stack_side) = tokio::io::duplex(64 * 1024);
                        let _ = fast_tx.send(test_side).await;
                        let (r, w) = tokio::io::split(stack_side);
                        Ok(ProxyDuplex {
                            reader: Box::new(r),
                            writer: Box::new(w),
                        })
                    }
                }) as OpenFuture
            })
        };

        let (to_stack_tx, to_stack_rx) = mpsc::unbounded_channel();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(to_stack_rx),
            outbound: to_client_tx,
        });

        // 快流远端：收到 pingB 回 pongB（独立任务推进）
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            if let Some(mut side) = fast_rx.recv().await {
                let mut buf = [0u8; 16];
                if let Ok(n) = side.read(&mut buf).await {
                    if n > 0 {
                        use tokio::io::AsyncWriteExt;
                        let _ = side.write_all(b"pongB").await;
                        let _ = side.flush().await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let cfg = TunConfig::default();
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let stack_task =
            tokio::spawn(async move { run_stack(transport, cfg, opener, None, shutdown2).await });

        // 客户端栈（模拟 TUN 后的应用）：两条 socket
        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev {
            inbound: cin.clone(),
            outbound: cout.clone(),
        };
        let (mut ciface, mut csockets, _) = client_iface(&mut cdev);

        let mut mk_sock = |ciface: &mut Interface, ip: [u8; 4], port: u16| {
            let mut s = ClientTcpSocket::new(
                SocketBuffer::new(vec![0u8; TCP_BUF]),
                SocketBuffer::new(vec![0u8; TCP_BUF]),
            );
            s.connect(
                ciface.context(),
                (IpAddress::Ipv4(Ipv4Address(ip)), 443),
                (Ipv4Address([10, 7, 0, 2]), port),
            )
            .unwrap();
            csockets.add(s)
        };
        // 先建慢流 A 并发数据（其上行将卡死在写任务），再建快流 B
        let h_slow = mk_sock(&mut ciface, [9, 9, 9, 9], 40011);
        let h_fast = mk_sock(&mut ciface, [8, 8, 8, 8], 40012);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut slow_sent = false;
        let mut fast_sent = false;
        let mut got_pong = false;
        while Instant::now() < deadline && !got_pong {
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);

            {
                let sock = csockets.get_mut::<ClientTcpSocket>(h_slow);
                if !slow_sent && sock.state() == State::Established && sock.may_send() {
                    let _ = sock.send_slice(b"pingA");
                    slow_sent = true;
                }
            }
            {
                let sock = csockets.get_mut::<ClientTcpSocket>(h_fast);
                if !fast_sent && sock.state() == State::Established && sock.may_send() {
                    let _ = sock.send_slice(b"pingB");
                    fast_sent = true;
                }
                let mut buf = [0u8; 16];
                if let Ok(n) = sock.recv_slice(&mut buf) {
                    if buf[..n].windows(5).any(|w| w == b"pongB") {
                        got_pong = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let slow_state = csockets.get_mut::<ClientTcpSocket>(h_slow).state();
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), stack_task).await;

        assert!(slow_sent, "慢流应已建立并发送数据（state={slow_state:?}）");
        assert!(
            got_pong,
            "慢流上行卡死时，快流必须在短超时内完成传输（队头阻塞回归！fast_sent={fast_sent}）"
        );
    }

    /// v1 完整版：IPv6 正向路径回环——客户端栈经 TUN 栈对 [2001:db8::1]:443
    /// 发起 v6 TCP，栈侧动态 AnyIP 挂载目的地址后由 smoltcp 完成 v6 握手与转发；
    /// opener 应收到 `[2001:db8::1]:443`（SocketAddr 标准形式）且数据双向透传。
    #[tokio::test(flavor = "multi_thread")]
    async fn 栈回环_ipv6正向路径_建连与透传() {
        let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
        let (opener, mut dup_rx) = mock_opener(recorded.clone());

        let (to_stack_tx, to_stack_rx) = mpsc::unbounded_channel();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(to_stack_rx),
            outbound: to_client_tx,
        });

        // 远端模拟任务：通道建成后写 "pong6"（独立任务推进）
        tokio::spawn(async move {
            if let Some(mut side) = dup_rx.recv().await {
                use tokio::io::AsyncWriteExt;
                let _ = side.write_all(b"pong6").await;
                let _ = side.flush().await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let cfg = TunConfig::default(); // ipv6_enabled 默认 true
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let _stack_task =
            tokio::spawn(async move { run_stack(transport, cfg, opener, None, shutdown2).await });

        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev {
            inbound: cin.clone(),
            outbound: cout.clone(),
        };
        let (mut ciface, mut csockets, _) = client_iface(&mut cdev);

        let rx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let tx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let mut csock = ClientTcpSocket::new(rx, tx);
        csock
            .connect(
                ciface.context(),
                (
                    IpAddress::Ipv6(smoltcp::wire::Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    443,
                ),
                (
                    smoltcp::wire::Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                    41001,
                ),
            )
            .unwrap();
        let ch = csockets.add(csock);

        let mut sent = false;
        let mut got_pong = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !got_pong {
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);
            {
                let sock = csockets.get_mut::<ClientTcpSocket>(ch);
                if !sent && sock.may_send() && sock.state() == State::Established {
                    let _ = sock.send_slice(b"ping6");
                    sent = true;
                }
                let mut buf = [0u8; 16];
                if let Ok(n) = sock.recv_slice(&mut buf) {
                    if buf[..n].windows(5).any(|w| w == b"pong6") {
                        got_pong = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(
            recorded.lock().unwrap().last().map(String::as_str),
            Some("[2001:db8::1]:443"),
            "v6 目标应为 SocketAddr 标准形式（recorded={:?}）",
            recorded.lock().unwrap()
        );
        assert!(sent, "v6 TCP 应完成握手进入 Established");
        assert!(got_pong, "v6 回环未收到 'pong6'（正向路径数据透传失败）");
    }

    /// P3-8 回归：应用把「最后 ACK + 数据 + FIN」打包同批到达（发送后立即半关闭），
    /// 流在栈侧同一次 poll 内进入 CloseWait——旧逻辑只见 CloseWait 不派生 opener，
    /// 该流挂满 30s 后被 RST、数据零转发；修复后 CloseWait 也照常建链转发。
    #[tokio::test(flavor = "multi_thread")]
    async fn 栈回环_半关闭同批到达仍建链转发() {
        let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
        let (opener, mut dup_rx) = mock_opener(recorded.clone());

        let (to_stack_tx, to_stack_rx) = mpsc::unbounded_channel();
        let (to_client_tx, mut to_client_rx) = mpsc::unbounded_channel();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(to_stack_rx),
            outbound: to_client_tx,
        });

        // 远端：读完请求即回 "pong"（半关闭场景：远端仍可下行写）
        tokio::spawn(async move {
            if let Some(mut side) = dup_rx.recv().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 16];
                let _ = side.read(&mut buf).await;
                use tokio::io::AsyncWriteExt;
                let _ = side.write_all(b"pong").await;
                let _ = side.flush().await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let cfg = TunConfig::default();
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let _stack_task =
            tokio::spawn(async move { run_stack(transport, cfg, opener, None, shutdown2).await });

        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev {
            inbound: cin.clone(),
            outbound: cout.clone(),
        };
        let (mut ciface, mut csockets, _) = client_iface(&mut cdev);

        let rx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let tx = SocketBuffer::new(vec![0u8; TCP_BUF]);
        let mut csock = ClientTcpSocket::new(rx, tx);
        csock
            .connect(
                ciface.context(),
                (IpAddress::Ipv4(Ipv4Address([6, 6, 6, 6])), 443),
                (Ipv4Address([10, 7, 0, 2]), 41002),
            )
            .unwrap();
        let ch = csockets.add(csock);

        // 关键：发送请求后**立即** close 写侧（ACK+数据+FIN 高概率同批到达栈）
        let mut closed = false;
        let mut got_pong = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !got_pong {
            while let Ok(pkt) = to_client_rx.try_recv() {
                cin.lock().unwrap().push_back(pkt);
            }
            let out: Vec<Vec<u8>> = cout.lock().unwrap().drain(..).collect();
            for p in out {
                let _ = to_stack_tx.send(p);
            }
            ciface.poll(smol_now(), &mut cdev, &mut csockets);
            {
                let sock = csockets.get_mut::<ClientTcpSocket>(ch);
                if !closed && sock.may_send() && sock.state() == State::Established {
                    let _ = sock.send_slice(b"req");
                    sock.close(); // 半关闭：请求 + FIN 一并发出
                    closed = true;
                }
                let mut buf = [0u8; 16];
                if let Ok(n) = sock.recv_slice(&mut buf) {
                    if buf[..n].windows(4).any(|w| w == b"pong") {
                        got_pong = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert!(closed, "应已发送请求并半关闭");
        assert!(
            got_pong,
            "半关闭（CloseWait 同批到达）的流必须照常建链并转发响应（P3-8 回归！）"
        );
        assert!(
            !recorded.lock().unwrap().is_empty(),
            "opener 应被调用（CloseWait 流也派生建链）"
        );
    }

    /// P3-7 回归：清理清单中 /1 接管路由排在最前（CTRL_CLOSE_EVENT 5s 宽限内
    /// 优先摘除危害最大的接管路由；豁免项即使残留也无害）
    #[test]
    fn cleanup_routes_接管路由先删() {
        // 构造「豁免在前、接管在后」的乱序方案（调用方理论上可任意排序）
        let plan = RoutePlan {
            add: vec![
                RouteCmd {
                    dest: Ipv4Addr::new(203, 0, 113, 7),
                    prefix: 32,
                    gateway: Ipv4Addr::new(192, 168, 1, 1),
                },
                RouteCmd {
                    dest: Ipv4Addr::new(128, 0, 0, 0),
                    prefix: 1,
                    gateway: Ipv4Addr::new(10, 7, 0, 1),
                },
                RouteCmd {
                    dest: Ipv4Addr::new(8, 8, 8, 8),
                    prefix: 32,
                    gateway: Ipv4Addr::new(192, 168, 1, 1),
                },
                RouteCmd {
                    dest: Ipv4Addr::new(0, 0, 0, 0),
                    prefix: 1,
                    gateway: Ipv4Addr::new(10, 7, 0, 1),
                },
            ],
            remove: Vec::new(),
        };
        let mut plan = plan;
        plan.remove = plan.add.clone();
        let exec = DryRunExecutor::default();
        cleanup_routes(&exec, &plan);
        let cmds = exec.commands.lock().unwrap();
        assert_eq!(cmds.len(), 4);
        // 前两条必须是 /1 接管路由（稳定排序保持两者原相对次序）
        assert!(cmds[0].ends_with("/1 via 10.7.0.1"), "首删应是 /1 接管: {cmds:?}");
        assert!(cmds[1].ends_with("/1 via 10.7.0.1"), "次删应是 /1 接管: {cmds:?}");
        // 豁免项保持原相对顺序排后
        assert!(cmds[2].contains("203.0.113.7/32"));
        assert!(cmds[3].contains("8.8.8.8/32"));
    }

    /// P3-7 对称：v6 清理中 ::/1 + 8000::/1 先删，豁免 /128 残留无害排后
    #[test]
    fn cleanup_routes_v6_接管路由先删() {
        let mut cfg = tun_v6();
        cfg.exclude_routes_v6.push(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9));
        // 乱序：豁免排在接管前（直接构造，验证排序而非构造顺序）
        let plan = RoutePlanV6 {
            add: vec![
                RouteCmdV6 {
                    dest: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9),
                    prefix: 128,
                    gateway: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                },
                RouteCmdV6 {
                    dest: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
                    prefix: 1,
                    gateway: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
                },
                RouteCmdV6 {
                    dest: Ipv6Addr::UNSPECIFIED,
                    prefix: 1,
                    gateway: Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1),
                },
            ],
            remove: Vec::new(),
        };
        let mut plan = plan;
        plan.remove = plan.add.clone();
        let _ = &cfg;
        let exec = DryRunExecutor::default();
        cleanup_routes_v6(&exec, &plan);
        let cmds = exec.commands.lock().unwrap();
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains("8000::/1"), "首删应是 8000::/1: {cmds:?}");
        assert!(cmds[1].contains("::/1"), "次删应是 ::/1: {cmds:?}");
        assert!(cmds[2].contains("2001:db8::9/128"));
    }


    /// 09 交付 E2E：TUN UDP-over-proxy 接线——真节点（进程内 HydraServer）+
    /// mock TUN 回环。客户端 UDP 包（10.7.0.1:40000 → 127.0.0.1:echo）经
    /// run_stack 分发 → 中继任务（keyed 会话）→ 节点中继 → 本机 UDP 回显 →
    /// 回包按流表构造注入 TUN 出口。验证：封装/分发/回包构造/回环全链路。
    #[tokio::test]
    async fn run_stack_udp接管_真节点mock回环端到端() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
        use hydra_core::udp_relay::{open_udp_channel, UdpChannelFactory};
        use hydra_node::{HydraServer, NodeOptions};
        use crate::tcp_transport::TlsTrust;

        // 1. 本机 UDP 回显服务
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                if let Ok((n, from)) = echo.recv_from(&mut b).await {
                    let _ = echo.send_to(&b[..n], from).await;
                }
            }
        });

        // 2. 进程内节点（随机端口 + 临时证书）
        let dir = std::env::temp_dir().join(format!(
            "hydra-tun-udp-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let auth_key = vec![7u8; 32];
        let server = HydraServer::new(
            "127.0.0.1:0".parse().unwrap(),
            auth_key.clone(),
            NodeOptions {
                max_connections: 16,
                cert_file: dir.join("cert.der"),
                key_file: dir.join("key.der"),
                ..NodeOptions::default()
            },
        )
        .await
        .expect("节点启动");
        let node_addr = server.tcp_listen_addr.expect("tcp 监听地址");
        let cert = server.cert_der().to_vec();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 3. 构造：栈配置 + 哑 opener（无 TCP 流）+ UDP 通道工厂
        let cfg = TunConfig {
            udp_relay: true,
            dns_via_proxy: true,
            ..Default::default()
        };
        let opener: ChannelOpener = Arc::new(|_t: String| {
            Box::pin(async { Err(HydraError::ConnectionError("测试未使用 TCP 路径".into())) })
                as OpenFuture
        }) as ChannelOpener;
        let trust = TlsTrust::pinned(vec![cert]);
        let auth2 = auth_key.clone();
        let factory: UdpChannelFactory = Arc::new(move || {
            let trust = trust.clone();
            let auth = auth2.clone();
            Box::pin(async move { open_udp_channel(node_addr, "hydra.node", &trust, &auth).await })
        });

        // 4. mock TUN：入站注入客户端 UDP 包，出站收集回包
        let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let transport = Arc::new(TestTransport {
            inbound: tokio::sync::Mutex::new(in_rx),
            outbound: out_tx,
        });
        // 客户端包：10.7.0.1:40000 → 127.0.0.1:echo（载荷即回显内容）
        let payload = b"hydra-tun-udp-e2e";
        let src_ip = Ipv4Addr::new(10, 7, 0, 1);
        let mut pkt = Vec::with_capacity(20 + 8 + payload.len());
        pkt.extend_from_slice(&[0x45, 0, 0, 0]); // 占位总长
        let total = (28 + payload.len()) as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]); // id/flags/TTL/proto/csum(0)
        pkt.extend_from_slice(&src_ip.octets());
        let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("测试回显 socket 应为 v4"),
    };
    pkt.extend_from_slice(&echo_v4.octets());
        pkt.extend_from_slice(&40000u16.to_be_bytes());
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // UDP 校验和（v4 可为 0，分发路径不校验）
        pkt.extend_from_slice(payload);
        assert!(parse_udp_v4(&pkt).is_some(), "测试包应可被分发解析");

        let shutdown = CancellationToken::new();
        tokio::spawn(run_stack(
            transport,
            cfg,
            opener,
            Some(factory),
            shutdown.clone(),
        ));
        in_tx.send(pkt).unwrap();

        // 5. 等回包（最长 8s）：src=echo, dst=10.7.0.1:40000, 载荷回显
        let mut got = false;
        for _ in 0..160 {
            match tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await {
                Ok(Some(p)) => {
                    if p.len() >= 28 + payload.len() && p[0] >> 4 == 4 && p[9] == 17 {
                        let s = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
                        let d = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                        let sp = u16::from_be_bytes([p[20], p[21]]);
                        let dp = u16::from_be_bytes([p[22], p[23]]);
                        if s == echo_addr.ip()
                            && d == src_ip
                            && sp == echo_addr.port()
                            && dp == 40000
                            && &p[28..] == payload
                        {
                            got = true;
                            break;
                        }
                    }
                }
                _ => continue,
            }
        }
        shutdown.cancel();
        assert!(got, "应在超时前收到经中继的 UDP 回包（src/dst/载荷匹配）");
    }
}
