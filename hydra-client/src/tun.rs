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
//! v1 边界（如实声明）：
//! - **UDP 一律丢弃**：项目无 UDP-over-proxy 能力（QUIC/HTTP3 流量需应用回落 TCP）。
//!   未回 ICMP 不可达（v1 简化，注释如实）。
//! - **无 DNS 劫持 / fake-IP**：DNS 服务器走豁免路由直出物理网卡。
//! - **smoltcp 无通配监听**：只能按端口 LISTEN，v1 拦截常用 TCP 端口列表
//!   （默认 80/443/8080/8443，`HYDRA_TUN_PORTS` 覆盖）。未在列表内的端口
//!   smoltcp 会回 RST，应用表现为连接被拒——v1 已知限制。
//! - **无域名分流**：TUN 拿不到域名，全部流量经节点（CN 分流退化为全走节点）。
//!
//! 真实设备路径（Wintun 全链路、路由生效、退出清理）需管理员运行，**人工验证**，
//! 见 README 部署指南指引。

use hydra_protocol::{HydraError, Result};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::Ipv4Addr;
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
    /// 并发流上限（超限对新流回 RST，防资源耗尽）
    pub max_flows: usize,
    /// smoltcp LISTEN 端口列表（smoltcp 无通配监听，v1 已知限制，见模块注释）
    pub listen_ports: Vec<u16>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::new(10, 7, 0, 1),
            prefix: 30,
            mtu: 1500,
            exclude_routes: Vec::new(),
            max_flows: 512,
            // 常用明文/加密 Web 端口；其余端口需 HYDRA_TUN_PORTS 扩展
            listen_ports: vec![80, 443, 8080, 8443],
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
    let v = if prefix == 0 { 0 } else { !0u32 << (32 - prefix as u32) };
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
    let mut add = Vec::new();
    // 1. 接管路由：两条 /1 覆盖整个 IPv4 空间且比 /0 更精确
    add.push(RouteCmd { dest: Ipv4Addr::new(0, 0, 0, 0), prefix: 1, gateway: tun.addr });
    add.push(RouteCmd { dest: Ipv4Addr::new(128, 0, 0, 0), prefix: 1, gateway: tun.addr });
    // 2. TUN 网段直连（保证 TUN 子网内部通信不绕行）
    add.push(RouteCmd { dest: tun.network(), prefix: tun.prefix, gateway: tun.addr });
    // 3. 豁免清单：/32 回物理网关（节点 IP / DNS —— 防环路关键）
    if let Some(gw) = physical_gw {
        for ip in &tun.exclude_routes {
            add.push(RouteCmd { dest: *ip, prefix: 32, gateway: gw });
        }
    } else if !tun.exclude_routes.is_empty() {
        warn!(
            "物理网关未知，{} 条豁免路由未能生成——代理到节点的流量可能形成环路！\
             请设置 HYDRA_TUN_GW 或确认默认网关可解析",
            tun.exclude_routes.len()
        );
    }
    let remove = add.iter().cloned().collect();
    RoutePlan { add, remove }
}

// ── 路由命令执行（可注入 dry-run）────────────────────────────────────────────

/// 路由命令执行器抽象（测试注入 fake，不真跑系统命令）
pub trait RouteExecutor: Send + Sync {
    fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()>;
}

/// 真实执行器：Windows `route` / Linux `ip route`（需管理员/root）
pub struct SystemRouteExecutor;

impl RouteExecutor for SystemRouteExecutor {
    fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            let args = cmd.windows_args(action);
            debug!("route {}", args.join(" "));
            let out = std::process::Command::new("route").args(&args).output()?;
            if !out.status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "route {} 失败: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                ));
            }
            Ok(())
        }
        #[cfg(unix)]
        {
            let args = cmd.linux_args(action);
            debug!("ip route {}", args.join(" "));
            let out = std::process::Command::new("ip").args(["route"]).args(&args).output()?;
            if !out.status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "ip route {} 失败: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                ));
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

/// 退出/任务结束时的幂等清理（best-effort，逐条删除并记录失败）
pub fn cleanup_routes(exec: &dyn RouteExecutor, plan: &RoutePlan) {
    for cmd in &plan.remove {
        if let Err(e) = exec.run(RouteAction::Delete, cmd) {
            // 忽略单条失败（残留路由由下次启动幂等清理兜底，方案 §2/§5）
            warn!("清理路由 {}/{} 失败: {}", cmd.dest, cmd.prefix, e);
        }
    }
}

/// drop guard：任务任何路径退出（含 panic 展开）都执行幂等删除
pub struct RouteGuard {
    exec: Arc<dyn RouteExecutor>,
    plan: RoutePlan,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.exec.as_ref(), &self.plan);
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
        if let Ok(out) = std::process::Command::new("route").args(["print", "-4", "0.0.0.0"]).output() {
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

/// best-effort 探测系统 DNS 服务器（豁免路由用：DNS 明文直出物理网卡，方案 §1 非目标）。
/// `HYDRA_TUN_DNS`（逗号分隔）优先；Windows 解析注册表 NameServer/DhcpNameServer，
/// Linux 解析 /etc/resolv.conf。
pub fn detect_dns_servers() -> Vec<Ipv4Addr> {
    if let Ok(s) = std::env::var("HYDRA_TUN_DNS") {
        let v = s
            .split(',')
            .filter_map(|p| p.trim().parse::<Ipv4Addr>().ok())
            .collect::<Vec<_>>();
        if !v.is_empty() {
            return v;
        }
    }
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        // reg query 递归导出各接口的静态/动态 DNS（输出含 REG_SZ 等噪声 token，
        // 统一按「能解析成 IPv4 就收」过滤，best-effort）
        if let Ok(outp) = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
                "/s",
            ])
            .output()
        {
            let text = String::from_utf8_lossy(&outp.stdout);
            for tok in text.split_whitespace() {
                if let Ok(ip) = tok.parse::<Ipv4Addr>() {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
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
                        if let Ok(ip) = tok.parse::<Ipv4Addr>() {
                            if !out.contains(&ip) {
                                out.push(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

// ── 代理通道开启器（proxy.rs 提供实现，见 ProxyServer::tun_channel_opener）──

/// 已建成的代理双工链路（既有 NodeLink 的读/写端，含流量统计）
pub struct ProxyDuplex {
    pub reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
}

/// 通道开启返回 future
pub type OpenFuture = Pin<Box<dyn Future<Output = Result<ProxyDuplex>> + Send>>;

/// TUN 新流 → 代理通道（target 形如 "ip:port"；复用 open_target 的故障切换 /
/// TargetUnreachable 判定 / mark_node_offline / 流量统计语义，零分叉）
pub type ChannelOpener = Arc<dyn Fn(String) -> OpenFuture + Send + Sync>;

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
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }

    fn send<'a>(&'a self, buf: &'a [u8]) -> BoxFut<'a, std::io::Result<()>> {
        Box::pin(async move {
            self.dev
                .send(buf)
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
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
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl ChanDevice {
    fn new(mtu: usize) -> (Self, Arc<Mutex<VecDeque<Vec<u8>>>>, Arc<Mutex<VecDeque<Vec<u8>>>>) {
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
            ChanTx { queue: self.outbound.clone() },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChanTx { queue: self.outbound.clone() })
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

/// 构建栈 Interface：IP medium、TUN 地址、默认路由（TUN 上一切目标都是 on-link）
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
            .push(IpCidr::new(IpAddress::Ipv4(Ipv4Address(cfg.addr.octets())), cfg.prefix))
            .expect("IP 地址表已满");
    });
    // 默认路由（TUN 是 IP 层端点，网关占位为 TUN 自身地址；仅用于路由查找存在性）
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address(cfg.addr.octets()))
        .map_err(|_| HydraError::ConnectionError("smoltcp 路由表已满".into()))?;
    // 关键：any-ip 模式。TUN 收到的包目标地址是「应用想访问的任意远端」，
    // 不是 TUN 接口自身地址；不开 any-ip 会被 smoltcp 当作非本机包丢弃。
    iface.set_any_ip(true);
    Ok(iface)
}

const TCP_BUF: usize = 64 * 1024;
/// 代理 → 栈 单条流的下行通道深度（背压用）
const FLOW_CHAN: usize = 64;
/// 建连超时（open_target 内部已有节点级超时，这里兜底总时限）
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// 流消息：代理侧任务 → 栈主循环
enum FlowMsg {
    /// 通道已建成（主循环随后派生下行读取任务）
    Link(ProxyDuplex),
    /// 通道开启失败（TargetUnreachable 等）→ 回 RST
    LinkErr,
    /// 代理侧读到的下行数据
    Data(Vec<u8>),
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
    /// 代理链路写端（上行：栈 → 代理；读端由下行读取任务持有）
    link_writer: Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    /// socket 发不下的积压（socket 缓冲满时暂存，防字节流损坏）
    pending: VecDeque<Vec<u8>>,
    last_active: Instant,
}

/// 栈主循环（与真实 TUN 设备解耦：任何 [`PacketTransport`] 都可驱动，
/// 测试用通道对接两个 smoltcp Interface 做回环验证）。
pub async fn run_stack<T: PacketTransport>(
    transport: Arc<T>,
    cfg: TunConfig,
    opener: ChannelOpener,
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
                    device.push_inbound(&buf[..n]);
                }
                Err(e) => {
                    error!("TUN 读包失败: {}（100ms 后重试）", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            // 周期 tick：驱动超时/重传/无包时的 poll
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }

        step(
            &cfg, &mut iface, &mut device, &mut sockets, &mut listeners,
            &mut flows, &opener,
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
    }
    Ok(())
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
        // 提取目标（TUN 视角：本地端点 = 应用想连的真实目的地）
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
        let target = format!("{dst_ip}:{dst_port}");
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
        // 生成流：up 任务负责开代理通道；Link 之后派生下行读取任务
        let (tx, rx) = mpsc::channel(FLOW_CHAN);
        let flow_tx = tx.clone();
        let opener2 = opener.clone();
        let target2 = target.clone();
        let up_task = tokio::spawn(async move {
            let open_fut = (opener2)(target2.clone());
            match tokio::time::timeout(OPEN_TIMEOUT, open_fut).await {
                Ok(Ok(duplex)) => {
                    let _ = tx.send(FlowMsg::Link(duplex)).await;
                    // 通道已交付主循环；up 任务结束（下行读取由 reader 任务负责）
                }
                Ok(Err(e)) => {
                    warn!("TUN 流开通道失败（{target2}）: {} → 回 RST", e);
                    let _ = tx.send(FlowMsg::LinkErr).await;
                }
                Err(_) => {
                    warn!("TUN 流开通道超时（{target2}）→ 回 RST");
                    let _ = tx.send(FlowMsg::LinkErr).await;
                }
            }
        });
        debug!("TUN 新流: {target}");
        flows.insert(
            h,
            Flow {
                target,
                up_rx: rx,
                up_task,
                reader_task: None,
                flow_tx,
                link_writer: None,
                pending: VecDeque::new(),
                last_active: Instant::now(),
            },
        );
        // 补一个新监听 socket 接下一个连接
        listeners[i] = add_listener(sockets, port);
        i += 1;
    }

    // 2. 泵代理下行数据入栈（socket 缓冲满则积压在 pending）
    let mut to_remove: Vec<SocketHandle> = Vec::new();
    for (&h, flow) in flows.iter_mut() {
        while let Ok(msg) = flow.up_rx.try_recv() {
            match msg {
                FlowMsg::Link(d) => {
                    // 拆出读写端：读端交给下行读取任务，写端留在 Flow（上行用）
                    let ProxyDuplex { reader, writer } = d;
                    let tx = flow.flow_tx.clone();
                    let mut reader = reader;
                    flow.reader_task = Some(tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            match reader.read(&mut buf).await {
                                Ok(0) => break,            // 代理侧 EOF（响应完整结束）
                                Ok(n) => {
                                    if tx.send(FlowMsg::Data(buf[..n].to_vec())).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,           // 代理链路故障 → EOF 语义（FIN）
                            }
                        }
                        // 任务结束 → 主循环检测 is_finished 后关写侧（发 FIN 给应用）
                    }));
                    flow.link_writer = Some(writer);
                }
                FlowMsg::LinkErr => {
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
            let chunk = flow.pending.front().unwrap().clone();
            // 0.11 的 send_slice 返回 Result<usize, SendError>（socket 已关闭等）
            let n = sock.send_slice(&chunk).unwrap_or(0);
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
    let mut buf = vec![0u8; 16 * 1024];
    for (&h, flow) in flows.iter_mut() {
        let sock = sockets.get_mut::<TcpSocket>(h);
        // 应用半关闭后我方也应关闭（CloseWait → 关写侧发 FIN）
        if sock.state() == State::CloseWait {
            sock.close();
        }
        // 通道未就绪（link_writer == None）时不 recv：数据留在 smoltcp rx 缓冲，
        // 接收窗口归零形成真实背压，对端会重传——此前先 recv 再丢弃是错的
        // （smoltcp 取走数据即推进 ACK，对端绝不会重传，窗口期字节被静默吞掉，
        // TLS ClientHello 丢失导致连接永久挂死）
        if sock.may_recv() && flow.link_writer.is_some() {
            // 0.11 的 recv_slice 返回 Result<usize, RecvError>
            let n = sock.recv_slice(&mut buf).unwrap_or(0);
            if n > 0 {
                flow.last_active = Instant::now();
                if let Some(w) = flow.link_writer.as_mut() {
                    if let Err(e) = w.write_all(&buf[..n]).await {
                        warn!("TUN 流写代理通道失败（{}）: {}", flow.target, e);
                        sock.abort();
                        to_remove.push(h);
                        continue;
                    }
                }
            }
        }
        // 代理下行读取任务结束 = 代理侧 EOF/故障 → 关写侧（发 FIN 给应用）
        if flow.reader_task.as_ref().map(|t| t.is_finished()).unwrap_or(false)
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
    shutdown: CancellationToken,
) -> Result<()> {
    // 1. 物理 gw 探测 + 路由方案（豁免失败只是告警，见 compute_routes）
    let gw = detect_physical_gateway();
    let plan = compute_routes(&cfg, gw);
    info!(
        "TUN 路由方案：{} 条添加（含 {} 条豁免），物理网关={}",
        plan.add.len(),
        plan.add.len() - 3,
        gw.map(|i| i.to_string()).unwrap_or_else(|| "未知".into())
    );

    // 2. 创建 TUN 设备（先于路由：路由指向 TUN 地址，设备必须先存在）
    let mut tcfg = tun2::Configuration::default();
    tcfg
        .address(cfg.addr)
        .netmask(prefix_to_mask(cfg.prefix).map(|o| o.to_string()).join("."))
        .mtu(cfg.mtu as u16)
        .up();
    // Windows：wintun.dll（与 exe 同架构）需放在 exe 目录或 PATH；非管理员创建会失败
    let dev = tun2::create_as_async(&tcfg).map_err(|e| {
        HydraError::ConnectionError(format!(
            "TUN 设备创建失败: {e}（Windows 需管理员运行且 wintun.dll 可用；Linux 需 root/CAP_NET_ADMIN）"
        ))
    })?;
    info!("✓ TUN 设备已创建（addr={} prefix={} mtu={}）", cfg.addr, cfg.prefix, cfg.mtu);

    // 3. 应用路由 + drop guard（任务结束/崩溃展开时幂等清理）
    let exec: Arc<dyn RouteExecutor> = Arc::new(SystemRouteExecutor);
    if let Err(e) = apply_routes(exec.as_ref(), &plan) {
        error!("路由配置失败: {e}——已回滚本次已添加的路由，放弃启动 TUN（无残留）");
        return Err(HydraError::ConnectionError(format!("TUN 路由配置失败: {e}")));
    }
    let _guard = RouteGuard { exec, plan };

    // 4. 栈主循环
    let transport = Arc::new(Tun2Transport::new(dev));
    let res = run_stack(transport, cfg, opener, shutdown).await;
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
                Ipv4Addr::new(203, 0, 113, 7),  // 节点 IP
                Ipv4Addr::new(8, 8, 8, 8),      // DNS
            ],
            ..Default::default()
        }
    }

    #[test]
    fn compute_routes_含豁免清单完备() {
        let gw = Some(Ipv4Addr::new(192, 168, 1, 1));
        let plan = compute_routes(&tun(), gw);
        // 添加清单：/1 x2 + TUN 网段 + 2 豁免
        assert_eq!(plan.add.len(), 5);
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
            gateway: gw.unwrap(),
        }));
        assert!(plan.add.contains(&RouteCmd {
            dest: Ipv4Addr::new(8, 8, 8, 8),
            prefix: 32,
            gateway: gw.unwrap(),
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
        let plan = compute_routes(&tun(), None);
        // 仅 /1 x2 + TUN 网段；豁免项不生成（避免生成错误路由）
        assert_eq!(plan.add.len(), 3);
        assert!(plan.remove.len() == 3);
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
            vec!["add", "0.0.0.0", "mask", "128.0.0.0", "10.7.0.1", "metric", "1"]
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
        let plan = compute_routes(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        apply_routes(&exec, &plan).unwrap();
        assert_eq!(exec.commands.lock().unwrap().len(), 5);
        cleanup_routes(&exec, &plan);
        assert_eq!(exec.commands.lock().unwrap().len(), 10);
        assert!(exec.commands.lock().unwrap()[0].starts_with("Add 0.0.0.0/1"));
        assert!(exec.commands.lock().unwrap()[5].starts_with("Delete 0.0.0.0/1"));
    }

    /// 注入式执行器：前 `ok` 条 Add 成功，之后全部失败；记录所有命令
    struct FailAfterExecutor {
        ok: usize,
        calls: Mutex<Vec<String>>,
    }

    impl RouteExecutor for FailAfterExecutor {
        fn run(&self, action: RouteAction, cmd: &RouteCmd) -> std::io::Result<()> {
            let line = format!("{:?} {}/{}", action, cmd.dest, cmd.prefix);
            let adds = self.calls.lock().unwrap().iter().filter(|c| c.starts_with("Add")).count();
            if action == RouteAction::Add && adds >= self.ok {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "注入失败"));
            }
            self.calls.lock().unwrap().push(line);
            Ok(())
        }
    }

    #[test]
    fn apply_routes_部分失败回滚已成功部分() {
        let plan = compute_routes(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        // 前 3 条（两条 /1 接管 + TUN 网段）成功，第 4 条（豁免路由，最易失败）失败
        let exec = FailAfterExecutor { ok: 3, calls: Mutex::new(Vec::new()) };
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
        let plan = compute_routes(&tun(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        let exec = FailAfterExecutor { ok: usize::MAX, calls: Mutex::new(Vec::new()) };
        assert!(apply_routes(&exec, &plan).is_ok());
        assert_eq!(exec.calls.lock().unwrap().len(), 5);
        assert!(exec.calls.lock().unwrap().iter().all(|c| c.starts_with("Add")));
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
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "closed"))?;
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
            Some((ChanRx(Some(frame)), ChanTx { queue: self.outbound.clone() }))
        }
        fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(ChanTx { queue: self.outbound.clone() })
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
    fn mock_opener(recorded: RecordedTargets) -> (ChannelOpener, mpsc::Receiver<tokio::io::DuplexStream>) {
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

    fn client_iface(
        dev: &mut ClientDev,
    ) -> (Interface, ClientSocketSet<'static>, SocketHandle) {
        let cfg = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(cfg, dev, smol_now());
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address([10, 7, 0, 2])),
                30,
            ))
            .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address([10, 7, 0, 1]))
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
        let stack_task = tokio::spawn(async move {
            run_stack(transport, cfg, opener, shutdown2).await
        });

        // 客户端栈（模拟 TUN 后面的应用）
        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev { inbound: cin.clone(), outbound: cout.clone() };
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

        let mut cfg = TunConfig::default();
        cfg.max_flows = 1;
        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let stack_task = tokio::spawn(async move {
            run_stack(transport, cfg, opener, shutdown2).await
        });

        let cin = Arc::new(Mutex::new(VecDeque::new()));
        let cout = Arc::new(Mutex::new(VecDeque::new()));
        let mut cdev = ClientDev { inbound: cin.clone(), outbound: cout.clone() };
        let (mut ciface, mut csockets, _) = client_iface(&mut cdev);

        let mk = |ciface: &mut Interface| {
            let mut s = ClientTcpSocket::new(
                SocketBuffer::new(vec![0u8; 4096]),
                SocketBuffer::new(vec![0u8; 4096]),
            );
            s.connect(
                ciface.context(),
                (IpAddress::Ipv4(Ipv4Address([1, 2, 3, 4])), 443),
                (Ipv4Address([10, 7, 0, 2]), 40000 + (rand::random::<u16>() % 1000)),
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
            ciface.poll(
                smol_now(),
                &mut cdev,
                &mut csockets,
            );
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
}
