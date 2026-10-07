use crate::routing;
use crate::scheduler::Scheduler;
use crate::tcp_transport::{self, TcpReadHalf, TcpWriteHalf};
use crate::traffic::{ByteCounter, CountingStream, TrafficMonitor};
use crate::transport::DEFAULT_SNI;
use hydra_protocol::{mask_target, HydraError, NodeInfo, NodeStatus, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// 活动中继计数器（A4）：每个双向转发启动时 +1，两个方向任务全部收敛后 -1。
/// 集成测试断言连接结束后归零，证明 relay select! 收敛改造没有留下孤儿任务。
/// （tokio `Handle::metrics().num_alive_tasks()` 需要 tokio_unstable cfg，会破坏
/// 标准命令行测试编译，故以此计数器代替基线差分。）
pub static ACTIVE_RELAYS: AtomicUsize = AtomicUsize::new(0);

/// 当前活动双向中继数量
pub fn active_relay_count() -> usize {
    ACTIVE_RELAYS.load(Ordering::Relaxed)
}

/// Team-T：TCP/TLS 路径凭据（信任配置 / SNI / 认证密钥）。
/// start 时随 ProxyServer 实例注入并随任务链传递（测试/多实例场景下
/// 各代理实例持各自凭据，互不串扰）。
/// Noise 指纹取 TLS 协商出的对端叶证书（见 tcp_transport::TlsTrust），
/// 因此这里**不再需要** 节点地址→证书 映射——多节点证书配对类故障从结构上消除。
#[derive(Clone)]
struct TcpCreds {
    trust: Arc<tcp_transport::TlsTrust>,
    sni: String,
    auth_key: Arc<Vec<u8>>,
}

/// 中继缓冲 16KB（05-R-14 收尾）：与 TLS 1.3 单条记录实际读出量（≤16KB）对齐，
/// 与节点侧 pump 一致；1000 并发常驻缓冲从 128MB 降到 32MB，64KB 无收益
const RELAY_BUF: usize = 16 * 1024;

    /// HTTP 头部区最大长度（防恶意超大头部无限累积）
const MAX_HTTP_HEAD: usize = 64 * 1024;
/// HTTP 头阶段**总时限**（09-P2-1 slowloris 修复）：此前每段读各自重置 30s
/// 超时且无总时长约束，攻击者每 29s 发 1 字节可让单连接合法存续约 22 天
/// （64KB × 29s），task+FD+缓冲常驻。总时限 30s 内头必须读完。
const HTTP_HEAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// 半关闭排水阶段等待另一方向的超时（浏览器已关写侧后，剩余响应应在此窗口内到齐）
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// 初始读超时（审查 R-39，Wave 3 修复）：协议探测 / HTTP 头循环 / SOCKS5 请求
/// 三处首读包 30s 超时——慢连接（连上不发数据）不再无限期占用任务与缓冲。
/// 与节点侧认证超时（10s）同级的防慢速资源泄漏面，`--listen 0.0.0.0` 时尤其必要。
const INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// 远端先 FIN 后给上行的有限排水窗口（审查 R-27：不再直接 abort 上行丢尾部数据）
const RELAY_DOWN_FIN_DRAIN: Duration = Duration::from_secs(5);
/// 连续 TargetUnreachable 阈值（审查 06-P2-1）：同一目标连续 N 次在首选节点
/// "目标不可达"后，允许一次跨节点重试——消除"节点 A resolver/出口整体故障被
/// R-01 语义放大为该目标全客户端黑洞且对评分隐形"；命中即重置计数。
const TARGET_UNREACH_FAILOVER_THRESHOLD: u32 = 3;

/// 同一目标"连续不可达"计数表（审查 06-P2-1）。进程级共享：key 为目标字符串。
/// 09-P1-3：value 带 (计数, 最近写入时刻)——**容量上限 + TTL 惰性过期**。
/// 此前 key 空间无界（客户端提交的任意目标串）且只增不减：`--listen 0.0.0.0`
/// 时任意 LAN 主机每连接提交一个唯一且必然被拒的目标（随机子域/私网 IP），
/// 每条约 350B 永久驻留，分钟级即可注入数百 MB 内存。
const TARGET_UNREACH_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const TARGET_UNREACH_MAX_ENTRIES: usize = 100_000;

fn target_unreach_counts()
-> &'static std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>> {
    static COUNTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
    > = std::sync::OnceLock::new();
    COUNTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 记录一次目标不可达，返回该目标当前连续不可达次数（TTL 内）。
/// 超过 TTL 未再失败的计数视为过期归零；容量达上限时先清过期项，仍满则
/// 整表清空（仅攻击流量可触达，语义损失可接受）。
fn record_target_unreachable(target: &str) -> u32 {
    let mut map = target_unreach_counts()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let now = std::time::Instant::now();
    if map.len() >= TARGET_UNREACH_MAX_ENTRIES {
        map.retain(|_, (_, t)| now.duration_since(*t) < TARGET_UNREACH_TTL);
        if map.len() >= TARGET_UNREACH_MAX_ENTRIES {
            map.clear();
        }
    }
    let entry = map.entry(target.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) >= TARGET_UNREACH_TTL {
        entry.0 = 0; // 过期：重新计数
    }
    entry.0 = entry.0.saturating_add(1);
    entry.1 = now;
    entry.0
}

/// 目标在某节点连接成功：清除其连续不可达计数。
fn clear_target_unreachable(target: &str) {
    target_unreach_counts()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(target);
}

/// TargetUnreachable 分支统一入口（07-P1-3）：记录一次失败并判定是否允许
/// 一次性跨节点重试。达阈值时**立即重置计数**（"命中即重置"语义，06-P2-1
/// 承诺此前未实现——计数只增不减导致偶发目标失败被永久放大为每请求 3 节点
/// 全握手）。返回 true = 本次允许继续尝试下一节点；false = 直接报错给客户端。
/// 时间窗：09-P1-3 起计数表带 60s TTL——过期目标的计数自动归零，并发突发
/// 下"命中即重置"仍可能短暂放大 MAX_NODE_ATTEMPTS × 在途请求数（原注释
/// 取舍保留，侵入面与收益不变）。
fn record_and_should_failover(target: &str) -> bool {
    let consecutive = record_target_unreachable(target);
    if consecutive >= TARGET_UNREACH_FAILOVER_THRESHOLD {
        // 命中阈值：重置，保证跨节点重试真正一次性
        clear_target_unreachable(target);
        true
    } else {
        false
    }
}
/// 国内直连分流的直连建连超时（超时后回退节点路径，不让浏览器干等）
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ProxyServer {
    listen_addr: SocketAddr,
    scheduler: Arc<Scheduler>,
    nodes: Vec<SocketAddr>,
    traffic_monitor: Option<Arc<TrafficMonitor>>,
    auth_key: Vec<u8>,
    node_certs: Vec<Vec<u8>>,
    trust: Option<tcp_transport::TlsTrust>,
    sni: String,
    bound_addr: Arc<std::sync::OnceLock<SocketAddr>>,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            scheduler: Arc::new(Scheduler::new()),
            nodes: Vec::new(),
            traffic_monitor: None,
            auth_key: Vec::new(),
            node_certs: Vec::new(),
            trust: None,
            sni: DEFAULT_SNI.to_string(),
            bound_addr: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn with_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.nodes = nodes;
        self
    }

    /// 节点预共享认证密钥（必填：没有认证的节点是公网开放代理）
    pub fn with_auth_key(mut self, key: Vec<u8>) -> Self {
        self.auth_key = key;
        self
    }

    /// 节点证书 DER 列表，加入客户端信任根执行标准校验（必填：防中间人；
    /// pin 模式默认信任根。真证书部署请改用 [`Self::with_trust`]）
    pub fn with_node_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.node_certs = certs;
        self
    }

    /// 覆盖 TLS 信任配置（真证书部署：`TlsTrust::public_ca(..)`；
    /// 未设置时默认 `TlsTrust::pinned(node_certs)`）
    pub fn with_trust(mut self, trust: tcp_transport::TlsTrust) -> Self {
        self.trust = Some(trust);
        self
    }

    /// 覆盖 SNI 伪装域名（默认 hydra.node）
    pub fn with_sni(mut self, sni: String) -> Self {
        self.sni = sni;
        self
    }

    /// 代理监听地址（start 绑定后可查询）
    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.bound_addr.get().copied()
    }

    /// 调度器句柄（供测试/上层观测节点状态，如 A2 恢复探测验证）
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    pub fn with_traffic_monitor(mut self, monitor: Arc<TrafficMonitor>) -> Self {
        self.traffic_monitor = Some(monitor);
        self
    }

    pub async fn start(&self) -> Result<()> {
        if self.auth_key.is_empty() {
            return Err(HydraError::ConnectionError(
                "未设置认证密钥：请设置 HYDRA_AUTH_KEY 环境变量（或调用 with_auth_key）"
                    .to_string(),
            ));
        }
        if self.node_certs.is_empty() && self.trust.is_none() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书：请设置 HYDRA_NODE_CERT 环境变量（或调用 with_node_certs / with_trust）"
                    .to_string(),
            ));
        }

        // Add nodes to scheduler（按加入顺序递减初始评分，测速上线后由实测数据取代；
        // register_nodes 幂等，TUN 模式可能已提前注册过）
        info!("Initializing proxy with {} nodes...", self.nodes.len());
        // Team-T：打包 TCP/TLS 路径凭据。Noise 指纹取对端叶证书（tcp_transport::TlsTrust
        // 文档），不再需要节点地址→证书映射——多节点各持自签证书也不会配对错。
        let trust = self
            .trust
            .clone()
            .unwrap_or_else(|| tcp_transport::TlsTrust::pinned(self.node_certs.clone()));
        let creds = TcpCreds {
            trust: Arc::new(trust.clone()),
            sni: self.sni.clone(),
            auth_key: Arc::new(self.auth_key.clone()),
        };
        self.register_nodes().await;
        info!("Binding proxy listener to {}...", self.listen_addr);
        let listener = TcpListener::bind(self.listen_addr).await?;
        if let Ok(local) = listener.local_addr() {
            let _ = self.bound_addr.set(local);
        }
        info!("✓ Proxy server listening on {}", self.listen_addr);

        // 流量统计：未显式注入 monitor 时用内置实例兜底——中继计数与测速吞吐差分
        // 始终有同一计数面（上层/GUI 不观察也不影响行为）
        let traffic = self
            .traffic_monitor
            .clone()
            .unwrap_or_else(|| Arc::new(TrafficMonitor::new()));

        // A2：Offline 节点自动恢复探测 + Online 节点活性探测 + 测速评分（常驻后台任务；
        // start 是 &self，故用 Arc clone）。HYDRA_SPEEDTEST=0 时仍做活性探测，
        // 评分维持静态初始值。
        crate::speedtest::spawn_recovery_probe(
            self.scheduler.clone(),
            trust,
            self.sni.clone(),
            creds.auth_key.clone(),
            traffic.clone(),
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("━━━ New SOCKS5 connection from {} ━━━", addr);
                    let scheduler = self.scheduler.clone();
                    let traffic = traffic.clone();
                    let creds = creds.clone();
                    tokio::spawn(async move {
                        // 包装错误处理，确保发送 SOCKS5 错误响应
                        match Self::handle_connection(stream, scheduler, traffic, creds).await {
                            Ok(()) => {
                                info!("━━━ Connection from {} completed successfully ━━━", addr);
                            }
                            Err(e) => {
                                error!("━━━ Connection error from {}: {} ━━━", addr, e);
                                // 注意：handle_connection 内部已经发送了 SOCKS5 错误响应
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// 将节点注册进调度器（幂等：重复添加同一地址会更新/去重视实现而定，这里
    /// 以「仅在不存在时添加」保证幂等）。
    /// 拆出独立方法：TUN 模式需要在 start() 之前让调度器已有节点
    /// （通道开启器依赖 get_nodes_by_priority）。
    pub async fn register_nodes(&self) {
        for (idx, addr) in self.nodes.iter().enumerate() {
            if self
                .scheduler
                .get_nodes_by_priority()
                .await
                .iter()
                .any(|n| n.address == *addr)
            {
                continue;
            }
            let node = NodeInfo {
                address: *addr,
                // 09-P3-6：第 11+ 个节点此前会得到 ≤0 的负初始带宽（评分面观感
                // 异常，测速关闭时永久负分）；下限 10.0
                bandwidth: (100.0 - idx as f64 * 10.0).max(10.0),
                latency: 10.0,
                loss_rate: 0.01,
                load: 0.5,
                status: NodeStatus::Online,
            };
            self.scheduler.add_node(node).await;
            info!("Added node to scheduler: {}", addr);
        }
    }

    /// TUN 模式通道开启器：把 [`Self::open_target`]（含故障切换 /
    /// TargetUnreachable 判定 / mark_node_offline / 流量统计语义）包成
    /// [`crate::channel::ChannelOpener`]。调用前请先 `register_nodes()` 并确保
    /// 凭据已设置（auth_key/证书）。
    /// （通道开启器 trait 抽象在 `channel` 模块、平台无关；TUN 设备/栈在
    /// 桌面 hydra-client::tun，未来 Android tun_core——均反向依赖本实现。）
    pub fn tun_channel_opener(&self) -> Result<crate::channel::ChannelOpener> {
        use crate::channel::{ChannelOpener, OpenFuture, ProxyDuplex};

        if self.auth_key.is_empty() {
            return Err(HydraError::ConnectionError(
                "未设置认证密钥：TUN 模式通道开启器无法构建".to_string(),
            ));
        }
        // 与 start() 同构的凭据打包（TcpCreds 为模块私有，此处直接构造）
        let trust = self
            .trust
            .clone()
            .unwrap_or_else(|| tcp_transport::TlsTrust::pinned(self.node_certs.clone()));
        let creds = TcpCreds {
            trust: Arc::new(trust),
            sni: self.sni.clone(),
            auth_key: Arc::new(self.auth_key.clone()),
        };
        let scheduler = self.scheduler.clone();
        // 流量统计与 SOCKS 路径同一计数面（monitor 未注入时兜底实例）
        let traffic = self
            .traffic_monitor
            .clone()
            .unwrap_or_else(|| Arc::new(TrafficMonitor::new()));
        // TUN 流没有"浏览器对端"，日志 peer 用 0.0.0.0:0 占位（目标本身才是关键信息）
        let pseudo_peer = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
        Ok(Arc::new(move |target: String| {
            let scheduler = scheduler.clone();
            let traffic = traffic.clone();
            let creds = creds.clone();
            Box::pin(async move {
                let link =
                    Self::open_target(&scheduler, &traffic, &creds, &target, pseudo_peer).await?;
                let (recv, send) = link.into_parts();
                Ok(ProxyDuplex {
                    reader: Box::new(recv),
                    writer: Box::new(send),
                })
            }) as OpenFuture
        }) as ChannelOpener)
    }

    async fn handle_connection(
        mut stream: TcpStream,
        scheduler: Arc<Scheduler>,
        traffic: Arc<TrafficMonitor>,
        creds: TcpCreds,
    ) -> Result<()> {
        let mut buf = [0u8; 4096];
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // 读取第一个字节来判断协议类型（R-39：30s 超时防慢连接挂起）
        info!("[{}] Reading first byte to detect protocol...", peer_addr);
        let n = match tokio::time::timeout(INITIAL_READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                error!("[{}] Failed to read: {}", peer_addr, e);
                return Err(e.into());
            }
            Err(_) => {
                return Err(HydraError::ConnectionError(format!(
                    "[{}] Initial read timeout ({:?})",
                    peer_addr, INITIAL_READ_TIMEOUT
                )));
            }
        };

        if n == 0 {
            return Err(HydraError::ProtocolError("Empty request".to_string()));
        }

        // 判断协议类型
        if buf[0] == 0x05 {
            // SOCKS5 协议
            info!("[{}] Detected SOCKS5 protocol", peer_addr);
            Self::handle_socks5(stream, &buf, n, scheduler, traffic, creds).await
        } else if buf[0] >= b'A' && buf[0] <= b'Z' {
            // HTTP 协议 (CONNECT, GET, POST 等)
            info!("[{}] Detected HTTP protocol", peer_addr);
            Self::handle_http(stream, &buf, n, scheduler, traffic, creds).await
        } else {
            error!(
                "[{}] Unknown protocol, first byte: 0x{:02x}",
                peer_addr, buf[0]
            );
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            Err(HydraError::ProtocolError("Unknown protocol".to_string()))
        }
    }

    /// 统一的节点连接入口（TCP 转型后唯一路径）：按调度器加权优先级尝试候选节点。
    /// - 建连失败（TCP/TLS/握手/应答超时）→ 标记节点 Offline、切换下一节点（最多 3 候选）
    /// - TCP 链路无应用错误码通道：认证失败时节点静默关流，客户端按"节点不可达"
    ///   处理并故障切换（v1 限制，如实记录；不区分"节点存活但目标不可达"）。
    async fn open_target(
        scheduler: &Scheduler,
        traffic: &Arc<TrafficMonitor>,
        creds: &TcpCreds,
        target: &str,
        peer_addr: SocketAddr,
    ) -> Result<NodeLink> {
        const MAX_NODE_ATTEMPTS: usize = 3;

        // 日志脱敏（Exec2）：info 及以上级别目标地址一律短哈希；完整明文仅 debug 级别
        //（排查时开 RUST_LOG=debug 可见）
        debug!(
            "[{}] open_target (plaintext for troubleshooting): {}",
            peer_addr, target
        );

        let sni = &creds.sni;
        let auth_key = &creds.auth_key;

        let candidates = scheduler.get_nodes_by_priority().await;
        if candidates.is_empty() {
            error!("[{}] No available nodes in scheduler!", peer_addr);
            return Err(HydraError::ConnectionError(
                "No available nodes".to_string(),
            ));
        }

        let mut last_err: Option<HydraError> = None;
        for node in candidates.iter().take(MAX_NODE_ATTEMPTS) {
            match tcp_transport::connect_target(node.address, sni, &creds.trust, auth_key, target)
                .await
            {
                Ok(tls) => {
                    // 连接成功：清除该目标的连续不可达计数（审查 06-P2-1）
                    clear_target_unreachable(target);
                    info!(
                        "[{}] ✓ Connected to {} via node {} (tcp/tls)",
                        peer_addr,
                        mask_target(target),
                        node.address
                    );
                    // 流量统计：节点路径流包上计数器（up=客户端→节点，down=节点→客户端）
                    let node_entry = traffic.node_entry(node.address);
                    let (r, w) = tokio::io::split(tls);
                    let send = CountingStream::new(
                        w,
                        ByteCounter::up(Some(traffic.clone()), Some(node_entry.clone())),
                    );
                    let recv = CountingStream::new(
                        r,
                        ByteCounter::down(Some(traffic.clone()), Some(node_entry)),
                    );
                    return Ok(NodeLink {
                        send,
                        recv,
                        node: node.address,
                    });
                }
                Err(e) => {
                    // 目标不可达（节点存活但目标连不上/SSRF 失败）：默认换节点无意义
                    //（目标在任意节点都同样不可达），且绝不污染节点评分——直接报错给
                    // 客户端（审查 R-01：原实现把健康节点连锁标记 Offline）。
                    // 但 06-P2-1：DNS 失败按节点出口位置解析（geo-DNS/局部污染/节点
                    // resolver 故障），节点 A 失败不代表节点 B 也失败——同一目标连续
                    // 达阈值后允许一次跨节点重试（仍不标记节点故障），命中即重置。
                    if matches!(e, HydraError::TargetUnreachable(_)) {
                        // 07-P1-3：达阈值判定与"命中即重置"统一在
                        // record_and_should_failover 内完成（一次性跨节点重试）
                        if record_and_should_failover(target) {
                            warn!(
                                "[{}] Target unreachable {}+ times in a row, retrying next node once (node {} still healthy)",
                                peer_addr, TARGET_UNREACH_FAILOVER_THRESHOLD, node.address
                            );
                            last_err = Some(e);
                            continue;
                        }
                        warn!(
                            "[{}] Target unreachable via node {} (node healthy, not failing over)",
                            peer_addr, node.address
                        );
                        return Err(e);
                    }
                    // 09-P3-3：本地请求侧错误（如目标串超长 MAX_TARGET_LEN 的
                    // 协议编码失败）与节点传输故障区分——此前一律
                    // mark_node_offline，畸形 Host 头即可把健康候选连锁误标
                    // Offline；协议错误换节点同样无意义，直接报错。
                    if matches!(e, HydraError::ProtocolError(_)) {
                        warn!(
                            "[{}] Local protocol error (node {} healthy, no failover): {}",
                            peer_addr, node.address, e
                        );
                        return Err(e);
                    }
                    warn!(
                        "[{}] Node {} tcp/tls connect failed ({}), failing over to next node",
                        peer_addr, node.address, e
                    );
                    scheduler.mark_node_offline(&node.address).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| HydraError::ConnectionError("All nodes failed".to_string())))
    }

    /// 处理 HTTP 代理请求（CONNECT 与普通明文请求共用入口）
    async fn handle_http(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        traffic: Arc<TrafficMonitor>,
        creds: TcpCreds,
    ) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // A6：头部读取保留原始字节。此前用 from_utf8_lossy 累积整个请求，
        // 与头部同批到达的二进制 body 会被 U+FFFD 替换而损坏；现仅解析用 lossy 视图，转发发原始字节。
        let mut raw: Vec<u8> = initial_buf[..initial_len].to_vec();
        let mut header_end = find_header_end(&raw);
        // 09-P2-1：头阶段总 deadline——逐段读超时只防单段挂起，防不了
        // "每段都在 29s 时到达 1 字节"的慢滴；整个头循环共用一个 deadline。
        let head_deadline = tokio::time::Instant::now() + HTTP_HEAD_TOTAL_TIMEOUT;
        while header_end.is_none() {
            if raw.len() > MAX_HTTP_HEAD {
                error!("[{}] HTTP head too large ({} bytes)", peer_addr, raw.len());
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return Err(HydraError::ProtocolError("HTTP head too large".to_string()));
            }
            let mut buf = [0u8; 4096];
            // R-39：头循环每段读同样包超时；同时受总 deadline 约束（取更早者）
            let segment = head_deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            let read_timeout = segment.min(INITIAL_READ_TIMEOUT);
            let n = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("[{}] Failed to read HTTP request: {}", peer_addr, e);
                    return Err(e.into());
                }
                Err(_) => {
                    return Err(HydraError::ConnectionError(format!(
                        "[{}] HTTP header read timeout ({:?})",
                        peer_addr, HTTP_HEAD_TOTAL_TIMEOUT
                    )));
                }
            };
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            header_end = find_header_end(&raw);
        }

        // 仅解析视图使用 lossy：头部的非 UTF-8 字节不影响 body 的字节保真
        let head_len = header_end.unwrap_or(raw.len());
        let head_view = String::from_utf8_lossy(&raw[..head_len]);

        // 日志脱敏（Exec2）：请求行含目标 URL，info 级一律脱敏；明文仅 debug 级别
        let first_line_view = head_view.lines().next().unwrap_or("");
        info!(
            "[{}] HTTP request: {}",
            peer_addr,
            mask_target(first_line_view)
        );
        debug!(
            "[{}] HTTP request (plaintext): {}",
            peer_addr, first_line_view
        );

        // 解析请求
        let first_line = first_line_view;
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 3 {
            // 审查 R-23：请求行含目标 URL 明文，error 级只记脱敏视图
            error!(
                "[{}] Invalid HTTP request: {}",
                peer_addr,
                mask_target(first_line)
            );
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Err(HydraError::ProtocolError(
                "Invalid HTTP request".to_string(),
            ));
        }

        let method = parts[0];
        let url = parts[1];

        info!(
            "[{}] HTTP method: {}, URL: {}",
            peer_addr,
            method,
            mask_target(url)
        );
        debug!(
            "[{}] HTTP request (plaintext): {} {}",
            peer_addr, method, url
        );

        if method == "CONNECT" {
            // CONNECT 请求 - 用于 HTTPS
            let target_str = url.to_string();
            info!(
                "[{}] >>> HTTP CONNECT request to {}",
                peer_addr,
                mask_target(&target_str)
            );
            debug!(
                "[{}] >>> HTTP CONNECT request (plaintext): {}",
                peer_addr, target_str
            );
            return Self::handle_http_connect(stream, target_str, scheduler, traffic, creds).await;
        }

        // 普通 HTTP 请求 (GET, POST etc.)
        // 对于 HTTP GET/POST，我们需要将请求转发到目标服务器
        // 从 URL 或 Host header 中提取主机名
        let mut authority = if let Some(without_protocol) = url.strip_prefix("http://") {
            // 从 http://host/path 中提取 authority
            match without_protocol.find('/') {
                Some(pos) => without_protocol[..pos].to_string(),
                None => without_protocol.to_string(),
            }
        } else {
            // 从 Host header 中获取（审查 R-44：跳过 obs-fold 续行——RFC 7230 折行
            // 以空白开头，不跳过的话折行片段可能被误判为 Host 头；多 Host 头取首个
            // 保持原语义，多 Host 本身非法）
            head_view
                .lines()
                .filter(|line| !line.starts_with(' ') && !line.starts_with('\t'))
                .find(|line| line.to_lowercase().starts_with("host:"))
                .map(|line| line[5..].trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };
        // 09-P3-2：剥 userinfo（http://user:pass@host/ 的 authority 含凭据段；
        // userinfo 不允许未编码 '@'，rsplit_once 取末段即 host）。此前不剥，
        // host:port 解析会把 "user:pass@host" 误拆为 (user, pass@host)。
        if let Some((_, host_part)) = authority.rsplit_once('@') {
            authority = host_part.to_string();
        }

        // 解析主机名和端口（09-P3-2 重写）：
        // - SocketAddr 形态（含 [v6]:port）直接解析；
        // - "[v6]" / "[v6]:port"：取 ']' 前为 host；
        // - "host:port"：rsplit_once 取**末个**冒号（裸 v6 无括号属非法 Host，
        //   rsplit 得空 host → 拒绝），端口必须完全为数字，非法显式 400——
        //   此前 splitn(2)+unwrap_or(80) 会把 "evil.com:443x" 静默改连 80 端口、
        //   把裸 "::1" 拆出空 host。
        let parse_failure = |peer_addr: SocketAddr, authority: &str| {
            error!(
                "[{}] Invalid HTTP authority (bad port form): {}",
                peer_addr,
                mask_target(authority)
            );
        };
        let (target_addr_str, default_port) = if let Ok(addr) = authority.parse::<SocketAddr>() {
            (addr.ip().to_string(), addr.port())
        } else if authority.starts_with('[') {
            match authority.rsplit_once(']') {
                Some((inner, rest)) => {
                    let host = inner.strip_prefix('[').unwrap_or(inner).to_string();
                    match rest.strip_prefix(':') {
                        Some(p) => match p.parse::<u16>() {
                            Ok(port) => (host, port),
                            Err(_) => {
                                parse_failure(peer_addr, &authority);
                                let _ = stream
                                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                                    .await;
                                return Err(HydraError::ProtocolError(
                                    "Invalid authority port".to_string(),
                                ));
                            }
                        },
                        None => (host, 80u16),
                    }
                }
                None => (authority.clone(), 80u16),
            }
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            match (h.is_empty(), p.parse::<u16>()) {
                (false, Ok(port)) => (h.to_string(), port),
                _ => {
                    parse_failure(peer_addr, &authority);
                    let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return Err(HydraError::ProtocolError(
                        "Invalid authority host/port".to_string(),
                    ));
                }
            }
        } else {
            (authority.clone(), 80u16)
        };
        let target_host = authority;

        info!(
            "[{}] >>> HTTP {} request to {}",
            peer_addr,
            method,
            mask_target(&target_host)
        );
        debug!(
            "[{}] >>> HTTP {} request (plaintext): {}",
            peer_addr, method, target_host
        );

        // 发送目标地址到服务器（包含端口）
        let target_with_port = format!("{}:{}", target_addr_str, default_port);

        // Exec2：国内直连分流——命中 CN 域名表时本机 TCP 直连（HTTP 直接转发原始字节），
        // 未开启/未命中/直连失败 → 走既有 open_target 节点路径
        let link = match Self::try_direct(&target_with_port, peer_addr).await {
            Some(mut tcp) => {
                // A6 语义保持：原始字节转发（含二进制 body），不经 lossy 字符串
                info!(
                    "[{}] Direct (CN split) forwarding HTTP request to {}",
                    peer_addr,
                    mask_target(&target_with_port)
                );
                if let Err(e) = tcp.write_all(&raw).await {
                    error!(
                        "[{}] Failed to forward HTTP request (direct): {}",
                        peer_addr, e
                    );
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
                }
                RemoteLink::Direct(tcp)
            }
            None => {
                // 连接到节点（带故障切换）
                let mut node_link = match Self::open_target(
                    &scheduler,
                    &traffic,
                    &creds,
                    &target_with_port,
                    peer_addr,
                )
                .await
                {
                    Ok(link) => link,
                    Err(e) => {
                        error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return Err(e);
                    }
                };

                // A6：发送原始 HTTP 请求到节点（原始字节转发，含二进制 body；不再经 lossy 字符串）
                info!("[{}] Forwarding HTTP request to node...", peer_addr);
                if let Err(e) = node_link.send.write_all(&raw).await {
                    error!("[{}] Failed to forward HTTP request: {}", peer_addr, e);
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
                }
                RemoteLink::Node { link: node_link }
            }
        };

        info!(
            "[{}] ✓ HTTP {} request forwarded to {}",
            peer_addr,
            method,
            mask_target(&target_host)
        );

        Self::relay_bidirectional(stream, link, peer_addr, &target_host, &[], traffic).await
    }

    /// 处理 HTTP CONNECT 请求（用于 HTTPS）
    async fn handle_http_connect(
        mut stream: TcpStream,
        target_str: String,
        scheduler: Arc<Scheduler>,
        traffic: Arc<TrafficMonitor>,
        creds: TcpCreds,
    ) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // 连接到节点（带故障切换）；Exec2：命中 CN 域名表时本机 TCP 直连
        let link = match Self::try_direct(&target_str, peer_addr).await {
            Some(tcp) => RemoteLink::Direct(tcp),
            None => {
                let node_link =
                    match Self::open_target(&scheduler, &traffic, &creds, &target_str, peer_addr)
                        .await
                    {
                        Ok(link) => link,
                        Err(e) => {
                            error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                            return Err(e);
                        }
                    };
                RemoteLink::Node { link: node_link }
            }
        };

        // 发送 HTTP 200 成功响应
        info!("[{}] Sending HTTP 200 success response...", peer_addr);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        Self::relay_bidirectional(stream, link, peer_addr, &target_str, &[], traffic).await
    }

    /// 分片安全 read_exact（09-P2-4）：先消化 handle_connection 预读缓冲的
    /// 剩余字节，不足部分再从流上 `read_exact` 补齐（每段读包
    /// INITIAL_READ_TIMEOUT，R-39 语义保持）。TCP 是字节流，SOCKS5 greeting/
    /// request 完全允许分段到达——此前按"单次 read 到齐"解析，经多级代理链
    /// /MTU 边缘设备分片交付的合法请求会被误判拒绝。
    async fn read_exact_socks(
        stream: &mut TcpStream,
        pending: &mut &[u8],
        out: &mut [u8],
    ) -> std::result::Result<(), std::io::Error> {
        let from_buf = pending.len().min(out.len());
        out[..from_buf].copy_from_slice(&pending[..from_buf]);
        *pending = &pending[from_buf..];
        if from_buf < out.len() {
            match tokio::time::timeout(
                INITIAL_READ_TIMEOUT,
                stream.read_exact(&mut out[from_buf..]),
            )
            .await
            {
                Ok(r) => r.map(|_| ()),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SOCKS5 request read timeout",
                )),
            }
        } else {
            Ok(())
        }
    }

    /// 处理 SOCKS5 代理请求
    async fn handle_socks5(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        traffic: Arc<TrafficMonitor>,
        creds: TcpCreds,
    ) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));
        // 预读字节游标：greeting/request 优先从这里消化，剩余部分（客户端在
        // 请求后同段捎带的早发数据）最后交给中继上行，不再丢弃
        let mut pending: &[u8] = &initial_buf[..initial_len];

        // 初始数据应该是 SOCKS5 greeting：[ver, nmethods] + nmethods 字节方法列表
        let mut greeting = [0u8; 2];
        if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut greeting).await {
            // 审查 R-23：error 级不再 dump 原始字节（含潜在目标明文/可被恶意方
            // 注入任意内容落日志）；只记长度与结构信息，字节 dump 降为 debug 级
            error!(
                "[{}] Invalid SOCKS5 greeting ({} bytes, ver=0x{:02x}, err={})",
                peer_addr,
                initial_len,
                initial_buf.first().copied().unwrap_or(0),
                e
            );
            debug!(
                "[{}] Invalid SOCKS5 greeting (plaintext bytes): {:?}",
                peer_addr,
                &initial_buf[..initial_len.min(initial_buf.len())]
            );
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 greeting".to_string(),
            ));
        }
        if greeting[0] != 0x05 {
            error!(
                "[{}] Invalid SOCKS5 greeting version 0x{:02x}",
                peer_addr, greeting[0]
            );
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 greeting".to_string(),
            ));
        }
        let nmethods = greeting[1] as usize;
        if nmethods == 0 {
            error!("[{}] SOCKS5 greeting with empty method list", peer_addr);
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 greeting".to_string(),
            ));
        }
        let mut methods = vec![0u8; nmethods];
        if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut methods).await {
            error!("[{}] Failed to read SOCKS5 methods: {}", peer_addr, e);
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 greeting".to_string(),
            ));
        }

        info!(
            "[{}] SOCKS5 greeting received ({} bytes, {} methods)",
            peer_addr, initial_len, nmethods
        );

        // 方法协商（09-P2-4 顺修）：本代理仅支持无认证（0x00）。客户端未提供
        // 0x00 时必须回 0xFF（无可接受方法）——此前恒回 0x00，只提供 user/pass
        // (0x02) 的客户端会随即开始子协商，与我们的请求解析必然失步。
        if !methods.contains(&0x00) {
            info!("[{}] SOCKS5 client offers no no-auth method, rejecting", peer_addr);
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "No acceptable SOCKS5 auth method".to_string(),
            ));
        }
        // 发送无需认证响应
        stream.write_all(&[0x05, 0x00]).await?;
        info!("[{}] Sent no-auth response", peer_addr);

        // 读取 SOCKS5 请求（R-39：分段读各自包 30s 超时防慢连接挂起）
        info!("[{}] Reading SOCKS5 request...", peer_addr);
        let mut req_head = [0u8; 4]; // [ver, cmd, rsv, atyp]
        if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut req_head).await {
            error!("[{}] Failed to read SOCKS5 request head: {}", peer_addr, e);
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 request".to_string(),
            ));
        }
        if req_head[0] != 0x05 {
            error!(
                "[{}] Invalid SOCKS5 request (ver=0x{:02x}, cmd=0x{:02x})",
                peer_addr, req_head[0], req_head[1]
            );
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 request".to_string(),
            ));
        }
        info!(
            "[{}] SOCKS5 request received, cmd={}",
            peer_addr, req_head[1]
        );

        // Parse command
        let cmd = req_head[1];
        if cmd != 0x01 {
            // Only CONNECT supported
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(HydraError::ProtocolError(
                "Unsupported SOCKS5 command".to_string(),
            ));
        }

        // Parse address type
        let atyp = req_head[3];
        info!("[{}] Address type: 0x{:02x}", peer_addr, atyp);
        // 最大地址体：1(len) + 255(域名) + 2(port) = 258，取 262 整备
        let mut body = [0u8; 262];

        let target_str = match atyp {
            0x01 => {
                // IPv4：4B 地址 + 2B 端口
                if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut body[..6])
                    .await
                {
                    error!("[{}] Invalid IPv4 address length: {}", peer_addr, e);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid IPv4 address".to_string(),
                    ));
                }
                let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                let port = u16::from_be_bytes([body[4], body[5]]);
                let v4_target = format!("{}:{}", ip, port);
                info!("[{}] Target IPv4: {}", peer_addr, mask_target(&v4_target));
                debug!("[{}] Target IPv4 (plaintext): {}", peer_addr, v4_target);
                v4_target
            }
            0x03 => {
                // Domain name - 发送域名到节点，由节点解析 DNS（域名不明文离开加密通道）
                if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut body[..1])
                    .await
                {
                    error!("[{}] Invalid domain name length byte: {}", peer_addr, e);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid domain name".to_string(),
                    ));
                }
                let domain_len = body[0] as usize;
                if domain_len == 0 {
                    error!("[{}] Empty domain name", peer_addr);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid domain name length".to_string(),
                    ));
                }
                if let Err(e) =
                    Self::read_exact_socks(&mut stream, &mut pending, &mut body[..domain_len + 2])
                        .await
                {
                    error!(
                        "[{}] Invalid domain name data length (need {}, err={})",
                        peer_addr,
                        domain_len + 2,
                        e
                    );
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid domain name length".to_string(),
                    ));
                }
                let domain = String::from_utf8_lossy(&body[..domain_len]);
                let port = u16::from_be_bytes([body[domain_len], body[domain_len + 1]]);
                let domain_target = format!("{}:{}", domain, port);

                info!(
                    "[{}] Target domain: {} - sending to node for DNS resolution",
                    peer_addr,
                    mask_target(&domain_target)
                );
                debug!(
                    "[{}] Target domain (plaintext): {} - sending to node for DNS resolution",
                    peer_addr, domain_target
                );
                domain_target
            }
            0x04 => {
                // IPv6：16B 地址 + 2B 端口
                if let Err(e) = Self::read_exact_socks(&mut stream, &mut pending, &mut body[..18])
                    .await
                {
                    error!("[{}] Invalid IPv6 address length: {}", peer_addr, e);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid IPv6 address length".to_string(),
                    ));
                }
                let ip = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([body[0], body[1]]),
                    u16::from_be_bytes([body[2], body[3]]),
                    u16::from_be_bytes([body[4], body[5]]),
                    u16::from_be_bytes([body[6], body[7]]),
                    u16::from_be_bytes([body[8], body[9]]),
                    u16::from_be_bytes([body[10], body[11]]),
                    u16::from_be_bytes([body[12], body[13]]),
                    u16::from_be_bytes([body[14], body[15]]),
                );
                let port = u16::from_be_bytes([body[16], body[17]]);
                let v6_target = format!("[{}]:{}", ip, port);
                info!("[{}] Target IPv6: {}", peer_addr, mask_target(&v6_target));
                debug!("[{}] Target IPv6 (plaintext): {}", peer_addr, v6_target);
                v6_target
            }
            _ => {
                error!("[{}] Unsupported address type: 0x{:02x}", peer_addr, atyp);
                stream
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Err(HydraError::ProtocolError(
                    "Unsupported address type".to_string(),
                ));
            }
        };

        // 客户端在请求后同段捎带的早发数据（pipelining）：交给中继上行，
        // 不再静默丢弃（09-P2-4）
        let pending_up = pending.to_vec();

        info!(
            "[{}] >>> SOCKS5 CONNECT request to {}",
            peer_addr,
            mask_target(&target_str)
        );
        debug!(
            "[{}] >>> SOCKS5 CONNECT request (plaintext): {}",
            peer_addr, target_str
        );

        // Exec2：国内直连分流——HYDRA_SPLIT=cn 且目标为域名形态并命中 CN 域名表时，
        // 客户端本机 TCP 直连目标（SOCKS5 直接回成功后走既有双向转发）。
        // IP 形态目标（atyp 0x01/0x04）由 routing 内部一律拒绝（无 GeoIP，如实不支持），
        // 未开启/未命中/直连失败 → 走既有 open_target 节点路径，行为与分流前完全一致。
        let link = match Self::try_direct(&target_str, peer_addr).await {
            Some(tcp) => RemoteLink::Direct(tcp),
            None => {
                // 连接到节点（带故障切换）
                let node_link =
                    match Self::open_target(&scheduler, &traffic, &creds, &target_str, peer_addr)
                        .await
                    {
                        Ok(link) => link,
                        Err(e) => {
                            error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                            stream
                                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await?;
                            return Err(e);
                        }
                    };
                RemoteLink::Node { link: node_link }
            }
        };

        // Send success response to client
        info!(
            "[{}] Sending SOCKS5 success response to client...",
            peer_addr
        );
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        Self::relay_bidirectional(stream, link, peer_addr, &target_str, &pending_up, traffic).await
    }

    /// Exec2：国内直连分流建连。命中 CN 域名表（且 HYDRA_SPLIT=cn）时客户端本机
    /// TCP 直连目标；直连失败/超时回退节点路径（返回 None），不改变既有可用性。
    async fn try_direct(target: &str, peer_addr: SocketAddr) -> Option<TcpStream> {
        if !routing::is_direct_target(target) {
            return None;
        }
        debug!(
            "[{}] Direct (CN split) connect (plaintext): {}",
            peer_addr, target
        );
        match tokio::time::timeout(
            DIRECT_CONNECT_TIMEOUT,
            Self::direct_connect_resolved(target),
        )
        .await
        {
            Ok(Ok(tcp)) => {
                // 09-P1-2：直连链路同样启用 keepalive（与节点路径同一静默死亡检测）
                crate::tcp_transport::enable_tcp_keepalive(&tcp);
                info!(
                    "[{}] ✓ Direct (CN split) connected to {} locally (bypasses node)",
                    peer_addr,
                    mask_target(target)
                );
                Some(tcp)
            }
            Ok(Err(e)) => {
                warn!(
                    "[{}] Direct (CN split) connect to {} failed ({}), falling back to node",
                    peer_addr,
                    mask_target(target),
                    e
                );
                None
            }
            Err(_) => {
                warn!(
                    "[{}] Direct (CN split) connect to {} timed out, falling back to node",
                    peer_addr,
                    mask_target(target)
                );
                None
            }
        }
    }

    /// 直连目标的解析 + 逐地址受保护建连（09-P1-7）：字面 IP 直接建连；域名经
    /// 系统解析后逐个候选尝试——每个新 socket 都过 protect 钩子（Android VPN
    /// 场景必须，未安装钩子时零开销）。
    async fn direct_connect_resolved(target: &str) -> std::io::Result<TcpStream> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?
            .collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DNS resolved no addresses",
            ));
        }
        let mut last_err = None;
        for addr in addrs {
            match crate::socket_protect::connect_tcp_protected(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("connect failed")))
    }

    /// 双向转发（A4 收敛版 + Exec2 直连支持）：
    /// - 远端既可以是加密节点（TCP/TLS 流），也可以是国内直连的明文 TCP（CN 分流），
    ///   两条路径复用同一套收敛/排水/计数逻辑；
    /// - 任一方向结束后显式 shutdown 另一方向并 join 收敛，不再留下孤儿任务；
    /// - 浏览器关写侧（半关闭）时保留 远端→浏览器 方向，在超时窗口内收完剩余响应；
    /// - `pending_up`：协议解析阶段消化预读缓冲后剩余的早发数据（SOCKS5 请求后
    ///   同段捎带），先行写入远端再进入稳态循环，不丢弃（09-P2-4）。
    async fn relay_bidirectional(
        stream: TcpStream,
        link: RemoteLink,
        peer_addr: SocketAddr,
        target: &str,
        pending_up: &[u8],
        traffic: Arc<TrafficMonitor>,
    ) -> Result<()> {
        ACTIVE_RELAYS.fetch_add(1, Ordering::Relaxed);
        let _guard = RelayGuard;

        // 日志脱敏：info 级目标一律短哈希；明文仅 debug 级别（RUST_LOG=debug）
        let masked = mask_target(target);
        debug!(
            "[{}] relay target (plaintext for troubleshooting): {}",
            peer_addr, target
        );

        // ── 连接注册表钩子（GUI「连接」页数据源，与 TrafficMonitor 同范式）──
        // 注册点 = 中继起点；字节计数条目交由上下行任务原子累加，热路径零锁。
        // 目标入库即脱敏（mask_target 短哈希），明文不进注册表。
        let conn = crate::connections::connections_registry().register(
            masked.clone(),
            match &link {
                RemoteLink::Node { link } => link.node,
                // 直连（CN 分流）无节点归属：0.0.0.0:0 占位（UI 显示「直连」）
                RemoteLink::Direct(_) => {
                    SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
                }
            },
        );

        // 节点路径：open_target 已包好计数器；直连路径（CN 分流，无节点归属）：
        // 仅计全局 monitor，不归属任何节点条目。
        let (mut up_sink, mut down_src) = match link {
            RemoteLink::Node { link } => (UpSink::Node(link.send), DownSource::Node(link.recv)),
            RemoteLink::Direct(tcp) => {
                let (r, w) = tcp.into_split();
                (
                    UpSink::Direct(CountingStream::new(
                        w,
                        ByteCounter::up(Some(traffic.clone()), None),
                    )),
                    DownSource::Direct(CountingStream::new(
                        r,
                        ByteCounter::down(Some(traffic), None),
                    )),
                )
            }
        };
        let (mut client_read, mut client_write) = stream.into_split();

        // 浏览器 → 远端（节点 TCP/TLS 流 / 直连 TCP）
        let up_conn = conn.clone();
        let pre_up = pending_up.to_vec();
        let mut up = tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUF];
            let mut total = 0u64;
            // 协议头同段捎带的早发数据先行写入（09-P2-4）
            if !pre_up.is_empty() {
                let write_res = match &mut up_sink {
                    UpSink::Node(w) => w
                        .write_all(&pre_up)
                        .await
                        .map(|_| ())
                        .map_err(|_| RelayError::Transport),
                    UpSink::Direct(w) => w
                        .write_all(&pre_up)
                        .await
                        .map(|_| ())
                        .map_err(RelayError::LocalIo),
                };
                write_res?;
                total += pre_up.len() as u64;
                up_conn.add_up(pre_up.len() as u64);
            }
            loop {
                match client_read.read(&mut buf).await {
                    // 浏览器关写侧：显式优雅结束上行（TCP 半关闭 shutdown，FIN 传给远端），
                    // 不依赖写端 drop 的隐式语义
                    Ok(0) => {
                        match up_sink {
                            UpSink::Node(mut w) => {
                                let _ = w.shutdown().await;
                            }
                            UpSink::Direct(mut w) => {
                                let _ = w.shutdown().await;
                            }
                        }
                        return Ok(total);
                    }
                    Ok(n) => {
                        total += n as u64;
                        // 连接注册表：上行字节回调（原子累加，热路径零锁）
                        up_conn.add_up(n as u64);
                        let write_res = match &mut up_sink {
                            // TCP 链路无错误码通道，写失败 = 传输故障
                            UpSink::Node(w) => w
                                .write_all(&buf[..n])
                                .await
                                .map(|_| ())
                                .map_err(|_| RelayError::Transport),
                            UpSink::Direct(w) => w
                                .write_all(&buf[..n])
                                .await
                                .map(|_| ())
                                .map_err(RelayError::LocalIo),
                        };
                        write_res?;
                    }
                    Err(_) => return Err(RelayError::Transport),
                }
            }
        });

        // 远端 → 浏览器
        let down_conn = conn.clone();
        let mut down = tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUF];
            let mut total = 0u64;
            loop {
                let n = match &mut down_src {
                    // TCP/TLS 链路。FIN = 响应完整结束（无应用错误码通道，v1 限制）
                    DownSource::Node(r) => match r.read(&mut buf).await {
                        Ok(0) => return Ok(total),
                        Ok(n) => n,
                        Err(_) => return Err(RelayError::Transport),
                    },
                    DownSource::Direct(r) => match r.read(&mut buf).await {
                        // 直连目标 FIN：响应完整结束
                        Ok(0) => return Ok(total),
                        Ok(n) => n,
                        Err(e) => return Err(RelayError::LocalIo(e)),
                    },
                };
                total += n as u64;
                // 连接注册表：下行字节回调（原子累加，热路径零锁）
                down_conn.add_down(n as u64);
                if client_write.write_all(&buf[..n]).await.is_err() {
                    return Err(RelayError::Transport);
                }
            }
        });

        // 等待任一方向结束（两个句柄均保留，供显式收敛另一方向）
        let (up_done, first_err): (bool, Option<RelayError>) = tokio::select! {
            r = &mut up => (true, join_relay_result(r)),
            r = &mut down => (false, join_relay_result(r)),
        };

        // 结果先绑定再收尾：中继终点（任意结束路径）统一标记连接关闭，
        // 注册表条目保留 60s 供 GUI「最近关闭」展示
        let relay_result = match (up_done, first_err) {
            // 浏览器已关写侧且上行干净：保留下行，在超时窗口内收完剩余响应（半关闭）
            (true, None) => match tokio::time::timeout(RELAY_DRAIN_TIMEOUT, &mut down).await {
                Ok(Ok(Ok(_))) => {
                    info!(
                        "[{}] Connection to {} closed (half-close drained)",
                        peer_addr, masked
                    );
                    Ok(())
                }
                Ok(Ok(Err(e))) => Err(Self::relay_error(e, peer_addr, target)),
                Ok(Err(_)) => Err(HydraError::ConnectionError(format!(
                    "[{}] relay task panicked: {}",
                    peer_addr, masked
                ))),
                Err(_) => {
                    // 排水超时：显式中止下行并收敛
                    down.abort();
                    let _ = down.await;
                    warn!(
                        "[{}] Relay drain timeout for {}, connection aborted",
                        peer_addr, masked
                    );
                    Err(HydraError::ConnectionError(format!(
                        "[{}] relay drain timeout: {}",
                        peer_addr, masked
                    )))
                }
            },
            // 上行故障：中止下行（读写端 drop → FIN/RST），收敛后向上报错
            (true, Some(e)) => {
                down.abort();
                let _ = down.await;
                Err(Self::relay_error(e, peer_addr, target))
            }
            // 远端响应已完整（FIN）：审查 R-27——此前直接 abort 上行，客户端仍在
            // write_all 途中的尾部数据被静默丢弃（与半关闭方向的排水语义不对称）。
            // 现给上行一个有限排水窗口：上行自然结束（客户端 EOF → shutdown 远端
            // 写端）或超时后再中止，超时告警保留。
            (false, None) => {
                match tokio::time::timeout(RELAY_DOWN_FIN_DRAIN, &mut up).await {
                    Ok(r) => {
                        let _ = join_relay_result(r);
                    }
                    Err(_) => {
                        up.abort();
                        let _ = up.await;
                        warn!(
                            "[{}] Upstream drain timeout after remote FIN for {}, aborted",
                            peer_addr, masked
                        );
                    }
                }
                info!("[{}] Connection to {} closed", peer_addr, masked);
                Ok(())
            }
            // 传输故障：对浏览器明确断开（两个半份直接丢弃，不排水）
            (false, Some(e)) => {
                up.abort();
                let _ = up.await;
                Err(Self::relay_error(e, peer_addr, target))
            }
        };
        // 连接注册表钩子（中继终点）：幂等标记关闭（连接页转「最近关闭」）
        conn.finish();
        relay_result
    }

    /// 传输/直连故障 → 明确的失败（供外层日志与错误传播；浏览器侧为显式断开而非 EOF 冒充）
    fn relay_error(e: RelayError, peer_addr: SocketAddr, target: &str) -> HydraError {
        let masked = mask_target(target);
        match e {
            RelayError::Transport => {
                error!(
                    "[{}] Relay transport failure for {} — connection aborted",
                    peer_addr, masked
                );
                HydraError::ConnectionError(format!("中继传输故障，连接已断开: {}", masked))
            }
            RelayError::LocalIo(err) => {
                error!(
                    "[{}] Direct relay IO failure for {} — connection aborted: {}",
                    peer_addr, masked, err
                );
                HydraError::ConnectionError(format!("直连目标 IO 故障，连接已断开: {}", masked))
            }
        }
    }
}

/// Team-T：已建成的节点转发链路（TCP/TLS，已完成认证并收到节点 0x00 成功应答）。
/// TCP 自带可靠有序：无多流聚合/ACK/应用错误码通道（QUIC 路径已随 TCP 转型移除）。
pub(crate) struct NodeLink {
    send: CountingStream<TcpWriteHalf>,
    recv: CountingStream<TcpReadHalf>,
    /// 出口节点地址（连接注册表展示「节点」列用；中继起点随链路携带，零额外查询）
    node: SocketAddr,
}

impl NodeLink {
    /// 拆分为（读端, 写端），供 TUN 模式把节点链路透传给用户态 TCP 栈
    /// （pub(crate)：仅 crate 内 tun 模块经 tun_channel_opener 使用）。
    pub(crate) fn into_parts(self) -> (CountingStream<TcpReadHalf>, CountingStream<TcpWriteHalf>) {
        (self.recv, self.send)
    }
}

/// Exec2：中继的远端链路——加密节点（TCP/TLS 流）或国内直连明文 TCP（CN 分流）。
/// 两种链路共用 relay_bidirectional 的收敛/排水/计数逻辑与 ACTIVE_RELAYS 计数器。
/// 节点路径的流为 CountingStream 包装。
enum RemoteLink {
    Node { link: NodeLink },
    Direct(TcpStream),
}

/// 上行终点（浏览器 → 远端）
enum UpSink {
    /// Team-T：TCP/TLS 链路上行写端
    Node(CountingStream<TcpWriteHalf>),
    Direct(CountingStream<tokio::net::tcp::OwnedWriteHalf>),
}

/// 下行源（远端 → 浏览器）
enum DownSource {
    /// Team-T：TCP/TLS 链路下行读端
    Node(CountingStream<TcpReadHalf>),
    Direct(CountingStream<tokio::net::tcp::OwnedReadHalf>),
}

/// 中继方向错误
enum RelayError {
    /// 本地或传输层故障
    Transport,
    /// 直连链路（CN 分流）的 IO 故障
    LocalIo(std::io::Error),
}

/// 归类单个中继方向的结束结果：干净结束 → None；故障 → Some(err)；任务 panic → 传输故障
fn join_relay_result(
    r: std::result::Result<std::result::Result<u64, RelayError>, tokio::task::JoinError>,
) -> Option<RelayError> {
    match r {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some(RelayError::Transport),
    }
}

/// RAII 守卫：中继完全收敛（对象销毁）时递减活动计数
struct RelayGuard;
impl Drop for RelayGuard {
    fn drop(&mut self) {
        ACTIVE_RELAYS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 在原始字节中定位 HTTP 头部结束标记 "\r\n\r\n"
fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 06-P2-1：连续 TargetUnreachable 计数与阈值重置逻辑（open_target 跨节点重试判定）
#[cfg(test)]
mod unreach_counter_tests {
    use super::*;

    #[test]
    fn 连续计数达阈值后由调用方重试_计数递增() {
        let t = "unit-test.example:443";
        clear_target_unreachable(t);
        assert_eq!(record_target_unreachable(t), 1);
        assert_eq!(record_target_unreachable(t), 2);
        assert_eq!(record_target_unreachable(t), 3);
        assert!(record_target_unreachable(t) >= TARGET_UNREACH_FAILOVER_THRESHOLD);
    }

    #[test]
    fn 连接成功后计数清零() {
        let t = "unit-test-clear.example:443";
        record_target_unreachable(t);
        record_target_unreachable(t);
        clear_target_unreachable(t);
        assert_eq!(record_target_unreachable(t), 1, "清零后应从 1 重新计数");
    }

    /// 07-P1-3：命中阈值重置后，同一目标的第 4 个请求（以及任何其他目标）
    /// 计数从 1 起步，不再触发跨节点重试——消除"永久 3 倍重试放大"。
    #[test]
    fn 命中阈值即重置_后续请求不再跨节点重试() {
        // 唯一目标名：避免与并行测试进程内其他用例的计数互相干扰
        let t = format!(
            "failover-once-{}.example:443",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        clear_target_unreachable(&t);
        // 前 3 次失败：第 1、2 次不重试（直接报错给客户端），第 3 次命中阈值 →
        // 允许一次跨节点重试，同时计数被重置
        assert!(!record_and_should_failover(&t), "第 1 次失败不应重试");
        assert!(!record_and_should_failover(&t), "第 2 次失败不应重试");
        assert!(
            record_and_should_failover(&t),
            "第 3 次失败应允许一次跨节点重试"
        );
        // 重置后的第 4 个请求（无论同目标还是不同目标——不同目标计数本就从 0
        // 起步）均不再跨节点重试：放大态已被解除
        assert!(
            !record_and_should_failover(&t),
            "命中重置后第 4 次请求不得再重试"
        );
        // 换一个全新目标：计数从 0 起步，同样不重试
        let t2 = format!("{}-alt", t);
        assert!(
            !record_and_should_failover(&t2),
            "全新目标不应触发跨节点重试"
        );
        clear_target_unreachable(&t);
        clear_target_unreachable(&t2);
    }
}
