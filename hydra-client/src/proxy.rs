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

/// HTTP 头部区最大长度（防恶意超大头部无限累积）
const MAX_HTTP_HEAD: usize = 64 * 1024;
/// 半关闭排水阶段等待另一方向的超时（浏览器已关写侧后，剩余响应应在此窗口内到齐）
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
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

        // A2：Offline 节点自动恢复探测 + 测速评分（常驻后台任务；start 是 &self，故用 Arc clone）。
        // HYDRA_SPEEDTEST=0 时退回纯恢复探测，评分维持静态初始值。
        crate::speedtest::spawn_recovery_probe(
            self.scheduler.clone(),
            trust,
            self.sni.clone(),
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
            if self.scheduler.get_nodes_by_priority().await.iter().any(|n| n.address == *addr) {
                continue;
            }
            let node = NodeInfo {
                address: *addr,
                bandwidth: 100.0 - idx as f64 * 10.0,
                latency: 10.0,
                loss_rate: 0.01,
                load: 0.5,
                status: NodeStatus::Online,
            };
            self.scheduler.add_node(node).await;
            info!("Added node to scheduler: {}", addr);
        }
    }

    #[cfg(feature = "tun")]
    /// TUN 模式通道开启器：把 [`Self::open_target`]（含故障切换 /
    /// TargetUnreachable 判定 / mark_node_offline / 流量统计语义）包成
    /// [`crate::tun::ChannelOpener`]。调用前请先 `register_nodes()` 并确保
    /// 凭据已设置（auth_key/证书）。
    pub fn tun_channel_opener(&self) -> Result<crate::tun::ChannelOpener> {
        use crate::tun::{ChannelOpener, OpenFuture, ProxyDuplex};

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

        // 读取第一个字节来判断协议类型
        info!("[{}] Reading first byte to detect protocol...", peer_addr);
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!("[{}] Failed to read: {}", peer_addr, e);
                return Err(e.into());
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
                    return Ok(NodeLink { send, recv });
                }
                Err(e) => {
                    // 目标不可达（节点存活但目标连不上/SSRF/DNS 失败）：换节点无意义
                    //（目标在任意节点都同样不可达），且绝不污染节点评分——直接报错给
                    // 客户端（审查 R-01：原实现把健康节点连锁标记 Offline）。
                    if matches!(e, HydraError::TargetUnreachable(_)) {
                        warn!(
                            "[{}] Target unreachable via node {} (node healthy, not failing over)",
                            peer_addr,
                            node.address
                        );
                        return Err(e);
                    }
                    warn!(
                        "[{}] Node {} tcp/tls connect failed ({}), failing over to next node",
                        peer_addr,
                        node.address,
                        e
                    );
                    scheduler.mark_node_offline(&node.address).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| HydraError::ConnectionError("All nodes failed".to_string())))
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
        while header_end.is_none() {
            if raw.len() > MAX_HTTP_HEAD {
                error!("[{}] HTTP head too large ({} bytes)", peer_addr, raw.len());
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                return Err(HydraError::ProtocolError("HTTP head too large".to_string()));
            }
            let mut buf = [0u8; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("[{}] Failed to read HTTP request: {}", peer_addr, e);
                    return Err(e.into());
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
            error!("[{}] Invalid HTTP request: {}", peer_addr, first_line);
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
        let target_host = if let Some(without_protocol) = url.strip_prefix("http://") {
            // 从 http://host/path 中提取 host
            match without_protocol.find('/') {
                Some(pos) => without_protocol[..pos].to_string(),
                None => without_protocol.to_string(),
            }
        } else {
            // 从 Host header 中获取
            head_view
                .lines()
                .find(|line| line.to_lowercase().starts_with("host:"))
                .map(|line| line[5..].trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };

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

        // 解析主机名和端口（兼容 IPv6 字面量 "[::1]:8080"）
        let (target_addr_str, default_port) =
            if let Ok(addr) = target_host.parse::<std::net::SocketAddr>() {
                (addr.ip().to_string(), addr.port())
            } else if target_host.contains(':') {
                let parts: Vec<&str> = target_host.splitn(2, ':').collect();
                (parts[0].to_string(), parts[1].parse::<u16>().unwrap_or(80))
            } else {
                (target_host.clone(), 80u16)
            };

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

        Self::relay_bidirectional(stream, link, peer_addr, &target_host, traffic).await
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

        Self::relay_bidirectional(stream, link, peer_addr, &target_str, traffic).await
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
        let mut buf = [0u8; 320];

        // 初始数据应该是 SOCKS5 greeting
        if initial_len < 2 || initial_buf[0] != 0x05 {
            error!(
                "[{}] Invalid SOCKS5 greeting: {:?}",
                peer_addr,
                &initial_buf[..initial_len]
            );
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 greeting".to_string(),
            ));
        }

        info!(
            "[{}] SOCKS5 greeting received ({} bytes)",
            peer_addr, initial_len
        );

        // 发送无需认证响应
        stream.write_all(&[0x05, 0x00]).await?;
        info!("[{}] Sent no-auth response", peer_addr);

        // 读取 SOCKS5 请求
        info!("[{}] Reading SOCKS5 request...", peer_addr);
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!("[{}] Failed to read request: {}", peer_addr, e);
                return Err(e.into());
            }
        };
        if n < 7 || buf[0] != 0x05 {
            error!("[{}] Invalid SOCKS5 request: {:?}", peer_addr, &buf[..n]);
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(HydraError::ProtocolError(
                "Invalid SOCKS5 request".to_string(),
            ));
        }
        info!(
            "[{}] SOCKS5 request received ({} bytes), cmd={}",
            peer_addr, n, buf[1]
        );

        // Parse command
        let cmd = buf[1];
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
        let atyp = buf[3];
        info!("[{}] Address type: 0x{:02x}", peer_addr, atyp);

        let target_str = match atyp {
            0x01 => {
                // IPv4
                if n < 10 {
                    error!("[{}] Invalid IPv4 address length: {}", peer_addr, n);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid IPv4 address".to_string(),
                    ));
                }
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                let v4_target = format!("{}:{}", ip, port);
                info!("[{}] Target IPv4: {}", peer_addr, mask_target(&v4_target));
                debug!("[{}] Target IPv4 (plaintext): {}", peer_addr, v4_target);
                v4_target
            }
            0x03 => {
                // Domain name - 发送域名到节点，由节点解析 DNS（域名不明文离开加密通道）
                if n < 7 {
                    error!("[{}] Invalid domain name length: {}", peer_addr, n);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError("Invalid domain name".to_string()));
                }
                let domain_len = buf[4] as usize;
                if n < 5 + domain_len + 2 {
                    error!(
                        "[{}] Invalid domain name data length: need {}, got {}",
                        peer_addr,
                        5 + domain_len + 2,
                        n
                    );
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid domain name length".to_string(),
                    ));
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]);
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
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
                // IPv6
                if n < 22 {
                    error!("[{}] Invalid IPv6 address length: {}", peer_addr, n);
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(HydraError::ProtocolError(
                        "Invalid IPv6 address length".to_string(),
                    ));
                }
                let ip = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                    u16::from_be_bytes([buf[16], buf[17]]),
                    u16::from_be_bytes([buf[18], buf[19]]),
                );
                let port = u16::from_be_bytes([buf[20], buf[21]]);
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

        Self::relay_bidirectional(stream, link, peer_addr, &target_str, traffic).await
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
        match tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(tcp)) => {
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

    /// 双向转发（A4 收敛版 + Exec2 直连支持）：
    /// - 远端既可以是加密节点（TCP/TLS 流），也可以是国内直连的明文 TCP（CN 分流），
    ///   两条路径复用同一套收敛/排水/计数逻辑；
    /// - 任一方向结束后显式 shutdown 另一方向并 join 收敛，不再留下孤儿任务；
    /// - 浏览器关写侧（半关闭）时保留 远端→浏览器 方向，在超时窗口内收完剩余响应。
    async fn relay_bidirectional(
        stream: TcpStream,
        link: RemoteLink,
        peer_addr: SocketAddr,
        target: &str,
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
        let mut up = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total = 0u64;
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
                        if let Err(e) = write_res {
                            return Err(e);
                        }
                    }
                    Err(_) => return Err(RelayError::Transport),
                }
            }
        });

        // 远端 → 浏览器
        let mut down = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
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

        match (up_done, first_err) {
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
            // 远端响应已完整（FIN）：显式中止上行并收敛（写端 drop → FIN 传给远端）
            (false, None) => {
                up.abort();
                let _ = up.await;
                info!("[{}] Connection to {} closed", peer_addr, masked);
                Ok(())
            }
            // 传输故障：对浏览器明确断开（两个半份直接丢弃，不排水）
            (false, Some(e)) => {
                up.abort();
                let _ = up.await;
                Err(Self::relay_error(e, peer_addr, target))
            }
        }
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
}

impl NodeLink {
    /// 拆分为（读端, 写端），供 TUN 模式把节点链路透传给用户态 TCP 栈
    /// （pub(crate)：仅 crate 内 tun 模块经 tun_channel_opener 使用）。
    pub(crate) fn into_parts(
        self,
    ) -> (CountingStream<TcpReadHalf>, CountingStream<TcpWriteHalf>) {
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
