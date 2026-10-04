use crate::pool::{ConnectionPool, PoolConfig};
use crate::routing;
use crate::scheduler::Scheduler;
use crate::traffic::TrafficMonitor;
use crate::transport::{Transport, DEFAULT_SNI};
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

// ── 节点侧应用错误码（与 hydra-node/src/handler.rs 保持一致；客户端经 ReadError::Reset 读到）──
/// 0x11：节点无法连接目标
pub const NODE_ERR_TARGET_CONNECT: u64 = 0x11;
/// 0x12：节点侧 DNS 解析失败
pub const NODE_ERR_DNS_FAIL: u64 = 0x12;
/// 0x13：转发阶段 IO 错误
pub const NODE_ERR_FORWARD_IO: u64 = 0x13;

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

    /// 节点证书 DER 列表，加入客户端信任根执行标准校验（必填：防中间人）
    pub fn with_node_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.node_certs = certs;
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
        if self.node_certs.is_empty() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书：请设置 HYDRA_NODE_CERT 环境变量（或调用 with_node_certs）"
                    .to_string(),
            ));
        }

        // Add nodes to scheduler（按加入顺序递减初始评分，测速上线后由实测数据取代）
        info!("Initializing proxy with {} nodes...", self.nodes.len());
        for (idx, addr) in self.nodes.iter().enumerate() {
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

        let (endpoint, client_config) =
            Transport::create_shared_endpoint(self.node_certs.clone(), &self.sni)?;
        let pool = Arc::new(ConnectionPool::new(
            endpoint,
            PoolConfig {
                max_idle_per_node: 4,
                idle_timeout: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(60),
                connect_timeout: Duration::from_secs(5),
                auth_key: self.auth_key.clone(),
                sni: self.sni.clone(),
                client_config,
            },
        ));

        // 预热连接池
        info!("Warming up connection pool...");
        for addr in &self.nodes {
            pool.warm_up(*addr, 2).await;
        }

        info!("Binding proxy listener to {}...", self.listen_addr);
        let listener = TcpListener::bind(self.listen_addr).await?;
        if let Ok(local) = listener.local_addr() {
            let _ = self.bound_addr.set(local);
        }
        info!("✓ Proxy server listening on {}", self.listen_addr);

        // A2：Offline 节点自动恢复探测（常驻后台任务；start 是 &self，故用 scheduler 的 Arc clone）。
        // 完整测速（带宽/延迟评分）显式推迟至 WS-E / V3.3——现阶段评分维持静态初始值。
        crate::speedtest::spawn_recovery_probe(
            self.scheduler.clone(),
            self.node_certs.clone(),
            self.sni.clone(),
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("━━━ New SOCKS5 connection from {} ━━━", addr);
                    let scheduler = self.scheduler.clone();
                    let pool = pool.clone();
                    tokio::spawn(async move {
                        // 包装错误处理，确保发送 SOCKS5 错误响应
                        match Self::handle_connection(stream, scheduler, pool).await {
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

    async fn handle_connection(
        mut stream: TcpStream,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
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
            Self::handle_socks5(stream, &buf, n, scheduler, pool).await
        } else if buf[0] >= b'A' && buf[0] <= b'Z' {
            // HTTP 协议 (CONNECT, GET, POST 等)
            info!("[{}] Detected HTTP protocol", peer_addr);
            Self::handle_http(stream, &buf, n, scheduler, pool).await
        } else {
            error!(
                "[{}] Unknown protocol, first byte: 0x{:02x}",
                peer_addr, buf[0]
            );
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            Err(HydraError::ProtocolError("Unknown protocol".to_string()))
        }
    }

    /// 统一的节点连接入口：按优先级尝试候选节点。
    /// - 传输失败（连接断开/流损坏/响应超时）→ 标记节点 Offline、清空其连接池、切换下一节点
    /// - 节点存活的显式应用错误码（A3：Reset 0x11 目标不可达 / 0x12 DNS 失败）→ 不切换节点，直接向调用方报错
    /// 返回的流已完成认证并收到节点 0x00 成功应答，可直接双向转发。
    async fn open_target(
        scheduler: &Scheduler,
        pool: &ConnectionPool,
        target: &str,
        peer_addr: SocketAddr,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        const MAX_NODE_ATTEMPTS: usize = 3;
        // 应答等待须大于节点侧目标连接超时（15s），否则慢目标会被误判为节点故障
        const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

        // 日志脱敏（Exec2）：info 及以上级别目标地址一律短哈希；完整明文仅 debug 级别
        //（排查时开 RUST_LOG=debug 可见）
        debug!(
            "[{}] open_target (plaintext for troubleshooting): {}",
            peer_addr, target
        );

        let mut candidates = scheduler.get_nodes_by_priority().await;
        if candidates.is_empty() {
            error!("[{}] No available nodes in scheduler!", peer_addr);
            return Err(HydraError::ConnectionError(
                "No available nodes".to_string(),
            ));
        }

        // V3.3 方案 B（连接级多路径分发，默认关闭）：HYDRA_AGGREGATE=1 且 Online
        // 节点 ≥2 时，把评分加权选中的节点换到候选首位，其余候选保持评分降序作为
        // 故障切换后备；未启用/单节点时本调用是空操作，候选顺序与启用前逐位一致。
        crate::aggregate::maybe_reorder_candidates(&mut candidates, peer_addr, target);

        // 目标地址带 2 字节大端长度前缀，节点侧 read_exact 读取，杜绝流式截断
        let addr_bytes = target.as_bytes();
        if addr_bytes.len() > 256 {
            return Err(HydraError::ProtocolError(
                "Target address too long".to_string(),
            ));
        }
        let mut request = Vec::with_capacity(2 + addr_bytes.len());
        request.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        request.extend_from_slice(addr_bytes);

        let mut last_err: Option<HydraError> = None;
        for node in candidates.iter().take(MAX_NODE_ATTEMPTS) {
            let (mut send, mut recv) = match pool.get_stream(node.address).await {
                Ok(streams) => streams,
                Err(e) => {
                    warn!(
                        "[{}] Node {} unreachable ({}), failing over to next node",
                        peer_addr, node.address, e
                    );
                    scheduler.mark_node_offline(&node.address).await;
                    pool.remove_all(&node.address).await;
                    last_err = Some(e);
                    continue;
                }
            };

            if let Err(e) = send.write_all(&request).await {
                warn!(
                    "[{}] Node {} failed to accept target address ({}), failing over",
                    peer_addr, node.address, e
                );
                scheduler.mark_node_offline(&node.address).await;
                pool.remove_all(&node.address).await;
                last_err = Some(HydraError::ProtocolError(format!("Write error: {}", e)));
                continue;
            }

            let mut resp = [0u8; 2];
            match tokio::time::timeout(RESPONSE_TIMEOUT, recv.read_exact(&mut resp)).await {
                Ok(Ok(())) if resp[0] == 0x00 => {
                    info!(
                        "[{}] ✓ Connected to {} via node {}",
                        peer_addr,
                        mask_target(target),
                        node.address
                    );
                    // V3.3：按实际承接节点计数（聚合观测/测试断言"两节点都收到流量"）
                    crate::aggregate::record_node_served(node.address);
                    return Ok((send, recv));
                }
                // 节点存活：目标连接失败/DNS 失败属于目标侧问题，不降级节点（兼容旧版节点状态字节路径）
                Ok(Ok(())) => {
                    error!(
                        "[{}] Node {} reported status {} for target {}",
                        peer_addr,
                        node.address,
                        resp[0],
                        mask_target(target)
                    );
                    let msg = if resp[0] == 0x02 {
                        format!("节点 DNS 解析失败: {}", mask_target(target))
                    } else {
                        format!("节点无法连接目标: {}", mask_target(target))
                    };
                    return Err(HydraError::ConnectionError(msg));
                }
                Ok(Err(e)) => {
                    // A3：节点存活的显式应用错误码（RESET_STREAM 携带 0x11-0x13）
                    let app_code = match &e {
                        quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)) => {
                            Some(u64::from(*code))
                        }
                        _ => None,
                    };
                    if app_code == Some(NODE_ERR_TARGET_CONNECT) {
                        error!(
                            "[{}] Node {} reported target-unreachable (0x11) for {}",
                            peer_addr,
                            node.address,
                            mask_target(target)
                        );
                        return Err(HydraError::ConnectionError(format!(
                            "节点无法连接目标: {}",
                            mask_target(target)
                        )));
                    }
                    if app_code == Some(NODE_ERR_DNS_FAIL) {
                        error!(
                            "[{}] Node {} reported DNS failure (0x12) for {}",
                            peer_addr,
                            node.address,
                            mask_target(target)
                        );
                        return Err(HydraError::ConnectionError(format!(
                            "节点 DNS 解析失败: {}",
                            mask_target(target)
                        )));
                    }
                    // 其余应用错误码（含 0x13 转发错误）：节点存活，不降级节点——
                    // 与 0x11/0x12 的"目标侧问题不切换"原则一致；只有非应用层（传输层）故障才降级
                    if let Some(code) = app_code {
                        warn!(
                            "[{}] Node {} reported app error 0x{:x} for {}, not failing over",
                            peer_addr,
                            node.address,
                            code,
                            mask_target(target)
                        );
                        return Err(HydraError::ConnectionError(format!(
                            "节点报告转发错误 (0x{:x}): {}",
                            code,
                            mask_target(target)
                        )));
                    }
                    warn!(
                        "[{}] Node {} stream broken ({}), failing over",
                        peer_addr, node.address, e
                    );
                }
                Err(_) => {
                    warn!(
                        "[{}] Node {} response timeout, failing over",
                        peer_addr, node.address
                    );
                }
            }
            scheduler.mark_node_offline(&node.address).await;
            pool.remove_all(&node.address).await;
            last_err = Some(HydraError::ConnectionError(format!(
                "Node {} failed",
                node.address
            )));
        }

        Err(last_err.unwrap_or_else(|| HydraError::ConnectionError("All nodes failed".to_string())))
    }

    /// 处理 HTTP 代理请求（CONNECT 与普通明文请求共用入口）
    async fn handle_http(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
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
            return Self::handle_http_connect(stream, target_str, scheduler, pool).await;
        }

        // 普通 HTTP 请求 (GET, POST, etc.)
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
        let link =
            match Self::try_direct(&target_with_port, peer_addr).await {
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
                    let (mut send, recv) =
                        match Self::open_target(&scheduler, &pool, &target_with_port, peer_addr)
                            .await
                        {
                            Ok(streams) => streams,
                            Err(e) => {
                                error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                                return Err(e);
                            }
                        };

                    // A6：发送原始 HTTP 请求到节点（原始字节转发，含二进制 body；不再经 lossy 字符串）
                    info!("[{}] Forwarding HTTP request to node...", peer_addr);
                    if let Err(e) = send.write_all(&raw).await {
                        error!("[{}] Failed to forward HTTP request: {}", peer_addr, e);
                        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
                    }
                    RemoteLink::Node { send, recv }
                }
            };

        info!(
            "[{}] ✓ HTTP {} request forwarded to {}",
            peer_addr,
            method,
            mask_target(&target_host)
        );

        Self::relay_bidirectional(stream, link, peer_addr, &target_host).await
    }

    /// 处理 HTTP CONNECT 请求（用于 HTTPS）
    async fn handle_http_connect(
        mut stream: TcpStream,
        target_str: String,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
    ) -> Result<()> {
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // 连接到节点（带故障切换）；Exec2：命中 CN 域名表时本机 TCP 直连
        let link = match Self::try_direct(&target_str, peer_addr).await {
            Some(tcp) => RemoteLink::Direct(tcp),
            None => {
                let (send, recv) =
                    match Self::open_target(&scheduler, &pool, &target_str, peer_addr).await {
                        Ok(streams) => streams,
                        Err(e) => {
                            error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                            return Err(e);
                        }
                    };
                RemoteLink::Node { send, recv }
            }
        };

        // 发送 HTTP 200 成功响应
        info!("[{}] Sending HTTP 200 success response...", peer_addr);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        Self::relay_bidirectional(stream, link, peer_addr, &target_str).await
    }

    /// 处理 SOCKS5 代理请求
    async fn handle_socks5(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
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
                let (send, recv) =
                    match Self::open_target(&scheduler, &pool, &target_str, peer_addr).await {
                        Ok(streams) => streams,
                        Err(e) => {
                            error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                            stream
                                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await?;
                            return Err(e);
                        }
                    };
                RemoteLink::Node { send, recv }
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

        Self::relay_bidirectional(stream, link, peer_addr, &target_str).await
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
    /// - 远端既可以是加密节点（QUIC 流对），也可以是国内直连的明文 TCP（CN 分流），
    ///   两条路径复用同一套收敛/排水/计数逻辑；
    /// - 任一方向结束后显式 shutdown/abort 另一方向并 join 收敛，不再留下孤儿任务；
    /// - 浏览器关写侧（半关闭）时保留 远端→浏览器 方向，在超时窗口内收完剩余响应；
    /// - 节点侧 A3 应用错误码（Reset 0x11-0x13）映射为对浏览器的显式断开并向上传播错误，
    ///   不再以干净 EOF 冒充正常结束。
    async fn relay_bidirectional(
        stream: TcpStream,
        link: RemoteLink,
        peer_addr: SocketAddr,
        target: &str,
    ) -> Result<()> {
        ACTIVE_RELAYS.fetch_add(1, Ordering::Relaxed);
        let _guard = RelayGuard;

        // 日志脱敏：info 级目标一律短哈希；明文仅 debug 级别（RUST_LOG=debug）
        let masked = mask_target(target);
        debug!(
            "[{}] relay target (plaintext for troubleshooting): {}",
            peer_addr, target
        );

        let (mut up_sink, mut down_src) = match link {
            RemoteLink::Node { send, recv } => (UpSink::Node(send), DownSource::Node(recv)),
            RemoteLink::Direct(tcp) => {
                let (r, w) = tcp.into_split();
                (UpSink::Direct(w), DownSource::Direct(r))
            }
        };
        let (mut client_read, mut client_write) = stream.into_split();

        // 浏览器 → 远端（节点 QUIC 流 / 直连 TCP）
        let mut up = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total = 0u64;
            loop {
                match client_read.read(&mut buf).await {
                    // 浏览器关写侧：显式优雅结束上行（quinn FIN / TCP 半关闭 shutdown），
                    // 不依赖 SendStream::drop 的 finish 语义
                    //（quinn 0.10 drop==finish 已核实，但升级版本时语义可能变化）
                    Ok(0) => {
                        match up_sink {
                            UpSink::Node(mut send) => {
                                let _ = send.finish().await;
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
                            UpSink::Node(send) => send.write_all(&buf[..n]).await.map_err(|e| {
                                // 节点 STOP_SENDING（携带 A3 错误码）或连接级故障
                                match e {
                                    quinn::WriteError::Stopped(code) => {
                                        RelayError::NodeAppError(u64::from(code))
                                    }
                                    _ => RelayError::Transport,
                                }
                            }),
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
                    DownSource::Node(recv) => match recv.read(&mut buf).await {
                        // 节点 FIN：响应完整结束
                        Ok(Some(0)) | Ok(None) => return Ok(total),
                        Ok(Some(n)) => n,
                        // A3：节点显式 RESET_STREAM(0x11-0x13)——不再冒充正常 EOF
                        Err(quinn::ReadError::Reset(code)) => {
                            return Err(RelayError::NodeAppError(u64::from(code)));
                        }
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
            // 上行故障：中止下行（recv/client_write drop → STOP_SENDING/FIN），收敛后向上报错
            (true, Some(e)) => {
                down.abort();
                let _ = down.await;
                Err(Self::relay_error(e, peer_addr, target))
            }
            // 远端响应已完整（FIN）：显式中止上行并收敛（send drop → FIN 传给远端）
            (false, None) => {
                up.abort();
                let _ = up.await;
                info!("[{}] Connection to {} closed", peer_addr, masked);
                Ok(())
            }
            // 远端侧显式错误码或传输故障：对浏览器明确断开（两个半份直接丢弃，不排水）
            (false, Some(e)) => {
                up.abort();
                let _ = up.await;
                Err(Self::relay_error(e, peer_addr, target))
            }
        }
    }

    /// A3 错误码/传输故障 → 明确的失败（供外层日志与错误传播；浏览器侧为显式断开而非 EOF 冒充）
    fn relay_error(e: RelayError, peer_addr: SocketAddr, target: &str) -> HydraError {
        let masked = mask_target(target);
        match e {
            RelayError::NodeAppError(code) => {
                error!(
                    "[{}] Node app error 0x{:x} for {} — connection aborted explicitly",
                    peer_addr, code, masked
                );
                HydraError::ConnectionError(format!(
                    "节点转发故障（错误码 0x{:02x}），连接已显式断开: {}",
                    code, masked
                ))
            }
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

/// Exec2：中继的远端链路——加密节点（QUIC 流对）或国内直连明文 TCP（CN 分流）。
/// 两种链路共用 relay_bidirectional 的收敛/排水/计数逻辑与 ACTIVE_RELAYS 计数器。
enum RemoteLink {
    Node {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    Direct(TcpStream),
}

/// 上行终点（浏览器 → 远端）
enum UpSink {
    Node(quinn::SendStream),
    Direct(tokio::net::tcp::OwnedWriteHalf),
}

/// 下行源（远端 → 浏览器）
enum DownSource {
    Node(quinn::RecvStream),
    Direct(tokio::net::tcp::OwnedReadHalf),
}

/// 中继方向错误
enum RelayError {
    /// 节点侧显式应用错误码（A3：ReadError::Reset / WriteError::Stopped 携带 0x11-0x13）
    NodeAppError(u64),
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
