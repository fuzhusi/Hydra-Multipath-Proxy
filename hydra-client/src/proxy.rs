use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn};
use hydra_protocol::{Result, HydraError, NodeInfo, NodeStatus};
use crate::scheduler::Scheduler;
use crate::transport::{Transport, DEFAULT_SNI};
use crate::pool::{ConnectionPool, PoolConfig};
use crate::traffic::TrafficMonitor;
use std::sync::Arc;

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

    pub fn with_traffic_monitor(mut self, monitor: Arc<TrafficMonitor>) -> Self {
        self.traffic_monitor = Some(monitor);
        self
    }

    pub async fn start(&self) -> Result<()> {
        if self.auth_key.is_empty() {
            return Err(HydraError::ConnectionError(
                "未设置认证密钥：请设置 HYDRA_AUTH_KEY 环境变量（或调用 with_auth_key）".to_string(),
            ));
        }
        if self.node_certs.is_empty() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书：请设置 HYDRA_NODE_CERT 环境变量（或调用 with_node_certs）".to_string(),
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
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

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
            error!("[{}] Unknown protocol, first byte: 0x{:02x}", peer_addr, buf[0]);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            Err(HydraError::ProtocolError("Unknown protocol".to_string()))
        }
    }

    /// 统一的节点连接入口：按优先级尝试候选节点。
    /// - 传输失败（连接断开/流损坏/响应超时）→ 标记节点 Offline、清空其连接池、切换下一节点
    /// - 节点存活但目标不可达（0x01）或节点侧 DNS 失败（0x02）→ 不切换节点，直接向调用方报错
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

        let candidates = scheduler.get_nodes_by_priority().await;
        if candidates.is_empty() {
            error!("[{}] No available nodes in scheduler!", peer_addr);
            return Err(HydraError::ConnectionError("No available nodes".to_string()));
        }

        // 目标地址带 2 字节大端长度前缀，节点侧 read_exact 读取，杜绝流式截断
        let addr_bytes = target.as_bytes();
        if addr_bytes.len() > 256 {
            return Err(HydraError::ProtocolError("Target address too long".to_string()));
        }
        let mut request = Vec::with_capacity(2 + addr_bytes.len());
        request.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        request.extend_from_slice(addr_bytes);

        let mut last_err: Option<HydraError> = None;
        for node in candidates.iter().take(MAX_NODE_ATTEMPTS) {
            let (mut send, mut recv) = match pool.get_stream(node.address).await {
                Ok(streams) => streams,
                Err(e) => {
                    warn!("[{}] Node {} unreachable ({}), failing over to next node", peer_addr, node.address, e);
                    scheduler.mark_node_offline(&node.address).await;
                    pool.remove_all(&node.address).await;
                    last_err = Some(e);
                    continue;
                }
            };

            if let Err(e) = send.write_all(&request).await {
                warn!("[{}] Node {} failed to accept target address ({}), failing over", peer_addr, node.address, e);
                scheduler.mark_node_offline(&node.address).await;
                pool.remove_all(&node.address).await;
                last_err = Some(HydraError::ProtocolError(format!("Write error: {}", e)));
                continue;
            }

            let mut resp = [0u8; 2];
            match tokio::time::timeout(RESPONSE_TIMEOUT, recv.read_exact(&mut resp)).await {
                Ok(Ok(())) if resp[0] == 0x00 => {
                    info!("[{}] ✓ Connected to {} via node {}", peer_addr, target, node.address);
                    return Ok((send, recv));
                }
                // 节点存活：目标连接失败/DNS 失败属于目标侧问题，不降级节点
                Ok(Ok(())) => {
                    error!("[{}] Node {} reported status {} for target {}", peer_addr, node.address, resp[0], target);
                    let msg = if resp[0] == 0x02 {
                        format!("节点 DNS 解析失败: {}", target)
                    } else {
                        format!("节点无法连接目标: {}", target)
                    };
                    return Err(HydraError::ConnectionError(msg));
                }
                Ok(Err(e)) => {
                    warn!("[{}] Node {} stream broken ({}), failing over", peer_addr, node.address, e);
                }
                Err(_) => {
                    warn!("[{}] Node {} response timeout, failing over", peer_addr, node.address);
                }
            }
            scheduler.mark_node_offline(&node.address).await;
            pool.remove_all(&node.address).await;
            last_err = Some(HydraError::ConnectionError(format!("Node {} failed", node.address)));
        }

        Err(last_err.unwrap_or_else(|| HydraError::ConnectionError("All nodes failed".to_string())))
    }

    /// 处理 HTTP CONNECT 代理请求
    async fn handle_http(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // 将初始数据转换为字符串
        let mut request = String::from_utf8_lossy(&initial_buf[..initial_len]).to_string();

        // 读取完整的 HTTP 请求头（直到 \r\n\r\n）
        while !request.contains("\r\n\r\n") {
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
            request.push_str(&String::from_utf8_lossy(&buf[..n]));
        }

        info!("[{}] HTTP request: {}", peer_addr, request.lines().next().unwrap_or(""));

        // 解析请求
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 3 {
            error!("[{}] Invalid HTTP request: {}", peer_addr, first_line);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Err(HydraError::ProtocolError("Invalid HTTP request".to_string()));
        }

        let method = parts[0];
        let url = parts[1];

        info!("[{}] HTTP method: {}, URL: {}", peer_addr, method, url);

        if method == "CONNECT" {
            // CONNECT 请求 - 用于 HTTPS
            let target_str = url.to_string();
            info!("[{}] >>> HTTP CONNECT request to {}", peer_addr, target_str);
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
            request.lines()
                .find(|line| line.to_lowercase().starts_with("host:"))
                .map(|line| line[5..].trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        };

        info!("[{}] >>> HTTP {} request to {}", peer_addr, method, target_host);

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

        // 连接到节点（带故障切换）
        let (mut send, mut recv) = match Self::open_target(&scheduler, &pool, &target_with_port, peer_addr).await {
            Ok(streams) => streams,
            Err(e) => {
                error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        // 发送原始 HTTP 请求到节点（转发完整的 HTTP 请求）
        info!("[{}] Forwarding HTTP request to node...", peer_addr);
        if let Err(e) = send.write_all(request.as_bytes()).await {
            error!("[{}] Failed to forward HTTP request: {}", peer_addr, e);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        info!("[{}] ✓ HTTP {} request forwarded to {}", peer_addr, method, target_host);
        info!("[{}] Starting bidirectional traffic forwarding...", peer_addr);

        // 转发流量
        let (mut client_read, mut client_write) = stream.into_split();

        let client_to_node = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let node_to_client = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => {
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        tokio::select! {
            _ = client_to_node => {},
            _ = node_to_client => {},
        }

        info!("[{}] Connection to {} closed", peer_addr, target_host);
        Ok(())
    }

    /// 处理 HTTP CONNECT 请求（用于 HTTPS）
    async fn handle_http_connect(
        mut stream: TcpStream,
        target_str: String,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));

        // 连接到节点（带故障切换）
        let (mut send, mut recv) = match Self::open_target(&scheduler, &pool, &target_str, peer_addr).await {
            Ok(streams) => streams,
            Err(e) => {
                error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        // 发送 HTTP 200 成功响应
        info!("[{}] Sending HTTP 200 success response...", peer_addr);
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        info!("[{}] Starting bidirectional traffic forwarding...", peer_addr);

        // 转发流量
        let (mut client_read, mut client_write) = stream.into_split();

        let client_to_node = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let node_to_client = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => {
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        tokio::select! {
            _ = client_to_node => {},
            _ = node_to_client => {},
        }

        info!("[{}] Connection to {} closed", peer_addr, target_str);
        Ok(())
    }

    /// 处理 SOCKS5 代理请求
    async fn handle_socks5(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
        pool: Arc<ConnectionPool>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));
        let mut buf = [0u8; 320];

        // 初始数据应该是 SOCKS5 greeting
        if initial_len < 2 || initial_buf[0] != 0x05 {
            error!("[{}] Invalid SOCKS5 greeting: {:?}", peer_addr, &initial_buf[..initial_len]);
            let _ = stream.write_all(&[0x05, 0xFF]).await;
            return Err(HydraError::ProtocolError("Invalid SOCKS5 greeting".to_string()));
        }

        info!("[{}] SOCKS5 greeting received ({} bytes)", peer_addr, initial_len);

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
            let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(HydraError::ProtocolError("Invalid SOCKS5 request".to_string()));
        }
        info!("[{}] SOCKS5 request received ({} bytes), cmd={}", peer_addr, n, buf[1]);

        // Parse command
        let cmd = buf[1];
        if cmd != 0x01 {
            // Only CONNECT supported
            stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(HydraError::ProtocolError("Unsupported SOCKS5 command".to_string()));
        }

        // Parse address type
        let atyp = buf[3];
        info!("[{}] Address type: 0x{:02x}", peer_addr, atyp);

        let target_str = match atyp {
            0x01 => {
                // IPv4
                if n < 10 {
                    error!("[{}] Invalid IPv4 address length: {}", peer_addr, n);
                    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(HydraError::ProtocolError("Invalid IPv4 address".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                info!("[{}] Target IPv4: {}:{}", peer_addr, ip, port);
                format!("{}:{}", ip, port)
            }
            0x03 => {
                // Domain name - 发送域名到节点，由节点解析 DNS（域名不明文离开加密通道）
                if n < 7 {
                    error!("[{}] Invalid domain name length: {}", peer_addr, n);
                    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(HydraError::ProtocolError("Invalid domain name".to_string()));
                }
                let domain_len = buf[4] as usize;
                if n < 5 + domain_len + 2 {
                    error!("[{}] Invalid domain name data length: need {}, got {}", peer_addr, 5 + domain_len + 2, n);
                    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(HydraError::ProtocolError("Invalid domain name length".to_string()));
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]);
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);

                info!("[{}] Target domain: {}:{} - sending to node for DNS resolution", peer_addr, domain, port);
                format!("{}:{}", domain, port)
            }
            0x04 => {
                // IPv6
                if n < 22 {
                    error!("[{}] Invalid IPv6 address length: {}", peer_addr, n);
                    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(HydraError::ProtocolError("Invalid IPv6 address".to_string()));
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
                info!("[{}] Target IPv6: [{}]:{}", peer_addr, ip, port);
                format!("[{}]:{}", ip, port)
            }
            _ => {
                error!("[{}] Unsupported address type: 0x{:02x}", peer_addr, atyp);
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(HydraError::ProtocolError("Unsupported address type".to_string()));
            }
        };

        info!("[{}] >>> SOCKS5 CONNECT request to {}", peer_addr, target_str);

        // 连接到节点（带故障切换）
        let (mut send, mut recv) = match Self::open_target(&scheduler, &pool, &target_str, peer_addr).await {
            Ok(streams) => streams,
            Err(e) => {
                error!("[{}] Failed to connect via any node: {}", peer_addr, e);
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(e);
            }
        };

        // Send success response to client
        info!("[{}] Sending SOCKS5 success response to client...", peer_addr);
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        info!("[{}] Starting bidirectional traffic forwarding...", peer_addr);

        // Forward traffic bidirectionally
        let (mut client_read, mut client_write) = stream.into_split();

        let client_to_node = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let node_to_client = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => {
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        // Wait for either direction to finish
        tokio::select! {
            _ = client_to_node => {},
            _ = node_to_client => {},
        }

        info!("Connection to {} closed", target_str);
        Ok(())
    }
}
