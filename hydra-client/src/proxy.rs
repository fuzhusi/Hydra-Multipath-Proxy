use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn};
use hydra_protocol::{Result, HydraError, NodeInfo, NodeStatus};
use crate::scheduler::Scheduler;
use crate::transport::Transport;
use std::sync::Arc;

pub struct ProxyServer {
    listen_addr: SocketAddr,
    scheduler: Arc<Scheduler>,
    nodes: Vec<SocketAddr>,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            scheduler: Arc::new(Scheduler::new()),
            nodes: Vec::new(),
        }
    }

    pub fn with_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.nodes = nodes;
        self
    }

    pub async fn start(&self) -> Result<()> {
        // Add nodes to scheduler
        info!("Initializing proxy with {} nodes...", self.nodes.len());
        for addr in &self.nodes {
            let node = NodeInfo {
                address: *addr,
                bandwidth: 100.0,
                latency: 10.0,
                loss_rate: 0.01,
                load: 0.5,
                status: NodeStatus::Online,
            };
            self.scheduler.add_node(node).await;
            info!("Added node to scheduler: {}", addr);
        }

        info!("Binding proxy listener to {}...", self.listen_addr);
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("✓ Proxy server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("━━━ New SOCKS5 connection from {} ━━━", addr);
                    let scheduler = self.scheduler.clone();
                    tokio::spawn(async move {
                        // 包装错误处理，确保发送 SOCKS5 错误响应
                        match Self::handle_connection(stream, scheduler).await {
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
    ) -> Result<()> {
        let mut buf = [0u8; 4096];
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());

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
            Self::handle_socks5(stream, &buf, n, scheduler).await
        } else if buf[0] >= b'A' && buf[0] <= b'Z' {
            // HTTP 协议 (CONNECT, GET, POST 等)
            info!("[{}] Detected HTTP protocol", peer_addr);
            Self::handle_http(stream, &buf, n, scheduler).await
        } else {
            error!("[{}] Unknown protocol, first byte: 0x{:02x}", peer_addr, buf[0]);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            Err(HydraError::ProtocolError("Unknown protocol".to_string()))
        }
    }

    /// 处理 HTTP CONNECT 代理请求
    async fn handle_http(
        mut stream: TcpStream,
        initial_buf: &[u8],
        initial_len: usize,
        scheduler: Arc<Scheduler>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());

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
            return Self::handle_http_connect(stream, target_str, scheduler).await;
        }

        // 普通 HTTP 请求 (GET, POST, etc.)
        // 对于 HTTP GET/POST，我们需要将请求转发到目标服务器
        // 从 URL 或 Host header 中提取主机名
        let target_host = if url.starts_with("http://") {
            // 从 http://host/path 中提取 host
            let without_protocol = &url[7..];
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

        // 解析主机名和端口
        let (target_addr_str, default_port) = if target_host.contains(':') {
            let parts: Vec<&str> = target_host.splitn(2, ':').collect();
            (parts[0].to_string(), parts[1].parse::<u16>().unwrap_or(80))
        } else {
            (target_host.clone(), 80u16)
        };

        // 发送目标地址到服务器（包含端口）
        let target_with_port = format!("{}:{}", target_addr_str, default_port);

        // 连接到节点
        info!("[{}] Selecting best node from scheduler...", peer_addr);
        let node = match scheduler.get_best_node().await {
            Some(node) => node,
            None => {
                error!("[{}] No available nodes in scheduler!", peer_addr);
                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await;
                return Err(HydraError::ConnectionError("No available nodes".to_string()));
            }
        };

        info!("[{}] Selected node: {} (score: {})", peer_addr, node.address, node.calculate_score());

        // 连接到节点
        info!("[{}] Connecting to node {} via QUIC...", peer_addr, node.address);
        let transport = match Transport::new_client().await {
            Ok(t) => t,
            Err(e) => {
                error!("[{}] Failed to create QUIC transport: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        let connection = match transport.connect(node.address).await {
            Ok(c) => {
                info!("[{}] QUIC connection established to {}", peer_addr, node.address);
                c
            }
            Err(e) => {
                error!("[{}] Failed to connect to node {}: {}", peer_addr, node.address, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        // 打开双向流
        info!("[{}] Opening bidirectional stream to node...", peer_addr);
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(stream) => {
                info!("[{}] Bidirectional stream opened successfully", peer_addr);
                stream
            }
            Err(e) => {
                error!("[{}] Failed to open bidirectional stream: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError(format!("Failed to open stream: {}", e)));
            }
        };

        // 发送目标地址到节点
        info!("[{}] Sending target address to node: {}", peer_addr, target_with_port);
        if let Err(e) = send.write_all(target_with_port.as_bytes()).await {
            error!("[{}] Failed to send target address: {}", peer_addr, e);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        // 读取节点响应
        info!("[{}] Waiting for response from node...", peer_addr);
        let mut resp_buf = [0u8; 2];
        let n = match recv.read(&mut resp_buf).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                error!("[{}] No response received from node (stream closed)", peer_addr);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError("No response from node".to_string()));
            }
            Err(e) => {
                error!("[{}] Failed to read response from node: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError(format!("Read error: {}", e)));
            }
        };

        info!("[{}] Received {} bytes response from node: {:?}", peer_addr, n, &resp_buf[..n]);

        if n < 2 || resp_buf[0] != 0x00 {
            error!("[{}] Node returned error response: {:?}", peer_addr, &resp_buf[..n]);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ConnectionError("Remote node connection failed".to_string()));
        }

        // 发送原始 HTTP 请求到节点（转发完整的 HTTP 请求）
        info!("[{}] Forwarding HTTP request to node...", peer_addr);
        if let Err(e) = send.write_all(request.as_bytes()).await {
            error!("[{}] Failed to forward HTTP request: {}", peer_addr, e);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        info!("[{}] ✓ HTTP {} request forwarded to {} via node {}", peer_addr, method, target_host, node.address);
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
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());

        // 连接到节点
        info!("[{}] Selecting best node from scheduler...", peer_addr);
        let node = match scheduler.get_best_node().await {
            Some(node) => node,
            None => {
                error!("[{}] No available nodes in scheduler!", peer_addr);
                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await;
                return Err(HydraError::ConnectionError("No available nodes".to_string()));
            }
        };

        info!("[{}] Selected node: {} (score: {})", peer_addr, node.address, node.calculate_score());

        // 连接到节点
        info!("[{}] Connecting to node {} via QUIC...", peer_addr, node.address);
        let transport = match Transport::new_client().await {
            Ok(t) => t,
            Err(e) => {
                error!("[{}] Failed to create QUIC transport: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        let connection = match transport.connect(node.address).await {
            Ok(c) => {
                info!("[{}] QUIC connection established to {}", peer_addr, node.address);
                c
            }
            Err(e) => {
                error!("[{}] Failed to connect to node {}: {}", peer_addr, node.address, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };

        // 打开双向流
        info!("[{}] Opening bidirectional stream to node...", peer_addr);
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(stream) => {
                info!("[{}] Bidirectional stream opened successfully", peer_addr);
                stream
            }
            Err(e) => {
                error!("[{}] Failed to open bidirectional stream: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError(format!("Failed to open stream: {}", e)));
            }
        };

        // 发送目标地址到节点
        info!("[{}] Sending target address to node: {}", peer_addr, target_str);
        if let Err(e) = send.write_all(target_str.as_bytes()).await {
            error!("[{}] Failed to send target address: {}", peer_addr, e);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        // 读取节点响应
        info!("[{}] Waiting for response from node...", peer_addr);
        let mut resp_buf = [0u8; 2];
        let n = match recv.read(&mut resp_buf).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                error!("[{}] No response received from node (stream closed)", peer_addr);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError("No response from node".to_string()));
            }
            Err(e) => {
                error!("[{}] Failed to read response from node: {}", peer_addr, e);
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(HydraError::ProtocolError(format!("Read error: {}", e)));
            }
        };

        info!("[{}] Received {} bytes response from node: {:?}", peer_addr, n, &resp_buf[..n]);

        if n < 2 || resp_buf[0] != 0x00 {
            error!("[{}] Node returned error response: {:?}", peer_addr, &resp_buf[..n]);
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(HydraError::ConnectionError("Remote node connection failed".to_string()));
        }

        // 发送 HTTP 200 成功响应
        info!("[{}] Sending HTTP 200 success response...", peer_addr);
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        info!("[{}] ✓ Connected to {} via node {}", peer_addr, target_str, node.address);
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
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
        let mut buf = [0u8; 256];

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

        let target_addr = match atyp {
            0x01 => {
                // IPv4
                if n < 10 {
                    error!("[{}] Invalid IPv4 address length: {}", peer_addr, n);
                    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err(HydraError::ProtocolError("Invalid IPv4 address".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                let addr = SocketAddr::new(ip.into(), port);
                info!("[{}] Target IPv4: {}", peer_addr, addr);
                addr
            }
            0x03 => {
                // Domain name - 发送域名到服务器，让服务器解析 DNS
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

                info!("[{}] Target domain: {}:{} - sending to server for DNS resolution", peer_addr, domain, port);

                // 直接返回域名格式的地址，让服务器解析 DNS
                // 使用一个特殊的 SocketAddr 来表示域名
                // 这里我们用 0.0.0.0:0 作为占位符，实际发送域名到服务器
                // 服务器会解析域名并连接
                SocketAddr::new(std::net::Ipv4Addr::new(0, 0, 0, 0).into(), 0)
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
                let addr = SocketAddr::new(ip.into(), port);
                info!("[{}] Target IPv6: {}", peer_addr, addr);
                addr
            }
            _ => {
                error!("[{}] Unsupported address type: 0x{:02x}", peer_addr, atyp);
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(HydraError::ProtocolError("Unsupported address type".to_string()));
            }
        };

        info!("[{}] >>> SOCKS5 CONNECT request to {}", peer_addr, target_addr);

        // Get best node from scheduler
        info!("[{}] Selecting best node from scheduler...", peer_addr);
        let node = match scheduler.get_best_node().await {
            Some(node) => node,
            None => {
                error!("[{}] No available nodes in scheduler!", peer_addr);
                let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return Err(HydraError::ConnectionError("No available nodes".to_string()));
            }
        };

        info!("[{}] Selected node: {} (score: {})", peer_addr, node.address, node.calculate_score());

        // Connect to remote node via QUIC
        info!("[{}] Connecting to node {} via QUIC...", peer_addr, node.address);
        let transport = match Transport::new_client().await {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to create QUIC transport: {}", e);
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(e);
            }
        };

        let connection = match transport.connect(node.address).await {
            Ok(c) => {
                info!("QUIC connection established to {}", node.address);
                c
            }
            Err(e) => {
                error!("Failed to connect to node {}: {}", node.address, e);
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(e);
            }
        };

        // Send target address to remote node
        info!("Opening bidirectional stream to node...");
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(stream) => {
                info!("Bidirectional stream opened successfully");
                stream
            }
            Err(e) => {
                error!("Failed to open bidirectional stream: {}", e);
                stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(HydraError::ProtocolError(format!("Failed to open stream: {}", e)));
            }
        };

        // Send connect request: [target_addr_str]
        // 对于域名类型，发送域名而不是 IP 地址
        let target_str = if atyp == 0x03 {
            // 域名类型，发送域名:端口格式
            let domain_len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]);
            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
            format!("{}:{}", domain, port)
        } else {
            target_addr.to_string()
        };
        info!("[{}] Sending target address to node: {}", peer_addr, target_str);
        if let Err(e) = send.write_all(target_str.as_bytes()).await {
            error!("[{}] Failed to send target address: {}", peer_addr, e);
            let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        // Read response from remote node
        info!("[{}] Waiting for response from node...", peer_addr);
        let mut resp_buf = [0u8; 2];
        let n = match recv.read(&mut resp_buf).await {
            Ok(Some(n)) => n,
            Ok(None) => {
                error!("[{}] No response received from node (stream closed)", peer_addr);
                let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return Err(HydraError::ProtocolError("No response from node".to_string()));
            }
            Err(e) => {
                error!("[{}] Failed to read response from node: {}", peer_addr, e);
                let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return Err(HydraError::ProtocolError(format!("Read error: {}", e)));
            }
        };

        info!("Received {} bytes response from node: {:?}", n, &resp_buf[..n]);

        if n < 2 || resp_buf[0] != 0x00 {
            // Connection failed
            error!("Node returned error response: {:?}", &resp_buf[..n]);
            stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(HydraError::ConnectionError("Remote node connection failed".to_string()));
        }

        // Send success response to client
        info!("[{}] Sending SOCKS5 success response to client...", peer_addr);
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        info!("[{}] ✓ Connected to {} via node {}", peer_addr, target_addr, node.address);
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

        info!("Connection to {} closed", target_addr);
        Ok(())
    }
}
