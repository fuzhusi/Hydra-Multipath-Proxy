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
            info!("Added node: {}", addr);
        }

        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Proxy server listening on {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("New connection from {}", addr);

            let scheduler = self.scheduler.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, scheduler).await {
                    error!("Error handling connection from {}: {}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        scheduler: Arc<Scheduler>,
    ) -> Result<()> {
        // SOCKS5 handshake
        let mut buf = [0u8; 256];

        // Read greeting
        let n = stream.read(&mut buf).await?;
        if n < 2 || buf[0] != 0x05 {
            return Err(HydraError::ProtocolError("Invalid SOCKS5 greeting".to_string()));
        }

        // Send no auth required
        stream.write_all(&[0x05, 0x00]).await?;

        // Read request
        let n = stream.read(&mut buf).await?;
        if n < 7 || buf[0] != 0x05 {
            return Err(HydraError::ProtocolError("Invalid SOCKS5 request".to_string()));
        }

        // Parse command
        let cmd = buf[1];
        if cmd != 0x01 {
            // Only CONNECT supported
            stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(HydraError::ProtocolError("Unsupported SOCKS5 command".to_string()));
        }

        // Parse address type
        let atyp = buf[3];
        let target_addr = match atyp {
            0x01 => {
                // IPv4
                if n < 10 {
                    return Err(HydraError::ProtocolError("Invalid IPv4 address".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                SocketAddr::new(ip.into(), port)
            }
            0x03 => {
                // Domain name
                if n < 7 {
                    return Err(HydraError::ProtocolError("Invalid domain name".to_string()));
                }
                let domain_len = buf[4] as usize;
                if n < 5 + domain_len + 2 {
                    return Err(HydraError::ProtocolError("Invalid domain name length".to_string()));
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]);
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);

                // DNS resolution - use a simple approach
                let ip = tokio::net::lookup_host(format!("{}:{}", domain, port))
                    .await?
                    .next()
                    .ok_or_else(|| HydraError::ProtocolError("DNS resolution failed".to_string()))?
                    .ip();
                SocketAddr::new(ip, port)
            }
            0x04 => {
                // IPv6
                if n < 22 {
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
                SocketAddr::new(ip.into(), port)
            }
            _ => {
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(HydraError::ProtocolError("Unsupported address type".to_string()));
            }
        };

        info!("SOCKS5 CONNECT request to {}", target_addr);

        // Get best node from scheduler
        let node = scheduler.get_best_node().await
            .ok_or_else(|| {
                error!("No available nodes in scheduler");
                HydraError::ConnectionError("No available nodes".to_string())
            })?;

        info!("Selected node: {}", node.address);

        // Connect to remote node via QUIC
        info!("Connecting to node {} via QUIC...", node.address);
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
        let target_str = target_addr.to_string();
        info!("Sending target address to node: {}", target_str);
        send.write_all(target_str.as_bytes()).await
            .map_err(|e| {
                error!("Failed to send target address: {}", e);
                HydraError::ProtocolError(format!("Write error: {}", e))
            })?;

        // Read response from remote node
        info!("Waiting for response from node...");
        let mut resp_buf = [0u8; 2];
        let n = recv.read(&mut resp_buf).await
            .map_err(|e| {
                error!("Failed to read response from node: {}", e);
                HydraError::ProtocolError(format!("Read error: {}", e))
            })?
            .ok_or_else(|| {
                error!("No response received from node");
                HydraError::ProtocolError("No response from node".to_string())
            })?;

        info!("Received {} bytes response from node: {:?}", n, &resp_buf[..n]);

        if n < 2 || resp_buf[0] != 0x00 {
            // Connection failed
            error!("Node returned error response: {:?}", &resp_buf[..n]);
            stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(HydraError::ConnectionError("Remote node connection failed".to_string()));
        }

        // Send success response to client
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        info!("Connected to {} via node {}", target_addr, node.address);

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
