use quinn::Connection;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};
use hydra_protocol::{Packet, HydraError, Result};
use bytes::Bytes;

pub struct ConnectionHandler;

impl Default for ConnectionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHandler {
    pub fn new() -> Self {
        Self
    }

    pub async fn handle_connection(&self, connection: Connection) -> Result<()> {
        info!("Waiting for bidirectional stream from client...");
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    info!("Accepted bidirectional stream, spawning handler");
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_stream(send, recv).await {
                            error!("Stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    info!("Connection closed by client");
                    break;
                }
                Err(e) => {
                    error!("Connection error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        // Read target address from client
        let mut buf = vec![0u8; 256];
        let n = recv.read(&mut buf).await
            .map_err(|e| HydraError::ProtocolError(format!("Read error: {}", e)))?
            .ok_or_else(|| HydraError::ProtocolError("No data received".to_string()))?;

        let target_addr_str = String::from_utf8_lossy(&buf[..n]);
        info!("Received target address: {}", target_addr_str);

        // 尝试解析为 SocketAddr，如果不是则进行 DNS 解析
        let target_addr: std::net::SocketAddr = if let Ok(addr) = target_addr_str.parse() {
            addr
        } else {
            // 可能是域名:端口格式，进行 DNS 解析
            info!("Resolving DNS for: {}", target_addr_str);
            match tokio::net::lookup_host(target_addr_str.to_string()).await {
                Ok(addrs) => {
                    let addrs_vec: Vec<_> = addrs.collect();
                    // 优先使用 IPv4 地址
                    let ipv4_addr = addrs_vec.iter().find(|a| a.is_ipv4());
                    match ipv4_addr {
                        Some(a) => *a,
                        None => match addrs_vec.first() {
                            Some(a) => *a,
                            None => {
                                error!("DNS resolution failed for {}: no addresses", target_addr_str);
                                send.write_all(&[0x01, 0x00]).await
                                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                                return Err(HydraError::ConnectionError(format!("DNS resolution failed for {}", target_addr_str)));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", target_addr_str, e);
                    send.write_all(&[0x01, 0x00]).await
                        .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                    return Err(HydraError::ConnectionError(format!("DNS resolution failed for {}: {}", target_addr_str, e)));
                }
            }
        };

        info!("Connecting to target: {} (with 30s timeout)", target_addr);
        let connect_start = std::time::Instant::now();

        // Connect to target with timeout
        let target_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            TcpStream::connect(target_addr)
        ).await {
            Ok(Ok(stream)) => {
                let elapsed = connect_start.elapsed();
                info!("Connected to target: {} (took {}ms)", target_addr, elapsed.as_millis());
                // Send success response
                send.write_all(&[0x00, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                stream
            }
            Ok(Err(e)) => {
                let elapsed = connect_start.elapsed();
                error!("Failed to connect to {}: {} (took {}ms)", target_addr, e, elapsed.as_millis());
                // Send failure response
                send.write_all(&[0x01, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                return Err(HydraError::ConnectionError(format!("Failed to connect to {}: {}", target_addr, e)));
            }
            Err(_) => {
                let elapsed = connect_start.elapsed();
                error!("Timeout connecting to {} ({}ms)", target_addr, elapsed.as_millis());
                // Send failure response
                send.write_all(&[0x01, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                return Err(HydraError::ConnectionError(format!("Timeout connecting to {}", target_addr)));
            }
        };

        // Forward traffic bidirectionally
        info!("Starting bidirectional traffic forwarding for {}", target_addr);
        let (mut target_read, mut target_write) = target_stream.into_split();

        let quic_to_target = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total_bytes = 0;
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => {
                        info!("QUIC stream closed (0 bytes read)");
                        break;
                    }
                    Ok(Some(n)) => {
                        total_bytes += n;
                        if n < 100 {
                            info!("Received {} bytes from QUIC: {:?}", n, String::from_utf8_lossy(&buf[..n]));
                        } else {
                            info!("Received {} bytes from QUIC (total: {})", n, total_bytes);
                        }
                        if target_write.write_all(&buf[..n]).await.is_err() {
                            error!("Failed to write to target");
                            break;
                        }
                    }
                    Ok(None) => {
                        info!("QUIC stream ended (None)");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading from QUIC: {}", e);
                        break;
                    }
                }
            }
            info!("QUIC to target forwarding finished (total: {} bytes)", total_bytes);
        });

        let target_to_quic = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total_bytes = 0;
            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => {
                        info!("Target stream closed (0 bytes read)");
                        break;
                    }
                    Ok(n) => {
                        total_bytes += n;
                        if n < 100 {
                            info!("Received {} bytes from target: {:?}", n, String::from_utf8_lossy(&buf[..n]));
                        } else {
                            info!("Received {} bytes from target (total: {})", n, total_bytes);
                        }
                        if send.write_all(&buf[..n]).await.is_err() {
                            error!("Failed to write to QUIC");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from target: {}", e);
                        break;
                    }
                }
            }
            info!("Target to QUIC forwarding finished (total: {} bytes)", total_bytes);
        });

        // Wait for either direction to finish
        tokio::select! {
            _ = quic_to_target => {},
            _ = target_to_quic => {},
        }

        info!("Connection to {} closed", target_addr);
        Ok(())
    }
}
