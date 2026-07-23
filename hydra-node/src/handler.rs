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
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_stream(send, recv).await {
                            error!("Stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    info!("Connection closed");
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
        let target_addr: std::net::SocketAddr = target_addr_str.parse()
            .map_err(|_| HydraError::ProtocolError(format!("Invalid target address: {}", target_addr_str)))?;

        info!("Connecting to target: {}", target_addr);

        // Connect to target
        let mut target_stream = match TcpStream::connect(target_addr).await {
            Ok(stream) => {
                // Send success response
                send.write_all(&[0x00, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                stream
            }
            Err(e) => {
                error!("Failed to connect to {}: {}", target_addr, e);
                // Send failure response
                send.write_all(&[0x01, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                return Err(HydraError::ConnectionError(format!("Failed to connect to {}: {}", target_addr, e)));
            }
        };

        info!("Connected to target: {}", target_addr);

        // Forward traffic bidirectionally
        let (mut target_read, mut target_write) = target_stream.into_split();

        let quic_to_target = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => {
                        if target_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        let target_to_quic = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match target_read.read(&mut buf).await {
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

        // Wait for either direction to finish
        tokio::select! {
            _ = quic_to_target => {},
            _ = target_to_quic => {},
        }

        info!("Connection to {} closed", target_addr);
        Ok(())
    }
}
