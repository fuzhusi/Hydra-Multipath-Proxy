use quinn::Connection;
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
        let data = recv.read_to_end(65536).await
            .map_err(|e| HydraError::ProtocolError(format!("Read error: {}", e)))?;
        
        let packet: Packet = serde_json::from_slice(&data)?;
        
        if !packet.verify_checksum() {
            return Err(HydraError::ProtocolError("Invalid checksum".to_string()));
        }
        
        info!("Received chunk {} for session {}", packet.chunk_id, packet.session_id);
        
        // TODO: Process chunk and forward to destination
        
        let response = Bytes::from("OK");
        send.write_all(&response).await
            .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
        
        Ok(())
    }
}