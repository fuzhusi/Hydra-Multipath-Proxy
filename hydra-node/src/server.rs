use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, error};
use hydra_protocol::Result;
use crate::handler::ConnectionHandler;

pub struct HydraServer {
    pub endpoint: Endpoint,
    handler: Arc<ConnectionHandler>,
}

impl HydraServer {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let endpoint = Self::create_endpoint(addr)?;
        let handler = Arc::new(ConnectionHandler::new());
        
        Ok(Self { endpoint, handler })
    }

    fn create_endpoint(addr: SocketAddr) -> Result<Endpoint> {
        let server_config = Self::configure_server()?;
        let endpoint = Endpoint::server(server_config, addr)?;
        Ok(endpoint)
    }

    fn configure_server() -> Result<quinn::ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = rustls::Certificate(cert.serialize_der().unwrap());
        let key_der = rustls::PrivateKey(cert.serialize_private_key_der());
        
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;
        
        server_crypto.alpn_protocols = vec![b"hydra".to_vec()];
        
        Ok(quinn::ServerConfig::with_crypto(Arc::new(server_crypto)))
    }

    pub async fn start(&self) -> Result<()> {
        info!("Hydra server listening on {}", self.endpoint.local_addr()?);
        
        while let Some(conn) = self.endpoint.accept().await {
            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, handler).await {
                    error!("Connection error: {}", e);
                }
            });
        }
        
        Ok(())
    }

    async fn handle_connection(conn: quinn::Connecting, handler: Arc<ConnectionHandler>) -> Result<()> {
        let connection = conn.await?;
        let addr = connection.remote_address();
        info!("New connection from {}", addr);
        
        handler.handle_connection(connection).await?;
        
        Ok(())
    }
}