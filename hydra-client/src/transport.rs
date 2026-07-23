use quinn::{Endpoint, ServerConfig, ClientConfig, Connection};
use std::net::SocketAddr;
use std::sync::Arc;
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig};
use hydra_protocol::Result;
use tracing::{info, error};

pub struct Transport {
    endpoint: Endpoint,
}

impl Transport {
    pub async fn new_client() -> Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;

        // Configure crypto
        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"hydra".to_vec()];

        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));

        info!("Created new QUIC client endpoint on {}", endpoint.local_addr()?);
        Ok(Self { endpoint })
    }

    pub async fn new_server(addr: SocketAddr) -> Result<Self> {
        let server_config = Self::configure_server()?;
        let endpoint = Endpoint::server(server_config, addr)?;
        info!("Created QUIC server endpoint on {}", addr);
        Ok(Self { endpoint })
    }

    fn configure_server() -> Result<ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = Certificate(cert.serialize_der().unwrap());
        let key_der = PrivateKey(cert.serialize_private_key_der());

        let mut server_crypto = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        server_crypto.alpn_protocols = vec![b"hydra".to_vec()];

        Ok(ServerConfig::with_crypto(Arc::new(server_crypto)))
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        info!("Attempting QUIC connection to {}...", addr);
        let connecting = self.endpoint.connect(addr, "localhost")?;
        match connecting.await {
            Ok(connection) => {
                info!("QUIC connection established to {}", addr);
                Ok(connection)
            }
            Err(e) => {
                error!("QUIC connection failed to {}: {}", addr, e);
                Err(e.into())
            }
        }
    }

    pub async fn accept(&self) -> Option<Connection> {
        self.endpoint.accept().await?.await.ok()
    }

    /// Test connectivity to a node with timeout
    pub async fn test_connection(&self, addr: SocketAddr, timeout_ms: u64) -> bool {
        let connect_future = self.connect(addr);
        match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            connect_future,
        ).await {
            Ok(Ok(_connection)) => {
                info!("Test connection to {} succeeded", addr);
                true
            }
            Ok(Err(e)) => {
                error!("Test connection to {} failed: {}", addr, e);
                false
            }
            Err(_) => {
                error!("Test connection to {} timed out after {}ms", addr, timeout_ms);
                false
            }
        }
    }
}

struct SkipVerification;

impl rustls::client::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}