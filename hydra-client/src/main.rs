use hydra_client::ProxyServer;
use hydra_protocol::Result;
use tracing::info;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let listen_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    info!("Starting Hydra client proxy on {}", listen_addr);
    
    let proxy = ProxyServer::new(listen_addr);
    proxy.start().await?;
    
    Ok(())
}