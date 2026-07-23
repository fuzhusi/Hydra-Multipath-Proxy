use hydra_node::{HydraServer, NodeConfig};
use hydra_protocol::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let config = NodeConfig::default();
    info!("Starting Hydra node with config: {:?}", config);
    
    let server = HydraServer::new(config.listen_addr).await?;
    server.start().await?;
    
    Ok(())
}