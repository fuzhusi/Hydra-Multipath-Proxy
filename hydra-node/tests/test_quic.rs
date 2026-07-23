use hydra_node::HydraServer;
use hydra_protocol::Result;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_quic_server() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = HydraServer::new(addr).await?;
    let server_addr = server.endpoint.local_addr()?;
    
    // Start server in background
    tokio::spawn(async move {
        server.start().await.unwrap();
    });
    
    // Give server time to start
    sleep(Duration::from_millis(100)).await;
    
    println!("Server started on {}", server_addr);
    
    Ok(())
}