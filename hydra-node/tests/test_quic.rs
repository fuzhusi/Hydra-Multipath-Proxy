use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_quic_server() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let auth_key = b"test-auth-key-0123456789abcdef".to_vec();
    let server = HydraServer::new(addr, auth_key, NodeOptions::default()).await?;
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
