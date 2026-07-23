use hydra_client::Transport;
use hydra_protocol::{Packet, Result};
use bytes::Bytes;
use std::net::SocketAddr;

#[tokio::test]
async fn test_client_connection() -> Result<()> {
    // Start a server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = hydra_node::HydraServer::new(server_addr).await?;
    let server_addr = server.endpoint.local_addr()?;
    
    tokio::spawn(async move {
        server.start().await.unwrap();
    });
    
    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Create client
    let client = Transport::new_client().await?;
    let connection = client.connect(server_addr).await?;
    
    // Create a test packet
    let payload = Bytes::from("Hello, Hydra!");
    let packet = Packet::new(1, 1, 1, 0, payload);
    let data = serde_json::to_vec(&packet)?;
    
    // Send packet
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&data).await?;
    send.finish().await?;
    
    // Read response
    let response = recv.read_to_end(1024).await?;
    let response_str = String::from_utf8_lossy(&response);
    
    assert_eq!(response_str, "OK");
    
    Ok(())
}