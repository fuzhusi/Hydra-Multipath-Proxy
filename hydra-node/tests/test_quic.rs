use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_quic_server() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let auth_key = b"test-auth-key-0123456789abcdef".to_vec();
    // 证书写入临时目录，避免污染源码树
    let dir = std::env::temp_dir().join(format!("hydra-test-quic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = NodeOptions {
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        ..NodeOptions::default()
    };
    let server = HydraServer::new(addr, auth_key, opts).await?;
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
