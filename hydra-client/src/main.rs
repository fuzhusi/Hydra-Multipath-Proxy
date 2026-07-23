use hydra_client::ProxyServer;
use hydra_protocol::Result;
use tracing::info;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let listen_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

    // Parse nodes from command line or use default
    let nodes: Vec<SocketAddr> = if std::env::args().len() > 1 {
        std::env::args()
            .skip(1)
            .filter_map(|arg| arg.parse().ok())
            .collect()
    } else {
        vec!["43.130.251.236:8080".parse().unwrap()]
    };

    info!("Starting Hydra client proxy on {}", listen_addr);
    info!("Configured nodes: {:?}", nodes);

    let proxy = ProxyServer::new(listen_addr).with_nodes(nodes);
    proxy.start().await?;

    Ok(())
}