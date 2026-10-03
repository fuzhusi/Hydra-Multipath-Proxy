use hydra_client::ProxyServer;
use hydra_protocol::Result;
use tracing::{info, error};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let listen_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

    let args: Vec<String> = std::env::args().collect();
    let nodes: Vec<SocketAddr> = args
        .iter()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    if nodes.is_empty() {
        error!("用法: hydra-client <节点地址:端口> [...多个节点用空格分隔]");
        error!("请同时设置环境变量 HYDRA_AUTH_KEY（认证密钥 hex）和 HYDRA_NODE_CERT（节点证书文件路径）");
        std::process::exit(1);
    }

    let auth_key = match hydra_client::auth_key_from_env() {
        Ok(k) => k,
        Err(e) => {
            error!("启动失败: {}", e);
            std::process::exit(1);
        }
    };
    let node_certs = match hydra_client::node_certs_from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("启动失败: {}", e);
            std::process::exit(1);
        }
    };

    info!("Starting Hydra client proxy on {}", listen_addr);
    info!("Configured nodes: {:?}", nodes);

    let proxy = ProxyServer::new(listen_addr)
        .with_nodes(nodes)
        .with_auth_key(auth_key)
        .with_node_certs(node_certs);
    proxy.start().await?;

    Ok(())
}
