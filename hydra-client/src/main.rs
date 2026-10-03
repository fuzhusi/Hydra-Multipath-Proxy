use hydra_client::ProxyServer;
use hydra_protocol::Result;
use std::net::SocketAddr;
use tracing::{error, info};

fn parse_args() -> (Option<SocketAddr>, Vec<SocketAddr>) {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: Option<SocketAddr> = None;
    let mut nodes: Vec<SocketAddr> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen = args.get(i + 1).and_then(|s| s.parse().ok());
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "用法: hydra-client [--listen <监听地址:端口>] <节点地址:端口> [更多节点...]"
                );
                println!("环境变量:");
                println!("  HYDRA_AUTH_KEY   节点预共享密钥（hex，必填）");
                println!("  HYDRA_NODE_CERT  节点证书文件路径（必填）");
                println!("  HYDRA_LISTEN     本地代理监听地址（默认 127.0.0.1:1080）");
                std::process::exit(0);
            }
            other => {
                if let Ok(a) = other.parse() {
                    nodes.push(a);
                } else {
                    error!("无法解析参数 \"{}\"（应为 地址:端口 格式）", other);
                }
                i += 1;
            }
        }
    }
    (listen, nodes)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let (listen_arg, nodes) = parse_args();
    // 优先级：--listen 参数 > HYDRA_LISTEN 环境变量 > 默认 127.0.0.1:1080
    let listen_addr: SocketAddr = listen_arg
        .or_else(|| {
            std::env::var("HYDRA_LISTEN")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap());

    if nodes.is_empty() {
        error!("用法: hydra-client [--listen <监听地址:端口>] <节点地址:端口> [更多节点...]");
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

    // SNI 伪装域名可覆盖（须与节点证书 SAN 匹配；默认 hydra.node）
    let sni = std::env::var("HYDRA_SNI").ok();

    let mut proxy = ProxyServer::new(listen_addr)
        .with_nodes(nodes)
        .with_auth_key(auth_key)
        .with_node_certs(node_certs);
    if let Some(s) = sni {
        proxy = proxy.with_sni(s);
    }
    proxy.start().await?;

    Ok(())
}
