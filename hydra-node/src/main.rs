use std::net::SocketAddr;
use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::Result;
use tracing::info;

fn parse_args() -> (Option<SocketAddr>, Option<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: Option<SocketAddr> = None;
    let mut auth_key: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--auth-key" => {
                auth_key = args.get(i + 1).cloned();
                i += 2;
            }
            "--help" | "-h" => {
                println!("用法: hydra-node [监听地址] [--auth-key <hex>]");
                println!("环境变量:");
                println!("  HYDRA_AUTH_KEY        预共享密钥（hex，解码后至少 16 字节，必填）");
                println!("  HYDRA_LISTEN          监听地址（默认 0.0.0.0:8080，推荐 0.0.0.0:443）");
                println!("  HYDRA_CERT_FILE       证书保存路径 (默认 hydra-node-cert.der)");
                println!("  HYDRA_KEY_FILE        私钥保存路径 (默认 hydra-node-key.der)");
                println!("  HYDRA_CERT_DOMAINS    证书 SAN，逗号分隔 (默认 hydra.node,localhost)");
                println!("  HYDRA_MAX_CONNECTIONS 最大并发连接数 (默认 1000)");
                std::process::exit(0);
            }
            other => {
                if listen.is_none() {
                    if let Ok(a) = other.parse() {
                        listen = Some(a);
                    }
                }
                i += 1;
            }
        }
    }
    (listen, auth_key)
}

fn resolve_auth_key(cli: Option<String>) -> Vec<u8> {
    let hex_str = match cli.or_else(|| std::env::var("HYDRA_AUTH_KEY").ok()) {
        Some(h) => h,
        None => {
            eprintln!("错误：未设置认证密钥。没有认证的节点是公网开放代理，会被扫描者滥用。");
            eprintln!("请设置环境变量 HYDRA_AUTH_KEY（hex 编码，解码后至少 16 字节），或使用 --auth-key 参数。");
            eprintln!("生成示例: openssl rand -hex 32");
            std::process::exit(1);
        }
    };
    match hydra_protocol::hex_decode(&hex_str) {
        Ok(key) if key.len() >= 16 => key,
        Ok(_) => {
            eprintln!("错误：认证密钥太短（解码后至少 16 字节）。");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("错误：认证密钥不是合法的 hex：{}", e);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let (listen_arg, auth_key_arg) = parse_args();
    // 优先级：命令行参数 > HYDRA_LISTEN 环境变量 > 默认 0.0.0.0:8080
    let listen_addr = listen_arg
        .or_else(|| {
            std::env::var("HYDRA_LISTEN")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());
    let auth_key = resolve_auth_key(auth_key_arg);
    let opts = NodeOptions::from_env();

    info!(
        "Starting Hydra node: listen={}, max_connections={}, cert={}",
        listen_addr,
        opts.max_connections,
        opts.cert_file.display()
    );

    let server = HydraServer::new(listen_addr, auth_key, opts).await?;
    server.start().await?;

    Ok(())
}
