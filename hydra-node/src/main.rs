use hydra_node::config::{self, CliOverrides, EffectiveConfig};
use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::Result;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

struct CliArgs {
    listen: Option<SocketAddr>,
    config: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: Option<SocketAddr> = None;
    let mut config: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            // 审查（报告 P2）：--auth-key 已移除——密钥作为 CLI 参数会进入
            // /proc/<pid>/cmdline（同机所有用户可读）与 shell history，与
            // config.rs「CLI 不暴露密钥」的设计不变量自相矛盾。
            // 密钥一律经 HYDRA_AUTH_KEY env 或 HYDRA_AUTH_KEY_FILE 提供。
            "--auth-key" => {
                eprintln!("错误：--auth-key 已移除（密钥进 cmdline 全机可读）。请改用 HYDRA_AUTH_KEY 环境变量或 HYDRA_AUTH_KEY_FILE 密钥文件。");
                std::process::exit(1);
            }
            "--config" => {
                config = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--help" | "-h" => {
                println!("用法: hydra-node [监听地址] [--config <node.toml>]");
                println!("传输: TCP/TLS（TLS 1.3 + Noise-PSK 应用层握手；TCP 是唯一传输，推荐监听 443）");
                println!("配置读取优先级: CLI 参数 > 环境变量 > 配置文件 > 默认值");
                println!("配置文件: --config 或 HYDRA_NODE_CONFIG 指定路径；未设时自动探测 ./node.toml → /etc/hydra/node.toml");
                println!("环境变量:");
                println!("  HYDRA_AUTH_KEY        预共享密钥（hex，解码后恰好 32 字节；或改用下方密钥文件）");
                println!("  HYDRA_AUTH_KEY_FILE   认证密钥文件（内容为 hex，权限须 600；优先级低于 HYDRA_AUTH_KEY）");
                println!("  HYDRA_LISTEN          TCP/TLS 监听地址（默认 0.0.0.0:8080，推荐 0.0.0.0:443）");
                println!("  HYDRA_CERT_FILE       证书保存路径 (默认 hydra-node-cert.der)");
                println!("  HYDRA_KEY_FILE        私钥保存路径 (默认 hydra-node-key.der)");
                println!("  HYDRA_CERT_DOMAINS    证书 SAN，逗号分隔 (默认 hydra.node,localhost)");
                println!("  HYDRA_MAX_CONNECTIONS 最大并发连接数 (默认 1000)");
                println!("  HYDRA_IDLE_TIMEOUT_SECS 转发空闲超时秒数 (默认 300，双向无数据即断开)");
                println!("  HYDRA_HEALTH_ADDR     健康检查端点地址 (如 127.0.0.1:8081；未设置=关闭；GET /health)");
                println!("  HYDRA_LOG_LEVEL       日志级别 (默认 info；RUST_LOG 存在时优先)");
                println!("字段样例见 config/default.toml（每个字段注明对应 env 与默认值）");
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
    CliArgs {
        listen,
        config,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    let env: BTreeMap<String, String> = std::env::vars().collect();

    // 配置文件层（--config > HYDRA_NODE_CONFIG > ./node.toml > /etc/hydra/node.toml）；
    // 显式指定但读不到/解析失败 → 显式退出，绝不静默忽略
    let file_layer = match config::load_file_layer(args.config.as_deref(), &env) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("错误：{}", e);
            std::process::exit(1);
        }
    };
    if let Some((path, _)) = &file_layer {
        eprintln!("已加载配置文件: {}", path.display());
    }

    // 分层解析（非法值显式报错退出，不静默回落）
    let cli = CliOverrides {
        listen: args.listen,
    };
    let cfg: EffectiveConfig =
        match config::resolve(&cli, &env, file_layer.as_ref().map(|(_, c)| c)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("错误：{}", e);
                std::process::exit(1);
            }
        };

    // 认证密钥：HYDRA_AUTH_KEY > 密钥文件（0600 检查+warn；修 env 泄漏面）
    let auth_key = match config::load_auth_key(&cfg.auth_key_source) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("错误：{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = config::init_tracing(&cfg.log_level) {
        eprintln!("错误：{}", e);
        std::process::exit(1);
    }

    let EffectiveConfig {
        listen_addr,
        max_connections,
        cert_file,
        key_file,
        cert_domains,
        health_addr,
        ..
    } = cfg;

    let opts = NodeOptions {
        max_connections,
        cert_file,
        key_file,
        cert_domains,
        // P2P 信令开关：main 未走 from_env（配置从 toml/env 解析而来），此处单独读 env
        p2p_signal: NodeOptions::from_env().p2p_signal,
    };

    info!(
        "Starting Hydra node: listen={}, max_connections={}, cert={}, transport=tcp/tls",
        listen_addr,
        opts.max_connections,
        opts.cert_file.display(),
    );

    let server = HydraServer::new(listen_addr, auth_key, opts).await?;

    // 健康检查端点（可选）：未配置 = 关闭；绑定失败显式退出
    // （显式配置了健康端点却起不来，静默吞掉会让拨测形同虚设）
    if let Some(haddr) = health_addr {
        if let Err(e) = hydra_node::HealthServer::new(haddr).spawn().await {
            eprintln!("错误：健康检查端点 {} 绑定失败: {}", haddr, e);
            std::process::exit(1);
        }
    }

    server.start().await?;

    Ok(())
}
