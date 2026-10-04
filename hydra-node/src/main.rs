use hydra_node::config::{self, CliOverrides, EffectiveConfig};
use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::Result;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

struct CliArgs {
    listen: Option<SocketAddr>,
    auth_key: Option<String>,
    config: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: Option<SocketAddr> = None;
    let mut auth_key: Option<String> = None;
    let mut config: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--auth-key" => {
                auth_key = args.get(i + 1).cloned();
                i += 2;
            }
            "--config" => {
                config = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--help" | "-h" => {
                println!("用法: hydra-node [监听地址] [--auth-key <hex>] [--config <node.toml>]");
                println!("配置读取优先级: CLI 参数 > 环境变量 > 配置文件 > 默认值");
                println!("配置文件: --config 或 HYDRA_NODE_CONFIG 指定路径；未设时自动探测 ./node.toml → /etc/hydra/node.toml");
                println!("环境变量:");
                println!("  HYDRA_AUTH_KEY        预共享密钥（hex，解码后至少 16 字节；或改用下方密钥文件）");
                println!("  HYDRA_AUTH_KEY_FILE   认证密钥文件（内容为 hex，权限须 600；优先级低于 HYDRA_AUTH_KEY）");
                println!("  HYDRA_LISTEN          监听地址（默认 0.0.0.0:8080，推荐 0.0.0.0:443）");
                println!("  HYDRA_CERT_FILE       证书保存路径 (默认 hydra-node-cert.der)");
                println!("  HYDRA_KEY_FILE        私钥保存路径 (默认 hydra-node-key.der)");
                println!("  HYDRA_CERT_DOMAINS    证书 SAN，逗号分隔 (默认 hydra.node,localhost)");
                println!("  HYDRA_MAX_CONNECTIONS 最大并发连接数 (默认 1000)");
                println!("  HYDRA_MODE            传输模式 masquerade|obfs (默认 masquerade；V3.1 双模式，两端须一致)");
                println!("  HYDRA_OBFS_KEY        obfs 模式独立混淆密码（两端一致；masquerade 模式无需设置）");
                println!("  HYDRA_TCP_LISTEN      可选 TCP/TLS 传输监听 ip:port（如 0.0.0.0:443；与 QUIC UDP 并存；");
                println!("                        未设置=不监听 TCP。线缆=标准 TLS+v2 token，不支持 obfs/多流聚合）");
                println!("  HYDRA_HEALTH_ADDR     健康检查端点地址 (如 127.0.0.1:8081；未设置=关闭；GET /health)");
                println!("  HYDRA_STUN_ADDR       STUN 服务器 ip:port（如 74.125.250.129:19302；未设置=关闭；");
                println!("                        启动及每 10 分钟做 RFC5389 公网地址发现，报入 /health 的 public_addr）");
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
        auth_key,
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
        auth_key: args.auth_key,
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
        mode,
        max_connections,
        cert_file,
        key_file,
        cert_domains,
        health_addr,
        stun_addr,
        ..
    } = cfg;

    let mut opts = NodeOptions {
        max_connections,
        cert_file,
        key_file,
        cert_domains,
        mode,
        tcp_listen: None,
    };

    // Team-T：可选 TCP/TLS 监听（HYDRA_TCP_LISTEN=ip:port；未设=不监听 TCP，零改动）。
    // config.rs 不在本任务文件所有权内，env 解析在 main 层完成；非法值显式退出。
    if let Ok(v) = std::env::var("HYDRA_TCP_LISTEN") {
        match v.parse() {
            Ok(a) => opts.tcp_listen = Some(a),
            Err(e) => {
                eprintln!("错误：HYDRA_TCP_LISTEN=\"{}\" 不是合法的 ip:port（{}）", v, e);
                std::process::exit(1);
            }
        }
    }

    info!(
        "Starting Hydra node: listen={}, max_connections={}, cert={}, mode={}, stun={}",
        listen_addr,
        opts.max_connections,
        opts.cert_file.display(),
        opts.mode.as_str(),
        stun_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "off".to_string())
    );

    // mode 字符串先取出来（opts 随后 move 进 HydraServer::new）
    let mode_str = opts.mode.as_str().to_string();
    let server = HydraServer::new(listen_addr, auth_key, opts).await?;

    // STUN 公网地址发现（HYDRA_STUN_ADDR 未配置 = 功能关闭）
    let public_slot = hydra_node::new_public_addr_slot();
    if let Some(stun) = stun_addr {
        hydra_node::spawn_public_addr_refresher(stun, public_slot.clone());
    }

    // 健康检查端点（可选）：未配置 = 关闭；绑定失败显式退出
    // （显式配置了健康端点却起不来，静默吞掉会让拨测形同虚设）
    if let Some(haddr) = health_addr {
        if let Err(e) = hydra_node::HealthServer::new(haddr, mode_str, public_slot)
            .spawn()
            .await
        {
            eprintln!("错误：健康检查端点 {} 绑定失败: {}", haddr, e);
            std::process::exit(1);
        }
    }

    server.start().await?;

    Ok(())
}
