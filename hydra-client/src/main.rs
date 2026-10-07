use hydra_client::nat::{self, PunchParams};
use hydra_client::tcp_transport::TlsTrust;
use hydra_client::ProxyServer;
use hydra_protocol::Result;
use std::net::SocketAddr;
use tracing::{error, info, warn};

/// P2P 实验参数（--p2p 出现时走演示流程）
struct P2pArgs {
    my_peer_id: String,
    peer_id: String,
    node: SocketAddr,
}

/// TUN 模式开关：`--tun` 参数或环境变量 `HYDRA_TUN=1`
fn tun_enabled(args: &[String]) -> bool {
    args.iter().any(|a| a == "--tun") || std::env::var("HYDRA_TUN").ok().as_deref() == Some("1")
}

/// TUN 模式配置：HYDRA_TUN_ADDR（形如 10.7.0.1/30）覆盖默认地址/前缀；
/// 豁免清单 = 节点 IP + 系统 DNS + HYDRA_TUN_EXCLUDE（逗号分隔）；端口列表 HYDRA_TUN_PORTS。
#[cfg(feature = "tun")]
fn tun_config_from_env(nodes: &[SocketAddr]) -> hydra_client::tun::TunConfig {
    let mut cfg = hydra_client::tun::TunConfig::default();
    if let Ok(s) = std::env::var("HYDRA_TUN_ADDR") {
        if let Some((ip, prefix)) = s.trim().split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip.parse::<std::net::Ipv4Addr>(), prefix.parse::<u8>()) {
                // 审查 06-P2-9：prefix>32 会使掩码计算下溢（debug panic / release
                // 错误接管路由）——非法时保持默认 /30 并明确告警
                if prefix <= 32 {
                    cfg.addr = ip;
                    cfg.prefix = prefix;
                } else {
                    error!(
                        "HYDRA_TUN_ADDR 前缀长度 {prefix} 非法（须 ≤32），使用默认 {}/30",
                        cfg.addr
                    );
                }
            } else {
                // 09-P3-6：设置了解析失败 → 显式告警（此前静默使用默认地址，
                // 路由豁免全部错位还无痕可查）
                error!(
                    "HYDRA_TUN_ADDR \"{s}\" 无法解析（应为形如 10.7.0.1/30），使用默认 {}/30",
                    cfg.addr
                );
            }
        } else if let Ok(ip) = s.trim().parse::<std::net::Ipv4Addr>() {
            cfg.addr = ip;
        } else {
            error!(
                "HYDRA_TUN_ADDR \"{s}\" 无法解析（应为形如 10.7.0.1/30），使用默认 {}/30",
                cfg.addr
            );
        }
    }
    // IPv6 接管开关（v1 完整版默认**开**：栈已启用 proto-ipv6，v6 TCP 走
    // 动态 AnyIP 正向代理路径）；HYDRA_TUN_IPV6=0 显式关闭（关闭时 v6 包被
    // 快速失败代答——SYN 回 RST、其余 ICMPv6 不可达，应用回落 IPv4）
    if let Ok(v) = std::env::var("HYDRA_TUN_IPV6") {
        if v.trim() == "0" {
            cfg.ipv6_enabled = false;
        }
    }
    // TUN v6 网关占位地址覆盖（形如 fd07::1；接管路由 via 指向它）
    if let Ok(s) = std::env::var("HYDRA_TUN_ADDR6") {
        if let Ok(ip) = s.trim().parse::<std::net::Ipv6Addr>() {
            cfg.addr6 = ip;
        }
    }
    // 防环路关键：节点 IP 豁免（IPv4 /32；IPv6 节点进 v6 豁免清单，/128 回物理网关 v6）
    for n in nodes {
        match n.ip() {
            std::net::IpAddr::V4(ip) => cfg.exclude_routes.push(ip),
            std::net::IpAddr::V6(ip) => cfg.exclude_routes_v6.push(ip),
        }
    }
    // 系统 DNS 豁免（best-effort；DNS 明文直出物理网卡——v1 无 DNS 劫持，如实边界）。
    // 09-P2-4：v6 DNS 同样豁免（详见 tun::detect_dns_servers_v6 文档）
    for dns in hydra_client::tun::detect_dns_servers() {
        cfg.exclude_routes.push(dns);
    }
    for dns in hydra_client::tun::detect_dns_servers_v6() {
        cfg.exclude_routes_v6.push(dns);
    }
    if let Ok(s) = std::env::var("HYDRA_TUN_EXCLUDE") {
        for ip in s
            .split(',')
            .filter_map(|p| p.trim().parse::<std::net::IpAddr>().ok())
        {
            match ip {
                std::net::IpAddr::V4(v4) => cfg.exclude_routes.push(v4),
                std::net::IpAddr::V6(v6) => cfg.exclude_routes_v6.push(v6),
            }
        }
    }
    if let Ok(s) = std::env::var("HYDRA_TUN_PORTS") {
        let mut ports = Vec::new();
        let mut bad = Vec::new();
        for p in s.split(',') {
            match p.trim().parse::<u16>() {
                Ok(port) => ports.push(port),
                Err(_) => bad.push(p.trim().to_string()),
            }
        }
        // 09-P3-6：非法端口显式告警（此前 filter_map 静默丢弃——"443,84434"
        // 只剩 443，用户以为 84434 也被拦截）
        if !bad.is_empty() {
            error!("HYDRA_TUN_PORTS 含非法端口项: {:?}（已忽略）", bad);
        }
        if !ports.is_empty() {
            cfg.listen_ports = ports;
        }
    }
    cfg
}

/// Windows 系统代理开启时 TUN 流量会二次进代理形成环路（方案 §5）：检测并告警（不自动关闭）。
/// 09-P3-3：复用 lib.rs 的共享实现（`contains("0x1")` 会把 `0x10`/`0x1f` 等
/// 误判为开启——同逻辑副本此前只在 lib.rs 修复，此处为漏改副本）。
#[cfg(all(windows, feature = "tun"))]
fn warn_system_proxy_loop() {
    if hydra_client::windows_system_proxy_enabled() {
        eprintln!(
            "⚠ 检测到 Windows 系统代理已开启：TUN 模式下经系统代理的流量会二次进入本代理形成环路，\
             建议关闭系统代理后使用 TUN 模式"
        );
    }
}

fn parse_args() -> (Option<SocketAddr>, Vec<SocketAddr>, Option<P2pArgs>) {
    let args: Vec<String> = std::env::args().collect();
    let mut listen: Option<SocketAddr> = None;
    let mut nodes: Vec<SocketAddr> = Vec::new();
    let mut p2p: Option<P2pArgs> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                match args.get(i + 1).map(|s| s.parse::<SocketAddr>()) {
                    Some(Ok(a)) => listen = Some(a),
                    // 09-P3-6：解析失败显式退出（此前静默回退默认且吞掉该参数位）
                    Some(Err(_)) => {
                        let raw = args.get(i + 1).cloned().unwrap_or_default();
                        error!("--listen 参数 \"{raw}\" 无法解析（应为 地址:端口，如 127.0.0.1:1080）");
                        std::process::exit(1);
                    }
                    None => {
                        error!("--listen 需要参数 <监听地址:端口>");
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "--tun" => {
                // TUN 透明代理开关（实际接线在 main：tun_enabled()）
                i += 1;
            }
            "--p2p" => {
                let id = args.get(i + 1).cloned().unwrap_or_default();
                let p = p2p.get_or_insert_with(|| P2pArgs {
                    my_peer_id: String::new(),
                    peer_id: String::new(),
                    node: "127.0.0.1:0".parse().unwrap(),
                });
                p.my_peer_id = id;
                i += 2;
            }
            "--peer" => {
                let id = args.get(i + 1).cloned().unwrap_or_default();
                let p = p2p.get_or_insert_with(|| P2pArgs {
                    my_peer_id: String::new(),
                    peer_id: String::new(),
                    node: "127.0.0.1:0".parse().unwrap(),
                });
                p.peer_id = id;
                i += 2;
            }
            "--node" => {
                // 审查 06-P2-7：--node 仅是 P2P 演示的节点参数——不得无条件把常规
                // 代理调用劫持进 demo 流程（仅当 --p2p/--peer 已出现时才写入）；
                // 解析失败按参数错误明确退出（不再静默回退 127.0.0.1:0）
                let Some(raw) = args.get(i + 1) else {
                    error!("--node 需要参数 <节点地址:端口>");
                    std::process::exit(1);
                };
                let Ok(n) = raw.parse::<SocketAddr>() else {
                    error!(
                        "--node 参数 \"{}\" 无法解析（应为 地址:端口，如 1.2.3.4:443）",
                        raw
                    );
                    std::process::exit(1);
                };
                match p2p.as_mut() {
                    Some(p) => p.node = n,
                    None => {
                        error!("--node 仅在 P2P 演示模式下有效：请先给出 --p2p <我的peer_id> 与 --peer <对方peer_id>；常规代理请直接用位置参数指定节点");
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "用法: hydra-client [--listen <监听地址:端口>] [--tun] <节点地址:端口> [更多节点...]"
                );
                println!("TUN 透明代理模式（免配置全局代理，仅 TCP；需管理员/root）:");
                println!(
                    "  --tun                在 SOCKS 监听之外叠加启动 TUN 虚拟网卡接管系统流量\n                       （Windows 需管理员运行且 wintun.dll 可用；Linux 需 root）"
                );
                println!(
                    "  HYDRA_TUN=1          同 --tun；HYDRA_TUN_ADDR 覆盖 TUN 地址（默认 10.7.0.1/30）\n                       HYDRA_TUN_EXCLUDE 额外豁免 IP（逗号分隔，/32 回物理网关）\n                       HYDRA_TUN_PORTS 覆盖拦截端口列表（默认 80,443,8080,8443；\n                       smoltcp 无通配监听，v1 已知限制）\n                       HYDRA_TUN_DNS/HYDRA_TUN_GW 手动指定 DNS/物理网关（默认自动探测）\n                       HYDRA_TUN_IPV6=0 关闭 IPv6 接管（默认开：v6 TCP 经动态 AnyIP\n                       代理转发，v6 非 TCP 回 ICMPv6 不可达回落 IPv4）\n                       HYDRA_TUN_GW6 手动指定物理网关 IPv6；HYDRA_TUN_IF Windows 下\n                       netsh v6 路由所需的 TUN 适配器名"
                );
                println!("P2P 打洞实验（NAT 穿透 §3.3，本轮仅验证输出，不接入代理热路径）:");
                println!(
                    "  --p2p <我的peer_id>  出现即走 P2P 演示流程（探测→信令→打洞→打印结果后退出）"
                );
                println!("  --peer <对方peer_id>  对端信令路由键");
                println!("  --node <节点地址:端口> 信令/中继节点地址");
                println!("环境变量:");
                println!("  HYDRA_AUTH_KEY    节点预共享密钥（hex，恰好 64 字符，必填）");
                println!("  HYDRA_NODE_CERT   节点证书文件路径（pin 模式必填；单节点）");
                println!("  HYDRA_NODE_CERTS  逗号分隔的多节点证书路径（pin 模式；顺序与节点参数一一对应）");
                println!("  HYDRA_TRUST       信任模式：pin（默认，自签 pinning）| ca（真证书/公共 CA，ACME 部署）");
                println!("  HYDRA_CERT_SHA256 ca 模式可选：叶证书 SHA-256 硬 pin（64 hex 字符，防 CA 误签发）");
                println!("  HYDRA_LISTEN      本地代理监听地址（默认 127.0.0.1:1080）");
                println!(
                    "  HYDRA_SNI         SNI 伪装域名（默认 hydra.node；真证书部署填你的域名）"
                );
                println!(
                    "  HYDRA_TRANSPORT  传输选择（TCP 转型后仅 TCP/TLS：TLS 1.3 + Noise-PSK；\n                   legacy 值 quic 告警回退 tcp）"
                );
                println!(
                    "  HYDRA_STUN_ADDRS  逗号分隔的 STUN 服务器（ip:port，需支持 TCP 的公共 STUN，\n                   如 stun.nextcloud.com:443）；未设置 = 公网地址发现关闭（回落中继）"
                );
                println!(
                    "  HYDRA_P2P_SIGNAL  节点侧信令开关（节点进程设 1 后 @hydra-p2p/<peer_id> 进入信令会话）"
                );
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
    (listen, nodes, p2p)
}

/// 从环境变量构建信任配置（P2P 演示与常规代理路径共用）
fn trust_from_env() -> std::result::Result<TlsTrust, String> {
    match std::env::var("HYDRA_TRUST").as_deref() {
        Ok("ca") => {
            let pin = std::env::var("HYDRA_CERT_SHA256")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            // 审查 06-P3-5（Wave 3 修复）：叶 pin 启动时做格式校验——此前畸形 pin
            // （长度/字符错）要到每条连接握手后才报误导性错误，现在启动即失败。
            if let Some(p) = &pin {
                if p.len() != 64 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(
                        "HYDRA_CERT_SHA256 格式非法：需要 64 位 hex 字符（SHA-256 摘要），\
                         当前值将无法与任何证书匹配"
                            .to_string(),
                    );
                }
            }
            if pin.is_none() {
                // 审查 06-P2-5：CA 模式无叶 pin 时，Noise confirm 只能防跨会话转发，
                // 防不了持合法证书的终结式 MITM——节点身份仅由公共 CA + 共享 PSK
                // 保密性保证；任一客户端泄露 PSK 即全体节点可被主动中间人。明示告警。
                warn!(
                    "HYDRA_TRUST=ca 且未设置 HYDRA_CERT_SHA256：无叶证书硬 pin，\
                     节点身份仅由公共 CA 与 PSK 保密性保证（PSK 泄露即可被 MITM），\
                     建议设置 HYDRA_CERT_SHA256=<节点叶证书 SHA-256>"
                );
            }
            info!(
                "TLS 信任模式：公共 CA（真证书部署）{}",
                if pin.is_some() {
                    "+ 叶证书硬 pin"
                } else {
                    ""
                }
            );
            Ok(TlsTrust::public_ca(pin))
        }
        _ => {
            let node_certs = if let Ok(paths) = std::env::var("HYDRA_NODE_CERTS") {
                hydra_client::node_certs_from_paths(&paths)?
            } else {
                hydra_client::node_certs_from_env()?
            };
            Ok(TlsTrust::pinned(node_certs))
        }
    }
}

/// P2P 打洞演示流程（--p2p 出现时）：探测 → 信令 → 打洞 → 打印结果退出。
/// 本轮仅验证输出，直连流不接入代理热路径。
async fn run_p2p_demo(p2p: P2pArgs, trust: TlsTrust, auth_key: Vec<u8>) -> Result<()> {
    if p2p.my_peer_id.is_empty() || p2p.peer_id.is_empty() {
        error!(
            "--p2p 演示需同时提供 --p2p <我的peer_id> --peer <对方peer_id> --node <节点地址:端口>"
        );
        std::process::exit(1);
    }
    let sni = std::env::var("HYDRA_SNI").unwrap_or_default();

    // 公网地址发现（未设 HYDRA_STUN_ADDRS = 功能关闭，直接回落中继）
    // 审查 06-P2-4：改用带 DNS 解析的版本，域名写法（文档主路径）不再必然失败
    let stun_addrs = match nat::stun_addrs_from_env_resolved().await {
        Ok(v) => v,
        Err(e) => {
            println!("fell back to relay (stun disabled: {e})");
            return Ok(());
        }
    };
    let disc = match nat::discover_full(&stun_addrs).await {
        Ok(d) => d,
        Err(e) => {
            println!("fell back to relay (stun discovery failed: {e})");
            return Ok(());
        }
    };
    let nat_str = match disc.nat {
        hydra_protocol::stun::NatType::Eim => "eim",
        hydra_protocol::stun::NatType::Symmetric => "symmetric",
    };
    println!(
        "discovery: mapped={} local={} nat={nat_str}",
        disc.mapped, disc.local
    );

    let params = PunchParams {
        node_addr: p2p.node,
        sni: &sni,
        trust: &trust,
        auth_key: &auth_key,
        stun_addrs: &stun_addrs,
        my_peer_id: &p2p.my_peer_id,
        peer_id: &p2p.peer_id,
    };
    match nat::punch_direct_with_discovery(&params, disc).await {
        Some(stream) => {
            // 直连流本轮仅验证：丢弃前向对端发一个标记字节确认链路存活
            let peer = stream.peer_addr().ok();
            println!("P2P direct established (peer={peer:?})");
            drop(stream);
        }
        None => {
            println!("fell back to relay (nat={nat_str})");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // 审查 R-30 收尾：启动时读取一次 HYDRA_TRANSPORT——设了 legacy `quic` 时
    // 如实告警回退 tcp（兑现 README 行为；此前该函数零调用，告警不存在）
    let _transport = hydra_client::tcp_transport::transport_from_env();

    let (listen_arg, nodes, p2p) = parse_args();

    // 09-P3-5：TUN 模式双实例互斥——两个 TUN 实例会争抢同一 TUN 网卡与 /1
    // 接管路由。守卫存到 main 作用域直至退出（进程死自动释放端口）。
    let _instance_guard = if tun_enabled(&std::env::args().collect::<Vec<String>>()) {
        match hydra_client::acquire_instance_guard(hydra_client::INSTANCE_PORT_CLI_TUN) {
            Ok(g) => Some(g),
            Err(e) => {
                error!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let auth_key = match hydra_client::auth_key_from_env() {
        Ok(k) => k,
        Err(e) => {
            error!("启动失败: {}", e);
            std::process::exit(1);
        }
    };
    let trust = match trust_from_env() {
        Ok(t) => t,
        Err(e) => {
            error!("启动失败: {}", e);
            std::process::exit(1);
        }
    };

    // --p2p 出现：走 P2P 演示流程后退出（不启动代理）
    if let Some(p2p) = p2p {
        return run_p2p_demo(p2p, trust, auth_key).await;
    }

    // 优先级：--listen 参数 > HYDRA_LISTEN 环境变量 > 默认 127.0.0.1:1080
    let listen_addr: SocketAddr = listen_arg
        .or_else(|| {
            std::env::var("HYDRA_LISTEN")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap());

    if nodes.is_empty() {
        error!(
            "用法: hydra-client [--listen <监听地址:端口>] [--tun] <节点地址:端口> [更多节点...]"
        );
        error!("请同时设置环境变量 HYDRA_AUTH_KEY（认证密钥 hex）和 HYDRA_NODE_CERT（节点证书文件路径）");
        std::process::exit(1);
    }

    info!("Starting Hydra client proxy on {}", listen_addr);
    info!("Configured nodes: {:?}", nodes);

    // SNI 伪装域名可覆盖（pin 模式须与节点证书 SAN 匹配；默认 hydra.node）
    let sni = std::env::var("HYDRA_SNI").ok();

    let mut proxy = ProxyServer::new(listen_addr)
        .with_nodes(nodes.clone())
        .with_auth_key(auth_key)
        .with_trust(trust);
    if let Some(s) = sni {
        proxy = proxy.with_sni(s);
    }

    // ── TUN 透明代理模式（与 SOCKS 监听并存；默认关闭）────────────────────────
    if tun_enabled(&std::env::args().collect::<Vec<String>>()) {
        #[cfg(feature = "tun")]
        {
            #[cfg(windows)]
            warn_system_proxy_loop();
            // TUN 通道开启器复用 open_target：调度器需先有节点（start 内部会再注册，幂等）
            proxy.register_nodes().await;
            let opener = match proxy.tun_channel_opener() {
                Ok(o) => o,
                Err(e) => {
                    error!("TUN 模式启动失败: {}", e);
                    std::process::exit(1);
                }
            };
            let tcfg = tun_config_from_env(&nodes);
            let shutdown = new_shutdown_token();
            let shutdown2 = shutdown.clone();
            info!(
                "TUN 模式启动中：addr={}/{} 豁免 {} 条 端口 {:?}",
                tcfg.addr,
                tcfg.prefix,
                tcfg.exclude_routes.len(),
                tcfg.listen_ports
            );
            // 保存 JoinHandle：停机时等待栈任务退出（RouteGuard Drop 清理路由）
            let tun_task = tokio::spawn(async move {
                if let Err(e) = hydra_client::tun::run_tun(tcfg, opener, shutdown2).await {
                    error!(
                        "TUN 模式启动失败: {}（设备创建需管理员/root；Windows 还需 wintun.dll）",
                        e
                    );
                    // 路由半接管比不接管更糟：明确退出
                    std::process::exit(1);
                }
            });
            // 停机信号：Ctrl+C 与 Windows 控制台关闭事件（点 X / 注销 / 关机）统一
            // 进入同一停机流程。此前只接 ctrl_c：CTRL_CLOSE_EVENT 等会无 unwind
            // 直接终止进程，RouteGuard 不执行 → /1 接管路由残留整机断网。
            let shutdown3 = shutdown;
            tokio::spawn(async move {
                #[cfg(windows)]
                {
                    use tokio::signal::windows::{ctrl_close, ctrl_logoff, ctrl_shutdown};
                    // 09-P3-4：注册失败不再 expect——panic 发生在 spawn 的任务内
                    // 无人收尸，此后 Ctrl+C/关机事件无任何处理器，进程被系统强杀，
                    // RouteGuard 不执行 → /1 接管路由残留整机断网。降级为 error 日志
                    // + None 流（select 对 None future 直接跳过该分支）。
                    let close = ctrl_close();
                    let shutdown_ev = ctrl_shutdown();
                    let logoff = ctrl_logoff();
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = async {
                            match close {
                                Ok(mut s) => { let _ = s.recv().await; }
                                Err(e) => error!("注册 ctrl_close 监听失败（降级忽略）: {e}"),
                            }
                        } => {}
                        _ = async {
                            match shutdown_ev {
                                Ok(mut s) => { let _ = s.recv().await; }
                                Err(e) => error!("注册 ctrl_shutdown 监听失败（降级忽略）: {e}"),
                            }
                        } => {}
                        _ = async {
                            match logoff {
                                Ok(mut s) => { let _ = s.recv().await; }
                                Err(e) => error!("注册 ctrl_logoff 监听失败（降级忽略）: {e}"),
                            }
                        } => {}
                    }
                }
                #[cfg(not(windows))]
                {
                    if tokio::signal::ctrl_c().await.is_err() {
                        return;
                    }
                }
                info!("收到停机信号，停止 TUN 模式并清理路由…");
                shutdown3.cancel();
                // 等栈任务真正退出（RouteGuard 已在任务展开时 Drop 清理路由），
                // 再 process::exit——此前固定 300ms 就 exit，会跳过仍在阻塞的
                // 栈任务的 Drop，路由全部残留
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tun_task).await;
                std::process::exit(0);
            });
        }
        #[cfg(not(feature = "tun"))]
        {
            error!("本构建未编译 TUN 支持（--no-default-features 关闭了 tun feature）");
            std::process::exit(1);
        }
    }

    proxy.start().await?;

    Ok(())
}

/// CancellationToken 组装点（仅 tun feature 需要 tokio-util）
#[cfg(feature = "tun")]
fn new_shutdown_token() -> tokio_util::sync::CancellationToken {
    tokio_util::sync::CancellationToken::new()
}
