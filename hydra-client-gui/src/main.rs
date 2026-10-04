use eframe::egui;
use hydra_client::{
    format_bytes, format_duration, format_speed, generate_share_links, parse_share_links,
    ProxyServer, Scheduler, TrafficMonitor, Transport,
};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
use config::GuiConfig;

#[derive(Clone, Debug)]
struct NodeStatusInfo {
    addr: String,
    connected: bool,
    last_check: Option<std::time::Instant>,
    latency_ms: Option<u64>,
}

struct HydraApp {
    // 应用状态
    proxy_running: bool,
    nodes: Vec<NodeInfo>,
    logs: Vec<String>,
    /// 持久化配置（配置文件 > 环境变量，见 config.rs）
    config: GuiConfig,
    /// 最近一次成功落盘的配置快照（用于差分 + 防抖保存）
    saved_snapshot: GuiConfig,
    last_config_save: Option<std::time::Instant>,

    // 输入状态
    new_node_input: String,

    // 分享链接相关
    share_link_text: String,
    show_share_link_dialog: bool,

    // 密钥明文显示开关（默认掩码显示）
    show_auth_key: bool,
    show_obfs_key: bool,

    // 运行时状态
    scheduler: Option<Arc<Scheduler>>,
    transport: Option<Arc<Transport>>,
    stop_flag: Option<Arc<AtomicBool>>,
    proxy_thread_handle: Option<std::thread::JoinHandle<()>>,
    proxy_exit_receiver: Option<std::sync::mpsc::Receiver<()>>,

    // 节点连接状态
    node_status: HashMap<String, NodeStatusInfo>,
    last_health_check: Option<std::time::Instant>,
    health_check_receiver:
        Option<std::sync::mpsc::Receiver<(String, std::result::Result<u64, String>)>>,
    /// 单节点手动测试（A5：后台线程+通道，UI 线程零阻塞）
    node_test_receiver:
        Option<std::sync::mpsc::Receiver<(String, std::result::Result<u64, String>)>>,

    // 流量统计
    traffic_monitor: Option<Arc<TrafficMonitor>>,
    last_traffic_update: Option<std::time::Instant>,
}

impl Default for HydraApp {
    fn default() -> Self {
        Self {
            proxy_running: false,
            nodes: Vec::new(),
            logs: Vec::new(),
            config: GuiConfig::default(),
            saved_snapshot: GuiConfig::default(),
            last_config_save: None,
            new_node_input: String::new(),
            share_link_text: String::new(),
            show_share_link_dialog: false,
            show_auth_key: false,
            show_obfs_key: false,
            scheduler: None,
            transport: None,
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status: HashMap::new(),
            last_health_check: None,
            health_check_receiver: None,
            node_test_receiver: None,
            traffic_monitor: None,
            last_traffic_update: None,
        }
    }
}

impl Drop for HydraApp {
    fn drop(&mut self) {
        // 应用退出时清除系统代理
        if self.proxy_running {
            Self::remove_system_proxy_static();
        }
    }
}

impl HydraApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // 设置自定义字体
        setup_custom_fonts(&cc.egui_ctx);

        // ── 启动时加载持久化配置（配置文件 > 环境变量，见 config.rs）──
        let mut startup_warning: Option<String> = None;
        let (mut cfg, from_file) = match config::config_path() {
            Some(path) => match config::load_from_file(&path) {
                Ok(Some(cfg)) => (cfg, true),
                Ok(None) => (GuiConfig::default(), false),
                Err(e) => {
                    // 文件损坏不静默：显式告警并降级为默认值/环境变量（不覆盖写坏文件）
                    startup_warning = Some(format!("⚠️ {}", e));
                    (GuiConfig::default(), false)
                }
            },
            None => {
                startup_warning = Some(
                    "⚠️ 无法定位配置目录（缺少 APPDATA/HOME），本次配置仅保存在内存".to_string(),
                );
                (GuiConfig::default(), false)
            }
        };

        // 缺省监听地址兜底（配置与 env 均未给出时的 UI 初始值）
        if cfg.proxy_listen_addr.trim().is_empty() {
            cfg.proxy_listen_addr = "127.0.0.1:1080".to_string();
        }

        // C2 双模式/obfs 密码/探测间隔：配置非空 → 覆盖 env（hydra-client 内部从 env 读取）。
        // 必须在任何工作线程 spawn 之前执行，避免 env 并发读写。
        config::apply_env_overrides(&cfg);

        // 节点状态表初始化
        let mut node_status = HashMap::new();
        for addr in &cfg.node_addrs {
            node_status.insert(
                addr.clone(),
                NodeStatusInfo {
                    addr: addr.clone(),
                    connected: false,
                    last_check: None,
                    latency_ms: None,
                },
            );
        }

        let mut app = Self {
            proxy_running: false,
            nodes: Vec::new(),
            logs: Vec::new(),
            saved_snapshot: cfg.clone(),
            last_config_save: None,
            config: cfg,
            new_node_input: String::new(),
            share_link_text: String::new(),
            show_share_link_dialog: false,
            show_auth_key: false,
            show_obfs_key: false,
            scheduler: None,
            transport: None,
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status,
            last_health_check: None,
            health_check_receiver: None,
            node_test_receiver: None,
            traffic_monitor: None,
            last_traffic_update: None,
        };

        // ── 首启向导（轻量版）：无配置文件且关键字段为空 → 日志区中文引导 ──
        let key_missing = app.config.auth_key.trim().is_empty();
        let cert_missing = app.config.cert_path.trim().is_empty();
        if !from_file {
            if key_missing || cert_missing || app.config.node_addrs.is_empty() {
                for line in Self::wizard_lines() {
                    app.add_log(line);
                }
            }
        } else if key_missing || cert_missing {
            app.add_log(
                "配置已加载，但认证密钥或节点证书路径尚未填写，请在左侧「安全与传输设置」中补全"
                    .to_string(),
            );
        } else {
            app.add_log("配置已从文件加载（配置文件优先于环境变量）".to_string());
        }
        if let Some(warning) = startup_warning {
            app.add_log(warning);
        }
        app
    }

    /// 首启向导引导文案
    fn wizard_lines() -> Vec<String> {
        let cfg_path = config::config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(配置目录不可用)".to_string());
        vec![
            "═══ 首次使用向导 ═══".to_string(),
            "① 填写认证密钥：左侧「安全与传输设置」→ 认证密钥 → 点「编辑/显示」输入 hex 密钥"
                .to_string(),
            "② 选择节点证书文件：同区「节点证书」→ 点「浏览...」选择节点生成的 hydra-node-cert.der"
                .to_string(),
            "③ 添加节点：左上「节点地址」输入 host:port 后点「添加」".to_string(),
            "④ 点「启动代理」即可使用".to_string(),
            format!(
                "完成一次后配置自动保存到 {}，以后双击本程序即可直接使用",
                cfg_path
            ),
        ]
    }

    /// 差分 + 防抖保存：配置与上次落盘快照不同才写；force=true（启停/退出）跳过防抖立即写。
    fn maybe_save_config(&mut self, force: bool) {
        if self.config == self.saved_snapshot {
            return;
        }
        if !force
            && self
                .last_config_save
                .map(|t| t.elapsed() < std::time::Duration::from_millis(1000))
                .unwrap_or(false)
        {
            return; // 防抖：1 秒内不重复写盘
        }
        let Some(path) = config::config_path() else {
            return; // 无法定位配置目录（new 时已提示过），保持内存态
        };
        match config::save_to_file(&path, &self.config) {
            Ok(()) => {
                self.saved_snapshot = self.config.clone();
                self.last_config_save = Some(std::time::Instant::now());
            }
            Err(e) => self.add_log(format!("⚠️ 配置保存失败: {}", e)),
        }
    }

    /// Test connectivity to a single node（A5：失败根因以 Err 透出，不再吞掉）
    /// Exec-1：证书由调用方先按「配置文件 > 环境变量」解析后传入（config.rs resolve_node_certs）
    async fn test_node_connection(
        addr_str: &str,
        node_certs: Vec<Vec<u8>>,
    ) -> std::result::Result<u64, String> {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("地址解析失败: {}", e))?;

        let transport = Transport::new_client(node_certs, hydra_client::DEFAULT_SNI)
            .await
            .map_err(|e| format!("创建 QUIC 传输失败: {}", e))?;

        let start = std::time::Instant::now();
        if transport.test_connection(addr, 3000).await {
            Ok(start.elapsed().as_millis() as u64)
        } else {
            Err(format!("QUIC 连接失败或超时（3s）: {}", addr))
        }
    }

    /// 发起单节点手动测试：后台线程 + 通道，结果在 update 循环中非阻塞收集
    fn start_node_test(&mut self, addr: String) {
        if self.node_test_receiver.is_some() {
            self.add_log("已有节点测试正在进行，请稍候".to_string());
            return;
        }
        // 证书按「配置文件 > 环境变量」解析；失败根因直接进日志（A5 行为保持）
        let certs = match config::resolve_node_certs(&self.config) {
            Ok(c) => c,
            Err(e) => {
                self.add_log(format!("节点 {} 测试失败: {}", addr, e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.add_log(format!("开始测试节点 {}...", addr));
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send((addr, Err(format!("创建 tokio 运行时失败: {}", e))));
                    return;
                }
            };
            let result = rt.block_on(HydraApp::test_node_connection(&addr, certs));
            let _ = tx.send((addr, result));
        });
        self.node_test_receiver = Some(rx);
    }

    /// 在 update 循环中非阻塞地收取单节点测试结果
    fn poll_node_test_results(&mut self) {
        let mut finished = None;
        if let Some(rx) = &self.node_test_receiver {
            match rx.try_recv() {
                Ok(result) => finished = Some(result),
                // 线程 panic 等原因导致 sender 被弃：清空 receiver，允许再次发起测试
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.node_test_receiver = None;
                    self.add_log("节点测试线程异常退出，已重置".to_string());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((addr, result)) = finished {
            self.node_test_receiver = None;
            let now = std::time::Instant::now();
            match result {
                Ok(latency) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            addr: addr.clone(),
                            connected: true,
                            last_check: Some(now),
                            latency_ms: Some(latency),
                        },
                    );
                    self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                }
                Err(reason) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            addr: addr.clone(),
                            connected: false,
                            last_check: Some(now),
                            latency_ms: None,
                        },
                    );
                    self.add_log(format!("节点 {} 测试失败: {}", addr, reason));
                }
            }
        }
    }

    /// Test all nodes and update status (non-blocking)
    fn test_all_nodes(&mut self) {
        let node_addrs = self.config.node_addrs.clone();
        // 证书按「配置文件 > 环境变量」解析一次；失败根因直接进日志
        let certs = match config::resolve_node_certs(&self.config) {
            Ok(c) => c,
            Err(e) => {
                self.add_log(format!("全部节点测试失败: {}", e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();

        // 在后台线程中测试所有节点
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // 并发测试所有节点
                let mut handles = Vec::new();
                for addr in &node_addrs {
                    let addr = addr.clone();
                    let certs = certs.clone();
                    let tx = tx.clone();
                    handles.push(tokio::spawn(async move {
                        let result = Self::test_node_connection(&addr, certs).await;
                        let _ = tx.send((addr, result));
                    }));
                }
                // 等待所有测试完成
                for handle in handles {
                    let _ = handle.await;
                }
            });
        });

        // 存储 receiver 以便在 update 循环中非阻塞地收集结果
        self.health_check_receiver = Some(rx);
        self.last_health_check = Some(std::time::Instant::now());
    }

    /// 在 update 循环中非阻塞地处理健康检查结果
    fn poll_health_check_results(&mut self) {
        // 先收集所有结果到临时列表，避免借用冲突
        let mut results = Vec::new();
        let mut should_clear = false;

        if let Some(rx) = &self.health_check_receiver {
            // 非阻塞地接收所有可用结果。
            // 必须区分 Empty 与 Disconnected：Empty = 结果尚未产生，保留 receiver 下帧再收；
            // Disconnected = 发送端已关闭且队列排空，本批即最终结果，才允许清除 receiver。
            // （此前首次 poll 时 Empty 也置 should_clear，导致 3s 后才到达的结果全部丢失）
            loop {
                match rx.try_recv() {
                    Ok((addr, result)) => results.push((addr, result)),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        should_clear = true;
                        break;
                    }
                }
            }
        }

        // 处理收集到的结果
        for (addr, result) in results {
            let now = std::time::Instant::now();
            match result {
                Ok(latency) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            addr: addr.clone(),
                            connected: true,
                            last_check: Some(now),
                            latency_ms: Some(latency),
                        },
                    );
                    self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                }
                Err(reason) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            addr: addr.clone(),
                            connected: false,
                            last_check: Some(now),
                            latency_ms: None,
                        },
                    );
                    // A5：把失败根因（含证书错误）完整显示
                    self.add_log(format!("节点 {} 测试失败: {}", addr, reason));
                }
            }
        }

        // 清除 receiver
        if should_clear {
            self.health_check_receiver = None;
        }
    }

    fn add_log(&mut self, message: String) {
        self.logs.push(format!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            message
        ));
        // 保持日志数量在合理范围
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    fn start_proxy(&mut self) {
        if self.proxy_running {
            self.add_log("代理已经在运行".to_string());
            return;
        }

        // Exec-1：模式/obfs 密码/探测间隔——配置非空 → 覆盖 env（hydra-client 内部从 env 读取）。
        // 此前已有线程在跑时本函数会被 proxy_running 拦截，故此处写 env 不会与之并发。
        config::apply_env_overrides(&self.config);

        let proxy_addr: SocketAddr = match self.config.proxy_listen_addr.trim().parse() {
            Ok(addr) => addr,
            Err(e) => {
                self.add_log(format!("地址解析错误: {}", e));
                return;
            }
        };

        // ── 认证密钥与节点证书：先读配置文件，缺项再回落环境变量（config.rs）──
        // 在 GUI 线程解析完成后再移交代理线程；失败根因直接进日志。
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };
        let node_certs = match config::resolve_node_certs(&self.config) {
            Ok(c) => c,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };

        // 先测试所有节点连接
        self.add_log("正在测试节点连接...".to_string());
        self.test_all_nodes();

        // 检查是否有可用节点
        let online_count = self.node_status.values().filter(|s| s.connected).count();
        if online_count == 0 {
            self.add_log("警告: 没有可用的节点连接，代理可能无法正常工作".to_string());
        } else {
            self.add_log(format!("有 {} 个节点可用", online_count));
        }

        // 解析节点地址。
        // P1-14 修复：首启时健康检查尚未返回、node_status 全是初始"未连接"值，
        // 据此过滤节点会导致首次启动必然"没有可用节点"而取消。
        // 现不再按可能过期的健康状态拦截，仅过滤非法地址；不可达节点
        // 由代理自身的故障切换与调度器 Offline 标记处理。
        let mut nodes = Vec::new();
        let node_addrs = self.config.node_addrs.clone();
        for node_addr in &node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                let state = match self.node_status.get(node_addr.as_str()) {
                    Some(st) if st.connected => "已验证",
                    Some(st) if st.last_check.is_some() => "上次检测不可达，仍尝试",
                    _ => "未验证",
                };
                nodes.push(addr);
                self.add_log(format!("添加节点: {} ({})", addr, state));
            } else {
                self.add_log(format!("跳过无效节点地址: {}", node_addr));
            }
        }

        if nodes.is_empty() {
            self.add_log("错误: 没有有效的节点地址，代理启动取消".to_string());
            return;
        }

        // 创建流量统计器
        let traffic_monitor = Arc::new(TrafficMonitor::new());
        self.traffic_monitor = Some(traffic_monitor.clone());

        // 使用独立线程运行代理
        let (tx, rx) = std::sync::mpsc::channel::<std::result::Result<(), std::io::Error>>();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let proxy_addr_clone = proxy_addr;
        let nodes_clone = nodes.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();
        let traffic_monitor_clone = traffic_monitor.clone();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                // 认证密钥/证书已由 GUI 线程按「配置文件 > 环境变量」解析完毕（见上）
                let proxy = ProxyServer::new(proxy_addr_clone)
                    .with_nodes(nodes_clone)
                    .with_traffic_monitor(traffic_monitor_clone)
                    .with_auth_key(auth_key)
                    .with_node_certs(node_certs);
                // 先绑定端口
                match tokio::net::TcpListener::bind(proxy_addr_clone).await {
                    Ok(listener) => {
                        // 端口绑定成功，发送信号
                        let _ = tx.send(Ok(()));
                        // 关闭测试 listener
                        drop(listener);
                        // 启动代理
                        println!("[Proxy Thread] Starting proxy server...");
                        tokio::select! {
                            result = proxy.start() => {
                                match result {
                                    Ok(()) => {
                                        println!("[Proxy Thread] Proxy server exited normally");
                                    }
                                    Err(e) => {
                                        eprintln!("[Proxy Thread] Proxy server error: {}", e);
                                    }
                                }
                            }
                            _ = async {
                                while !stop_flag_clone.load(Ordering::Relaxed) {
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                }
                            } => {
                                println!("[Proxy Thread] Received stop signal");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Proxy Thread] Failed to bind port: {}", e);
                        let _ = tx.send(Err(e));
                    }
                }
            });
            println!("[Proxy Thread] Thread exiting...");
            // 代理线程退出时发送通知
            let _ = exit_tx.send(());
        });

        self.stop_flag = Some(stop_flag);
        self.proxy_thread_handle = Some(handle);
        self.proxy_exit_receiver = Some(exit_rx);

        // 等待代理启动
        match rx.recv() {
            Ok(Ok(())) => {
                // 等待端口绑定完成
                std::thread::sleep(std::time::Duration::from_millis(200));
                self.proxy_running = true;
                self.add_log(format!("代理已启动，监听地址: {}", proxy_addr));
                // 关键动作立即落盘（监听地址/节点等可能的变更）
                self.maybe_save_config(true);

                // 设置系统全局代理
                let proxy_url = format!("socks5://{}", proxy_addr);
                self.set_system_proxy(&proxy_url);
                self.add_log("已设置系统全局代理".to_string());
            }
            Ok(Err(e)) => {
                self.add_log(format!("代理启动失败: {}", e));
            }
            Err(e) => {
                self.add_log(format!("代理启动错误: {}", e));
            }
        }
    }

    fn set_system_proxy(&mut self, proxy_url: &str) {
        // 设置环境变量
        std::env::set_var("http_proxy", proxy_url);
        std::env::set_var("https_proxy", proxy_url);
        std::env::set_var("all_proxy", proxy_url);
        std::env::set_var("HTTP_PROXY", proxy_url);
        std::env::set_var("HTTPS_PROXY", proxy_url);
        std::env::set_var("ALL_PROXY", proxy_url);

        // 解析代理地址和端口
        let parts: Vec<&str> = proxy_url.split("://").collect();
        let addr_port = if parts.len() > 1 { parts[1] } else { parts[0] };
        let addr_parts: Vec<&str> = addr_port.split(':').collect();
        let proxy_host = addr_parts.get(0).unwrap_or(&"127.0.0.1");
        let proxy_port = addr_parts.get(1).unwrap_or(&"1080");

        // A1：Windows 注册表真实实现（HKCU Internet Settings + WinINet 刷新）
        #[cfg(windows)]
        {
            match windows_proxy::enable(addr_port) {
                Ok(()) => {}
                Err(e) => self.add_log(format!("设置 Windows 系统代理失败: {}", e)),
            }
        }

        // Linux 桌面代理（gsettings / KDE），Windows 下不执行
        #[cfg(unix)]
        {
            // 设置 GNOME 桌面代理（参考 v2rayN 实现）
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .output();

            // 设置所有协议的代理（http, https, ftp, socks）
            for protocol in &["http", "https", "ftp", "socks"] {
                let _ = std::process::Command::new("gsettings")
                    .args([
                        "set",
                        &format!("org.gnome.system.proxy.{}", protocol),
                        "host",
                        proxy_host,
                    ])
                    .output();
                let _ = std::process::Command::new("gsettings")
                    .args([
                        "set",
                        &format!("org.gnome.system.proxy.{}", protocol),
                        "port",
                        proxy_port,
                    ])
                    .output();
            }

            // 设置忽略的主机（本地地址不走代理）
            let _ = std::process::Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
                ])
                .output();

            // 检测并设置 KDE 代理（如果在 KDE 环境下）
            if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
                if desktop.contains("KDE") || desktop.contains("plasma") {
                    let kwriteconfig =
                        if std::env::var("KDE_SESSION_VERSION").unwrap_or_default() == "6" {
                            "kwriteconfig6"
                        } else {
                            "kwriteconfig5"
                        };
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "ProxyType",
                            "1",
                        ])
                        .output();
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "socksProxy",
                            &format!("socks://{}:{}", proxy_host, proxy_port),
                        ])
                        .output();
                    // 通知 KDE 重新加载配置
                    let _ = std::process::Command::new("dbus-send")
                        .args([
                            "--type=signal",
                            "/KIO/Scheduler",
                            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                            "string:",
                        ])
                        .output();
                }
            }
        }

        let _ = (proxy_host, proxy_port);
    }

    fn remove_system_proxy_static() {
        // 清除环境变量
        std::env::remove_var("http_proxy");
        std::env::remove_var("https_proxy");
        std::env::remove_var("all_proxy");
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("ALL_PROXY");

        // A1：Windows 恢复旧值（stop/panic/Drop 三条清理路径都经此静态函数）
        #[cfg(windows)]
        windows_proxy::disable();

        // Linux 桌面代理清理，Windows 下不执行
        #[cfg(unix)]
        {
            // 清除 GNOME 桌面代理
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .output();

            // 清除 KDE 代理
            if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
                if desktop.contains("KDE") || desktop.contains("plasma") {
                    let kwriteconfig =
                        if std::env::var("KDE_SESSION_VERSION").unwrap_or_default() == "6" {
                            "kwriteconfig6"
                        } else {
                            "kwriteconfig5"
                        };
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "ProxyType",
                            "0",
                        ])
                        .output();
                    let _ = std::process::Command::new("dbus-send")
                        .args([
                            "--type=signal",
                            "/KIO/Scheduler",
                            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                            "string:",
                        ])
                        .output();
                }
            }
        }
    }

    fn remove_system_proxy(&self) {
        Self::remove_system_proxy_static();
    }

    fn stop_proxy(&mut self) {
        if let Some(stop_flag) = &self.stop_flag {
            stop_flag.store(true, Ordering::Relaxed);
        }

        // 等待代理线程退出
        if let Some(handle) = self.proxy_thread_handle.take() {
            let _ = handle.join();
        }

        self.proxy_running = false;
        self.stop_flag = None;
        self.proxy_thread_handle = None;
        self.proxy_exit_receiver = None;

        // 移除系统全局代理
        self.remove_system_proxy();
        self.add_log("代理已停止，已移除系统代理".to_string());
        // 关键动作立即落盘
        self.maybe_save_config(true);
    }

    fn export_share_links(&mut self) {
        // 将当前节点配置转换为NodeInfo列表
        let mut nodes = Vec::new();
        for node_addr in &self.config.node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                let node_info = NodeInfo {
                    address: addr,
                    bandwidth: 100.0,
                    latency: 10.0,
                    loss_rate: 0.01,
                    load: 0.5,
                    status: NodeStatus::Online,
                };
                nodes.push(node_info);
            }
        }

        // 生成分享链接
        let share_links = generate_share_links(&nodes);
        self.share_link_text = share_links;
        self.show_share_link_dialog = true;
        self.add_log("已生成分享链接".to_string());
    }

    fn import_share_links(&mut self) {
        let links = parse_share_links(&self.share_link_text);
        match links {
            Ok(links) => {
                let mut imported_count = 0;
                for link in links {
                    let addr_str = format!("{}:{}", link.address, link.port);
                    if !self.config.node_addrs.contains(&addr_str) {
                        self.config.node_addrs.push(addr_str);
                        imported_count += 1;
                    }
                }
                self.add_log(format!("导入了 {} 个节点", imported_count));
                self.show_share_link_dialog = false;
            }
            Err(e) => {
                self.add_log(format!("导入失败: {}", e));
            }
        }
    }
}

impl eframe::App for HydraApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // 窗口关闭时停止代理并清除系统代理
        if self.proxy_running {
            self.stop_proxy();
        }
        // Exec-1：退出前强制落盘（兜底防抖窗口内尚未写盘的变更）
        self.maybe_save_config(true);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 检查代理线程是否异常退出
        if self.proxy_running {
            if let Some(receiver) = &self.proxy_exit_receiver {
                match receiver.try_recv() {
                    Ok(_) => {
                        // 代理线程退出了（非正常退出，因为没有通过 stop_proxy）
                        self.proxy_running = false;
                        self.stop_flag = None;
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;

                        // 自动清除系统代理
                        Self::remove_system_proxy_static();
                        self.add_log("⚠️ 代理异常退出，已自动清除系统代理设置".to_string());
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // 代理还在运行
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // 通道断开，代理线程已退出
                        self.proxy_running = false;
                        self.stop_flag = None;
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;

                        // 自动清除系统代理
                        Self::remove_system_proxy_static();
                        self.add_log("⚠️ 代理线程异常断开，已自动清除系统代理设置".to_string());
                    }
                }
            }
        }

        // 定期健康检查（每30秒）
        if self.proxy_running {
            let should_check = match self.last_health_check {
                Some(last) => last.elapsed().as_secs() >= 30,
                None => true,
            };
            if should_check && self.health_check_receiver.is_none() {
                self.test_all_nodes();
            }
        }

        // 非阻塞地处理健康检查结果
        self.poll_health_check_results();
        // 非阻塞地处理单节点手动测试结果（A5）
        self.poll_node_test_results();

        // 分享链接对话框
        if self.show_share_link_dialog {
            egui::Window::new("分享链接")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label("分享链接内容:");
                    ui.text_edit_multiline(&mut self.share_link_text);

                    ui.horizontal(|ui| {
                        if ui.button("导入").clicked() {
                            self.import_share_links();
                        }
                        if ui.button("关闭").clicked() {
                            self.show_share_link_dialog = false;
                        }
                    });
                });
        }

        // 顶部面板
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("文件", |ui| {
                    if ui.button("退出").clicked() {
                        // 退出前停止代理并清除系统代理
                        if self.proxy_running {
                            self.stop_proxy();
                        }
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("帮助", |ui| {
                    if ui.button("关于").clicked() {
                        // 显示关于对话框
                    }
                });
            });
        });

        // 左侧面板 - 节点管理
        egui::SidePanel::left("side_panel").show(ctx, |ui| {
            ui.heading("节点管理");
            ui.separator();

            // 添加节点
            ui.horizontal(|ui| {
                ui.label("节点地址:");
                ui.text_edit_singleline(&mut self.new_node_input);
                if ui.button("添加").clicked() {
                    if !self.new_node_input.is_empty() {
                        let new_node = self.new_node_input.clone();
                        // 初始化节点状态
                        self.node_status.insert(
                            new_node.clone(),
                            NodeStatusInfo {
                                addr: new_node.clone(),
                                connected: false,
                                last_check: None,
                                latency_ms: None,
                            },
                        );
                        self.config.node_addrs.push(new_node.clone());
                        self.add_log(format!("添加节点配置: {}", new_node));
                        self.new_node_input.clear();
                    }
                }
            });

            // 测试所有节点按钮
            if ui.button("测试所有节点").clicked() {
                self.test_all_nodes();
            }

            ui.separator();

            // 分享链接功能
            ui.heading("分享链接");
            ui.horizontal(|ui| {
                if ui.button("导入分享链接").clicked() {
                    self.show_share_link_dialog = true;
                }
                if ui.button("导出分享链接").clicked() {
                    self.export_share_links();
                }
            });

            ui.separator();

            // 节点列表
            ui.heading("节点列表");
            let mut indices_to_remove = Vec::new();
            let node_addrs_clone = self.config.node_addrs.clone();
            for (i, node_addr) in node_addrs_clone.iter().enumerate() {
                ui.horizontal(|ui| {
                    // 显示连接状态图标
                    let status_icon = if let Some(status) = self.node_status.get(node_addr.as_str())
                    {
                        if status.connected {
                            "🟢" // 已连接
                        } else {
                            "🔴" // 未连接
                        }
                    } else {
                        "⚪" // 未测试
                    };
                    ui.label(status_icon);

                    // 显示节点地址和延迟
                    let label_text = if let Some(status) = self.node_status.get(node_addr.as_str())
                    {
                        if let Some(latency) = status.latency_ms {
                            format!("{}. {} ({}ms)", i + 1, node_addr, latency)
                        } else {
                            format!("{}. {} (超时)", i + 1, node_addr)
                        }
                    } else {
                        format!("{}. {} (未测试)", i + 1, node_addr)
                    };
                    ui.label(label_text);

                    if ui.button("测试").clicked() {
                        // A5：后台线程 + 通道模式（对齐 test_all_nodes），UI 线程零阻塞，
                        // 测试期间窗口可正常拖动/重绘
                        self.start_node_test(node_addr.clone());
                    }

                    if ui.button("删除").clicked() {
                        indices_to_remove.push(i);
                    }
                });
            }

            // 删除节点并添加日志
            for &i in indices_to_remove.iter().rev() {
                let removed = self.config.node_addrs.remove(i);
                self.node_status.remove(&removed);
                self.add_log(format!("删除节点: {}", removed));
            }

            ui.separator();

            // 代理控制
            ui.heading("代理控制");
            ui.horizontal(|ui| {
                ui.label("监听地址:");
                ui.text_edit_singleline(&mut self.config.proxy_listen_addr);
            });

            ui.horizontal(|ui| {
                if self.proxy_running {
                    if ui.button("停止代理").clicked() {
                        self.stop_proxy();
                    }
                } else {
                    if ui.button("启动代理").clicked() {
                        self.start_proxy();
                    }
                }
            });

            ui.separator();

            // ── Exec-1：安全与传输设置（配置文件 > 环境变量，自动持久化）──
            ui.heading("安全与传输设置");
            if ui.button("新手引导").clicked() {
                for line in HydraApp::wizard_lines() {
                    self.add_log(line);
                }
            }

            // 认证密钥：默认掩码显示（如 a1b2****8f90），点击「编辑/显示」查看并编辑明文
            ui.horizontal(|ui| {
                ui.label("认证密钥:");
                if self.show_auth_key {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.config.auth_key).desired_width(170.0),
                    );
                    if ui.button("隐藏").clicked() {
                        self.show_auth_key = false;
                    }
                } else {
                    let shown = if self.config.auth_key.is_empty() {
                        "（未设置）".to_string()
                    } else {
                        config::mask_secret(self.config.auth_key.trim())
                    };
                    ui.monospace(shown);
                    if ui.button("编辑/显示").clicked() {
                        self.show_auth_key = true;
                    }
                }
            });
            // 密钥有效性实时校验（hex + 最短 16 字节）
            if self.show_auth_key && !self.config.auth_key.trim().is_empty() {
                match hydra_client::auth_key_from_hex(self.config.auth_key.trim()) {
                    Ok(_) => ui.label("✓ 密钥格式有效"),
                    Err(e) => ui.label(format!("✗ {}", e)),
                };
            }

            // 节点证书文件：浏览选择（rfd 文件对话框）+ 手动粘贴路径，实时校验存在性
            ui.label("节点证书:");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.config.cert_path)
                        .desired_width(ui.available_width() - 80.0)
                        .hint_text("节点生成的 hydra-node-cert.der"),
                );
                if ui.button("浏览...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("证书文件", &["der", "pem", "crt", "cer"])
                        .add_filter("全部文件", &["*"])
                        .pick_file()
                    {
                        self.config.cert_path = path.display().to_string();
                        self.add_log(format!("已选择节点证书: {}", path.display()));
                    }
                }
            });
            let cert = self.config.cert_path.trim().to_string();
            if !cert.is_empty() {
                if std::path::Path::new(&cert).exists() {
                    ui.label("✓ 证书文件存在");
                } else {
                    ui.colored_label(egui::Color32::RED, "✗ 证书文件不存在，请检查路径");
                }
            }

            // 传输模式（对应 HYDRA_MODE；两端须一致）
            ui.horizontal(|ui| {
                ui.label("传输模式:");
                let obfs = self.config.is_obfs();
                if ui.radio(!obfs, "伪装 masquerade").clicked() && obfs {
                    self.config.hydra_mode = "masquerade".to_string();
                    self.add_log("已切换为 masquerade 模式，下次启动代理生效".to_string());
                }
                if ui.radio(obfs, "混淆 obfs").clicked() && !obfs {
                    self.config.hydra_mode = "obfs".to_string();
                    self.add_log("已切换为 obfs 模式（需两端一致），下次启动代理生效".to_string());
                }
            });

            // obfs 独立第二密码（对应 HYDRA_OBFS_KEY；masquerade 模式忽略）
            ui.horizontal(|ui| {
                ui.label("obfs 密码:");
                if self.show_obfs_key {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.config.obfs_key).desired_width(170.0),
                    );
                    if ui.button("隐藏").clicked() {
                        self.show_obfs_key = false;
                    }
                } else {
                    let shown = if self.config.obfs_key.is_empty() {
                        "（未设置）".to_string()
                    } else {
                        config::mask_secret(self.config.obfs_key.trim())
                    };
                    ui.monospace(shown);
                    if ui.button("编辑/显示").clicked() {
                        self.show_obfs_key = true;
                    }
                }
            });
            if self.config.is_obfs() && self.config.obfs_key.trim().is_empty() {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "⚠ obfs 模式要求独立第二密码，否则代理无法启动",
                );
            }

            // Offline 恢复探测间隔（对应 HYDRA_PROBE_INTERVAL_SECS）
            ui.horizontal(|ui| {
                ui.label("探测间隔(秒):");
                let mut secs = self.config.probe_interval_secs.unwrap_or(30);
                if ui
                    .add(egui::DragValue::new(&mut secs).clamp_range(1..=3600))
                    .changed()
                {
                    self.config.probe_interval_secs = Some(secs);
                }
                if self.config.probe_interval_secs.is_some() && ui.small_button("默认").clicked()
                {
                    self.config.probe_interval_secs = None;
                }
            });
            ui.label("（Offline 节点自动恢复探测，默认 30 秒）");
            ui.small(format!(
                "配置自动保存: {}",
                config::config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(配置目录不可用)".to_string())
            ));

            ui.separator();

            // 状态信息
            ui.heading("状态信息");
            ui.label(format!(
                "代理状态: {}",
                if self.proxy_running {
                    "运行中"
                } else {
                    "已停止"
                }
            ));

            let connected_count = self.node_status.values().filter(|s| s.connected).count();
            let total_count = self.config.node_addrs.len();
            ui.label(format!(
                "节点数量: {} / {} 可用",
                connected_count, total_count
            ));

            if let Some(last_check) = self.last_health_check {
                let elapsed = last_check.elapsed().as_secs();
                ui.label(format!("上次检测: {}秒前", elapsed));
            }

            // 流量统计
            if self.proxy_running {
                ui.separator();
                ui.heading("流量统计");

                // 更新流量数据（每秒更新一次）
                let should_update = match self.last_traffic_update {
                    Some(last) => last.elapsed().as_secs() >= 1,
                    None => true,
                };

                if should_update {
                    self.last_traffic_update = Some(std::time::Instant::now());
                }

                if let Some(monitor) = &self.traffic_monitor {
                    // 使用 block_in_place 获取异步数据（在 tokio runtime 内安全阻塞）
                    let stats = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(monitor.get_stats())
                    });

                    ui.label(format!(
                        "上传: {} ({})",
                        format_bytes(stats.bytes_sent),
                        format_speed(stats.upload_speed)
                    ));
                    ui.label(format!(
                        "下载: {} ({})",
                        format_bytes(stats.bytes_received),
                        format_speed(stats.download_speed)
                    ));
                    ui.label(format!("活跃连接: {}", stats.active_connections));
                    ui.label(format!("总连接数: {}", stats.total_connections));
                    ui.label(format!("运行时间: {}", format_duration(stats.uptime_secs)));
                }
            }
        });

        // 中央面板 - 日志显示
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("运行日志");
            ui.separator();

            // 日志显示区域
            egui::ScrollArea::vertical().show(ui, |ui| {
                for log in &self.logs {
                    ui.label(log);
                }
            });

            ui.separator();

            // 底部控制栏
            ui.horizontal(|ui| {
                if ui.button("清空日志").clicked() {
                    self.logs.clear();
                }
                if ui.button("刷新").clicked() {
                    ctx.request_repaint();
                }
            });
        });

        // Exec-1：配置差分 + 防抖落盘（有变更时每秒至多写一次；启停/退出时强制写）
        self.maybe_save_config(false);
    }
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 添加中文字体支持
    // 尝试加载Noto Sans CJK字体
    let font_data = include_bytes!("../fonts/NotoSansCJK-Regular.ttc");
    fonts.font_data.insert(
        "noto_sans_cjk".to_owned(),
        egui::FontData::from_owned(font_data.to_vec()),
    );

    // 将中文字体添加到字体族中
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("noto_sans_cjk".to_owned());

    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("noto_sans_cjk".to_owned());

    ctx.set_fonts(fonts);
}

// ═══════════════ A1：Windows 系统代理真实实现 ═══════════════
//
// 写 HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings：
//   ProxyEnable(DWORD)=1、ProxyServer="127.0.0.1:port"（裸 host:port）、
//   ProxyOverride（Windows 不支持 CIDR，用通配符）、删除 AutoConfigURL（PAC 会覆盖手动代理）。
// 停止时恢复旧值而非清除（enable 前先读旧值）；刷新用 windows-sys InternetSetOptionW(39/37)。
// 恢复所需旧值存放在全局槽位：panic hook / Drop / stop_proxy 三条清理路径都是静态函数。
#[cfg(windows)]
mod windows_proxy {
    use std::sync::Mutex;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Windows 不支持 CIDR，使用通配符；<local> 覆盖裸主机名
    const PROXY_OVERRIDE: &str = "localhost;127.*;192.168.*;172.*;10.*;<local>";

    /// enable 之前的注册表旧值（disable 时恢复）
    #[derive(Debug, Default, Clone)]
    pub struct SavedProxyState {
        pub proxy_enable: Option<u32>,
        pub proxy_server: Option<String>,
        pub proxy_override: Option<String>,
        pub autoconfig_url: Option<String>,
    }

    /// 全局旧值槽位：清理路径（panic hook 等）无法访问 GUI 状态，经此恢复。
    /// Mutex 中毒时直接取回内部数据——panic 清理路径本身必须可用。
    static SAVED_STATE: Mutex<Option<SavedProxyState>> = Mutex::new(None);

    fn lock_saved() -> std::sync::MutexGuard<'static, Option<SavedProxyState>> {
        SAVED_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn open_settings_key() -> std::io::Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_SET_VALUE)
    }

    /// 开启系统代理。返回 Err 时 GUI 侧显式报错，不静默。
    pub fn enable(proxy_addr: &str) -> std::io::Result<()> {
        let key = open_settings_key()?;
        let saved = SavedProxyState {
            proxy_enable: key.get_value("ProxyEnable").ok(),
            proxy_server: key.get_value("ProxyServer").ok(),
            proxy_override: key.get_value("ProxyOverride").ok(),
            autoconfig_url: key.get_value("AutoConfigURL").ok(),
        };
        *lock_saved() = Some(saved);

        key.set_value("ProxyEnable", &1u32)?;
        // 裸 host:port（不带协议前缀；WinINet 对 SOCKS 可用 "socks=host:port" 形式，
        // 裸 host:port 表示所有协议的 HTTP 代理，浏览器按需升级 CONNECT）
        key.set_value("ProxyServer", &proxy_addr.to_string())?;
        key.set_value("ProxyOverride", &PROXY_OVERRIDE)?;
        // PAC 会覆盖手动代理，必须删除
        let _ = key.delete_value("AutoConfigURL");
        refresh();
        Ok(())
    }

    /// 恢复 enable 之前的注册表状态（旧值恢复而非一律清除；原先不存在的键值则删除）。
    /// 从未 enable 过时不做任何事。
    pub fn disable() {
        let saved = match lock_saved().take() {
            Some(s) => s,
            None => return,
        };
        if let Ok(key) = open_settings_key() {
            match saved.proxy_enable {
                Some(v) => {
                    let _ = key.set_value("ProxyEnable", &v);
                }
                None => {
                    let _ = key.delete_value("ProxyEnable");
                }
            }
            match saved.proxy_server {
                Some(v) => {
                    let _ = key.set_value("ProxyServer", &v);
                }
                None => {
                    let _ = key.delete_value("ProxyServer");
                }
            }
            match saved.proxy_override {
                Some(v) => {
                    let _ = key.set_value("ProxyOverride", &v);
                }
                None => {
                    let _ = key.delete_value("ProxyOverride");
                }
            }
            match saved.autoconfig_url {
                Some(v) => {
                    let _ = key.set_value("AutoConfigURL", &v);
                }
                None => {
                    let _ = key.delete_value("AutoConfigURL");
                }
            }
        }
        refresh();
    }

    /// 通知 WinINet 设置已更改并立即刷新：
    /// InternetSetOptionW(NULL, 39=INTERNET_OPTION_SETTINGS_CHANGED) +
    /// InternetSetOptionW(NULL, 37=INTERNET_OPTION_REFRESH)
    fn refresh() {
        use windows_sys::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
    }
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 设置 panic hook，确保代理异常时清除系统代理
    let main_thread_id = std::thread::current().id();
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // 仅主线程（GUI 崩溃路径）panic 才清理系统代理：后台线程 panic 不会终止进程，
        // 此时清理会让用户的网络在代理仍在运行时被静默断开
        if std::thread::current().id() == main_thread_id {
            HydraApp::remove_system_proxy_static();
        }
        // 调用原始 hook
        original_hook(panic_info);
    }));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Hydra Multipath Proxy",
        options,
        Box::new(|cc| Box::new(HydraApp::new(cc))),
    )
}
