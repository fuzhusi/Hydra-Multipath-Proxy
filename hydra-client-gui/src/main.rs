// Windows 下隐藏随 GUI 弹出的终端窗口（仅 release；debug 保留控制台便于看日志）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use hydra_client::{
    format_bytes, format_duration, format_speed, generate_share_links, hex_encode_lower,
    parse_share_links, sha256_hex, ProxyServer, Scheduler, ShareLink, TrafficMonitor, Transport,
    TransportMode,
};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
use config::{GuiConfig, SubscriptionConfig};
mod qr;
mod subscription;
mod tray;
use tray::TrayCommand;

/// T2：左侧导航五区（状态总览 / 节点管理 / 分享 / 设置 / 日志）
/// Team-UI：订阅管理并入「节点管理」（统一节点列表 + 来源标记，消除功能重叠页面）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Overview,
    Nodes,
    Share,
    Settings,
    Logs,
}

impl Tab {
    const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Nodes,
        Tab::Share,
        Tab::Settings,
        Tab::Logs,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "📊 状态总览",
            Tab::Nodes => "🌐 节点管理",
            Tab::Share => "🔗 分享",
            Tab::Settings => "⚙️ 设置",
            Tab::Logs => "📜 运行日志",
        }
    }
}

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

    // 订阅（Exec-C v1）：新订阅输入 + 后台更新线程/队列
    new_sub_name: String,
    new_sub_source: String,
    sub_update_receiver: Option<
        std::sync::mpsc::Receiver<std::result::Result<subscription::SubscriptionOutcome, String>>,
    >,
    /// 待更新订阅队列（"更新全部订阅"与单条更新共用一条后台通道，逐个串行拉取）
    pending_sub_updates: VecDeque<(String, String)>,

    // 分享链接相关
    share_link_text: String,
    show_share_link_dialog: bool,

    // Team-Q 分享体系 v2：单节点分享对话框（二维码 + 完整链接 + 安全提示）
    share_dialog_open: bool,
    share_node_addr: String,
    share_compact: bool,
    share_link: Option<ShareLink>,
    share_url_cache: String,
    share_qr_texture: Option<egui::TextureHandle>,
    // Team-Q 导入区状态：粘贴文本 + 最近一次导入结果提示（成功绿/失败红）
    import_text: String,
    import_status: Option<(bool, String)>,

    // 密钥明文显示开关（默认掩码显示）
    show_auth_key: bool,
    show_obfs_key: bool,

    // ── Team-UI：节点编辑对话框（备注名/地址 + 全局安全参数，实时校验）──
    node_edit_open: bool,
    /// 被编辑节点的原始地址（保存时的迁移键）
    edit_orig_addr: String,
    edit_name: String,
    edit_addr: String,
    edit_auth_key: String,
    edit_show_auth: bool,
    edit_cert_path: String,
    edit_obfs_key: String,
    edit_obfs: bool,
    edit_show_obfs: bool,

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

    // ── T2：托盘 + UI 重排 ──
    /// 当前导航页签
    current_tab: Tab,
    /// 系统托盘（None = 初始化失败，GUI 照常运行）
    tray: Option<tray::HydraTray>,
    /// 真·退出标记：托盘「退出」或菜单退出后放行窗口关闭（区别于隐藏到托盘）
    really_quit: bool,
    /// 托盘 tooltip 缓存（变化才 set_tooltip）
    last_tray_tooltip: String,
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
            new_sub_name: String::new(),
            new_sub_source: String::new(),
            sub_update_receiver: None,
            pending_sub_updates: VecDeque::new(),
            share_link_text: String::new(),
            show_share_link_dialog: false,
            share_dialog_open: false,
            share_node_addr: String::new(),
            share_compact: false,
            share_link: None,
            share_url_cache: String::new(),
            share_qr_texture: None,
            import_text: String::new(),
            import_status: None,
            show_auth_key: false,
            show_obfs_key: false,
            node_edit_open: false,
            edit_orig_addr: String::new(),
            edit_name: String::new(),
            edit_addr: String::new(),
            edit_auth_key: String::new(),
            edit_show_auth: false,
            edit_cert_path: String::new(),
            edit_obfs_key: String::new(),
            edit_obfs: false,
            edit_show_obfs: false,
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
            current_tab: Tab::Overview,
            tray: None,
            really_quit: false,
            last_tray_tooltip: String::new(),
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
        // T2：统一暗色主题（圆角 6 / 强调蓝 / 间距）
        apply_dark_theme(&cc.egui_ctx);
        // T2：系统托盘（失败不阻断 GUI，仅记日志）
        let tray = match tray::create_tray(cc.egui_ctx.clone()) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("[Tray] {}", e);
                None
            }
        };

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
            new_sub_name: String::new(),
            new_sub_source: String::new(),
            sub_update_receiver: None,
            pending_sub_updates: VecDeque::new(),
            share_link_text: String::new(),
            show_share_link_dialog: false,
            share_dialog_open: false,
            share_node_addr: String::new(),
            share_compact: false,
            share_link: None,
            share_url_cache: String::new(),
            share_qr_texture: None,
            import_text: String::new(),
            import_status: None,
            show_auth_key: false,
            show_obfs_key: false,
            node_edit_open: false,
            edit_orig_addr: String::new(),
            edit_name: String::new(),
            edit_addr: String::new(),
            edit_auth_key: String::new(),
            edit_show_auth: false,
            edit_cert_path: String::new(),
            edit_obfs_key: String::new(),
            edit_obfs: false,
            edit_show_obfs: false,
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
            current_tab: Tab::Overview,
            tray,
            really_quit: false,
            last_tray_tooltip: "Hydra 代理已停止".to_string(),
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
            "① 填写认证密钥：左侧「⚙ 设置」→「安全与传输」→ 认证密钥 → 点「编辑/显示」输入 hex 密钥"
                .to_string(),
            "② 选择节点证书文件：同区「节点证书」→ 点「浏览...」选择节点生成的 hydra-node-cert.der"
                .to_string(),
            "③ 添加节点：「🌐 节点管理」页顶部输入框填 host:port 后点「添加」"
                .to_string(),
            "④ 点「▶ 启动代理」即可使用（也可直接点状态总览页的大按钮）".to_string(),
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

    // ═══════════════ Team-Q：分享体系 v2（二维码 + 密钥链接）═══════════════

    /// 为指定节点构造 v2 分享链接：带认证密钥 + 证书（完整）或证书指纹（紧凑）。
    /// obfs 模式时附 obfs 第二密码。密钥/证书按当前配置解析，取不到的字段自动省略。
    fn build_share_link(&self, addr_str: &str, compact: bool) -> Option<ShareLink> {
        let addr: SocketAddr = addr_str.trim().parse().ok()?;
        let node_info = NodeInfo {
            address: addr,
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        };
        let mode = if self.config.is_obfs() {
            TransportMode::Obfs
        } else {
            TransportMode::Masquerade
        };
        let mut link = ShareLink::new_with_mode(&node_info, mode);

        // 认证密钥（完整分享核心字段；解析失败则省略，链接退化为仅地址信息）
        if let Ok(key) = config::resolve_auth_key(&self.config) {
            link = link.with_auth_key_bytes(&key);
        }

        // 证书：完整模式带 DER 本体，紧凑模式只带 SHA-256 指纹
        let cert_der = std::fs::read(self.config.cert_path.trim()).ok();
        match cert_der {
            Some(der) if compact => link = link.with_cert_fp(sha256_hex(&der)),
            Some(der) => link = link.with_cert_der(&der),
            None => {}
        }

        // obfs 第二密码（仅 obfs 模式且已设置时携带）
        if self.config.is_obfs() && !self.config.obfs_key.trim().is_empty() {
            link = link.with_obfs_key(self.config.obfs_key.trim());
        }
        Some(link)
    }

    /// 打开单节点分享对话框（完整/紧凑默认完整）
    fn open_share_dialog(&mut self, addr: String) {
        self.share_node_addr = addr;
        self.share_compact = false;
        self.share_link = self.build_share_link(&self.share_node_addr, false);
        self.share_url_cache = String::new(); // 强制重建二维码纹理
        self.share_dialog_open = true;
        if let Some(link) = &self.share_link {
            if link.is_full_share() {
                self.add_log(format!(
                    "已生成节点 {} 的完整分享（含密钥，注意仅限可信渠道）",
                    self.share_node_addr
                ));
            } else {
                self.add_log(format!(
                    "已生成节点 {} 的分享（缺少密钥或证书，对方可能需要手动补全）",
                    self.share_node_addr
                ));
            }
        }
    }

    /// 应用一条导入的 v2 分享链接：节点地址 + 密钥/证书/模式自动入配置。
    /// 返回 Err 时不改动任何配置（先全部校验再落库）。
    fn apply_imported_link(&mut self, link: &ShareLink) -> Result<(), String> {
        use base64::Engine as _;

        // 先校验后写：密钥/证书解码失败直接报错，不产生半套配置
        let auth_key_hex = match link.auth_key_bytes().map_err(|e| e.to_string())? {
            Some(bytes) => {
                let hex = hex_encode_lower(&bytes);
                // 校验 hex + 长度（与启动代理同一套规则）
                hydra_client::auth_key_from_hex(&hex)?;
                Some(hex)
            }
            None => None,
        };
        let cert_b64 = match link.cert_der_bytes().map_err(|e| e.to_string())? {
            Some(der) => Some(base64::engine::general_purpose::STANDARD.encode(&der)),
            None => None,
        };
        let obfs_key = link.obfs_key_string().map_err(|e| e.to_string())?;

        // ── 以下为落库（不会再失败）──
        if let Some(hex) = auth_key_hex {
            self.config.auth_key = hex;
        }
        if let Some(b64) = cert_b64 {
            self.config.cert_der_b64 = b64;
            // 已有证书文件时提示覆盖语义（cert_path 优先，导入值仅在路径为空时生效）
            if !self.config.cert_path.trim().is_empty() {
                self.add_log(
                    "提示：已存在证书文件路径，链接携带的证书仅在清空证书路径后生效".to_string(),
                );
            }
        }
        // 紧凑模式指纹：本地有证书文件时核对，不一致显式告警
        if let Some(fp) = &link.cert_fp {
            if let Ok(der) = std::fs::read(self.config.cert_path.trim()) {
                let local_fp = sha256_hex(&der);
                if &local_fp != fp {
                    self.add_log(format!(
                        "⚠ 证书指纹不一致！链接 cf={}，本地证书 sha256={}，请确认证书来源",
                        fp, local_fp
                    ));
                }
            }
        }
        if let Some(ok) = obfs_key {
            self.config.obfs_key = ok;
        }
        if link.mode == TransportMode::Obfs {
            self.config.hydra_mode = "obfs".to_string();
        }

        let addr_str = format!("{}:{}", link.address, link.port);
        if !self.config.node_addrs.contains(&addr_str) {
            self.config.node_addrs.push(addr_str.clone());
            self.node_status.insert(
                addr_str.clone(),
                NodeStatusInfo {
                    addr: addr_str.clone(),
                    connected: false,
                    last_check: None,
                    latency_ms: None,
                },
            );
        }
        Ok(())
    }

    /// 记录一次导入结果（UI 绿/红提示 + 日志）
    fn set_import_status(&mut self, ok: bool, msg: String) {
        if ok {
            self.add_log(msg.clone());
        } else {
            self.add_log(format!("导入失败: {}", msg));
        }
        self.import_status = Some((ok, msg));
    }

    /// 导入粘贴文本中的分享链接（支持多行，每行一条）
    fn import_pasted_links(&mut self) {
        let text = self.import_text.clone();
        if text.trim().is_empty() {
            self.set_import_status(false, "请先粘贴 hydra:// 分享链接".to_string());
            return;
        }
        match parse_share_links(&text) {
            Ok(links) if links.is_empty() => {
                self.set_import_status(false, "未在文本中找到 hydra:// 分享链接".to_string());
            }
            Ok(links) => {
                let (ok_count, fail_msgs) = self.apply_many_links(&links);
                if ok_count > 0 {
                    self.set_import_status(
                        true,
                        format!(
                            "成功导入 {} 个节点（失败 {} 条）",
                            ok_count,
                            fail_msgs.len()
                        ),
                    );
                } else {
                    self.set_import_status(false, fail_msgs.into_iter().next().unwrap_or_default());
                }
            }
            Err(e) => self.set_import_status(false, format!("链接解析失败: {}", e)),
        }
    }

    /// 逐条应用链接，返回（成功数, 失败原因列表）
    fn apply_many_links(&mut self, links: &[ShareLink]) -> (usize, Vec<String>) {
        let mut ok = 0;
        let mut fails = Vec::new();
        for link in links {
            match self.apply_imported_link(link) {
                Ok(()) => ok += 1,
                Err(e) => fails.push(format!("{}:{}: {}", link.address, link.port, e)),
            }
        }
        (ok, fails)
    }

    /// 从二维码图片文件导入（rfd 选 png/jpg → rqrr 解码 → 解析链接）
    fn import_from_qr_image(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("图片文件", &["png", "jpg", "jpeg"])
            .add_filter("全部文件", &["*"])
            .pick_file()
        else {
            return; // 用户取消
        };
        let result = std::fs::read(&path)
            .map_err(|e| format!("读取图片 {} 失败: {}", path.display(), e))
            .and_then(|bytes| qr::decode_qr_from_bytes(&bytes))
            .and_then(|text| {
                ShareLink::from_share_url(text.trim())
                    .map_err(|e| format!("二维码内容不是有效的 hydra 分享链接: {}", e))
            });
        match result {
            Ok(link) => match self.apply_imported_link(&link) {
                Ok(()) => self.set_import_status(
                    true,
                    format!(
                        "二维码导入成功：{}:{}（含密钥 {}）",
                        link.address,
                        link.port,
                        if link.auth_key.is_some() {
                            "是"
                        } else {
                            "否"
                        }
                    ),
                ),
                Err(e) => self.set_import_status(false, e),
            },
            Err(e) => self.set_import_status(false, e),
        }
    }

    /// 从 .txt 链接文件导入（每行一条，支持 v1/v2 混排）
    fn import_from_link_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("链接文件", &["txt"])
            .add_filter("全部文件", &["*"])
            .pick_file()
        else {
            return;
        };
        let result = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取文件 {} 失败: {}", path.display(), e))
            .and_then(|text| parse_share_links(&text).map_err(|e| format!("链接解析失败: {}", e)));
        match result {
            Ok(links) if links.is_empty() => {
                self.set_import_status(false, "文件中未找到 hydra:// 分享链接".to_string());
            }
            Ok(links) => {
                let (ok_count, fails) = self.apply_many_links(&links);
                if ok_count > 0 {
                    self.set_import_status(
                        true,
                        format!(
                            "从 {} 导入 {} 个节点（失败 {} 条）",
                            path.display(),
                            ok_count,
                            fails.len()
                        ),
                    );
                } else {
                    self.set_import_status(false, fails.into_iter().next().unwrap_or_default());
                }
            }
            Err(e) => self.set_import_status(false, e),
        }
    }

    // ═══════════════ Exec-C：订阅（hydra-sub v1）═══════════════
    //
    // 数据流：UI 线程 queue_subscription_update → 后台线程 fetch_and_parse_subscription
    // （ureq 阻塞拉取/文件读取 + parse_subscription）→ mpsc → UI 线程
    // poll_subscription_updates → apply_subscription_update 合并替换。
    // 单条后台通道 + 待更新队列：多订阅串行拉取，UI 零阻塞。

    /// 添加订阅（名称可留空自动编号；名称重复拒绝——名称是来源标记与更新对号的键）
    fn add_subscription(&mut self) {
        let source = self.new_sub_source.trim().to_string();
        if source.is_empty() {
            self.add_log(
                "订阅来源不能为空（http(s) URL、文件路径或 hydra-sub:// 前缀）".to_string(),
            );
            return;
        }
        let name = if self.new_sub_name.trim().is_empty() {
            format!("订阅{}", self.config.subscriptions.len() + 1)
        } else {
            self.new_sub_name.trim().to_string()
        };
        if self.config.subscriptions.iter().any(|s| s.name == name) {
            self.add_log(format!("订阅名称「{}」已存在，请换一个名称", name));
            return;
        }
        self.config.subscriptions.push(SubscriptionConfig {
            name: name.clone(),
            source,
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        self.add_log(format!("已添加订阅「{}」，点「更新」拉取节点", name));
        self.new_sub_name.clear();
        self.new_sub_source.clear();
    }

    /// 删除订阅：连带清理仅该订阅认领的节点（手动/其他订阅认领的保留）
    fn delete_subscription(&mut self, idx: usize) {
        if idx >= self.config.subscriptions.len() {
            return;
        }
        let sub = self.config.subscriptions.remove(idx);
        let others_owned: HashSet<String> =
            self.config.subscription_owned_addrs().into_iter().collect();
        let removed: Vec<String> = sub
            .nodes
            .iter()
            .filter(|a| !others_owned.contains(*a))
            .cloned()
            .collect();
        self.config.node_addrs.retain(|a| !removed.contains(a));
        for a in &removed {
            self.node_status.remove(a);
        }
        self.add_log(format!(
            "删除订阅「{}」，连带移除其节点 {} 个",
            sub.name,
            removed.len()
        ));
    }

    /// 排队更新一个订阅（后台串行）
    fn queue_subscription_update(&mut self, name: String, source: String) {
        self.pending_sub_updates.push_back((name, source));
        self.start_next_subscription_update();
    }

    /// 更新全部订阅
    fn update_all_subscriptions(&mut self) {
        if self.config.subscriptions.is_empty() {
            self.add_log("没有订阅可更新，请先在「订阅」区添加".to_string());
            return;
        }
        for s in &self.config.subscriptions {
            self.pending_sub_updates
                .push_back((s.name.clone(), s.source.clone()));
        }
        self.start_next_subscription_update();
    }

    /// 启动队列中的下一个订阅更新（已有更新在跑则返回；已删除的订阅跳过）
    fn start_next_subscription_update(&mut self) {
        if self.sub_update_receiver.is_some() {
            return;
        }
        loop {
            let Some((name, source)) = self.pending_sub_updates.pop_front() else {
                return;
            };
            if !self.config.subscriptions.iter().any(|s| s.name == name) {
                self.add_log(format!("订阅「{}」已删除，跳过更新", name));
                continue;
            }
            let (tx, rx) = std::sync::mpsc::channel();
            self.add_log(format!("开始更新订阅「{}」...", name));
            std::thread::spawn(move || {
                let result = subscription::fetch_and_parse_subscription(
                    name.clone(),
                    source.clone(),
                    subscription::SUBSCRIPTION_FETCH_TIMEOUT,
                );
                let _ = tx.send(result);
            });
            self.sub_update_receiver = Some(rx);
            return;
        }
    }

    /// 在 update 循环中非阻塞地收取订阅更新结果并启动下一个排队更新
    fn poll_subscription_updates(&mut self) {
        let mut finished = None;
        if let Some(rx) = &self.sub_update_receiver {
            match rx.try_recv() {
                Ok(result) => finished = Some(result),
                // 线程 panic 等导致 sender 被弃：重置，允许再次发起
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.sub_update_receiver = None;
                    self.add_log("订阅更新线程异常退出，已重置".to_string());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(result) = finished {
            self.sub_update_receiver = None;
            match result {
                Ok(outcome) => {
                    // 安全约定：明文 http 允许但必须提示（订阅可被中间人注入任意节点地址）
                    if outcome.plaintext_http {
                        self.add_log(format!(
                            "⚠ 订阅「{}」使用明文 HTTP 拉取，内容可能被篡改，建议改用 https",
                            outcome.name
                        ));
                    }
                    self.apply_subscription_update(&outcome.name, outcome.links, outcome.errors);
                }
                Err(e) => self.add_log(format!("订阅更新失败: {}", e)),
            }
        }
        self.start_next_subscription_update();
    }

    /// 订阅更新成功后的节点合并替换：
    /// - 手动节点与其它订阅的节点全部保留；
    /// - 本订阅旧节点被新列表替换（仅移除"仅本订阅认领"的地址）；
    /// - 与手动/其它订阅冲突的地址不重复添加，归属保持原状（单一事实来源 =
    ///   各订阅 nodes 列表，见 GuiConfig::node_source_label）。
    fn apply_subscription_update(
        &mut self,
        name: &str,
        links: Vec<ShareLink>,
        errors: Vec<String>,
    ) {
        let Some(idx) = self
            .config
            .subscriptions
            .iter()
            .position(|s| s.name == name)
        else {
            self.add_log(format!("订阅「{}」已在更新期间被删除，丢弃更新结果", name));
            return;
        };

        // 新地址列表（去重保序）
        let mut new_addrs: Vec<String> = Vec::new();
        for link in links {
            let addr = format!("{}:{}", link.address, link.port);
            if !new_addrs.contains(&addr) {
                new_addrs.push(addr);
            }
        }

        let old_sub_nodes = self.config.subscriptions[idx].nodes.clone();
        let owned_before: HashSet<String> =
            self.config.subscription_owned_addrs().into_iter().collect();
        let manual_set: HashSet<String> = self
            .config
            .node_addrs
            .iter()
            .filter(|a| !owned_before.contains(*a))
            .cloned()
            .collect();
        let others_set: HashSet<String> = self
            .config
            .subscriptions
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .flat_map(|(_, s)| s.nodes.iter().cloned())
            .collect();
        let new_set: HashSet<String> = new_addrs.iter().cloned().collect();

        // 1) 移除：仅本订阅认领、且新列表不再包含的旧节点
        let to_remove: Vec<String> = old_sub_nodes
            .iter()
            .filter(|a| {
                !new_set.contains(*a) && !manual_set.contains(*a) && !others_set.contains(*a)
            })
            .cloned()
            .collect();
        self.config.node_addrs.retain(|a| !to_remove.contains(a));
        for a in &to_remove {
            self.node_status.remove(a);
        }

        // 2) 追加：新地址中尚未在列表、且不被其他订阅认领的
        let mut added = 0usize;
        for a in &new_addrs {
            if self.config.node_addrs.contains(a) || others_set.contains(a) {
                continue;
            }
            self.node_status.entry(a.clone()).or_insert(NodeStatusInfo {
                addr: a.clone(),
                connected: false,
                last_check: None,
                latency_ms: None,
            });
            self.config.node_addrs.push(a.clone());
            added += 1;
        }

        // 3) 本订阅新认领列表：最终在列表中、非手动、非其他订阅的地址
        let claimed: Vec<String> = new_addrs
            .iter()
            .filter(|a| {
                self.config.node_addrs.contains(*a)
                    && !manual_set.contains(*a)
                    && !others_set.contains(*a)
            })
            .cloned()
            .collect();
        self.config.subscriptions[idx].nodes = claimed;
        self.config.subscriptions[idx].last_updated_secs = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );

        self.add_log(format!(
            "订阅「{}」更新成功：{} 个节点（坏行 {} 条跳过，新增 {}、移除 {}）",
            name,
            new_addrs.len(),
            errors.len(),
            added,
            to_remove.len()
        ));
        for e in errors.iter().take(3) {
            self.add_log(format!("  订阅坏行: {}", e));
        }
        if errors.len() > 3 {
            self.add_log(format!("  ...另有 {} 条坏行省略", errors.len() - 3));
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
        // ── T2：托盘命令轮询 + 关窗行为（隐藏到托盘 vs 真退出）──
        self.poll_tray_commands(ctx);
        self.handle_close_request(ctx);

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
        // 非阻塞地处理订阅更新结果（Exec-C，串行驱动排队更新）
        self.poll_subscription_updates();

        // ── Team-Q v2：单节点分享对话框（二维码 + 完整链接 + 安全提示）──
        if self.share_dialog_open {
            let mut compact = self.share_compact;
            egui::Window::new(format!("分享节点 {}", self.share_node_addr))
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("模式:");
                        if ui
                            .radio(!compact, "完整（含密钥/证书，对方即用）")
                            .clicked()
                            && compact
                        {
                            compact = false;
                        }
                        if ui
                            .radio(compact, "紧凑（仅证书指纹，需另发证书）")
                            .clicked()
                            && !compact
                        {
                            compact = true;
                        }
                    });

                    // 二维码显示（纹理缓存：URL 变化才重建）
                    let url = self
                        .share_link
                        .as_ref()
                        .map(|l| l.to_share_url())
                        .unwrap_or_default();
                    if url != self.share_url_cache || self.share_qr_texture.is_none() {
                        self.share_url_cache = url.clone();
                        self.share_qr_texture = qr::qr_color_image(&url).and_then(|img| {
                            ctx.load_texture("share_qr", img, egui::TextureOptions::NEAREST)
                                .into()
                        });
                    }
                    ui.separator();
                    match &self.share_qr_texture {
                        Some(tex) => {
                            ui.vertical_centered(|ui| {
                                ui.add(egui::Image::new((tex.id(), egui::vec2(240.0, 240.0))));
                            });
                        }
                        None => {
                            ui.colored_label(egui::Color32::RED, "✗ 二维码生成失败（链接过长？）");
                        }
                    }

                    ui.separator();
                    ui.label("分享链接（可复制）:");
                    egui::ScrollArea::vertical()
                        .max_height(90.0)
                        .show(ui, |ui| {
                            // 只读展示：clone 后丢弃编辑，避免用户改动影响二维码/复制内容
                            let mut url_display = self.share_url_cache.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut url_display)
                                    .desired_width(460.0)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                    ui.horizontal(|ui| {
                        if ui.button("复制链接").clicked() {
                            ui.ctx().copy_text(self.share_url_cache.clone());
                            self.add_log("分享链接已复制到剪贴板".to_string());
                        }
                    });

                    // 密钥掩码显示（明文永不出现在分享 UI）
                    let has_key = self
                        .share_link
                        .as_ref()
                        .map(|l| l.auth_key.is_some())
                        .unwrap_or(false);
                    let key_masked = if has_key {
                        config::mask_secret(self.config.auth_key.trim())
                    } else {
                        "（未携带）".to_string()
                    };
                    ui.horizontal(|ui| {
                        ui.label("认证密钥:");
                        ui.monospace(key_masked);
                    });
                    ui.small(format!(
                        "证书: {}",
                        if self
                            .share_link
                            .as_ref()
                            .map(|l| l.cert_der.is_some())
                            .unwrap_or(false)
                        {
                            "已包含 DER 本体"
                        } else if self
                            .share_link
                            .as_ref()
                            .map(|l| l.cert_fp.is_some())
                            .unwrap_or(false)
                        {
                            "仅含指纹（紧凑模式）"
                        } else {
                            "未包含（对方需自行导入）"
                        }
                    ));
                    ui.label(format!(
                        "传输模式: {}",
                        if self.config.is_obfs() {
                            "obfs"
                        } else {
                            "masquerade"
                        }
                    ));

                    // 红字安全提示
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::RED,
                        "⚠ 完整链接 = 持有节点（含密钥与证书），仅限可信渠道分享！",
                    );
                    ui.colored_label(
                        egui::Color32::RED,
                        "  请勿粘贴到群聊/公开网页/明文 http；普通渠道请用「紧凑」模式。",
                    );

                    ui.horizontal(|ui| {
                        if ui.button("关闭").clicked() {
                            self.share_dialog_open = false;
                        }
                    });
                });
            // 单选切换后重建链接（紧凑 = 去掉证书本体只留指纹）
            if compact != self.share_compact {
                self.share_compact = compact;
                self.share_link = self.build_share_link(&self.share_node_addr, compact);
                self.share_url_cache = String::new(); // 触发二维码重建
            }
        }

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

        // ── T2：左侧导航栏（六区：状态总览/节点管理/订阅/分享/设置/日志）──
        egui::SidePanel::left("nav_panel")
            .exact_width(160.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                ui.heading("Hydra");
                ui.small("Multipath Proxy");
                ui.add_space(6.0);
                ui.separator();
                for tab in Tab::ALL {
                    let selected = self.current_tab == tab;
                    if ui
                        .add_sized(
                            [ui.available_width(), 26.0],
                            egui::SelectableLabel::new(selected, tab.label()),
                        )
                        .clicked()
                    {
                        self.current_tab = tab;
                    }
                    ui.add_space(2.0);
                }
                // 底部常驻：代理运行状态指示
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(if self.proxy_running {
                        "🟢 代理运行中"
                    } else {
                        "⚪ 代理已停止"
                    });
                });
            });

        // ── T2：中央面板（按导航页签切换）──
        egui::CentralPanel::default().show(ctx, |ui| match self.current_tab {
            Tab::Overview => self.ui_overview(ui),
            Tab::Nodes => self.ui_nodes(ui),
            Tab::Share => self.ui_share(ui),
            Tab::Settings => self.ui_settings(ui),
            Tab::Logs => self.ui_logs(ui),
        });

        // ── Team-UI：节点编辑对话框 ──
        if self.node_edit_open {
            self.ui_node_edit_dialog(ctx);
        }

        // T2：托盘 tooltip 随代理状态同步；隐藏到托盘后仍需周期重绘
        // （轮询代理退出通道 / 托盘命令 / 实时速率刷新）
        self.sync_tray_tooltip();
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

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

// ═══════════════ T2（Team-G）：托盘接线 + UI 六区实现 ═══════════════
impl HydraApp {
    /// 托盘命令轮询：把托盘菜单/点击事件落到与 UI 按钮相同的内部方法上。
    fn poll_tray_commands(&mut self, ctx: &egui::Context) {
        let commands: Vec<TrayCommand> = match &self.tray {
            Some(t) => t.command_rx.try_iter().collect(),
            None => return,
        };
        for cmd in commands {
            match cmd {
                TrayCommand::ToggleWindow | TrayCommand::ShowWindow => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayCommand::StartProxy => self.start_proxy(),
                TrayCommand::StopProxy => self.stop_proxy(),
                TrayCommand::Quit => {
                    // 真退出：先停代理（含系统代理清理）再关闭窗口；on_exit 兜底落盘
                    if self.proxy_running {
                        self.stop_proxy();
                    }
                    self.really_quit = true;
                    self.add_log("正在退出 Hydra...".to_string());
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// 关窗行为：默认隐藏到托盘（代理继续跑，隐藏 ≠ 退出）；
    /// 托盘「退出」或设置 close_to_tray=false 时放行真正关闭（on_exit 清理）。
    fn handle_close_request(&mut self, ctx: &egui::Context) {
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if !close_requested {
            return;
        }
        // 托盘不存在时隐藏=应用不可达（无任何唤回入口），必须放行真关闭
        if self.really_quit || !self.config.close_to_tray || self.tray.is_none() {
            return; // 放行关闭；on_exit 会停代理 + 清系统代理 + 强制落盘
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.add_log(
            "窗口已隐藏到系统托盘，代理继续运行（左键托盘恢复，右键菜单退出）".to_string(),
        );
    }

    /// 托盘 tooltip 与代理运行状态同步（变化才调用 set_tooltip）
    fn sync_tray_tooltip(&mut self) {
        let tip = if self.proxy_running {
            "Hydra 代理运行中"
        } else {
            "Hydra 代理已停止"
        };
        if self.last_tray_tooltip != tip {
            if let Some(t) = &self.tray {
                t.set_tooltip(tip);
            }
            self.last_tray_tooltip = tip.to_string();
        }
    }

    /// 状态总览：状态卡（大字状态 + 速率 + 活跃连接）+ 快捷启停 + 节点健康概要
    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("状态总览");
        ui.separator();

        // 状态卡
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (status_text, status_color) = if self.proxy_running {
                        ("● 运行中", egui::Color32::from_rgb(0x53, 0xC2, 0x6E))
                    } else {
                        ("○ 已停止", egui::Color32::GRAY)
                    };
                    ui.label(
                        egui::RichText::new(status_text)
                            .size(24.0)
                            .color(status_color),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let btn_text = if self.proxy_running {
                            "■ 停止代理"
                        } else {
                            "▶ 启动代理"
                        };
                        if ui
                            .add(egui::Button::new(egui::RichText::new(btn_text).size(18.0)))
                            .clicked()
                        {
                            if self.proxy_running {
                                self.stop_proxy();
                            } else {
                                self.start_proxy();
                            }
                        }
                    });
                });
                ui.label(format!("监听地址: {}", self.config.proxy_listen_addr));

                // 实时流量（TrafficMonitor 既有接口，每秒刷新由 500ms 周期重绘驱动）
                if self.proxy_running {
                    if let Some(monitor) = &self.traffic_monitor {
                        let stats = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(monitor.get_stats())
                        });
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label(format!("⬆ {} /s", format_speed(stats.upload_speed)));
                            ui.label(format!("⬇ {} /s", format_speed(stats.download_speed)));
                            ui.label(format!("活跃连接: {}", stats.active_connections));
                        });
                        ui.label(format!(
                            "累计 ⬆ {} ｜ ⬇ {} ｜ 总连接 {} ｜ 运行 {}",
                            format_bytes(stats.bytes_sent),
                            format_bytes(stats.bytes_received),
                            stats.total_connections,
                            format_duration(stats.uptime_secs)
                        ));
                    }
                }
            });

        ui.add_space(8.0);
        ui.heading("节点健康");
        ui.separator();
        let online = self.node_status.values().filter(|s| s.connected).count();
        let total = self.config.node_addrs.len();
        ui.label(format!("在线 {} / 总数 {}", online, total));
        if let Some(last_check) = self.last_health_check {
            ui.label(format!("上次检测: {}秒前", last_check.elapsed().as_secs()));
        }
        if ui.button("测试所有节点").clicked() {
            self.test_all_nodes();
        }
    }

    /// 节点管理（Team-UI 合并版）：统一节点列表（手动+订阅同列，来源标记）
    /// + 导入节点 + 订阅管理（订阅页已并入本页）+ 每行「编辑」
    fn ui_nodes(&mut self, ui: &mut egui::Ui) {
        ui.heading("节点管理");
        ui.separator();

        // 添加节点（实时校验 host:port，非法地址直接提示不再静默入库）
        ui.horizontal(|ui| {
            ui.label("节点地址:");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.new_node_input)
                    .desired_width(220.0)
                    .hint_text("host:port，如 1.2.3.4:4433"),
            );
            let add_clicked = ui.button("➕ 添加节点").clicked();
            if add_clicked {
                let input = self.new_node_input.trim().to_string();
                if input.is_empty() {
                    self.add_log("请先输入节点地址（host:port）".to_string());
                } else if input.parse::<SocketAddr>().is_err() {
                    self.add_log(format!(
                        "「{}」不是有效的 地址:端口（示例 1.2.3.4:4433 / [::1]:4433），未添加",
                        input
                    ));
                } else {
                    self.node_status.insert(
                        input.clone(),
                        NodeStatusInfo {
                            addr: input.clone(),
                            connected: false,
                            last_check: None,
                            latency_ms: None,
                        },
                    );
                    self.config.node_addrs.push(input.clone());
                    self.add_log(format!("已添加节点: {}", input));
                    self.new_node_input.clear();
                }
            }
            if !self.new_node_input.trim().is_empty()
                && self.new_node_input.trim().parse::<SocketAddr>().is_err()
            {
                response.on_hover_text("尚未输入完整的 地址:端口");
            }
        });

        if ui.button("🔁 测试所有节点").clicked() {
            self.test_all_nodes();
        }

        // ── 统一节点列表（Team-UI：手动 + 订阅节点同一列，来源标记区分）──
        ui.add_space(4.0);
        ui.heading(format!(
            "节点列表（手动 {} / 订阅 {} / 共 {}）",
            self.config
                .node_addrs
                .iter()
                .filter(|a| self.config.node_source_label(a) == config::NODE_SOURCE_MANUAL)
                .count(),
            self.config.node_addrs.len()
                - self
                    .config
                    .node_addrs
                    .iter()
                    .filter(|a| self.config.node_source_label(a) == config::NODE_SOURCE_MANUAL)
                    .count(),
            self.config.node_addrs.len()
        ));
        if self.config.node_addrs.is_empty() {
            ui.weak(
                "还没有节点。请在上方添加，或用「导入节点」粘贴分享链接，或在下方订阅自动拉取。",
            );
        }
        let mut indices_to_remove = Vec::new();
        let mut edit_target: Option<String> = None;
        let node_addrs_clone = self.config.node_addrs.clone();
        for (i, node_addr) in node_addrs_clone.iter().enumerate() {
            ui.horizontal(|ui| {
                // 连接状态图标
                let status_icon = match self.node_status.get(node_addr.as_str()) {
                    Some(status) => {
                        if status.connected {
                            "🟢"
                        } else {
                            "🔴"
                        }
                    }
                    None => "⚪",
                };
                ui.label(status_icon);

                // 备注 + 地址 + 延迟
                let name = self.config.node_display_name(node_addr);
                let latency_text = match self.node_status.get(node_addr.as_str()) {
                    Some(status) => match status.latency_ms {
                        Some(latency) => format!("{}ms", latency),
                        None if status.last_check.is_some() => "超时".to_string(),
                        None => "未测试".to_string(),
                    },
                    None => "未测试".to_string(),
                };
                if name == node_addr.as_str() {
                    ui.label(format!("{}. {}", i + 1, node_addr));
                } else {
                    ui.label(format!("{}. {}", i + 1, name))
                        .on_hover_text(node_addr.as_str());
                    ui.weak(node_addr.as_str());
                }
                ui.weak(format!("({})", latency_text));

                // 来源标记（手动 / 订阅名）——不同来源着色区分
                let source = self.config.node_source_label(node_addr);
                ui.colored_label(
                    if source == config::NODE_SOURCE_MANUAL {
                        egui::Color32::from_rgb(0xA8, 0xB0, 0xBC)
                    } else {
                        egui::Color32::from_rgb(0x7A, 0xB3, 0xFF)
                    },
                    format!("[{}]", source),
                );

                if ui.small_button("测试").clicked() {
                    self.start_node_test(node_addr.clone());
                }
                if ui.small_button("分享").clicked() {
                    self.open_share_dialog(node_addr.clone());
                }
                if ui.small_button("✏ 编辑").clicked() {
                    edit_target = Some(node_addr.clone());
                }
                if ui.small_button("删除").clicked() {
                    indices_to_remove.push(i);
                }
            });
        }

        // 删除节点并添加日志
        for &i in indices_to_remove.iter().rev() {
            let removed = self.config.node_addrs.remove(i);
            self.node_status.remove(&removed);
            self.config.node_names.remove(&removed);
            self.add_log(format!("已删除节点: {}", removed));
        }
        if let Some(addr) = edit_target {
            self.open_node_edit(&addr);
        }

        ui.separator();

        // ── Team-Q v2：导入节点（粘贴链接 / 二维码图片 / 链接文件）──
        ui.heading("导入节点");
        ui.add(
            egui::TextEdit::multiline(&mut self.import_text)
                .desired_rows(3)
                .hint_text("粘贴 hydra:// 分享链接（支持多行）"),
        );
        ui.horizontal(|ui| {
            if ui.button("导入粘贴的链接").clicked() {
                self.import_pasted_links();
            }
            if ui.button("从二维码图片导入").clicked() {
                self.import_from_qr_image();
            }
            if ui.button("从链接文件导入").clicked() {
                self.import_from_link_file();
            }
        });
        if let Some((ok, msg)) = &self.import_status {
            ui.colored_label(
                if *ok {
                    egui::Color32::from_rgb(0x7D, 0xE2, 0x97)
                } else {
                    egui::Color32::from_rgb(0xFF, 0x8A, 0x80)
                },
                format!("{} {}", if *ok { "✓" } else { "✗" }, msg),
            );
        }
        ui.small("完整分享含密钥/证书，导入后自动配置，无需再填密钥与证书文件");

        // ── Team-UI：订阅管理并入本页（原先与节点管理功能重叠的独立「订阅」页）──
        ui.separator();
        self.ui_subscription_section(ui);
    }

    /// 订阅管理（Exec-C，Team-UI 并入节点管理页）：添加 / 更新 / 删除，后台串行拉取
    fn ui_subscription_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("订阅管理");
        ui.small("订阅来源拉取的节点会自动加入上方节点列表，并以订阅名作为来源标记");
        ui.horizontal(|ui| {
            ui.label("名称:");
            ui.add(
                egui::TextEdit::singleline(&mut self.new_sub_name)
                    .desired_width(110.0)
                    .hint_text("可留空自动编号"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("来源:");
            ui.add(
                egui::TextEdit::singleline(&mut self.new_sub_source)
                    .desired_width(ui.available_width() - 80.0)
                    .hint_text("https://… / 文件路径 / hydra-sub://…"),
            );
            if ui.button("浏览...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("订阅文件", &["txt", "sub"])
                    .add_filter("全部文件", &["*"])
                    .pick_file()
                {
                    self.new_sub_source = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            if ui.button("➕ 添加订阅").clicked() {
                self.add_subscription();
            }
            if ui.button("🔄 更新全部订阅").clicked() {
                self.update_all_subscriptions();
            }
            if self.sub_update_receiver.is_some() {
                ui.label("⏳ 更新中...");
            }
        });

        // 订阅列表：名称 / 节点数 / 上次更新 + 单条更新/删除
        let subs_clone = self.config.subscriptions.clone();
        let mut subs_to_remove: Vec<usize> = Vec::new();
        for (i, sub) in subs_clone.iter().enumerate() {
            let updated = sub
                .last_updated_secs
                .and_then(|s| chrono::DateTime::from_timestamp(s as i64, 0))
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string()
                })
                .unwrap_or_else(|| "从未".to_string());
            ui.horizontal(|ui| {
                ui.label(format!(
                    "{}（{} 节点，更新: {}）",
                    sub.name,
                    sub.nodes.len(),
                    updated
                ));
                if ui.small_button("更新").clicked() {
                    self.queue_subscription_update(sub.name.clone(), sub.source.clone());
                }
                if ui.small_button("删除").clicked() {
                    subs_to_remove.push(i);
                }
            });
            ui.small(&sub.source);
        }
        for &i in subs_to_remove.iter().rev() {
            self.delete_subscription(i);
        }
    }

    /// 分享：批量导出（v1 地址信息）+ 使用说明；单节点分享从节点管理触发
    fn ui_share(&mut self, ui: &mut egui::Ui) {
        ui.heading("分享");
        ui.separator();
        ui.label("批量导出分享链接（v1 格式，仅含节点地址，不含密钥）:");
        if ui.button("批量导出分享链接").clicked() {
            self.export_share_links();
        }
        ui.separator();
        ui.heading("使用说明");
        ui.small("• 单节点分享：「🌐 节点管理」→ 节点列表 →「分享」，可生成二维码与完整/紧凑链接");
        ui.small("• 完整链接含认证密钥与证书，对方导入即用；仅限可信渠道发送");
        ui.small("• 紧凑链接仅含证书指纹，需另行发送证书文件");
        ui.small("• 导入：「🌐 节点管理」→「导入节点」，支持粘贴链接 / 二维码图片 / 链接文件");
        ui.small(
            "• 订阅节点：「🌐 节点管理」→「订阅管理」添加 http(s)/文件来源后点「更新」自动拉取",
        );
    }

    // ═══════════════ Team-UI：节点编辑对话框 ═══════════════

    /// 打开节点编辑对话框（备注名/地址 + 全局安全与传输参数）
    fn open_node_edit(&mut self, addr: &str) {
        self.edit_orig_addr = addr.to_string();
        self.edit_name = self
            .config
            .node_names
            .get(addr)
            .cloned()
            .unwrap_or_default();
        self.edit_addr = addr.to_string();
        self.edit_auth_key = self.config.auth_key.clone();
        self.edit_show_auth = false;
        self.edit_cert_path = self.config.cert_path.clone();
        self.edit_obfs_key = self.config.obfs_key.clone();
        self.edit_obfs = self.config.is_obfs();
        self.edit_show_obfs = false;
        self.node_edit_open = true;
    }

    /// 编辑对话框中证书区域的当前状态描述：文件路径（存在性）或内嵌 DER 指纹短哈希
    fn cert_status_text(cfg: &GuiConfig) -> String {
        let path = cfg.cert_path.trim();
        if !path.is_empty() {
            return if std::path::Path::new(path).exists() {
                format!("✓ 证书文件: {}", path)
            } else {
                format!("✗ 证书文件不存在: {}", path)
            };
        }
        let b64 = cfg.cert_der_b64.trim();
        if !b64.is_empty() {
            use base64::Engine as _;
            return match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(der) => format!(
                    "✓ 内嵌证书 DER（sha256 前 16 位: {}）",
                    &sha256_hex(&der)[..16]
                ),
                Err(_) => "✗ 内嵌证书数据损坏（base64 解码失败）".to_string(),
            };
        }
        "未设置（将回落 HYDRA_NODE_CERT 环境变量）".to_string()
    }

    /// 保存节点编辑：先全量校验（任一失败不改配置），再写回 + 迁移地址 + 提示重启代理
    fn save_node_edit(&mut self) {
        // ── 校验阶段 ──
        let new_addr = self.edit_addr.trim().to_string();
        if new_addr.parse::<SocketAddr>().is_err() {
            self.add_log(format!(
                "节点编辑保存失败:「{}」不是有效的 地址:端口（示例 1.2.3.4:4433）",
                new_addr
            ));
            return;
        }
        let addr_changed = new_addr != self.edit_orig_addr;
        if addr_changed && self.config.node_addrs.contains(&new_addr) {
            self.add_log(format!("节点编辑保存失败: 地址 {} 已存在于列表", new_addr));
            return;
        }
        let key = self.edit_auth_key.trim().to_string();
        if !key.is_empty() {
            if let Err(e) = hydra_client::auth_key_from_hex(&key) {
                self.add_log(format!("节点编辑保存失败: 认证密钥无效 — {}", e));
                return;
            }
        }
        let cert_path = self.edit_cert_path.trim().to_string();
        if !cert_path.is_empty() && !std::path::Path::new(&cert_path).exists() {
            self.add_log(format!(
                "节点编辑保存失败: 证书文件不存在 {}（可清空路径改用内嵌证书）",
                cert_path
            ));
            return;
        }
        let obfs_key = self.edit_obfs_key.trim().to_string();
        let obfs = self.edit_obfs;

        // ── 写回阶段（不会再失败）──
        let orig = self.edit_orig_addr.clone();
        if addr_changed {
            self.config.rename_node(&orig, &new_addr);
            // 运行时状态表同步换键
            if let Some(st) = self.node_status.remove(&orig) {
                self.node_status.insert(new_addr.clone(), st);
            }
        }
        self.config.set_node_name(&new_addr, &self.edit_name.trim());
        self.config.auth_key = key;
        self.config.cert_path = cert_path;
        self.config.obfs_key = obfs_key;
        self.config.hydra_mode = if obfs {
            "obfs".to_string()
        } else {
            "masquerade".to_string()
        };
        self.node_edit_open = false;
        self.add_log(format!("节点 {} 已保存", new_addr));
        // 全局参数（密钥/证书/模式）只在代理启动时读取，运行中修改必须重启才生效
        if self.proxy_running {
            self.add_log(
                "⚠ 代理正在运行：本次修改（密钥/证书/模式/地址）需停止并重新启动代理后才生效"
                    .to_string(),
            );
        }
    }

    /// 节点编辑对话框 UI（egui::Window，实时校验提示）
    fn ui_node_edit_dialog(&mut self, ctx: &egui::Context) {
        let mut save_clicked = false;
        egui::Window::new(format!("编辑节点 {}", self.edit_orig_addr))
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label("节点信息（仅本节点）");
                egui::Grid::new("node_edit_grid")
                    .num_columns(2)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("备注名:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_name)
                                .desired_width(260.0)
                                .hint_text("可选，如「家里节点」"),
                        );
                        ui.end_row();
                        ui.label("地址:端口:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_addr)
                                .desired_width(260.0)
                                .hint_text("1.2.3.4:4433"),
                        );
                        ui.end_row();
                    });
                if !self.edit_addr.trim().is_empty()
                    && self.edit_addr.trim().parse::<SocketAddr>().is_err()
                {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0x8A, 0x80),
                        "✗ 地址格式应为 host:port（示例 1.2.3.4:4433 / [::1]:4433）",
                    );
                }

                ui.separator();
                ui.label("安全与传输（当前全局配置，所有节点共用）");

                // 认证密钥（默认掩码）
                ui.horizontal(|ui| {
                    ui.label("认证密钥:");
                    if self.edit_show_auth {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_auth_key)
                                .desired_width(240.0),
                        );
                        if ui.small_button("隐藏").clicked() {
                            self.edit_show_auth = false;
                        }
                    } else {
                        let shown = if self.edit_auth_key.trim().is_empty() {
                            "（未设置）".to_string()
                        } else {
                            config::mask_secret(self.edit_auth_key.trim())
                        };
                        ui.monospace(shown);
                        if ui.small_button("编辑/显示").clicked() {
                            self.edit_show_auth = true;
                        }
                    }
                });
                if self.edit_show_auth && !self.edit_auth_key.trim().is_empty() {
                    match hydra_client::auth_key_from_hex(self.edit_auth_key.trim()) {
                        Ok(_) => ui.colored_label(
                            egui::Color32::from_rgb(0x7D, 0xE2, 0x97),
                            "✓ 密钥格式有效",
                        ),
                        Err(e) => ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0x8A, 0x80),
                            format!("✗ {}", e),
                        ),
                    };
                }

                // 证书：当前状态（路径/内嵌指纹短哈希）+ 浏览替换
                ui.label("节点证书:");
                ui.small(Self::cert_status_text(&self.config));
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.edit_cert_path)
                            .desired_width(320.0)
                            .hint_text("证书文件路径（清空则使用内嵌证书）"),
                    );
                    if ui.small_button("浏览替换...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("证书文件", &["der", "pem", "crt", "cer"])
                            .add_filter("全部文件", &["*"])
                            .pick_file()
                        {
                            self.edit_cert_path = path.display().to_string();
                        }
                    }
                });

                // 传输模式 + obfs 密码
                ui.horizontal(|ui| {
                    ui.label("传输模式:");
                    if ui.radio(!self.edit_obfs, "伪装 masquerade").clicked() && self.edit_obfs {
                        self.edit_obfs = false;
                    }
                    if ui.radio(self.edit_obfs, "混淆 obfs").clicked() && !self.edit_obfs {
                        self.edit_obfs = true;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("obfs 密码:");
                    if self.edit_show_obfs {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_obfs_key)
                                .desired_width(240.0),
                        );
                        if ui.small_button("隐藏").clicked() {
                            self.edit_show_obfs = false;
                        }
                    } else {
                        let shown = if self.edit_obfs_key.is_empty() {
                            "（未设置）".to_string()
                        } else {
                            config::mask_secret(self.edit_obfs_key.trim())
                        };
                        ui.monospace(shown);
                        if ui.small_button("编辑/显示").clicked() {
                            self.edit_show_obfs = true;
                        }
                    }
                });
                if self.edit_obfs && self.edit_obfs_key.trim().is_empty() {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xD6, 0x66),
                        "⚠ obfs 模式要求独立第二密码，否则代理无法启动",
                    );
                }

                if self.proxy_running {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xD6, 0x66),
                        "⚠ 代理正在运行：保存后需停止并重新启动代理，修改才会生效",
                    );
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("💾 保存").strong()))
                        .clicked()
                    {
                        save_clicked = true;
                    }
                    if ui.button("取消").clicked() {
                        self.node_edit_open = false;
                    }
                });
            });
        if save_clicked {
            self.save_node_edit();
        }
    }

    /// 设置：代理监听 / 安全与传输 / 托盘行为 / 密钥证书 / 退出
    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("设置");
        ui.separator();

        // 代理监听
        ui.heading("代理监听");
        ui.horizontal(|ui| {
            ui.label("监听地址:");
            ui.text_edit_singleline(&mut self.config.proxy_listen_addr);
        });
        ui.separator();

        // ── Exec-1：安全与传输设置（配置文件 > 环境变量，自动持久化）──
        ui.heading("安全与传输");
        if ui.button("新手引导").clicked() {
            for line in HydraApp::wizard_lines() {
                self.add_log(line);
            }
        }

        // 认证密钥：默认掩码显示（如 a1b2****8f90），点击「编辑/显示」查看并编辑明文
        ui.horizontal(|ui| {
            ui.label("认证密钥:");
            if self.show_auth_key {
                ui.add(egui::TextEdit::singleline(&mut self.config.auth_key).desired_width(170.0));
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
        } else if !self.config.cert_der_b64.trim().is_empty() {
            // Team-Q v2：完整分享导入的内嵌证书（无需文件）
            ui.label("✓ 使用分享链接导入的证书（未设置证书文件）");
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
                ui.add(egui::TextEdit::singleline(&mut self.config.obfs_key).desired_width(170.0));
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
            if self.config.probe_interval_secs.is_some() && ui.small_button("默认").clicked() {
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

        // ── T2：托盘行为 ──
        ui.heading("托盘行为");
        if ui
            .checkbox(
                &mut self.config.close_to_tray,
                "关闭窗口时隐藏到系统托盘（代理继续运行）",
            )
            .changed()
        {
            self.add_log(if self.config.close_to_tray {
                "关窗行为：隐藏到系统托盘".to_string()
            } else {
                "关窗行为：直接退出（停止代理并清理系统代理）".to_string()
            });
        }
        ui.small("托盘左键单击 = 显示/隐藏主窗；托盘右键菜单 = 显示主窗 / 启动 / 停止 / 退出");

        ui.separator();

        // 退出入口（原「文件→退出」菜单迁移至此；托盘菜单同样可退出）
        if ui.button("退出程序（停止代理并清理系统代理）").clicked() {
            if self.proxy_running {
                self.stop_proxy();
            }
            self.really_quit = true;
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    /// 运行日志（保留自动滚动 + 清空/刷新）
    fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("运行日志");
        ui.separator();

        // 日志显示区域（stick_to_bottom：新日志自动滚动到底）
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
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
                ui.ctx().request_repaint();
            }
        });
    }
}

/// Team-UI：统一深色主题。
///
/// 根因说明：旧版 `apply_dark_theme` 从 egui 默认 style（**浅色 Visuals**）出发，
/// 只改了圆角/选中色/个别 fg_stroke，从未设置 `Visuals::dark()`——
/// 因此面板背景保持白色，而按深底设计的淡灰文字落在白底上不可读。
/// 修复：以 `Visuals::dark()` 为基底整体替换，再叠加高对比配色与圆角/间距；
/// SidePanel/CentralPanel/Window 均未单独设置 fill，全部走 visuals，一处生效全局生效。
///
/// 对比度清单（正文对各自背景，WCAG 相对亮度计算）：
/// - 正文 TEXT   #E8EAED（相对亮度≈0.79）on 面板底 #1B1E24（≈0.012）→ ≈13.5:1
/// - 次要 WEAK   #A8B0BC（≈0.43）on #1B1E24 → ≈7.7:1（ui.small/来源标记仍达标）
/// - 强调 ACCENT #7AB3FF（≈0.44）on #1B1E24 → ≈7.9:1
/// - 成功 GREEN  #7DE297（≈0.63）on #1B1E24 → ≈11:1
/// - 警告 YELLOW #FFD666（≈0.70）on #1B1E24 → ≈12:1
/// - 错误 RED    #FF8A80（≈0.42）on #1B1E24 → ≈7.6:1
/// - 输入框文字  #E8EAED on 输入框底 #121418（≈0.006）→ ≈14.6:1
fn apply_dark_theme(ctx: &egui::Context) {
    const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x1B, 0x1E, 0x24);
    const BG_WINDOW: egui::Color32 = egui::Color32::from_rgb(0x22, 0x26, 0x2E);
    const BG_EXTREME: egui::Color32 = egui::Color32::from_rgb(0x12, 0x14, 0x18);
    const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE8, 0xEA, 0xED);
    const WEAK: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB0, 0xBC);
    const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);

    let mut style = (*ctx.style()).clone();
    // 关键修复：以深色 Visuals 为基底（默认是 light = 白底）
    style.visuals = egui::Visuals::dark();
    let vis = &mut style.visuals;
    // 面板/窗口/输入框背景统一深色
    vis.panel_fill = BG_PANEL;
    vis.window_fill = BG_WINDOW;
    vis.extreme_bg_color = BG_EXTREME; // TextEdit / 折叠区背景
    vis.faint_bg_color = egui::Color32::from_rgb(0x24, 0x28, 0x30); // 斑马纹/弱分隔
                                                                    // 文字：正文高对比，次要文字（ui.small / weak）仍 ≥7:1
    vis.override_text_color = Some(TEXT);
    vis.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, WEAK); // 分隔线文字等
    vis.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, TEXT);
    vis.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
    vis.widgets.active.fg_stroke = egui::Stroke::new(1.5_f32, ACCENT);
    vis.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
    vis.hyperlink_color = ACCENT;
    // 选中态
    vis.selection.bg_fill = ACCENT.gamma_multiply(0.45);
    vis.selection.stroke = egui::Stroke::new(1.0_f32, ACCENT);
    // 圆角 / 行间距
    vis.window_rounding = egui::Rounding::same(6.0);
    vis.menu_rounding = egui::Rounding::same(6.0);
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    ctx.set_style(style);
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
