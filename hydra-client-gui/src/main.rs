use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use hydra_client::{Scheduler, ProxyServer, Transport, parse_share_links, generate_share_links};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::net::SocketAddr;
use std::collections::HashMap;

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
    proxy_addr: String,
    nodes: Vec<NodeInfo>,
    logs: Vec<String>,
    config: AppConfig,

    // 分享链接相关
    share_link_text: String,
    show_share_link_dialog: bool,

    // 运行时状态
    scheduler: Option<Arc<Scheduler>>,
    transport: Option<Arc<Transport>>,
    stop_flag: Option<Arc<AtomicBool>>,
    proxy_thread_handle: Option<std::thread::JoinHandle<()>>,
    proxy_exit_receiver: Option<std::sync::mpsc::Receiver<()>>,

    // 节点连接状态
    node_status: HashMap<String, NodeStatusInfo>,
    last_health_check: Option<std::time::Instant>,
}

impl Default for HydraApp {
    fn default() -> Self {
        Self {
            proxy_running: false,
            proxy_addr: String::new(),
            nodes: Vec::new(),
            logs: Vec::new(),
            config: AppConfig::default(),
            share_link_text: String::new(),
            show_share_link_dialog: false,
            scheduler: None,
            transport: None,
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status: HashMap::new(),
            last_health_check: None,
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

#[derive(Default, Clone)]
struct AppConfig {
    proxy_addr: String,
    node_addrs: Vec<String>,
}

impl HydraApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // 设置自定义字体
        setup_custom_fonts(&cc.egui_ctx);

        let node_addrs = vec!["127.0.0.1:8080".to_string()];
        let mut node_status = HashMap::new();
        for addr in &node_addrs {
            node_status.insert(addr.clone(), NodeStatusInfo {
                addr: addr.clone(),
                connected: false,
                last_check: None,
                latency_ms: None,
            });
        }

        Self {
            proxy_running: false,
            proxy_addr: "127.0.0.1:1080".to_string(),
            nodes: Vec::new(),
            logs: Vec::new(),
            config: AppConfig {
                proxy_addr: "127.0.0.1:1080".to_string(),
                node_addrs,
            },
            share_link_text: String::new(),
            show_share_link_dialog: false,
            scheduler: None,
            transport: None,
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status,
            last_health_check: None,
        }
    }

    /// Test connectivity to a single node
    async fn test_node_connection(addr_str: &str) -> Option<(bool, u64)> {
        let addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return None,
        };

        let start = std::time::Instant::now();
        let transport = match Transport::new_client().await {
            Ok(t) => t,
            Err(_) => return None,
        };

        let connected = transport.test_connection(addr, 3000).await;
        let elapsed = start.elapsed().as_millis() as u64;

        Some((connected, elapsed))
    }

    /// Test all nodes and update status
    fn test_all_nodes(&mut self) {
        let node_addrs = self.config.node_addrs.clone();
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                for addr in &node_addrs {
                    let result = Self::test_node_connection(addr).await;
                    let _ = tx.send((addr.clone(), result));
                }
            });
        });

        // Collect results with timeout
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok((addr, Some((connected, latency)))) => {
                    self.node_status.insert(addr.clone(), NodeStatusInfo {
                        addr: addr.clone(),
                        connected,
                        last_check: Some(std::time::Instant::now()),
                        latency_ms: Some(latency),
                    });
                    if connected {
                        self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                    } else {
                        self.add_log(format!("节点 {} 连接失败", addr));
                    }
                }
                Ok((addr, None)) => {
                    self.node_status.insert(addr.clone(), NodeStatusInfo {
                        addr: addr.clone(),
                        connected: false,
                        last_check: Some(std::time::Instant::now()),
                        latency_ms: None,
                    });
                    self.add_log(format!("节点 {} 测试失败", addr));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                Err(_) => break,
            }
        }
        self.last_health_check = Some(std::time::Instant::now());
    }
    
    fn add_log(&mut self, message: String) {
        self.logs.push(format!("[{}] {}", chrono::Local::now().format("%H:%M:%S"), message));
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

        let proxy_addr: SocketAddr = match self.proxy_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                self.add_log(format!("地址解析错误: {}", e));
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

        // 解析节点地址（只使用可达的节点）
        let mut nodes = Vec::new();
        let node_addrs = self.config.node_addrs.clone();
        for node_addr in &node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                // 如果节点状态显示已连接，添加到节点列表
                if let Some(status) = self.node_status.get(node_addr.as_str()) {
                    if status.connected {
                        nodes.push(addr);
                        self.add_log(format!("添加节点: {} (已验证)", addr));
                    } else {
                        self.add_log(format!("跳过节点: {} (不可达)", addr));
                    }
                } else {
                    // 未测试的节点也添加（向后兼容）
                    nodes.push(addr);
                    self.add_log(format!("添加节点: {} (未验证)", addr));
                }
            }
        }

        if nodes.is_empty() {
            self.add_log("错误: 没有可用节点，代理启动取消".to_string());
            return;
        }

        // 使用独立线程运行代理
        let (tx, rx) = std::sync::mpsc::channel::<std::result::Result<(), std::io::Error>>();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let proxy_addr_clone = proxy_addr;
        let nodes_clone = nodes.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let proxy = ProxyServer::new(proxy_addr_clone).with_nodes(nodes_clone);
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

    fn set_system_proxy(&self, proxy_url: &str) {
        // 设置环境变量
        std::env::set_var("http_proxy", proxy_url);
        std::env::set_var("https_proxy", proxy_url);
        std::env::set_var("all_proxy", proxy_url);
        std::env::set_var("HTTP_PROXY", proxy_url);
        std::env::set_var("HTTPS_PROXY", proxy_url);
        std::env::set_var("ALL_PROXY", proxy_url);

        // 设置 GNOME 桌面代理
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .output();

        // 设置 SOCKS 代理
        let socks_port = proxy_url.split(':').last().unwrap_or("1080");
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"])
            .output();
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", socks_port])
            .output();
    }

    fn remove_system_proxy_static() {
        // 清除环境变量
        std::env::remove_var("http_proxy");
        std::env::remove_var("https_proxy");
        std::env::remove_var("all_proxy");
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("ALL_PROXY");

        // 清除 GNOME 桌面代理
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .output();
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
            if should_check {
                self.test_all_nodes();
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
                let mut new_node = String::new();
                ui.text_edit_singleline(&mut new_node);
                if ui.button("添加").clicked() {
                    if !new_node.is_empty() {
                        // 初始化节点状态
                        self.node_status.insert(new_node.clone(), NodeStatusInfo {
                            addr: new_node.clone(),
                            connected: false,
                            last_check: None,
                            latency_ms: None,
                        });
                        self.config.node_addrs.push(new_node.clone());
                        self.add_log(format!("添加节点配置: {}", new_node));
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
                    let status_icon = if let Some(status) = self.node_status.get(node_addr.as_str()) {
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
                    let label_text = if let Some(status) = self.node_status.get(node_addr.as_str()) {
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
                        let addr = node_addr.clone();
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            let result = rt.block_on(async {
                                Self::test_node_connection(&addr).await
                            });
                            let _ = tx.send((addr, result));
                        });
                        // 收集结果
                        if let Ok((addr, Some((connected, latency)))) = rx.recv_timeout(std::time::Duration::from_secs(5)) {
                            self.node_status.insert(addr.clone(), NodeStatusInfo {
                                addr: addr.clone(),
                                connected,
                                last_check: Some(std::time::Instant::now()),
                                latency_ms: Some(latency),
                            });
                            if connected {
                                self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                            } else {
                                self.add_log(format!("节点 {} 连接失败", addr));
                            }
                        }
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
                ui.text_edit_singleline(&mut self.proxy_addr);
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
            
            // 状态信息
            ui.heading("状态信息");
            ui.label(format!("代理状态: {}", if self.proxy_running { "运行中" } else { "已停止" }));

            let connected_count = self.node_status.values().filter(|s| s.connected).count();
            let total_count = self.config.node_addrs.len();
            ui.label(format!("节点数量: {} / {} 可用", connected_count, total_count));

            if let Some(last_check) = self.last_health_check {
                let elapsed = last_check.elapsed().as_secs();
                ui.label(format!("上次检测: {}秒前", elapsed));
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
    fonts.families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("noto_sans_cjk".to_owned());
    
    fonts.families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("noto_sans_cjk".to_owned());
    
    ctx.set_fonts(fonts);
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 设置 panic hook，确保代理异常时清除系统代理
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // 清除系统代理
        HydraApp::remove_system_proxy_static();
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