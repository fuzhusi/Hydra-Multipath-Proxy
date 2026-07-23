use eframe::egui;
use std::sync::Arc;
use tokio::sync::RwLock;
use hydra_client::{Scheduler, ProxyServer, Transport, ShareLink, parse_share_links, generate_share_links};
use hydra_protocol::{NodeInfo, NodeStatus, Result};
use std::net::SocketAddr;
use std::collections::HashMap;

#[derive(Default)]
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
        
        Self {
            proxy_addr: "127.0.0.1:1080".to_string(),
            nodes: Vec::new(),
            logs: Vec::new(),
            config: AppConfig {
                proxy_addr: "127.0.0.1:1080".to_string(),
                node_addrs: vec!["127.0.0.1:8080".to_string()],
            },
            ..Default::default()
        }
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

        // 解析节点地址
        let mut nodes = Vec::new();
        let mut logs_to_add = Vec::new();
        for node_addr in &self.config.node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                nodes.push(addr);
                logs_to_add.push(format!("添加节点: {}", addr));
            }
        }

        // 添加日志
        for log in logs_to_add {
            self.add_log(log);
        }

        // 使用独立线程运行代理
        let (tx, rx) = std::sync::mpsc::channel::<std::result::Result<(), std::io::Error>>();
        let proxy_addr_clone = proxy_addr;
        let nodes_clone = nodes.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let proxy = ProxyServer::new(proxy_addr_clone).with_nodes(nodes_clone);
                // 发送启动信号
                let _ = tx.send(Ok(()));
                if let Err(e) = proxy.start().await {
                    eprintln!("代理错误: {}", e);
                }
            });
        });

        // 等待代理启动
        match rx.recv() {
            Ok(Ok(())) => {
                // 等待端口绑定
                std::thread::sleep(std::time::Duration::from_millis(100));
                self.proxy_running = true;
                self.add_log(format!("代理已启动，监听地址: {}", proxy_addr));
            }
            Ok(Err(e)) => {
                self.add_log(format!("代理启动失败: {}", e));
            }
            Err(e) => {
                self.add_log(format!("代理启动错误: {}", e));
            }
        }
    }
    
    fn stop_proxy(&mut self) {
        // 代理会在下次连接时检测到端口关闭而停止
        self.proxy_running = false;
        self.add_log("代理已停止（请重启应用以完全释放端口）".to_string());
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
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                        self.config.node_addrs.push(new_node.clone());
                        self.add_log(format!("添加节点配置: {}", new_node));
                    }
                }
            });
            
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
            for (i, node_addr) in self.config.node_addrs.clone().iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("{}. {}", i + 1, node_addr));
                    if ui.button("删除").clicked() {
                        indices_to_remove.push(i);
                    }
                });
            }
            
            // 删除节点并添加日志
            for &i in indices_to_remove.iter().rev() {
                let removed = self.config.node_addrs.remove(i);
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
            ui.label(format!("节点数量: {}", self.config.node_addrs.len()));
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