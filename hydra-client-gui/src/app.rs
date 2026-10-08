//! HydraApp 应用骨架：构造/析构、配置差分防抖落盘、日志入口、
//! 启动大按钮状态机（纯函数，UI 渲染与单测共用）。

use crate::config;
use crate::config::GuiConfig;
use crate::nodes::{NodeStatusInfo, Tab};
use crate::theme::{apply_dark_theme, setup_custom_fonts};
use crate::tray;
use crate::HydraApp;
use crate::speed_history::SpeedHistory;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

impl Default for HydraApp {
    fn default() -> Self {
        Self {
            proxy_running: false,
            proxy_start_receiver: None,
            proxy_bound_addr: None,
            proxy_starting: false,
            logs: Vec::new(),
            config: GuiConfig::default(),
            saved_snapshot: GuiConfig::default(),
            last_config_save: None,
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
            import_status: None,
            import_dialog_open: false,
            import_group_name: String::new(),
            import_paste_text: String::new(),
            manual_add_open: false,
            manual_group_name: String::new(),
            manual_form_addr: String::new(),
            manual_form_port: String::new(),
            manual_form_cert_path: String::new(),
            manual_add_status: None,
            share_pick_open: false,
            node_testing_addr: None,
            node_group: None,
            pending_node_tests: VecDeque::new(),
            sub_add_open: false,
            show_auth_key: false,
            node_edit_open: false,
            edit_orig_addr: String::new(),
            edit_name: String::new(),
            edit_addr: String::new(),
            edit_auth_key: String::new(),
            edit_show_auth: false,
            edit_cert_path: String::new(),
            expanded_sub: None,
            sub_edit_idx: None,
            sub_edit_name: String::new(),
            sub_edit_source: String::new(),
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status: HashMap::new(),
            last_health_check: None,
            health_check_receiver: None,
            node_test_receiver: None,
            qr_import_receiver: None,
            traffic_monitor: None,
            traffic_stats_cache: Arc::new(std::sync::Mutex::new(None)),
            traffic_sampler_stop: None,
            traffic_history: Arc::new(std::sync::Mutex::new(SpeedHistory::new())),
            conn_snapshot: Vec::new(),
            conn_prev: HashMap::new(),
            conn_rates: HashMap::new(),
            conn_last_refresh: None,
            tray: None,
            current_tab: Tab::Overview,
            really_quit: false,
            last_tray_tooltip: String::new(),
            tun_shutdown: None,
            #[cfg(windows)]
            sys_proxy_check_cache: None,
            #[cfg(windows)]
            sys_proxy_check_receiver: None,
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

/// 启动大按钮状态机（问题 1）：把「按钮文字 + 是否可点」收口为纯函数，
/// UI 渲染与单测共用同一套转换规则。
/// - 停止态：「▶ 启动代理」可点；
/// - 启动期（proxy_starting，bound 未就绪）：「⏳ 启动中…」且禁用——用户点击后
///   立即可见反馈，不再"看似没反应"；重复点击也被禁用天然拦截；
/// - 运行态（bound 就绪）：「■ 停止代理」可点；
/// - 失败/异常退出：poll_start_receiver / 异常退出分支把两个状态位复位，
///   自然回到「▶ 启动代理」，日志区给出失败根因。
pub(crate) fn start_button_state(proxy_running: bool, proxy_starting: bool) -> (&'static str, bool) {
    if proxy_running {
        ("■ 停止代理", true)
    } else if proxy_starting {
        ("⏳ 启动中…", false)
    } else {
        ("▶ 启动代理", true)
    }
}

impl HydraApp {

    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
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

        // 探测间隔：配置非空 → 覆盖 env（hydra-client 内部从 env 读取）。
        // 必须在任何工作线程 spawn 之前执行，避免 env 并发读写。
        config::apply_env_overrides(&cfg);

        // 节点状态表初始化
        let mut node_status = HashMap::new();
        for addr in &cfg.node_addrs {
            node_status.insert(
                addr.clone(),
                NodeStatusInfo {
                    connected: false,
                    last_check: None,
                    latency_ms: None,
                },
            );
        }

        let mut app = Self {
            proxy_running: false,
            proxy_start_receiver: None,
            proxy_bound_addr: None,
            proxy_starting: false,
            logs: Vec::new(),
            saved_snapshot: cfg.clone(),
            last_config_save: None,
            config: cfg,
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
            import_status: None,
            import_dialog_open: false,
            import_group_name: String::new(),
            import_paste_text: String::new(),
            manual_add_open: false,
            manual_group_name: String::new(),
            manual_form_addr: String::new(),
            manual_form_port: String::new(),
            manual_form_cert_path: String::new(),
            manual_add_status: None,
            share_pick_open: false,
            node_testing_addr: None,
            node_group: None,
            pending_node_tests: VecDeque::new(),
            sub_add_open: false,
            show_auth_key: false,
            node_edit_open: false,
            edit_orig_addr: String::new(),
            edit_name: String::new(),
            edit_addr: String::new(),
            edit_auth_key: String::new(),
            edit_show_auth: false,
            edit_cert_path: String::new(),
            expanded_sub: None,
            sub_edit_idx: None,
            sub_edit_name: String::new(),
            sub_edit_source: String::new(),
            stop_flag: None,
            proxy_thread_handle: None,
            proxy_exit_receiver: None,
            node_status,
            last_health_check: None,
            health_check_receiver: None,
            node_test_receiver: None,
            qr_import_receiver: None,
            traffic_monitor: None,
            traffic_stats_cache: Arc::new(std::sync::Mutex::new(None)),
            traffic_sampler_stop: None,
            traffic_history: Arc::new(std::sync::Mutex::new(SpeedHistory::new())),
            conn_snapshot: Vec::new(),
            conn_prev: HashMap::new(),
            conn_rates: HashMap::new(),
            conn_last_refresh: None,
            current_tab: Tab::Overview,
            tray,
            really_quit: false,
            last_tray_tooltip: "Hydra 代理已停止".to_string(),
            tun_shutdown: None,
            #[cfg(windows)]
            sys_proxy_check_cache: None,
            #[cfg(windows)]
            sys_proxy_check_receiver: None,
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
                "配置已加载，但认证密钥或节点证书路径尚未填写，请在「⚙ 设置」页「全局凭据」区补全"
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
    pub(crate) fn wizard_lines() -> Vec<String> {
        let cfg_path = config::config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(配置目录不可用)".to_string());
        vec![
            "═══ 首次使用向导 ═══".to_string(),
            "① 填写认证密钥：「⚙ 设置」页「全局凭据」折叠区 → 认证密钥 → 点「编辑/显示」输入 hex 密钥"
                .to_string(),
            "② 选择节点证书文件：同区「节点证书」→ 点「浏览...」选择节点生成的 hydra-node-cert.der"
                .to_string(),
            "③ 添加节点/分组：「📡 订阅」页右上角「＋ 新建」→「✏️ 手动添加节点」（创建命名分组）"
                .to_string(),
            "④ 点「🏠 首页」页的大按钮「▶ 启动代理」即可使用".to_string(),
            format!(
                "完成一次后配置自动保存到 {}，以后双击本程序即可直接使用",
                cfg_path
            ),
        ]
    }

    /// 差分 + 防抖保存：配置与上次落盘快照不同才写；force=true（启停/退出）跳过防抖立即写。
    pub(crate) fn maybe_save_config(&mut self, force: bool) {
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

    pub(crate) fn add_log(&mut self, message: String) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 问题 1：启动按钮状态机转换 ──

    #[test]
    fn start_button_state_transitions() {
        // 停止态：可点「启动代理」
        assert_eq!(start_button_state(false, false), ("▶ 启动代理", true));
        // 启动期（proxy_starting，bound 未就绪）：显示「启动中…」且禁用——
        // 用户点击后立即可见反馈，修复"点了没反应"
        assert_eq!(start_button_state(false, true), ("⏳ 启动中…", false));
        // bound 就绪：变「停止代理」可点
        assert_eq!(start_button_state(true, false), ("■ 停止代理", true));
        // 运行态下 starting 残留（不可能出现，但规则应保持确定）：以 running 优先
        assert_eq!(start_button_state(true, true), ("■ 停止代理", true));
    }
}
