// Windows 下隐藏随 GUI 弹出的终端窗口（无条件：GUI 有应用内日志页，控制台
// 只在拖累体验——用户反馈 debug 运行时背后常驻黑色命令行窗口）
#![cfg_attr(windows, windows_subsystem = "windows")]

//! Hydra GUI 主入口（crate root）：模块树 + `HydraApp` 状态中心 + 启动。
//!
//! 模块地图（2026-10 模块化拆分，见 docs/improvement/施工方案-GUI-mainrs模块化拆分.md）：
//! - 纯逻辑层  palette / speed_history / nodes / groups / probe / theme / windows_proxy
//! - 动作层    app（骨架）/ node_test / proxy_control / share_io / subscription_actions
//! - UI 层     ui_shell（eframe 主循环 + 托盘接线）/ ui_overview / ui_nodes /
//!   ui_subscriptions / ui_node_edit / ui_settings / ui_logs / ui_connections
//! - 既有模块  config / qr / subscription / tray / icon
//!
//! `struct HydraApp` 留在 crate root：Rust 隐私模型下 root 类型的私有字段对全 crate
//! 子模块可见，各模块的 `impl HydraApp` 块因此无需给字段加 pub(crate)。

use eframe::egui;
use hydra_client::{ShareLink, TrafficMonitor, TrafficStats};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

mod app;
mod config;
mod groups;
mod icon;
mod node_test;
mod nodes;

/// 视觉规范化第一步（UI 重设计第一批）：集中式色板 + 字号层级 + 延迟/状态色标。
/// 全部 UI 用色只允许引用本模块常量，禁止在页面代码里再写散落的 from_rgb。
mod palette;
mod components;

mod probe;
mod proxy_control;
mod qr;
mod share_io;
mod speed_history;
mod subscription;
mod subscription_actions;
mod theme;
mod tray;
mod ui_connections;
mod ui_logs;
mod ui_node_edit;
mod ui_nodes;
mod ui_overview;
mod ui_settings;
mod ui_shell;
mod ui_subscriptions;

/// Windows 系统代理注册表操作（A1）：enable / disable / WinINet 刷新。
#[cfg(windows)]
mod windows_proxy;

use config::GuiConfig;
use nodes::{NodeStatusInfo, Tab};
use speed_history::SpeedHistory;

/// 运行日志级别（LG-01：结构化级别 + 着色 + 过滤）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogLevel {
    Info,
    Warn,
    Error,
}

/// 日志容量（评审决策：100 行 → 1000，排障核心场景）
pub(crate) const LOG_CAPACITY: usize = 1000;

struct HydraApp {
    // 应用状态
    proxy_running: bool,
    proxy_start_receiver: Option<
        std::sync::mpsc::Receiver<std::result::Result<std::net::SocketAddr, std::io::Error>>,
    >,
    proxy_starting: bool,
    /// 代理监听地址（09-P1-6：TUN 失败降级回退系统代理时需要；就绪信号携带）
    proxy_bound_addr: Option<std::net::SocketAddr>,
    logs: Vec<(crate::LogLevel, String)>,
    confirm_state: Option<crate::components::ConfirmAction>,
    dialog_cancel_requested: bool,
    /// 日志级别过滤（LG-01）
    log_show_info: bool,
    log_show_warn: bool,
    log_show_error: bool,
    /// 持久化配置（配置文件 > 环境变量，见 config.rs）
    config: GuiConfig,
    /// 最近一次成功落盘的配置快照（用于差分 + 防抖保存）
    saved_snapshot: GuiConfig,
    last_config_save: Option<std::time::Instant>,

    // 输入状态
    // （手动添加已表单化：原 new_node_input 单行 host:port 输入移除，见 manual_form_* 字段）

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
    // 「＋ → 从分享链接导入」对话框：最近一次导入结果提示（成功绿/失败红）
    import_status: Option<(bool, String)>,
    /// UI 重设计第一批：「＋ → 从分享链接导入」对话框开关（原节点页内联导入区迁入）
    import_dialog_open: bool,
    /// 分享导入分组的名称输入（默认自动生成「分享导入N」避重；重名校验与 add_subscription 同规则）
    import_group_name: String,
    /// 分享导入粘贴文本（多行 hydra:// 链接 / base64 订阅文本；导入语义 = import_share_links_as_group）
    import_paste_text: String,
    /// UI 重设计第一批：「＋ → 手动添加节点」对话框开关（原页顶输入行迁入）
    manual_add_open: bool,
    /// 手动添加分组的名称输入（默认自动生成「手动节点N」避重）
    manual_group_name: String,
    /// 手动添加表单：服务器地址（IP 或域名均可）
    manual_form_addr: String,
    /// 手动添加表单：端口文本（默认 443，提交时按 1..=65535 校验）
    manual_form_port: String,
    /// 手动添加表单：证书文件路径（可选；写入 node_cert_paths 按节点独立证书）
    manual_form_cert_path: String,
    /// 手动添加对话框：最近一次提交结果提示（成功绿/失败红，失败不关窗）
    manual_add_status: Option<(bool, String)>,
    /// UI 重设计第一批：「＋ → 分享节点」按节点选择对话框开关（批量导出也在其中）
    share_pick_open: bool,
    /// 正在单节点测速的节点地址（卡片上显示 spinner；None = 无进行中的单测）
    node_testing_addr: Option<String>,

    // ── UI 重设计第二批：节点页组视图（复刻 Clash Meta 代理组 tabs）──
    /// 当前选中的节点组：None=全部，Some("manual")=手动，Some(订阅名)=该订阅认领
    node_group: Option<String>,
    /// 组级测速队列（逐个 start_node_test，复用单测互斥通道；完成后自动取下一个）
    pending_node_tests: VecDeque<String>,
    /// 订阅页「＋ 新建 → 📡 添加订阅源」对话框开关（原平铺添加行收进对话框）
    sub_add_open: bool,

    // 密钥明文显示开关（默认掩码显示）
    show_auth_key: bool,

    // ── UI 重设计 v2：订阅页展开查看归属节点 + 订阅编辑对话框 ──
    /// 当前展开归属节点列表的订阅名（None = 全部收起）
    expanded_sub: Option<String>,
    /// 订阅编辑对话框：被编辑订阅在列表中的下标
    sub_edit_idx: Option<usize>,
    sub_edit_name: String,
    sub_edit_source: String,

    // ── Team-UI：节点编辑对话框（备注名/地址 + 全局安全参数，实时校验）──
    node_edit_open: bool,
    /// 被编辑节点的原始地址（保存时的迁移键）
    edit_orig_addr: String,
    edit_name: String,
    edit_addr: String,
    edit_auth_key: String,
    edit_show_auth: bool,
    edit_cert_path: String,

    // 运行时状态（scheduler 字段已随死代码清理移除：只写不读，代理线程自带实例）
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
    /// 二维码图片导入（R-15：解码在后台线程执行，结果经通道回投，UI 轮询非阻塞收集）
    qr_import_receiver: Option<std::sync::mpsc::Receiver<std::result::Result<ShareLink, String>>>,

    // 流量统计
    traffic_monitor: Option<Arc<TrafficMonitor>>,
    /// 流量统计缓存（R-16：后台采样线程每 500ms 写入最新 TrafficStats，UI 帧只读零阻塞）
    traffic_stats_cache: Arc<std::sync::Mutex<Option<TrafficStats>>>,
    /// 流量采样线程停止标记（stop_proxy / 重新启动代理时置位，旧线程自行退出）
    traffic_sampler_stop: Option<Arc<AtomicBool>>,
    /// UI 重设计第三批：速率历史 + 当日流量（采样线程每 500ms 追加一个点，
    /// UI 帧只读快照供仪表盘曲线卡与统计卡使用）
    traffic_history: Arc<std::sync::Mutex<SpeedHistory>>,

    // ── 连接页：活跃连接注册表快照（GUI 每 500ms 拉一次，UI 帧只读零阻塞）──
    /// 最近一次注册表快照（按活跃优先 + 注册序排列）
    conn_snapshot: Vec<hydra_client::connections::ConnInfo>,
    /// 上次快照的 (上行累计, 下行累计, 时刻)，用于差分推算每连接速率
    conn_prev: HashMap<u64, (u64, u64, std::time::Instant)>,
    /// 本帧展示的每连接速率 (↑B/s, ↓B/s)
    conn_rates: HashMap<u64, (f64, f64)>,
    /// 上次快照拉取时刻（节流至 500ms）
    conn_last_refresh: Option<std::time::Instant>,

    // ── T2：托盘 + UI 重排 ──
    /// 当前导航页签
    current_tab: Tab,
    /// 系统托盘（None = 初始化失败，GUI 照常运行）
    tray: Option<tray::HydraTray>,
    /// 真·退出标记：托盘「退出」或菜单退出后放行窗口关闭（区别于隐藏到托盘）
    really_quit: bool,
    /// 托盘 tooltip 缓存（变化才 set_tooltip）
    last_tray_tooltip: String,
    /// TUN 停机令牌（审查修复：从代理线程内部提升到 HydraApp，真退出路径
    /// 可直接 cancel，确保 RouteGuard 执行路由清理，不再依赖线程内时序）
    tun_shutdown: Option<hydra_client::ShutdownToken>,

    // ── 系统代理检测缓存（修复：移出渲染路径，杜绝每帧 spawn reg 子进程）──
    /// Windows 系统代理状态缓存：(检测完成时刻, 是否开启)。UI 只读缓存；
    /// 缓存缺失或超过 10s 过期时由后台线程刷新（node_test_receiver 同范式）。
    /// 仅 Windows 有意义（reg query 检测 + 告警 UI 均 cfg(windows)），
    /// 非 Windows 平台不定义该字段（否则 dead_code 阻断 CI）
    #[cfg(windows)]
    sys_proxy_check_cache: Option<(std::time::Instant, bool)>,
    /// 在途检测结果接收端（Some = 后台检测进行中，防止每帧重复 spawn 线程）
    #[cfg(windows)]
    sys_proxy_check_receiver: Option<std::sync::mpsc::Receiver<bool>>,
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // 初始化日志：HYDRA_LOG_LEVEL（默认 info；RUST_LOG 优先）——与 CLI/节点
    // 同款（应用内日志页之外，内部组件的 tracing 诊断也写 stderr 供排查；
    // info 级安全：目标地址已在日志层脱敏）
    {
        use tracing_subscriber::EnvFilter;
        let level = std::env::var("HYDRA_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let filter = match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info")),
        };
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    // 09-P3-5：双实例互斥——双 GUI 实例会并发写配置、互相抢系统代理开关状态。
    // 守卫存到 main 作用域直至退出。async main 里用阻塞 bind 可接受（一次性、
    // 内核立即返回、无 await 竞争）。
    let _instance_guard =
        match hydra_client::acquire_instance_guard(hydra_client::INSTANCE_PORT_GUI) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("Hydra GUI 无法启动：{e}");
                std::process::exit(1);
            }
        };

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

    // 应用图标：解码嵌入的 ICO（失败不 panic，仅无自定义窗口图标）
    let window_icon = icon::load_window_icon();
    // 标题栏左上角/任务栏窗口缩略图图标；解码失败时不设置（系统默认 fallback）
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([800.0, 600.0])
        .with_min_inner_size([400.0, 300.0]);
    if let Some(icon_data) = window_icon {
        viewport = viewport.with_icon(icon_data);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Hydra Multipath Proxy",
        options,
        Box::new(|cc| Box::new(HydraApp::new(cc))),
    )
}
