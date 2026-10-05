// Windows 下隐藏随 GUI 弹出的终端窗口（仅 release；debug 保留控制台便于看日志）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use hydra_client::{
    format_bytes, format_duration, format_speed, generate_share_links, hex_encode_lower,
    parse_share_links, sha256_hex, ProxyServer, ShareLink, TrafficMonitor, TrafficStats,
};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
use config::{GuiConfig, SubscriptionConfig};

/// 视觉规范化第一步（UI 重设计第一批）：集中式色板 + 字号层级 + 延迟/状态色标。
/// 全部 UI 用色只允许引用本模块常量，禁止在页面代码里再写散落的 from_rgb。
mod palette {
    use eframe::egui;

    // ── 底色（暗色优先）──
    /// 面板底（侧栏/内容区）
    pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x1B, 0x1E, 0x24);
    /// 卡片底
    pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(0x22, 0x26, 0x2E);
    /// 输入框/极端底
    pub const BG_EXTREME: egui::Color32 = egui::Color32::from_rgb(0x12, 0x14, 0x18);
    /// 卡片描边/分隔线
    pub const BORDER: egui::Color32 = egui::Color32::from_rgb(0x2E, 0x33, 0x3D);

    // ── 语义色 ──
    /// 主强调色（选中/主按钮/链接）
    pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);
    /// 成功 / 低延迟（<200ms）
    pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(0x7D, 0xE2, 0x97);
    /// 警告 / 中延迟（200–500ms）
    pub const WARNING: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xD6, 0x66);
    /// 危险 / 高延迟（≥500ms）与错误
    pub const DANGER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x8A, 0x80);

    // ── 文本三级 ──
    /// 一级：正文/标题
    pub const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE8, 0xEA, 0xED);
    /// 二级：次要说明（ui.small 同级）
    pub const TEXT_WEAK: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB0, 0xBC);
    /// 三级：占位/未验证状态点
    pub const TEXT_FAINT: egui::Color32 = egui::Color32::from_rgb(0x7A, 0x82, 0x8F);

    // ── 字号层级（全局统一）──
    /// 页面标题
    pub const FONT_HEADING: f32 = 18.0;
    /// 卡片标题/节点名
    pub const FONT_TITLE: f32 = 15.0;
    /// 正文
    pub const FONT_BODY: f32 = 13.0;
    /// 次要文字/标签
    pub const FONT_SECONDARY: f32 = 11.5;

    /// 延迟色标：<200ms 绿 / <500ms 黄 / 其余红；None（未测）= 灰。
    /// 与 v3 设计文档 §交互细节 的色阶一致。
    pub fn latency_color(latency_ms: Option<u64>) -> egui::Color32 {
        match latency_ms {
            None => TEXT_FAINT,
            Some(ms) if ms < 200 => SUCCESS,
            Some(ms) if ms < 500 => WARNING,
            Some(_) => DANGER,
        }
    }

    /// 节点状态色点：绿=Online / 黄=Degraded（在线但延迟 ≥500ms）/
    /// 红=Offline（测过但失败）/ 灰=未验证（从未测速）。
    pub fn status_color(connected: bool, checked: bool, latency_ms: Option<u64>) -> egui::Color32 {
        if !checked {
            TEXT_FAINT // 未验证
        } else if connected {
            if latency_ms.is_some_and(|ms| ms >= 500) {
                WARNING // Degraded：握手通过但延迟过高
            } else {
                SUCCESS // Online
            }
        } else {
            DANGER // Offline
        }
    }
}
mod qr;
mod subscription;
mod tray;
/// 应用图标：从嵌入的 assets/app.ico 解码窗口/托盘所需 RGBA（见 icon.rs）
mod icon;
use tray::TrayCommand;

/// UI 重设计 v2：左侧导航五页（状态总览 / 节点 / 订阅 / 日志 / 设置）。
/// 分享入口并入节点页（单节点分享在节点行内，批量导出在节点页工具区）；
/// 订阅独立成页：只管订阅源生命周期，节点归属在节点页以来源标记区分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Overview,
    Nodes,
    Subscriptions,
    Logs,
    Settings,
}

impl Tab {
    const ALL: [Tab; 5] = [
        Tab::Overview,
        Tab::Nodes,
        Tab::Subscriptions,
        Tab::Logs,
        Tab::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "📊 状态总览",
            Tab::Nodes => "🌐 节点",
            Tab::Subscriptions => "📡 订阅",
            Tab::Logs => "📜 日志",
            Tab::Settings => "⚙️ 设置",
        }
    }
}

#[derive(Clone, Debug)]
struct NodeStatusInfo {
    connected: bool,
    last_check: Option<std::time::Instant>,
    latency_ms: Option<u64>,
}

// ── UI 重设计第二批：节点页组视图（复刻 Clash Meta 代理组 tabs）──
/// 组标签的保留键：手动组（未被任何订阅认领的节点）。
const GROUP_MANUAL: &str = "manual";

/// 节点所属组的组键（与 GuiConfig 认领机制一致，单一事实来源 = 各订阅 nodes 列表）：
/// 被某订阅认领 → Some(订阅名)；否则 → None（手动）。多订阅含同一地址取先匹配者。
fn node_group_of(cfg: &GuiConfig, addr: &str) -> Option<String> {
    cfg.subscriptions
        .iter()
        .find(|s| s.nodes.iter().any(|n| n == addr))
        .map(|s| s.name.clone())
}

/// 按组过滤节点列表（组视图纯函数，供 UI 与单测共用）：
/// group=None → 全部；Some(GROUP_MANUAL) → 未被任何订阅认领的手动节点；
/// Some(订阅名) → 该订阅认领且仍在节点列表中的地址。
fn filter_nodes_by_group(
    cfg: &GuiConfig,
    node_addrs: &[String],
    group: &Option<String>,
) -> Vec<String> {
    match group.as_deref() {
        None => node_addrs.to_vec(),
        Some(GROUP_MANUAL) => node_addrs
            .iter()
            .filter(|a| node_group_of(cfg, a).is_none())
            .cloned()
            .collect(),
        Some(name) => node_addrs
            .iter()
            .filter(|a| node_group_of(cfg, a).as_deref() == Some(name))
            .cloned()
            .collect(),
    }
}

/// 组成员的在线/离线摘要（测过且连通=在线；测过但失败=离线；未测不计入）。
fn group_summary(
    status: &HashMap<String, NodeStatusInfo>,
    addrs: &[String],
) -> (usize, usize) {
    let mut online = 0;
    let mut offline = 0;
    for a in addrs {
        match status.get(a) {
            Some(s) if s.last_check.is_some() => {
                if s.connected {
                    online += 1;
                } else {
                    offline += 1;
                }
            }
            _ => {}
        }
    }
    (online, offline)
}

struct HydraApp {
    // 应用状态
    proxy_running: bool,
    proxy_start_receiver: Option<
        std::sync::mpsc::Receiver<std::result::Result<std::net::SocketAddr, std::io::Error>>,
    >,
    proxy_starting: bool,
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
    /// UI 重设计第一批：「＋ → 从分享链接导入」对话框开关（原节点页内联导入区迁入）
    import_dialog_open: bool,
    /// UI 重设计第一批：「＋ → 手动添加节点」对话框开关（原页顶输入行迁入）
    manual_add_open: bool,
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

    // ── UI 重设计 v2：节点页顶部「全局凭据」折叠区（过渡期全局生效，诚实标注）──
    global_creds_open: bool,

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
}

impl Default for HydraApp {
    fn default() -> Self {
        Self {
            proxy_running: false,
            proxy_start_receiver: None,
            proxy_starting: false,
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
            import_dialog_open: false,
            manual_add_open: false,
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
            global_creds_open: false,
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
            current_tab: Tab::Overview,
            tray: None,
            really_quit: false,
            last_tray_tooltip: String::new(),
            tun_shutdown: None,
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

/// 进程级探测 runtime（审查 R-34）：健康检查（每 30s）与单节点手动测试共用，
/// 不再每次在后台线程里冷启动/销毁一个多线程 tokio runtime（num_cpus 个
/// worker 线程 + epoll 实例 + 线程创建毛刺）。多线程可从任意线程 block_on。
fn probe_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("创建探测 tokio 运行时失败")
    })
}

/// 代理线程异步主体（抽出为自由函数以便单测时序回归）。
///
/// 【问题 2 根因与修复】此前版本在此处先 `let _ = watcher.await;` 再进 select 跑
/// `proxy.start()`——watcher 的完成条件是 bound_addr 就绪，而 bound_addr 只有
/// start() 里的 bind 才会置位，于是 watcher 在等 start、start 却排在 watcher
/// 之后从未开始执行：两者互相等待，每次启动必然干等 60s 超时
///（用户日志 16:56:34 启动 → 16:57:39 "60s 内未就绪"即此）。
/// 修复：就绪 watcher 保持 tokio 后台任务并发运行（发出就绪/超时信号即返回，
/// 克隆的 ready_tx 丢弃无副作用），不再阻塞等待；start() 立即进入 select 执行
/// 认证检查 → register_nodes → bind → 置 bound_addr（正常数毫秒完成）。
/// stop 信号通过 stop_flag 轮询分支优雅停机（含 TUN 任务取消与路由清理）。
async fn run_proxy_until_stopped(
    proxy: Arc<ProxyServer>,
    tx: std::sync::mpsc::Sender<std::result::Result<SocketAddr, std::io::Error>>,
    stop_flag: Arc<AtomicBool>,
    tun_task: Option<(hydra_client::ShutdownToken, tokio::task::JoinHandle<()>)>,
) {
    // 就绪信号以真实 bound_addr 置位为准——后台并发 watcher，绝不阻塞 start()
    let p2 = proxy.clone();
    let ready_tx = tx.clone();
    tokio::spawn(async move {
        for _ in 0..600 {
            if let Some(bound) = p2.bound_addr() {
                let _ = ready_tx.send(Ok(bound));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = ready_tx.send(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "代理监听 60s 内未就绪（地址被占用或节点预热超时）",
        )));
    });
    tokio::select! {
        result = proxy.start() => {
            match result {
                Ok(()) => {
                    println!("[Proxy Thread] Proxy server exited normally");
                }
                Err(e) => {
                    eprintln!("[Proxy Thread] Proxy server error: {}", e);
                    // release 版无控制台：失败必须回传 UI 可见
                    let _ = tx.send(Err(std::io::Error::other(format!("代理异常退出: {e}"))));
                }
            }
        }
        _ = async {
            while !stop_flag.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => {
            println!("[Proxy Thread] Received stop signal");
            // TUN 任务优雅停机：取消令牌 → 栈任务退出 → RouteGuard Drop 清理路由；
            // 最多等 5s（与 CLI 停机超时一致），超时则随 runtime 关闭强收
            if let Some((token, task)) = tun_task {
                token.cancel();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
            }
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
fn start_button_state(proxy_running: bool, proxy_starting: bool) -> (&'static str, bool) {
    if proxy_running {
        ("■ 停止代理", true)
    } else if proxy_starting {
        ("⏳ 启动中…", false)
    } else {
        ("▶ 启动代理", true)
    }
}

/// 单节点测速探测目标默认值（问题 3）。
///
/// 此前用 `192.0.0.1:9`（TEST-NET-3 文档段 discard 端口）：该网段不路由，多数
/// 防火墙对不可路由地址静默丢包 → 节点侧建连挂满超时 → 节点明明健康却报
/// "测速超时"。改为 `1.1.1.1:443`（Cloudflare，TCP 443 全球快速可连，节点侧
/// 建连 ~1ms 级）：节点回 TargetUnreachable（0x01 应答）仍代表"认证通过、
/// 节点健康"（目标侧失败不影响节点判定），成功/握手失败/连接超时三分逻辑不变。
const PROBE_TARGET_DEFAULT: &str = "1.1.1.1:443";

/// 探测目标 env 覆盖键（特殊网络环境下可指向自选可达地址）
const PROBE_TARGET_ENV: &str = "HYDRA_PROBE_TARGET";

/// 探测目标解析（纯函数便于单测）：env 值非空（去首尾空白）则覆盖，否则用默认值。
fn probe_target_from(env_value: Option<&str>) -> String {
    match env_value {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => PROBE_TARGET_DEFAULT.to_string(),
    }
}

/// 当前生效的探测目标（读 env 覆盖；只读不写，无 R-24 数据竞争面）
fn probe_target() -> String {
    probe_target_from(std::env::var(PROBE_TARGET_ENV).ok().as_deref())
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
            proxy_starting: false,
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
            import_dialog_open: false,
            manual_add_open: false,
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
            global_creds_open: false,
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
            current_tab: Tab::Overview,
            tray,
            really_quit: false,
            last_tray_tooltip: "Hydra 代理已停止".to_string(),
            tun_shutdown: None,
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
                "配置已加载，但认证密钥或节点证书路径尚未填写，请在「⚙️ 设置」页「全局凭据」区补全"
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
            "① 填写认证密钥：「⚙️ 设置」页「全局凭据」折叠区 → 认证密钥 → 点「编辑/显示」输入 hex 密钥"
                .to_string(),
            "② 选择节点证书文件：同区「节点证书」→ 点「浏览...」选择节点生成的 hydra-node-cert.der"
                .to_string(),
            "③ 添加节点：「🌐 节点」页右上角「＋」→「✏️ 手动添加节点」".to_string(),
            "④ 点「📊 状态总览」页的大按钮「▶ 启动代理」即可使用".to_string(),
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
    /// 信任根由调用方按「配置文件 > 环境变量」构造后传入（config.rs resolve_trust，
    /// 支持 pin/ca 双信任模式与逐节点证书）
    /// 0-7 修复"测速假绿"：不再只做 TCP connect（测不出密钥错误），而是完整走
    /// `connect_target`（TCP+TLS+Noise-PSK 认证 + 节点应答）。探测目标默认
    /// `1.1.1.1:443`（问题 3：原 `192.0.0.1:9` 撞静默丢包防火墙导致健康节点被
    /// 误判"测速超时"；现可用 `HYDRA_PROBE_TARGET` env 覆盖，见 PROBE_TARGET_*），
    /// 错误分类：
    /// - 节点回"目标不可达"（TargetUnreachable / 应答 0x01）→ **认证已通过，节点健康 ✓**，
    ///   返回耗时 ms（测速语义不变）；
    /// - Noise 握手失败 → 认证/密钥错误 ✗；
    /// - TCP 连接失败/超时 → 节点不可达 ✗。
    async fn test_node_connection(
        addr_str: &str,
        trust: hydra_client::tcp_transport::TlsTrust,
        auth_key: Vec<u8>,
    ) -> std::result::Result<u64, String> {
        use hydra_client::tcp_transport::connect_target;
        use hydra_protocol::HydraError;

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("地址解析失败: {}", e))?;

        let start = std::time::Instant::now();
        // 总时限 10s：目标探测在节点侧快速失败（1.1.1.1:443 节点侧建连 ~1ms 级），
        // 正常远小于该值；覆盖 TCP/TLS 5s+握手
        let probe = tokio::time::timeout(
            std::time::Duration::from_millis(10_000),
            connect_target(addr, hydra_client::DEFAULT_SNI, &trust, &auth_key, &probe_target()),
        )
        .await;
        match probe {
            // 目标探测成功（1.1.1.1:443 可直连时可能发生）——握手已通过，同样算节点健康
            Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
            Ok(Err(e)) => match &e {
                // 节点存活且完成了 Noise 认证，只是目标连不上（含 SSRF 拒绝/DNS 失败）
                // → 节点健康，测速语义 = 返回耗时 ms
                HydraError::TargetUnreachable(_) => Ok(start.elapsed().as_millis() as u64),
                _ => {
                    let msg = e.to_string();
                    if msg.contains("Noise 握手失败") || msg.contains("认证失败") {
                        Err(format!("认证/密钥错误（Noise 握手失败）: {}", msg))
                    } else if msg.contains("TCP connect") {
                        Err(format!("节点不可达: {}", msg))
                    } else {
                        Err(msg)
                    }
                }
            },
            Err(_) => Err(format!("节点测速超时（10s）: {}", addr)),
        }
    }

    /// 发起单节点手动测试：后台线程 + 通道，结果在 update 循环中非阻塞收集
    fn start_node_test(&mut self, addr: String) {
        if self.node_test_receiver.is_some() {
            self.add_log("已有节点测试正在进行，请稍候".to_string());
            return;
        }
        // 信任根按「配置文件 > 环境变量」构造（支持 ca 模式与逐节点证书）；失败根因直接进日志
        let trust = match config::resolve_trust(&self.config, std::slice::from_ref(&addr)) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("节点 {} 测试失败: {}", addr, e));
                return;
            }
        };
        // 0-7：完整握手测速需要认证密钥（PSK）——解析失败直接报错（假密钥测不出健康）
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("节点 {} 测试失败（认证密钥未就绪）: {}", addr, e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.add_log(format!("开始测试节点 {}...", addr));
        // 卡片 spinner 依据：记录正在测速的节点地址，结果落地后在 poll 中清除
        self.node_testing_addr = Some(addr.clone());
        std::thread::spawn(move || {
            // 审查 R-34：复用进程级探测 runtime（不再每次冷启动一个多线程 runtime）
            let result =
                probe_runtime().block_on(HydraApp::test_node_connection(&addr, trust, auth_key));
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
                    self.node_testing_addr = None;
                    self.add_log("节点测试线程异常退出，已重置".to_string());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((addr, result)) = finished {
            self.node_test_receiver = None;
            // 单测结束：清除卡片 spinner 标记
            if self.node_testing_addr.as_deref() == Some(addr.as_str()) {
                self.node_testing_addr = None;
            }
            let now = std::time::Instant::now();
            match result {
                Ok(latency) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
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
                            connected: false,
                            last_check: Some(now),
                            latency_ms: None,
                        },
                    );
                    self.add_log(format!("节点 {} 测试失败: {}", addr, reason));
                }
            }
            // UI 重设计第二批：组级测速——上一个单测完成后自动取队列中的下一个成员
            // （复用 start_node_test 的互斥通道，逐个串行，不与「全部测速」并发通道冲突）
            if let Some(next) = self.pending_node_tests.pop_front() {
                self.start_node_test(next);
            }
        }
    }

    /// Test all nodes and update status (non-blocking)
    fn test_all_nodes(&mut self) {
        // 审查修复：节点列表为空直接记日志返回，不做静默空测
        //（配合 resolve_trust pin 模式空信任根报错，双保险）
        if self.config.node_addrs.is_empty() {
            self.add_log("没有节点可测试（节点列表为空），已跳过".to_string());
            return;
        }
        let node_addrs = self.config.node_addrs.clone();
        // 信任根按「配置文件 > 环境变量」构造（支持 ca 模式与逐节点证书）；失败根因直接进日志
        let trust = match config::resolve_trust(&self.config, &node_addrs) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("全部节点测试失败: {}", e));
                return;
            }
        };
        // 0-7：完整握手测速需要认证密钥（PSK）
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("全部节点测试失败（认证密钥未就绪）: {}", e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();

        // 在后台线程中测试所有节点（审查 R-34：复用进程级探测 runtime，
        // 不再每 30s 冷启动/销毁一个多线程 runtime——num_cpus 个 worker 线程、
        // epoll 实例与线程创建毛刺全部消除）
        std::thread::spawn(move || {
            probe_runtime().block_on(async {
                // 并发测试所有节点
                let mut handles = Vec::new();
                for addr in &node_addrs {
                    let addr = addr.clone();
                    let trust = trust.clone();
                    let auth_key = auth_key.clone();
                    let tx = tx.clone();
                    handles.push(tokio::spawn(async move {
                        let result = Self::test_node_connection(&addr, trust, auth_key).await;
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

    /// UI 重设计第二批：组级测速——对本组成员逐个发起单节点测试。
    /// 复用 start_node_test 的互斥逻辑：已有单测进行中时直接提示并放弃本次排队；
    /// 后续成员进入 pending_node_tests 队列，poll_node_test_results 串行接续。
    fn start_group_test(&mut self, addrs: Vec<String>) {
        if addrs.is_empty() {
            self.add_log("本组没有节点可测试".to_string());
            return;
        }
        if self.node_test_receiver.is_some() {
            self.add_log("已有节点测试正在进行，请稍候".to_string());
            return;
        }
        let mut it = addrs.into_iter();
        let first = it.next().expect("非空队列必有首元素");
        self.pending_node_tests.extend(it);
        self.start_node_test(first);
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
        if self.proxy_starting {
            self.add_log("代理正在启动中（节点预热可能需要数十秒），请稍候".to_string());
            return;
        }

        // Exec-1：探测间隔 env 覆盖已移至 HydraApp::new（审查 R-24：多线程进程
        // 运行期调用 std::env::set_var 与后台线程的 env 读取构成数据竞争 UB；
        // new 阶段确认尚无工作线程，仅此一次安全）。

        let proxy_addr: SocketAddr = match self.config.proxy_listen_addr.trim().parse() {
            Ok(addr) => addr,
            Err(e) => {
                self.add_log(format!("地址解析错误: {}", e));
                return;
            }
        };

        // ── 认证密钥：先读配置文件，缺项再回落环境变量（config.rs）──
        // 在 GUI 线程解析完成后再移交代理线程；失败根因直接进日志。
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };

        // 先测试所有节点连接（审查 R-37，Wave 3 修复）：test_all_nodes 的结果是异步
        // 回来的（经健康检查通道在后续帧落地），此刻统计 node_status 必然是上一轮的
        // 过期值（首启恒为 0，"没有可用节点"与"代理已就绪"并存的自相矛盾日志）。
        // 改为中性提示；真实结果由 poll_health_check_results 落地后自然刷新 UI。
        self.add_log("正在测试节点连接...".to_string());
        self.test_all_nodes();
        self.add_log("节点连通性检测已在后台启动，结果稍后自动更新".to_string());

        // 解析节点地址。
        // P1-14 修复：首启时健康检查尚未返回、node_status 全是初始"未连接"值，
        // 据此过滤节点会导致首次启动必然"没有可用节点"而取消。
        // 现不再按可能过期的健康状态拦截，仅过滤非法地址；不可达节点
        // 由代理自身的故障切换与调度器 Offline 标记处理。
        let mut nodes = Vec::new();
        let mut valid_node_addrs = Vec::new();
        let node_addrs = self.config.node_addrs.clone();
        for node_addr in &node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                let state = match self.node_status.get(node_addr.as_str()) {
                    Some(st) if st.connected => "已验证",
                    Some(st) if st.last_check.is_some() => "上次检测不可达，仍尝试",
                    _ => "未验证",
                };
                nodes.push(addr);
                valid_node_addrs.push(node_addr.clone());
                self.add_log(format!("添加节点: {} ({})", addr, state));
            } else {
                self.add_log(format!("跳过无效节点地址: {}", node_addr));
            }
        }

        if nodes.is_empty() {
            self.add_log("错误: 没有有效的节点地址，代理启动取消".to_string());
            return;
        }

        // ── 信任根：pin（默认，逐节点证书按序收集）/ ca（真证书 + 可选叶 pin）──
        // 节点顺序与 with_nodes 传入顺序一致（with_node_certs 按序对应）
        let trust = match config::resolve_trust(&self.config, &valid_node_addrs) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };
        let trust_for_proxy = trust.clone();

        // ── TUN 透明代理（实验性）：GUI 与代理同进程，TUN 需在 ProxyServer::start
        // 之外叠加（run_tun 独立任务，共享同一调度器/凭据）。配置在此解析，
        // 权限不足等错误经就绪通道透传到日志区。
        let tun_enabled = self.config.tun_enabled;
        let tun_cfg = if tun_enabled {
            match hydra_client::tun_config_from_settings(
                Some(self.config.tun_addr_or_default()),
                Some(self.config.tun_ports_or_default()),
                &nodes,
            ) {
                Ok(c) => {
                    // 与 CLI（main.rs warn_system_proxy_loop）一致的环路告警：
                    // TUN 全流量接管 + 系统代理 → 经系统代理的流量二次进本代理
                    #[cfg(windows)]
                    if hydra_client::windows_system_proxy_enabled() {
                        self.add_log(
                            "⚠ 检测到 Windows 系统代理已开启：TUN 模式下经系统代理的流量会\
                             二次进入本代理形成环路，建议关闭系统代理后使用 TUN 模式"
                                .to_string(),
                        );
                    }
                    self.add_log(format!(
                        "TUN 透明代理开启（实验性）：地址 {} 端口 {:?}（需管理员/root；\
                         Windows 还需 wintun.dll）",
                        self.config.tun_addr_or_default(),
                        c.listen_ports
                    ));
                    Some(c)
                }
                Err(e) => {
                    self.add_log(format!("代理启动失败: {}", e));
                    return;
                }
            }
        } else {
            None
        };

        // 创建流量统计器
        let traffic_monitor = Arc::new(TrafficMonitor::new());
        self.traffic_monitor = Some(traffic_monitor.clone());

        // R-16：启动后台流量采样线程（每 500ms 采一次 TrafficStats 写入缓存槽，
        // UI 帧只读缓存，不再 block_in_place/block_on 阻塞渲染）。复用进程级探测
        // runtime（R-34 范式），采样线程可在任意线程 block_on。
        // 旧采样线程若在（重复启动场景），先置位其停止标记。
        if let Some(old) = self.traffic_sampler_stop.take() {
            old.store(true, Ordering::Relaxed);
        }
        {
            let cache = self.traffic_stats_cache.clone();
            let monitor = traffic_monitor.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            std::thread::spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    let stats = probe_runtime().block_on(monitor.get_stats());
                    if let Ok(mut slot) = cache.lock() {
                        *slot = Some(stats);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            });
            self.traffic_sampler_stop = Some(stop);
        }
        // 新会话清空上一轮的过期统计快照，避免启动瞬间显示旧速率
        if let Ok(mut slot) = self.traffic_stats_cache.lock() {
            *slot = None;
        }

        // 使用独立线程运行代理
        let (tx, rx) =
            std::sync::mpsc::channel::<std::result::Result<std::net::SocketAddr, std::io::Error>>();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let proxy_addr_clone = proxy_addr;
        let nodes_clone = nodes.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();
        let traffic_monitor_clone = traffic_monitor.clone();
        // 审查修复：TUN 停机令牌提升到 GUI 线程创建并存入 HydraApp 字段——
        // 真退出路径（托盘退出/关窗退出/on_exit）可直接 cancel，保证
        // RouteGuard 的路由清理在任何停机时序下都有机会执行
        let tun_shutdown_token = if tun_cfg.is_some() {
            Some(hydra_client::new_tun_shutdown_token())
        } else {
            None
        };
        self.tun_shutdown = tun_shutdown_token.clone();
        let mut tun_token_for_thread = tun_shutdown_token.clone();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                // 认证密钥/信任根已由 GUI 线程按「配置文件 > 环境变量」解析完毕（见上）
                let proxy = std::sync::Arc::new(
                    ProxyServer::new(proxy_addr_clone)
                        .with_nodes(nodes_clone)
                        .with_traffic_monitor(traffic_monitor_clone)
                        .with_auth_key(auth_key)
                        .with_trust(trust_for_proxy),
                );
                println!("[Proxy Thread] Starting proxy server...");
                // ── TUN 叠加（实验性）：与 SOCKS 监听并存。register_nodes 需在
                // start 之前让调度器已有节点（tun_channel_opener 依赖节点优先级表）
                // tun_task = (停机令牌, TUN 栈任务句柄)；None = 未开启或启动失败
                let tun_task: Option<(
                    hydra_client::ShutdownToken,
                    tokio::task::JoinHandle<()>,
                )> = if let Some(tcfg) = tun_cfg {
                    // GUI 依赖 hydra-client 默认 features（含 tun）；配置构造失败已在
                    // GUI 线程拦截，此处失败（设备创建/路由）经通道透传日志区
                    {
                        proxy.register_nodes().await;
                        match proxy.tun_channel_opener() {
                            Ok(opener) => {
                                // 令牌本体已在 GUI 线程创建并存入 HydraApp（真退出
                                // 路径可达），此处取传入的令牌 clone 给 TUN 栈任务。
                                // tx 用独立克隆（任务内发送失败根因，不占用主通道所有权）
                                let tun_tx = tx.clone();
                                let tun_token = tun_token_for_thread
                                    .take()
                                    .expect("TUN 已启用时停机令牌必须存在");
                                let shutdown2 = tun_token.clone();
                                let task = tokio::spawn(async move {
                                    if let Err(e) =
                                        hydra_client::tun::run_tun(tcfg, opener, shutdown2).await
                                    {
                                        // 权限不足（非管理员/root）/ 缺 wintun.dll 等根因
                                        // 经就绪通道透传到 GUI 日志区，不静默
                                        let _ = tun_tx.send(Err(std::io::Error::other(format!(
                                            "TUN 模式启动失败: {e}（设备创建需管理员/root；\
                                             Windows 还需 wintun.dll）"
                                        ))));
                                    }
                                });
                                Some((tun_token, task))
                            }
                            Err(e) => {
                                let _ = tx.send(Err(std::io::Error::other(format!(
                                    "TUN 模式启动失败: {e}"
                                ))));
                                None
                            }
                        }
                    }
                } else {
                    None
                };
                run_proxy_until_stopped(proxy, tx, stop_flag_clone, tun_task).await;
            });
            println!("[Proxy Thread] Thread exiting...");
            // 代理线程退出时发送通知
            let _ = exit_tx.send(());
        });

        self.stop_flag = Some(stop_flag);
        self.proxy_thread_handle = Some(handle);
        self.proxy_exit_receiver = Some(exit_rx);
        // 非阻塞启动：就绪信号经 proxy_start_receiver 在 update 轮询中处理。
        // 阻塞式 recv 会冻结 UI（节点预热/弱网下可达数十秒）
        self.proxy_start_receiver = Some(rx);
        self.proxy_starting = true;
        self.add_log("代理启动中…（节点预热可能需要数十秒，视网络质量而定）".to_string());
        // 启动阶段性日志（问题 1/2 附加）：让用户知道当前卡在哪一步，
        // 就绪后 poll_start_receiver 会接续输出「✓ 代理已就绪」
        self.add_log(format!("正在绑定 {}…", proxy_addr));
    }

    /// update 轮询：消费代理就绪信号（非阻塞，替代原先冻结 UI 的阻塞 recv）
    fn poll_start_receiver(&mut self) -> Option<()> {
        // 07-P2-5：必须区分 Empty 与 Disconnected——Empty = 结果尚未产生，保留
        // receiver 下帧再收；Disconnected = 代理线程在就绪信号发出前已退出
        //（如 Runtime::new().unwrap() panic），若吞掉则 proxy_starting 恒为 true，
        // 「启动代理」按钮从此永久命中早退分支，无法再次启动。
        // 审查修复：每轮一次性排空通道——此前只消费一条就丢弃 receiver，
        // 同帧内随后到达的消息（典型：TUN 启动失败根因紧跟就绪/失败信号）
        // 会被静默丢弃，故障定位线索丢失。
        let mut messages: Vec<std::result::Result<std::net::SocketAddr, std::io::Error>> =
            Vec::new();
        let mut disconnected = false;
        if let Some(rx) = &self.proxy_start_receiver {
            loop {
                match rx.try_recv() {
                    Ok(sig) => messages.push(sig),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        // 首条为处理对象，剩余消息全部入日志（不静默丢弃）
        let first = if messages.is_empty() {
            None
        } else {
            let mut it = messages.into_iter();
            let head = it.next();
            for sig in it {
                match sig {
                    Ok(addr) => self.add_log(format!("（附加就绪信号）代理监听地址: {addr}")),
                    Err(e) => self.add_log(format!("⚠ 附加启动消息（勿忽略）: {e}")),
                }
            }
            head
        };
        if first.is_none() {
            if disconnected {
                // 代理线程异常退出：清 receiver、复位启动态，恢复可再次启动
                self.proxy_start_receiver = None;
                self.proxy_starting = false;
                self.add_log("代理启动线程异常退出（未发出就绪信号即终止）".to_string());
                return Some(());
            }
            return None;
        }
        let signal = first.unwrap();
        self.proxy_start_receiver = None;
        self.proxy_starting = false;
        match signal {
            Ok(addr) => {
                self.proxy_running = true;
                // 阶段性日志收尾（问题 1/2 附加）：明确告知用户代理可用
                self.add_log(format!("✓ 代理已就绪，监听地址: {addr}"));
                self.maybe_save_config(true);
                // 审查修复：TUN 模式已全局接管流量，就绪后不再叠加系统代理
                //（否则制造"系统代理 + TUN"二次进本代理的被警示终态）
                if self.config.tun_enabled {
                    self.add_log("TUN 模式运行中：已全局接管流量，跳过系统代理设置".to_string());
                } else {
                    let proxy_url = format!("socks5://{addr}");
                    self.set_system_proxy(&proxy_url);
                    self.add_log("已设置系统全局代理".to_string());
                }
            }
            Err(e) => {
                self.add_log(format!("代理启动失败: {e}"));
                if let Some(flag) = &self.stop_flag {
                    flag.store(true, Ordering::Relaxed);
                }
                // 07-P3-10 零成本顺修：置位 stop_flag 后立即清空，让 update 的
                // 收敛分支（!proxy_running && stop_flag.is_none()）正常接管
                // JoinHandle / exit_receiver 清理
                self.stop_flag = None;
            }
        }
        Some(())
    }

    fn set_system_proxy(&mut self, proxy_url: &str) {
        // 审查 R-24：不再向本进程写 http_proxy 等 6 个 env var——GUI 自身进程不
        // 通过 env 读代理（env 只对子进程有意义，GUI 不 spawn 走代理的子进程）；
        // 运行期 set_var 与代理/健康检查/订阅线程的 env 读取构成数据竞争（UB）。
        // 系统代理设置由下方各平台原生路径（注册表/gsettings/kwriteconfig）完成。

        // 解析代理地址和端口（审查 R-38，Wave 3 修复）：不再按 ':' 盲切——
        // IPv6 监听（GUI 支持 `[::1]:4433`）时 `socks5://[::1]:1080` 会被切碎成
        // 错误端口段，gsettings/kwriteconfig 写入损坏的桌面代理配置。
        // 按 RFC 3986 authority 解析：先剥 scheme，再区分方括号 IPv6 与 host:port。
        let after_scheme = proxy_url.split("://").nth(1).unwrap_or(proxy_url);
        // Windows 注册表分支直接用 host:port 原串（含 IPv6 方括号形态，WinINet 惯例）；
        // Linux/macOS 分支自行动构造代理串，不用该绑定
        #[cfg(windows)]
        let addr_port = after_scheme;
        let (proxy_host, proxy_port) = if let Some(rest) = after_scheme.strip_prefix('[') {
            // IPv6 字面量：`[::1]:1080`
            match rest.split_once("]:") {
                Some((host, port)) => (host, port),
                None => (rest.trim_end_matches(']'), "1080"),
            }
        } else {
            // host:port（rsplit 从右侧取最后一个 ':'，兼容无端口 host）
            match after_scheme.rsplit_once(':') {
                Some((host, port)) => (host, port),
                None => (after_scheme, "1080"),
            }
        };

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
        // 审查 R-24：对应 set_system_proxy，移除本进程 6 个 proxy env var 的运行期
        // 写入（remove_var 同样是多线程进程的 UB 面；GUI 不依赖这些变量）

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

        // 审查 R-35：不在 UI 线程 join 代理线程——停止信号靠线程内 100ms 轮询，
        // join 至少阻塞 UI 100ms；若 start() 正处于长 await 链（节点预热数十秒）
        // UI 将冻结同样久，托盘/按钮/窗口全部无响应。退出确认交给 update 里已有的
        // proxy_exit_receiver 轮询分支（收到退出通知后再清理 handle）。
        // 此处只置 stop_flag、立即返回，UI 状态先置"停止中"。
        self.proxy_running = false;
        self.proxy_starting = false;
        self.proxy_start_receiver = None;
        self.stop_flag = None;
        // R-16：停止流量采样线程（线程内 ≤500ms 自行退出，不 join）
        if let Some(stop) = self.traffic_sampler_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Ok(mut slot) = self.traffic_stats_cache.lock() {
            *slot = None;
        }
        // handle/exit receiver 保留给 update 的退出通知分支收敛，避免泄漏：
        // 线程退出后 exit_rx 断开 → 该分支清理两者。

        // 移除系统全局代理
        self.remove_system_proxy();
        self.add_log("代理停止中，已移除系统代理".to_string());
        // 关键动作立即落盘
        self.maybe_save_config(true);
    }

    /// 真退出专用：停止代理并同步等待代理线程退出（含 TUN 停机），上限 5s。
    ///
    /// 审查修复背景：此前三条真退出路径（托盘退出 / 关窗退出 / on_exit）只调用
    /// stop_proxy 即放行进程关闭，TUN 的停机令牌锁在代理线程内部，RouteGuard
    /// 可能来不及 Drop 清理路由 → 退出后路由残留导致断网。
    /// 现退出时序：置 stop_flag → 直接 cancel TUN 令牌（令牌已提升为 HydraApp
    /// 字段）→ UI 线程带超时轮询 proxy_exit_receiver（std::thread::sleep，
    /// 5s 内可接受）；超时也保证 cancel 已发出，路由清理由线程随后完成。
    /// 注：GUI 退出等待逻辑依赖真实窗口事件循环，无法自动化单测，以人工验证为准。
    fn shutdown_and_wait_for_exit(&mut self) {
        let running = self.proxy_running
            || self.stop_flag.is_some()
            || self.proxy_exit_receiver.is_some();
        if !running {
            return; // 代理未在运行，无需等待
        }
        self.stop_proxy();
        // 确保 TUN 停机令牌已发出（代理线程内也会 cancel，这里双保险且不依赖时序）
        if let Some(token) = &self.tun_shutdown {
            token.cancel();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut exited = false;
        while std::time::Instant::now() < deadline {
            match &self.proxy_exit_receiver {
                Some(rx) => match rx.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        exited = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                },
                None => {
                    exited = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if exited {
            self.proxy_thread_handle = None;
            self.proxy_exit_receiver = None;
            self.add_log("代理线程已退出（TUN 路由清理完成）".to_string());
        } else {
            self.add_log(
                "⚠ 等待代理/TUN 停机超时（5s）：停机信号与 TUN 令牌已发出，\
                 路由清理将由代理线程退出时的 RouteGuard 完成"
                    .to_string(),
            );
        }
        self.tun_shutdown = None;
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
    /// 密钥/证书按当前配置解析，取不到的字段自动省略。
    /// TCP/TLS（TLS 1.3 + Noise-PSK）是唯一传输：不再附加 mode=obfs/ok 参数
    /// （legacy 链接的兼容解析由 hydra-client 的 share_link 层处理）。
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
        let mut link = ShareLink::new(&node_info);

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
        let cert_b64 = link
            .cert_der_bytes()
            .map_err(|e| e.to_string())?
            .map(|der| base64::engine::general_purpose::STANDARD.encode(&der));

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
        // legacy 链接中的 mode/ok 参数由 hydra-client 兼容解析层处理；GUI 不再落库
        // hydra_mode/obfs_key（TCP/TLS 是唯一传输，配置字段已删除）。

        let addr_str = format!("{}:{}", link.address, link.port);
        if !self.config.node_addrs.contains(&addr_str) {
            self.config.node_addrs.push(addr_str.clone());
            self.node_status.insert(
                addr_str.clone(),
                NodeStatusInfo {
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

    /// 从二维码图片文件导入（R-15：rfd 选文件在 UI 线程，读文件+缩图+rqrr 解码
    /// 全部移入后台 std::thread，结果经 mpsc 回投，由 update 轮询非阻塞收集——
    /// 大图解码不再冻结界面；同一时刻仅允许一个导入任务进行）
    fn import_from_qr_image(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("图片文件", &["png", "jpg", "jpeg"])
            .add_filter("全部文件", &["*"])
            .pick_file()
        else {
            return; // 用户取消
        };
        if self.qr_import_receiver.is_some() {
            self.set_import_status(false, "已有二维码导入进行中，请稍候".to_string());
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.qr_import_receiver = Some(rx);
        std::thread::spawn(move || {
            // 后台线程：读文件 → 缩图 → rqrr 解码 → 解析分享链接（CPU 密集部分全部离 UI 线程）
            let result = std::fs::read(&path)
                .map_err(|e| format!("读取图片 {} 失败: {}", path.display(), e))
                .and_then(|bytes| qr::decode_qr_from_bytes(&bytes))
                .and_then(|text| {
                    ShareLink::from_share_url(text.trim())
                        .map_err(|e| format!("二维码内容不是有效的 hydra 分享链接: {}", e))
                });
            let _ = tx.send(result);
        });
        self.set_import_status(
            true,
            "二维码解码中…（后台执行，完成后自动导入）".to_string(),
        );
    }

    /// 在 update 循环中非阻塞收集二维码导入结果并应用（R-15）
    fn poll_qr_import_result(&mut self) {
        let result = match &self.qr_import_receiver {
            Some(rx) => match rx.try_recv() {
                Ok(result) => Some(result),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // 后台线程异常退出：重置以允许再次发起导入
                    self.qr_import_receiver = None;
                    self.set_import_status(false, "二维码解码线程异常退出".to_string());
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
            },
            None => None,
        };
        if let Some(result) = result {
            self.qr_import_receiver = None;
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
    fn add_subscription(&mut self) -> bool {
        let source = self.new_sub_source.trim().to_string();
        if source.is_empty() {
            self.add_log(
                "订阅来源不能为空（http(s) URL、文件路径或 hydra-sub:// 前缀）".to_string(),
            );
            return false;
        }
        let name = if self.new_sub_name.trim().is_empty() {
            format!("订阅{}", self.config.subscriptions.len() + 1)
        } else {
            self.new_sub_name.trim().to_string()
        };
        if self.config.subscriptions.iter().any(|s| s.name == name) {
            self.add_log(format!("订阅名称「{}」已存在，请换一个名称", name));
            return false;
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
        true
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
            // 审查修复：连带清备注名与独立证书路径（remove_node_state 收口）
            self.config.remove_node_state(a);
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
            // 审查修复：订阅更新移除旧节点时同样清残留状态（remove_node_state 收口）
            self.config.remove_node_state(a);
        }

        // 2) 追加：新地址中尚未在列表、且不被其他订阅认领的
        let mut added = 0usize;
        for a in &new_addrs {
            if self.config.node_addrs.contains(a) || others_set.contains(a) {
                continue;
            }
            self.node_status.entry(a.clone()).or_insert(NodeStatusInfo {
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
        // 审查修复：改走 shutdown_and_wait_for_exit——带超时等待代理线程退出
        //（含 TUN 停机令牌 cancel），确保 RouteGuard 清理路由后再放行进程退出
        self.shutdown_and_wait_for_exit();
        // Exec-1：退出前强制落盘（兜底防抖窗口内尚未写盘的变更）
        self.maybe_save_config(true);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_start_receiver();
        // ── R-35：stop_proxy 后的非阻塞收敛 ──
        // 代理线程退出使 exit receiver 可读/断开时，在此清理 handle 与 receiver
        //（不在 UI 线程 join；JoinHandle drop = detach，线程自然结束）
        if !self.proxy_running && self.stop_flag.is_none() {
            if let Some(receiver) = &self.proxy_exit_receiver {
                match receiver.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;
                        self.add_log("代理线程已退出".to_string());
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
        }
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
        // 非阻塞地处理二维码图片导入结果（R-15：解码在后台线程）
        self.poll_qr_import_result();

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
                    ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）".to_string());

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
            Tab::Subscriptions => self.ui_subscriptions(ui),
            Tab::Settings => self.ui_settings(ui),
            Tab::Logs => self.ui_logs(ui),
        });

        // ── Team-UI：节点编辑对话框 ──
        if self.node_edit_open {
            self.ui_node_edit_dialog(ctx);
        }

        // ── UI 重设计第二批：导入/手动添加/分享选择/添加订阅 对话框集中渲染 ──
        // （入口分布在订阅页「＋ 新建」下拉与节点页「🔗 分享节点」，跨页切换窗口不丢失）
        self.ui_nodes_dialogs(ctx);
        if self.sub_add_open {
            self.ui_sub_add_dialog(ctx);
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
                    // 真退出：停代理并带超时等待线程退出（含 TUN 停机 + 路由清理，
                    // 见 shutdown_and_wait_for_exit）再关闭窗口；on_exit 兜底落盘
                    self.shutdown_and_wait_for_exit();
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
        } else if self.proxy_starting {
            "Hydra 代理启动中…"
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

    /// 状态总览（v2 方案 §2.1）：仪表盘 + 全局启停大开关。
    /// 含：运行状态、在线节点 x/y、实时上/下行速率、当前模式（传输+认证概要）、
    /// 最近日志摘要（点击跳日志页）。本页无任何配置项。
    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("状态总览");
        ui.separator();

        // 状态卡：启停大开关 + 监听地址 + 在线节点 + 速率
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // 状态文本三态（问题 1）：启动期也给可见反馈，不再"看似没反应"
                    let (status_text, status_color) = if self.proxy_running {
                        ("● 运行中", egui::Color32::from_rgb(0x53, 0xC2, 0x6E))
                    } else if self.proxy_starting {
                        ("◐ 启动中…", egui::Color32::from_rgb(0xE5, 0xA5, 0x0A))
                    } else {
                        ("○ 已停止", egui::Color32::GRAY)
                    };
                    ui.label(
                        egui::RichText::new(status_text)
                            .size(24.0)
                            .color(status_color),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // 问题 1：按钮文字/可用性走 start_button_state 状态机——
                        // 启动期显示「⏳ 启动中…」并禁用，bound 就绪后变「停止代理」，
                        // 失败复位后回「启动代理」（状态转换单测见 tests 模块）
                        let (btn_text, btn_enabled) =
                            start_button_state(self.proxy_running, self.proxy_starting);
                        let btn = egui::Button::new(egui::RichText::new(btn_text).size(18.0));
                        let resp = ui.add_enabled(btn_enabled, btn);
                        if resp.clicked() {
                            if self.proxy_running {
                                self.stop_proxy();
                            } else {
                                self.start_proxy();
                            }
                        }
                    });
                });
                let online = self.node_status.values().filter(|s| s.connected).count();
                let total = self.config.node_addrs.len();
                ui.label(format!(
                    "本地监听 {}   活动: {}/{} 节点在线",
                    self.config.proxy_listen_addr, online, total
                ));

                // 实时流量（R-16：后台采样线程每 500ms 写缓存，UI 帧只读零阻塞）
                if self.proxy_running {
                    if let Some(stats) =
                        self.traffic_stats_cache.lock().ok().and_then(|g| g.clone())
                    {
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

        // 概要卡：当前模式（传输 + 认证概要）与节点健康
        ui.add_space(8.0);
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.heading("当前模式");
                ui.separator();
                let mode = "TCP/TLS（TLS 1.3 + Noise-PSK）";
                let psk_ok = !self.config.auth_key.trim().is_empty();
                let cert_ok = !self.config.cert_path.trim().is_empty()
                    || !self.config.cert_der_b64.trim().is_empty();
                ui.label(format!(
                    "传输: {} ｜ 认证: PSK {} ｜ 证书: {}",
                    mode,
                    if psk_ok { "已设置" } else { "未设置" },
                    if cert_ok { "已设置" } else { "未设置" }
                ));
                ui.small("凭据为全局配置，在「⚙️ 设置」页「全局凭据」区修改");
                if let Some(last_check) = self.last_health_check {
                    ui.small(format!(
                        "上次节点检测: {}秒前",
                        last_check.elapsed().as_secs()
                    ));
                }
                if ui.button("测试所有节点").clicked() {
                    self.test_all_nodes();
                }
            });

        // 最近日志摘要（最近 3 条，点击跳日志页）
        ui.add_space(8.0);
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("最近日志");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("查看全部 →").clicked() {
                            self.current_tab = Tab::Logs;
                        }
                    });
                });
                ui.separator();
                let start = self.logs.len().saturating_sub(3);
                if start == self.logs.len() {
                    ui.weak("暂无日志");
                }
                for line in &self.logs[start..] {
                    ui.small(line);
                }
            });
    }

    /// 节点页（UI 重设计第一批，按老板构想重做）：
    /// - 页面主体 = 节点卡片列表（状态色点/名称/地址/延迟色标/操作按钮）；
    /// - 右上角固定「＋」按钮 → 下拉四项：从分享链接导入 / 扫描二维码导入 /
    ///   手动添加节点 / 分享节点（分享与导入全部收进菜单，不再平铺占页面）；
    /// - 全局凭据（认证密钥/证书）移出本页，收敛到「⚙️ 设置」页「全局凭据」区，
    ///   本页仅在缺失时显示一条窄横幅提示并跳转；
    /// - 页尾订阅快捷管理区移除（完整生命周期全部在「📡 订阅」页，功能零丢失）。
    fn ui_nodes(&mut self, ui: &mut egui::Ui) {
        // ── 页头：标题 + 右侧「分享节点」+「全部测速」──
        // （UI 重设计第二批：「＋」菜单及其对话框入口整体迁往「📡 订阅」页「＋ 新建」；
        //   分享节点（含批量导出）不是"新建"动作，保留在节点页页头）
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("节点")
                    .size(palette::FONT_HEADING)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // 全部测速（测速进行中显示 spinner + 进度提示）
                if self.health_check_receiver.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label("全部测速中…");
                }
                if ui.button("⚡ 全部测速").clicked() {
                    self.test_all_nodes();
                }
                if ui
                    .button("🔗 分享节点")
                    .on_hover_text("按节点分享（二维码/完整/紧凑链接），或批量导出分享链接")
                    .clicked()
                {
                    self.share_pick_open = true;
                }
            });
        });
        ui.separator();

        // ── 全局凭据缺失横幅（凭据编辑已收敛到「⚙️ 设置」页，此处只提示不编辑）──
        let key_missing = self.config.auth_key.trim().is_empty();
        let cert_missing = self.config.cert_path.trim().is_empty()
            && self.config.cert_der_b64.trim().is_empty();
        if key_missing || cert_missing {
            egui::Frame::none()
                .fill(palette::BG_CARD)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(12.0_f32, 6.0_f32))
                .outer_margin(egui::Margin::symmetric(0.0_f32, 4.0_f32))
                .stroke(egui::Stroke::new(1.0_f32, palette::WARNING.gamma_multiply(0.5)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            palette::WARNING,
                            "⚠ 全局凭据未配置（认证密钥或节点证书缺失），代理无法启动",
                        );
                        if ui.small_button("前往设置 →").clicked() {
                            self.current_tab = Tab::Settings;
                        }
                    });
                });
        }

        // ── 组视图（复刻 Clash Meta 代理组 tabs）──
        // 组 = 数据来源过滤：全部 / 手动认领 / 某订阅认领的地址（与 GuiConfig 认领机制一致）。
        // 选中的订阅组已被删除时回落「全部」（订阅在「📡 订阅」页删除的场景）
        if let Some(g) = &self.node_group {
            if g != GROUP_MANUAL
                && !self.config.subscriptions.iter().any(|s| &s.name == g)
            {
                self.node_group = None;
            }
        }
        ui.add_space(4.0);

        // ── 顶部组标签行：横排可滚动按钮组，选中高亮，含成员数量徽标 ──
        let all_count = self.config.node_addrs.len();
        let manual_count = self
            .config
            .node_addrs
            .iter()
            .filter(|a| node_group_of(&self.config, a).is_none())
            .count();
        let mut tabs: Vec<(Option<String>, String)> = Vec::new();
        tabs.push((None, format!("全部 · {}", all_count)));
        tabs.push((
            Some(GROUP_MANUAL.to_string()),
            format!("✏️ 手动 · {}", manual_count),
        ));
        for sub in &self.config.subscriptions {
            let cnt = self
                .config
                .node_addrs
                .iter()
                .filter(|a| node_group_of(&self.config, a).as_deref() == Some(sub.name.as_str()))
                .count();
            tabs.push((Some(sub.name.clone()), format!("📡 {} · {}", sub.name, cnt)));
        }
        egui::ScrollArea::new([true, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                for (key, label) in &tabs {
                    let selected = self.node_group.as_deref() == key.as_deref();
                    if ui
                        .selectable_label(selected, egui::RichText::new(label).size(palette::FONT_BODY))
                        .clicked()
                    {
                        self.node_group = key.clone();
                    }
                }
            });
        });
        ui.separator();

        // ── 组头栏：组名 + 节点数 + 在线/离线摘要 +「⚡ 全部测速（本组）」──
        let members = filter_nodes_by_group(&self.config, &self.config.node_addrs, &self.node_group);
        let (online, offline) = group_summary(&self.node_status, &members);
        let group_name = match &self.node_group {
            None => "全部节点".to_string(),
            Some(g) if g == GROUP_MANUAL => "✏️ 手动节点".to_string(),
            Some(name) => format!("📡 {}", name),
        };
        egui::Frame::none()
            .fill(palette::BG_CARD)
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::symmetric(12.0_f32, 6.0_f32))
            .outer_margin(egui::Margin::symmetric(0.0_f32, 4.0_f32))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&group_name)
                            .size(palette::FONT_TITLE)
                            .strong(),
                    );
                    ui.colored_label(
                        palette::TEXT_WEAK,
                        format!("{} 节点 ｜ 在线 {} / 离线 {}", members.len(), online, offline),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button("⚡ 全部测速（本组）")
                            .on_hover_text("对本组成员逐个发起握手测速（串行，复用单测通道）")
                            .clicked()
                        {
                            self.start_group_test(members.clone());
                        }
                    });
                });
            });

        // ── 组内节点卡片（紧凑双列/三列自适应网格，沿用第一批卡片元素）──
        if self.config.node_addrs.is_empty() {
            egui::Frame::none()
                .fill(palette::BG_CARD)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(12.0))
                .outer_margin(egui::Margin::symmetric(0.0_f32, 4.0_f32))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("还没有节点。")
                            .size(palette::FONT_BODY)
                            .color(palette::TEXT_WEAK),
                    );
                    ui.small("多个节点自动更新 → 「📡 订阅」页右上「＋ 新建」添加订阅源；单个节点 → 从分享链接导入");
                });
        } else if members.is_empty() {
            ui.add_space(4.0);
            ui.colored_label(palette::TEXT_WEAK, "（本组暂无节点）");
        }
        let mut indices_to_remove = Vec::new();
        let mut edit_target: Option<String> = None;
        let mut manual_target: Option<String> = None;
        let node_addrs_clone = self.config.node_addrs.clone();
        // 组成员（按原列表顺序保留原始下标，供删除与操作定位）
        let entries: Vec<(usize, String)> = node_addrs_clone
            .iter()
            .enumerate()
            .filter(|(_, a)| members.contains(a))
            .map(|(i, a)| (i, a.clone()))
            .collect();
        // 紧凑化：按可用宽度自适应 1–3 列（卡宽约 300px 起）
        let card_min = 300.0_f32;
        let cols = ((ui.available_width() / card_min).floor() as usize).clamp(1, 3);
        let cell_width = ((ui.available_width() - 12.0 * (cols as f32 - 1.0)) / cols as f32
            - 12.0)
            .max(220.0);
        egui::Grid::new("node_group_grid")
            .num_columns(cols)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                for chunk in entries.chunks(cols) {
                    for (i, node_addr) in chunk {
                        let node_addr = node_addr.as_str();
                        // 状态三态：绿=Online / 黄=Degraded（在线但延迟≥500ms）/
                        // 红=Offline / 灰=未验证
                        let (connected, checked, latency) =
                            match self.node_status.get(node_addr) {
                                Some(s) => (s.connected, s.last_check.is_some(), s.latency_ms),
                                None => (false, false, None),
                            };
                        let dot = palette::status_color(connected, checked, latency);
                        let name = self.config.node_display_name(node_addr);
                        let source = self.config.node_source_label(node_addr);
                        let is_manual = source == config::NODE_SOURCE_MANUAL;
                        let latency_text = match latency {
                            Some(ms) => format!("{}ms", ms),
                            None if checked => "超时".to_string(),
                            None => "未测试".to_string(),
                        };
                        let testing_this =
                            self.node_testing_addr.as_deref() == Some(node_addr);
                        // ── 紧凑节点卡片：圆角 + 统一内边距，宽度锁定为网格列宽 ──
                        egui::Frame::none()
                            .fill(palette::BG_CARD)
                            .rounding(egui::Rounding::same(8.0))
                            .inner_margin(egui::Margin::same(10.0))
                            .outer_margin(egui::Margin::same(2.0))
                            .stroke(egui::Stroke::new(1.0_f32, palette::BORDER))
                            .show(ui, |ui| {
                                ui.set_min_width(cell_width);
                                // 第一行：状态色点 + 名称/地址 + 延迟色标（来源已由组标签表达）
                                ui.horizontal(|ui| {
                                    let (rect, _) = ui
                                        .allocate_exact_size(
                                            egui::vec2(10.0, 10.0),
                                            egui::Sense::hover(),
                                        );
                                    ui.painter().circle_filled(rect.center(), 5.0, dot);
                                    if name == node_addr {
                                        ui.label(
                                            egui::RichText::new(node_addr)
                                                .size(palette::FONT_TITLE)
                                                .strong(),
                                        );
                                    } else {
                                        ui.label(
                                            egui::RichText::new(&name)
                                                .size(palette::FONT_TITLE)
                                                .strong(),
                                        )
                                        .on_hover_text(node_addr);
                                    }
                                    // 「全部」组里来源混合，补小组来源标记；组内已由标签行表达
                                    if self.node_group.is_none() {
                                        ui.colored_label(
                                            if is_manual {
                                                palette::TEXT_FAINT
                                            } else {
                                                palette::ACCENT
                                            },
                                            format!("[{}]", source),
                                        );
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new(latency_text.as_str())
                                                    .size(palette::FONT_BODY)
                                                    .color(palette::latency_color(latency)),
                                            );
                                        },
                                    );
                                });
                                // 第二行：操作按钮（测速/分享/编辑（或另存为手动）/删除）
                                ui.horizontal(|ui| {
                                    if testing_this {
                                        ui.add(egui::Spinner::new().size(14.0));
                                        ui.label(
                                            egui::RichText::new("测速中…")
                                                .size(palette::FONT_SECONDARY)
                                                .color(palette::TEXT_WEAK),
                                        );
                                    } else if ui.small_button("⚡").on_hover_text("测速（完整握手）").clicked() {
                                        self.start_node_test(node_addr.to_string());
                                    }
                                    if ui.small_button("🔗").on_hover_text("分享").clicked() {
                                        self.open_share_dialog(node_addr.to_string());
                                    }
                                    // 订阅节点默认只读（地址/凭据随订阅更新覆盖），不提供编辑；
                                    // 可「另存为手动」解除认领后再改
                                    if is_manual {
                                        if ui.small_button("✏").on_hover_text("编辑").clicked() {
                                            edit_target = Some(node_addr.to_string());
                                        }
                                    } else if ui
                                        .small_button("⇥")
                                        .on_hover_text(
                                            "另存为手动：解除订阅认领，变为可编辑的手动节点（后续订阅更新不再覆盖/认领它）",
                                        )
                                        .clicked()
                                    {
                                        manual_target = Some(node_addr.to_string());
                                    }
                                    if ui.small_button("🗑").on_hover_text("删除").clicked() {
                                        indices_to_remove.push(*i);
                                    }
                                });
                            });
                    }
                    // 末行补空位，保持网格对齐
                    for _ in chunk.len()..cols {
                        ui.label("");
                    }
                    ui.end_row();
                }
            });

        // 删除节点并添加日志
        for &i in indices_to_remove.iter().rev() {
            let removed = self.config.node_addrs.remove(i);
            self.node_status.remove(&removed);
            // 审查修复：备注名 + 独立证书路径一并清理（remove_node_state 收口），
            // 防止同地址复用节点时旧证书静默生效
            self.config.remove_node_state(&removed);
            self.add_log(format!("已删除节点: {}", removed));
        }
        if let Some(addr) = edit_target {
            self.open_node_edit(&addr);
        }
        if let Some(addr) = manual_target {
            if self.config.save_subscription_node_as_manual(&addr) {
                self.add_log(format!("节点 {} 已另存为手动节点（不再随订阅更新）", addr));
            }
        }

        // （导入/手动添加/分享选择对话框已集中到 update() 统一渲染：
        //   入口在「📡 订阅」页「＋ 新建」下拉与节点页「🔗 分享节点」，跨页不丢窗口）

        // 提示：订阅源的完整管理（增删改/更新/展开归属节点）在「📡 订阅」页
        ui.add_space(4.0);
        ui.small("订阅来源拉取的节点自动进入上方列表（来源标记为订阅名）；订阅源的添加与更新见「📡 订阅」页右上「＋ 新建」");
    }

    /// 节点/订阅共用的三个对话框窗口（UI 重设计第一批迁入，第二批起集中渲染）：
    /// ① 从分享链接导入（粘贴多行 / 链接文件）
    /// ② 手动添加节点（host:port 实时校验）
    /// ③ 分享节点（按节点选择打开分享对话框；批量导出 v1 也在其中）
    /// 改为直接持 ctx 渲染（跨页窗口不丢失），由 update() 每帧统一调用
    fn ui_nodes_dialogs(&mut self, ctx: &egui::Context) {
        // ① 从分享链接导入
        if self.import_dialog_open {
            egui::Window::new("📋 从分享链接导入")
                .collapsible(false)
                .resizable(true)
                .default_width(480.0)
                .show(ctx, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.import_text)
                            .desired_rows(4)
                            .hint_text("粘贴 hydra:// 分享链接（支持多行，每行一条）"),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("导入粘贴的链接").clicked() {
                            self.import_pasted_links();
                        }
                        if ui.button("从链接文件导入 (.txt)").clicked() {
                            self.import_from_link_file();
                        }
                        if ui.button("关闭").clicked() {
                            self.import_dialog_open = false;
                        }
                    });
                    if let Some((ok, msg)) = &self.import_status {
                        ui.colored_label(
                            if *ok { palette::SUCCESS } else { palette::DANGER },
                            format!("{} {}", if *ok { "✓" } else { "✗" }, msg),
                        );
                    }
                    ui.small("完整分享含密钥/证书，导入后自动配置，无需再填密钥与证书文件");
                    ui.small("ℹ 导入的节点是「手动节点」（单个分享链接 ≠ 订阅源）：可自由编辑、不随订阅更新；如需多节点自动更新，请到「📡 订阅」页添加订阅源");
                });
        }

        // ② 手动添加节点（与旧「添加节点」同一套校验：非法地址直接提示不静默入库）
        if self.manual_add_open {
            let mut add_clicked = false;
            egui::Window::new("✏️ 手动添加节点")
                .collapsible(false)
                .resizable(false)
                .default_width(420.0)
                .show(ctx, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_node_input)
                            .desired_width(320.0)
                            .hint_text("host:port，如 1.2.3.4:4433"),
                    );
                    if !self.new_node_input.trim().is_empty()
                        && self.new_node_input.trim().parse::<SocketAddr>().is_err()
                    {
                        ui.colored_label(
                            palette::DANGER,
                            "✗ 格式应为 地址:端口（示例 1.2.3.4:4433 / [::1]:4433）",
                        );
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("➕ 添加").strong(),
                            ))
                            .clicked()
                        {
                            add_clicked = true;
                        }
                        if ui.button("取消").clicked() {
                            self.manual_add_open = false;
                            self.new_node_input.clear();
                        }
                    });
                });
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
                            connected: false,
                            last_check: None,
                            latency_ms: None,
                        },
                    );
                    self.config.node_addrs.push(input.clone());
                    self.add_log(format!("已添加节点: {}", input));
                    self.new_node_input.clear();
                    self.manual_add_open = false;
                }
            }
        }

        // ③ 分享节点（按节点选择；批量导出 v1 也在此，功能零丢失）
        if self.share_pick_open {
            egui::Window::new("🔗 分享节点")
                .collapsible(false)
                .resizable(true)
                .default_width(460.0)
                .show(ctx, |ui| {
                    ui.label("选择要分享的节点：");
                    let addrs = self.config.node_addrs.clone();
                    if addrs.is_empty() {
                        ui.colored_label(palette::TEXT_WEAK, "（暂无节点可分享）");
                    }
                    for addr in &addrs {
                        ui.horizontal(|ui| {
                            ui.label(self.config.node_display_name(addr));
                            ui.small(addr);
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.small_button("分享").clicked() {
                                    // 打开现有分享对话框（二维码 + 完整/紧凑链接）
                                    self.open_share_dialog(addr.clone());
                                    self.share_pick_open = false;
                                }
                            });
                        });
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("批量导出分享链接（v1，仅地址）").clicked() {
                            self.export_share_links();
                            self.share_pick_open = false;
                        }
                        if ui.button("关闭").clicked() {
                            self.share_pick_open = false;
                        }
                    });
                    ui.small("• 单节点分享可生成二维码与完整/紧凑链接");
                    ui.small("• 完整链接含认证密钥与证书，对方导入即用；仅限可信渠道发送");
                    ui.small("• 紧凑链接仅含证书指纹，需另行发送证书文件");
                });
        }
    }

    /// 订阅页（v2 方案 §2.3）：只管订阅源的生命周期（增/改/更新/删除）。
    /// 每条订阅可展开查看归属节点（只读标记 + 「另存为手动」）；
    /// 节点的统一列表与来源标记见「🌐 节点」页。
    fn ui_subscriptions(&mut self, ui: &mut egui::Ui) {
        // ── 页头：标题 + 右侧「更新全部订阅」+「＋ 新建」下拉（复刻 Clash Profiles 新建入口）──
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("订阅")
                    .size(palette::FONT_HEADING)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // 「＋ 新建」：四种创建/导入入口统一收纳（原节点页「＋」整体迁来）
                ui.menu_button(
                    egui::RichText::new("＋ 新建").size(palette::FONT_TITLE),
                    |ui| {
                        if ui.button("📡 添加订阅源").clicked() {
                            // 展开添加对话框（交互选定：对话框比内联展开少一次布局跳动）
                            self.new_sub_name.clear();
                            self.new_sub_source.clear();
                            self.sub_add_open = true;
                            ui.close_menu();
                        }
                        if ui.button("📋 从分享链接导入").clicked() {
                            self.import_dialog_open = true;
                            ui.close_menu();
                        }
                        if ui.button("📷 扫描二维码导入").clicked() {
                            // 复用现有二维码文件识别（后台解码，结果经通道回收）
                            self.import_from_qr_image();
                            ui.close_menu();
                        }
                        if ui.button("✏️ 手动添加节点").clicked() {
                            self.new_node_input.clear();
                            self.manual_add_open = true;
                            ui.close_menu();
                        }
                    },
                )
                .response
                .on_hover_text("添加订阅源 / 从分享链接导入 / 扫描二维码导入 / 手动添加节点");
                if self.sub_update_receiver.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label("更新中...");
                }
                if ui.button("🔄 更新全部订阅").clicked() {
                    self.update_all_subscriptions();
                }
            });
        });
        ui.add_space(2.0);
        ui.small("节点分两种归属：订阅节点由订阅源拉取、随订阅更新自动覆盖（只读，可「另存为手动」解除认领）；手动节点通过「＋ 新建」导入/添加、可自由编辑且不受订阅影响。节点页顶部组标签按下方订阅动态分组");
        ui.separator();

        // 订阅列表：名称 / 来源 / 更新时间 / 节点数 + 立即更新 / 展开节点 / 编辑 / 删除
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
            let expanded = self.expanded_sub.as_deref() == Some(sub.name.as_str());
            ui.horizontal(|ui| {
                ui.strong(&sub.name);
                ui.colored_label(
                    egui::Color32::from_rgb(0xA8, 0xB0, 0xBC),
                    format!("{} 节点", sub.nodes.len()),
                );
                ui.weak(format!("更新于 {}", updated));
                if ui.small_button("立即更新").clicked() {
                    self.queue_subscription_update(sub.name.clone(), sub.source.clone());
                }
                if ui
                    .small_button(if expanded {
                        "收起节点"
                    } else {
                        "展开节点"
                    })
                    .clicked()
                {
                    self.expanded_sub = if expanded {
                        None
                    } else {
                        Some(sub.name.clone())
                    };
                }
                if ui.small_button("编辑").clicked() {
                    self.sub_edit_idx = Some(i);
                    self.sub_edit_name = sub.name.clone();
                    self.sub_edit_source = sub.source.clone();
                }
                if ui.small_button("删除").clicked() {
                    subs_to_remove.push(i);
                }
            });
            ui.small(&sub.source);

            // 展开归属节点：只读清单 + 单条「另存为手动」
            if expanded {
                if sub.nodes.is_empty() {
                    ui.small("  （该订阅暂无归属节点，请先「立即更新」）");
                }
                for addr in &sub.nodes {
                    let testing_this = self.node_testing_addr.as_deref() == Some(addr.as_str());
                    ui.indent(addr.as_str(), |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(egui::Color32::from_rgb(0x7A, 0xB3, 0xFF), "[只读]");
                            ui.label(addr);
                            // 测速中显示 spinner；结果进全局日志与调度器评分（与节点页一致）
                            if testing_this {
                                ui.add(egui::Spinner::new().size(14.0));
                                ui.label(
                                    egui::RichText::new("测速中…")
                                        .size(palette::FONT_SECONDARY)
                                        .color(palette::TEXT_WEAK),
                                );
                            }
                            // 紧凑操作行：分享 / 测速 / 另存为手动（原位）
                            if ui.small_button("🔗 分享").clicked() {
                                // 订阅节点不带密钥本体：build_share_link 按地址解析失败时
                                // 自动退化为仅地址信息（能带证书则带），与现有分享行为一致
                                self.open_share_dialog(addr.clone());
                            }
                            if ui.small_button("⚡ 测速").clicked() {
                                self.start_node_test(addr.clone());
                            }
                            if ui
                                .small_button("另存为手动")
                                .on_hover_text(
                                    "解除订阅认领，变为可编辑的手动节点（后续订阅更新不再覆盖/认领它）",
                                )
                                .clicked()
                                && self.config.save_subscription_node_as_manual(addr)
                            {
                                self.add_log(format!(
                                    "节点 {} 已另存为手动节点（不再随订阅更新）",
                                    addr
                                ));
                            }
                        });
                    });
                }
            }
        }
        for &i in subs_to_remove.iter().rev() {
            self.delete_subscription(i);
        }

        // 订阅编辑对话框（名称重复校验与添加同一套规则）。
        // 对话框打开期间订阅可能被删除（同页删除按钮）→ 索引失效时静默关闭对话框，
        // 否则 subs_clone[idx] 越界 panic 崩溃整个 UI 线程
        if let Some(idx) = self.sub_edit_idx {
            if subs_clone.get(idx).is_none() {
                self.sub_edit_idx = None;
                self.add_log("编辑的订阅已被删除，对话框已关闭".to_string());
            }
        }
        if let Some(idx) = self.sub_edit_idx {
            let mut save_clicked = false;
            egui::Window::new(format!("编辑订阅「{}」", subs_clone[idx].name))
                .collapsible(false)
                .resizable(false)
                .default_width(480.0)
                .show(ui.ctx(), |ui| {
                    egui::Grid::new("sub_edit_grid")
                        .num_columns(2)
                        .spacing([8.0, 6.0])
                        .show(ui, |ui| {
                            ui.label("名称:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.sub_edit_name)
                                    .desired_width(300.0),
                            );
                            ui.end_row();
                            ui.label("来源:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.sub_edit_source)
                                    .desired_width(300.0)
                                    .hint_text("https://… / 文件路径 / hydra-sub://…"),
                            );
                            ui.end_row();
                        });
                    if self.sub_edit_source.trim().is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0x8A, 0x80),
                            "✗ 来源不能为空",
                        );
                    }
                    let name = self.sub_edit_name.trim();
                    let name_conflict = !name.is_empty()
                        && self
                            .config
                            .subscriptions
                            .iter()
                            .enumerate()
                            .any(|(j, s)| j != idx && s.name == name);
                    if name_conflict {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0x8A, 0x80),
                            "✗ 订阅名称已存在（名称是来源标记与更新对号的键）",
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
                            self.sub_edit_idx = None;
                        }
                    });
                });
            if save_clicked {
                let name = self.sub_edit_name.trim().to_string();
                let source = self.sub_edit_source.trim().to_string();
                if source.is_empty()
                    || name.is_empty()
                    || self
                        .config
                        .subscriptions
                        .iter()
                        .enumerate()
                        .any(|(j, s)| j != idx && s.name == name)
                {
                    self.add_log("订阅编辑保存失败：来源为空或名称重复/为空".to_string());
                } else {
                    self.config.subscriptions[idx].name = name.clone();
                    self.config.subscriptions[idx].source = source;
                    self.sub_edit_idx = None;
                    self.add_log(format!("订阅「{}」已保存", name));
                }
            }
        }

        // （导入/手动添加对话框已由 update() 集中渲染，本页不再重复调用）
    }

    /// 「＋ 新建 → 📡 添加订阅源」对话框（原平铺添加行收进对话框，交互更顺：
    /// 添加是低频动作，不必常驻占位；校验逻辑与原 add_subscription 完全一致）
    fn ui_sub_add_dialog(&mut self, ctx: &egui::Context) {
        let mut add_clicked = false;
        egui::Window::new("📡 添加订阅源")
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ctx, |ui| {
                egui::Grid::new("sub_add_grid")
                    .num_columns(2)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("名称:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_sub_name)
                                .desired_width(320.0)
                                .hint_text("可留空自动编号"),
                        );
                        ui.end_row();
                        ui.label("来源:");
                        ui.vertical(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_sub_source)
                                    .desired_width(320.0)
                                    .hint_text("https://… / 文件路径 / hydra-sub://…"),
                            );
                            if ui.small_button("浏览...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("订阅文件", &["txt", "sub"])
                                    .add_filter("全部文件", &["*"])
                                    .pick_file()
                                {
                                    self.new_sub_source = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("➕ 添加订阅").strong()))
                        .clicked()
                    {
                        add_clicked = true;
                    }
                    if ui.button("取消").clicked() {
                        self.sub_add_open = false;
                        self.new_sub_name.clear();
                        self.new_sub_source.clear();
                    }
                });
                ui.small("支持 http(s) 订阅 URL、本地订阅文件路径与 hydra-sub:// 分享订阅");
            });
        if add_clicked && self.add_subscription() {
            // 添加成功才关闭对话框；校验失败保留窗口让用户修改
            self.sub_add_open = false;
        }
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
        // 逐节点独立证书路径（多节点证书 HYDRA_NODE_CERTS 的 GUI 形态）；
        // 缺项 = 空串，回落全局证书（cert_path / 内嵌 DER / 环境变量）
        self.edit_cert_path = self
            .config
            .node_cert_paths
            .get(addr)
            .cloned()
            .unwrap_or_default();
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

        // ── 写回阶段（不会再失败）──
        let orig = self.edit_orig_addr.clone();
        if addr_changed {
            self.config.rename_node(&orig, &new_addr);
            // 运行时状态表同步换键
            if let Some(st) = self.node_status.remove(&orig) {
                self.node_status.insert(new_addr.clone(), st);
            }
        }
        self.config.set_node_name(&new_addr, self.edit_name.trim());
        self.config.auth_key = key;
        // 逐节点独立证书路径（空串 = 清除，回落全局证书）；rename_node 已随迁旧键，
        // 此处以编辑值覆盖新地址键（清除场景同步移除）
        self.config.set_node_cert_path(&new_addr, &cert_path);
        self.node_edit_open = false;
        self.add_log(format!("节点 {} 已保存", new_addr));
        // 全局参数（密钥/证书）只在代理启动时读取，运行中修改必须重启才生效
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
                        // 来源只读（手动 / 订阅名；订阅节点不在本对话框编辑，见节点页）
                        ui.label("来源:");
                        ui.label(format!(
                            "[{}]（只读）",
                            self.config.node_source_label(&self.edit_orig_addr)
                        ));
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

                // 证书：逐节点独立路径（仅本节点）；全局证书为回落
                ui.label("节点证书路径（仅本节点）:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.edit_cert_path)
                            .desired_width(320.0)
                            .hint_text("本节点独立证书（留空 = 用全局证书）"),
                    );
                    if ui.small_button("浏览...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("证书文件", &["der", "pem", "crt", "cer"])
                            .add_filter("全部文件", &["*"])
                            .pick_file()
                        {
                            self.edit_cert_path = path.display().to_string();
                        }
                    }
                });
                ui.small(format!(
                    "全局证书（回落）: {}",
                    Self::cert_status_text(&self.config)
                ));

                // 传输为固定 TCP/TLS（TLS 1.3 + Noise-PSK）：Wave 3 起无其他模式
                ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）");

                if self.proxy_running {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xD6, 0x66),
                        "⚠ 代理正在运行：保存后需停止并重新启动代理，修改才会生效",
                    );
                }

                // 方案 §4：诚实提示——认证密钥为全局单值；证书已支持逐节点独立路径（上）
                ui.separator();
                ui.small("当前认证密钥为全局单值（所有节点共用）；节点证书已支持逐节点独立路径，留空回落全局证书");

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

    /// 设置页（v2 方案 §2.5 / 裁决 C）：应用级配置，无任何凭据。
    /// 分区：代理核心 / 安全与信任 / TUN 透明代理（实验）/ 系统 / 外观与数据 / 关于。
    /// 认证密钥、全局证书在「🌐 节点」页「全局凭据」区；信任模式与 TUN 在本页。
    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("设置");
        ui.separator();

        // ◈ 全局凭据（UI 重设计第一批：自「🌐 节点」页迁入，独立折叠区）
        // 过渡期这些字段仍为全局单值（GuiConfig），后端节点级凭据落地前
        // 对所有节点生效——此处诚实标注，不假装是节点级凭据。
        ui.heading("全局凭据（当前对所有节点生效）");
        egui::CollapsingHeader::new("🔑 认证密钥 / 节点证书")
            .default_open(self.global_creds_open)
            .show(ui, |ui| {
                ui.colored_label(
                    palette::WARNING,
                    "⚠ 当前 hydra-client 按全局凭据连接：以下配置对所有节点生效；节点级凭据将在后端改造后逐节点生效",
                );
                // 认证密钥：默认掩码显示（如 a1b2****8f90），点击「编辑/显示」查看并编辑明文
                ui.horizontal(|ui| {
                    ui.label("认证密钥:");
                    if self.show_auth_key {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.config.auth_key)
                                .desired_width(200.0),
                        );
                        if ui.small_button("隐藏").clicked() {
                            self.show_auth_key = false;
                        }
                    } else {
                        let shown = if self.config.auth_key.is_empty() {
                            "（未设置）".to_string()
                        } else {
                            config::mask_secret(self.config.auth_key.trim())
                        };
                        ui.monospace(shown);
                        if ui.small_button("编辑/显示").clicked() {
                            self.show_auth_key = true;
                        }
                    }
                });
                // 密钥有效性实时校验（hex + 最短 16 字节）
                if self.show_auth_key && !self.config.auth_key.trim().is_empty() {
                    match hydra_client::auth_key_from_hex(self.config.auth_key.trim()) {
                        Ok(_) => {
                            ui.colored_label(palette::SUCCESS, "✓ 密钥格式有效")
                        }
                        Err(e) => ui.colored_label(palette::DANGER, format!("✗ {}", e)),
                    };
                }

                // 节点证书：当前状态（路径/内嵌指纹）+ 浏览替换，实时校验存在性
                ui.horizontal(|ui| {
                    ui.label("节点证书:");
                    ui.small(Self::cert_status_text(&self.config));
                });
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.config.cert_path)
                            .desired_width(ui.available_width() - 80.0)
                            .hint_text("证书文件路径（清空则使用内嵌/分享导入的证书）"),
                    );
                    if ui.button("浏览替换...").clicked() {
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
                if !self.config.cert_path.trim().is_empty()
                    && !std::path::Path::new(self.config.cert_path.trim()).exists()
                {
                    ui.colored_label(palette::DANGER, "✗ 证书文件不存在，请检查路径");
                }

                // 传输为固定 TCP/TLS（TLS 1.3 + Noise-PSK）：Wave 3 起无其他模式
                ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）");
            });

        ui.separator();

        // ◈ 代理核心
        ui.heading("代理核心");
        ui.horizontal(|ui| {
            ui.label("本地监听地址:");
            ui.add(
                egui::TextEdit::singleline(&mut self.config.proxy_listen_addr)
                    .desired_width(180.0)
                    .hint_text("127.0.0.1:1080"),
            );
        });
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
            ui.weak("（Offline 节点自动恢复探测，默认 30 秒）");
        });
        ui.small("认证密钥与节点证书在本页上方「全局凭据」区；新手引导可随时重看");
        if ui.button("显示新手引导").clicked() {
            for line in HydraApp::wizard_lines() {
                self.add_log(line);
            }
        }

        ui.separator();

        // ◈ 安全与信任（双信任模式：自签 pinning 默认 / 真证书 CA）
        ui.heading("安全与信任");
        // 拷贝为 String：后续要可变借用 self.config（pin 输入框），避免借用冲突
        let mode = self.config.trust_mode_effective().to_string();
        ui.horizontal(|ui| {
            ui.label("信任模式:");
            if ui
                .radio(mode == "pin", "自签 pinning（默认）")
                .clicked()
            {
                self.config.trust_mode = String::new(); // 空串 = 默认 pin（配置语义与 serde 默认一致）
                self.add_log("信任模式：自签 pinning（节点证书入本地信任根）".to_string());
            }
            if ui.radio(mode == "ca", "真证书 CA").clicked() {
                self.config.trust_mode = "ca".to_string();
                self.add_log(
                    "信任模式：真证书 CA（节点需 ACME 等真证书部署；自定义域名需另设 SNI，见 README）"
                        .to_string(),
                );
            }
        });
        // ca 模式：可选叶证书 SHA-256 硬 pin（64 hex，防 CA 误签发）
        if mode == "ca" {
            ui.horizontal(|ui| {
                ui.label("叶证书 SHA-256 硬 pin（可选）:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.config.ca_leaf_pin)
                        .desired_width(380.0)
                        .hint_text("64 位 hex，留空 = 仅信任公共 CA"),
                );
            });
            match config::validate_leaf_pin(&self.config.ca_leaf_pin) {
                Ok(()) if self.config.ca_leaf_pin.trim().is_empty() => {}
                Ok(()) => {
                    ui.colored_label(
                        egui::Color32::from_rgb(0x7D, 0xE2, 0x97),
                        "✓ 格式有效（64 hex）",
                    );
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::from_rgb(0xFF, 0x8A, 0x80), format!("✗ {e}"));
                }
            }
            ui.small("ca 模式不使用节点证书文件；节点侧用真证书（如 ACME）部署，SNI 须与证书 SAN 一致");
        } else {
            ui.small("pin 模式使用本页「全局凭据」区的节点证书（支持逐节点独立证书，见节点编辑）");
        }
        if self.proxy_running {
            ui.small("⚠ 代理正在运行：信任模式修改需停止并重新启动代理后生效");
        }

        ui.separator();

        // ◈ TUN 透明代理（实验性：需管理员/root；Windows 另需 wintun.dll）
        ui.heading("TUN 透明代理（实验）");
        if ui
            .checkbox(
                &mut self.config.tun_enabled,
                "TUN 透明代理（实验，需管理员/root）",
            )
            .changed()
        {
            self.add_log(if self.config.tun_enabled {
                "TUN 透明代理：已开启（下次启动代理生效；仅拦截 TCP，按端口列表）".to_string()
            } else {
                "TUN 透明代理：已关闭（下次启动代理生效）".to_string()
            });
        }
        let tun_on = self.config.tun_enabled;
        ui.add_enabled(
            tun_on,
            egui::TextEdit::singleline(&mut self.config.tun_addr)
                .desired_width(200.0)
                .hint_text("TUN 地址（默认 10.7.0.1/30）"),
        )
        .on_disabled_hover_text("先开启 TUN 透明代理");
        ui.add_enabled(
            tun_on,
            egui::TextEdit::singleline(&mut self.config.tun_ports)
                .desired_width(200.0)
                .hint_text("拦截端口列表（默认 80,443,8080,8443）"),
        )
        .on_disabled_hover_text("先开启 TUN 透明代理");
        ui.small("TUN 全流量接管，应用无需配置代理；仅 TCP（UDP 含 QUIC 丢弃）、无 DNS 劫持；\n节点 IP 与系统 DNS 自动豁免防环路；退出/崩溃自动清理路由");
        // 与 CLI（hydra-client main.rs warn_system_proxy_loop）一致的环路告警：
        // Windows 系统代理 + TUN 全流量接管 → 经系统代理的流量二次进本代理
        #[cfg(windows)]
        if tun_on && hydra_client::windows_system_proxy_enabled() {
            ui.colored_label(
                egui::Color32::from_rgb(0xFF, 0xD6, 0x66),
                "⚠ 检测到 Windows 系统代理已开启：TUN 模式下经系统代理的流量会二次进入本代理形成环路，建议关闭系统代理",
            );
        }

        ui.separator();

        // ◈ 系统
        ui.heading("系统");
        ui.add_enabled(false, egui::Checkbox::new(&mut false, "开机自启（规划中）"))
            .on_disabled_hover_text("规划中：需随 TUN 服务模式一并实现");
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

        // ◈ 外观与数据
        ui.heading("外观与数据");
        ui.horizontal(|ui| {
            ui.label("主题:");
            ui.add_enabled(
                false,
                egui::Checkbox::new(&mut false, "深色（当前唯一主题）"),
            )
            .on_disabled_hover_text("主题选择预留，后续版本提供多主题");
        });
        ui.horizontal(|ui| {
            ui.label("配置目录:");
            ui.monospace(
                config::config_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(配置目录不可用)".to_string()),
            );
            if ui.button("打开目录").clicked() {
                if let Some(dir) = config::config_dir() {
                    #[cfg(windows)]
                    let _ = std::process::Command::new("explorer").arg(&dir).spawn();
                    #[cfg(not(windows))]
                    let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
                }
            }
        });
        ui.small(format!(
            "配置文件: {}（自动保存）",
            config::config_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(配置目录不可用)".to_string())
        ));

        ui.separator();

        // ◈ 关于
        ui.heading("关于");
        ui.label(format!(
            "Hydra Multipath Proxy v{}",
            env!("CARGO_PKG_VERSION")
        ));
        ui.hyperlink_to(
            "项目文档（GitHub）",
            "https://github.com/hydra-multipath-proxy/hydra-multipath-proxy",
        );
        ui.small("检查更新：预留");

        ui.separator();

        // 退出入口（托盘菜单同样可退出）
        if ui.button("退出程序（停止代理并清理系统代理）").clicked() {
            // 真退出：带超时等待代理线程退出（含 TUN 停机 + 路由清理）再关窗
            self.shutdown_and_wait_for_exit();
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
    // 视觉规范化第一步：颜色全部取自集中式色板 palette（本函数只做 Visuals 装配）
    let bg_panel = palette::BG_PANEL;
    let bg_window = palette::BG_CARD;
    let bg_extreme = palette::BG_EXTREME;
    let text = palette::TEXT;
    let weak = palette::TEXT_WEAK;
    let accent = palette::ACCENT;

    let mut style = (*ctx.style()).clone();
    // 关键修复：以深色 Visuals 为基底（默认是 light = 白底）
    style.visuals = egui::Visuals::dark();
    let vis = &mut style.visuals;
    // 面板/窗口/输入框背景统一深色
    vis.panel_fill = bg_panel;
    vis.window_fill = bg_window;
    vis.extreme_bg_color = bg_extreme; // TextEdit / 折叠区背景
    vis.faint_bg_color = egui::Color32::from_rgb(0x24, 0x28, 0x30); // 斑马纹/弱分隔
                                                                    // 文字：正文高对比，次要文字（ui.small / weak）仍 ≥7:1
    vis.override_text_color = Some(text);
    vis.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, weak); // 分隔线文字等
    vis.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, text);
    vis.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, accent);
    vis.widgets.active.fg_stroke = egui::Stroke::new(1.5_f32, accent);
    vis.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, accent);
    vis.hyperlink_color = accent;
    // 选中态
    vis.selection.bg_fill = accent.gamma_multiply(0.45);
    vis.selection.stroke = egui::Stroke::new(1.0_f32, accent);
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

/// 单元测试：GUI 状态机（问题 1）、代理启动时序（问题 2）、探测目标解析（问题 3）
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

    // ── 问题 3：测速探测目标常量与 env 覆盖 ──

    #[test]
    fn probe_target_defaults_to_cloudflare_443() {
        // 默认目标必须是 1.1.1.1:443（修复 192.0.0.1:9 静默丢包导致的测速误判）
        assert_eq!(probe_target_from(None), "1.1.1.1:443");
        assert_eq!(probe_target_from(Some("")), "1.1.1.1:443");
        assert_eq!(probe_target_from(Some("   ")), "1.1.1.1:443");
        assert_eq!(PROBE_TARGET_DEFAULT, "1.1.1.1:443");
        assert_eq!(PROBE_TARGET_ENV, "HYDRA_PROBE_TARGET");
    }

    #[test]
    fn probe_target_env_override() {
        // env 覆盖生效（去首尾空白）；纯函数无进程 env 副作用，可并行
        assert_eq!(probe_target_from(Some("10.0.0.1:8080")), "10.0.0.1:8080");
        assert_eq!(
            probe_target_from(Some("  1.2.3.4:443  ")),
            "1.2.3.4:443"
        );
    }

    // ── 视觉规范化第一步：延迟色标 / 节点状态色点 ──

    #[test]
    fn latency_color_thresholds() {
        use palette::latency_color;
        // 未测 = 灰
        assert_eq!(latency_color(None), palette::TEXT_FAINT);
        // <200ms 绿
        assert_eq!(latency_color(Some(0)), palette::SUCCESS);
        assert_eq!(latency_color(Some(199)), palette::SUCCESS);
        // 200–500ms 黄
        assert_eq!(latency_color(Some(200)), palette::WARNING);
        assert_eq!(latency_color(Some(499)), palette::WARNING);
        // ≥500ms 红（老板实测节点 319-451ms 属黄区间）
        assert_eq!(latency_color(Some(500)), palette::DANGER);
        assert_eq!(latency_color(Some(2000)), palette::DANGER);
    }

    #[test]
    fn node_status_color_states() {
        use palette::status_color;
        // 未验证（从未测速）= 灰
        assert_eq!(status_color(false, false, None), palette::TEXT_FAINT);
        // Online = 绿
        assert_eq!(status_color(true, true, Some(45)), palette::SUCCESS);
        // Degraded（在线但延迟 ≥500ms）= 黄
        assert_eq!(status_color(true, true, Some(800)), palette::WARNING);
        // Offline（测过但失败）= 红
        assert_eq!(status_color(false, true, None), palette::DANGER);
    }

    // ── 问题 2：bound_addr 时序回归（run_proxy_until_stopped）──

    /// 构造一个不依赖真实节点证书的代理实例：带 auth key + 显式 trust（空 pin 列表
    /// 即可通过 start() 的前置检查），监听地址由调用方给定。bind 在任何连接发生前
    /// 完成，因此无需真实节点。
    fn test_proxy(addr: SocketAddr) -> Arc<ProxyServer> {
        Arc::new(
            ProxyServer::new(addr)
                .with_auth_key(vec![0x42u8; 32])
                .with_trust(hydra_client::tcp_transport::TlsTrust::pinned(Vec::new())),
        )
    }

    /// 抓一个当前空闲的 TCP 端口（临时监听后立即释放）
    fn free_port() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("绑定临时端口失败")
            .local_addr()
            .expect("读取临时端口失败")
    }

    /// 根因回归：修复前 watcher 在 proxy.start() 之前被 await（互相等待），
    /// bound_addr 永远等不到、必然 60s 超时；修复后 start() 立即执行 bind，
    /// 就绪信号应在 3s 内到达。
    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_binds_within_3s() {
        let addr = free_port();
        let proxy = test_proxy(addr);
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let task =
            tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
        // 阻塞 recv 移入 spawn_blocking，避免冻结异步测试执行器
        let signal = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                rx.recv_timeout(std::time::Duration::from_secs(3))
            }),
        )
        .await
        .expect("bound_addr 未在 3s 内就绪（问题 2 回归）")
        .expect("阻塞接收任务失败")
        .expect("recv 失败");
        match signal {
            Ok(bound) => assert_eq!(bound, addr),
            Err(e) => panic!("启动失败信号: {e}"),
        }
        // 收尾：置 stop 让 select 的停机分支结束，任务正常退出
        stop.store(true, Ordering::Relaxed);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    /// 场景回归：「启动 → 立即 stop → 再启动」同一端口两轮都应在 3s 内就绪
    #[tokio::test(flavor = "multi_thread")]
    async fn start_stop_restart_binds_within_3s_each_round() {
        let addr = free_port();
        for round in 1..=2 {
            let proxy = test_proxy(addr);
            let (tx, rx) = std::sync::mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let task =
                tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
            let signal = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    rx.recv_timeout(std::time::Duration::from_secs(3))
                }),
            )
            .await
            .unwrap_or_else(|_| panic!("第 {round} 轮 bound_addr 未在 3s 内就绪"))
            .expect("阻塞接收任务失败")
            .expect("recv 失败");
            match signal {
                Ok(bound) => assert_eq!(bound, addr),
                Err(e) => panic!("第 {round} 轮启动失败信号: {e}"),
            }
            // 立即 stop：停机分支退出 select，端口释放后下一轮可复用
            stop.store(true, Ordering::Relaxed);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
            // 给内核一点时间释放监听套接字
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// 场景回归：「并发测速负载 + 启动」——启动路径不得被后台负载拖过 3s
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_load_does_not_delay_bind() {
        let addr = free_port();
        // 模拟并发测速负载：持续 2s 的小睡眠任务（真实测速为网络 IO，同样是
        // 独立任务不占用启动路径；此前根因是启动路径自我串行死锁）
        let load = tokio::spawn(async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        let proxy = test_proxy(addr);
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let task =
            tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
        let started = std::time::Instant::now();
        let signal = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                rx.recv_timeout(std::time::Duration::from_secs(3))
            }),
        )
        .await
        .expect("并发负载下 bound_addr 未在 3s 内就绪")
        .expect("阻塞接收任务失败")
        .expect("recv 失败");
        assert!(
            matches!(signal, Ok(bound) if bound == addr),
            "信号异常: {signal:?}"
        );
        // 额外断言实际耗时远小于 3s（一般毫秒级）
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        let _ = load.await;
    }

    // ── UI 重设计第二批：节点页组视图（组过滤纯函数）──

    /// 组过滤测试夹具：手动 1 节点 + 订阅A 认领 2 节点 + 订阅B 认领 1 节点
    fn group_fixture() -> GuiConfig {
        let mut cfg = GuiConfig::default();
        cfg.node_addrs = vec![
            "10.0.0.1:1".to_string(),  // 手动
            "10.0.0.2:2".to_string(),  // 订阅A
            "10.0.0.3:3".to_string(),  // 订阅A
            "10.0.0.4:4".to_string(),  // 订阅B
        ];
        cfg.subscriptions.push(SubscriptionConfig {
            name: "订阅A".to_string(),
            source: "https://a.example".to_string(),
            last_updated_secs: None,
            nodes: vec!["10.0.0.2:2".to_string(), "10.0.0.3:3".to_string()],
        });
        cfg.subscriptions.push(SubscriptionConfig {
            name: "订阅B".to_string(),
            source: "https://b.example".to_string(),
            last_updated_secs: None,
            nodes: vec!["10.0.0.4:4".to_string()],
        });
        cfg
    }

    #[test]
    fn node_group_of_claims_follow_subscription_nodes() {
        let cfg = group_fixture();
        // 被订阅认领 → Some(订阅名)；未被认领 → None（手动）
        assert_eq!(node_group_of(&cfg, "10.0.0.1:1"), None);
        assert_eq!(node_group_of(&cfg, "10.0.0.2:2"), Some("订阅A".to_string()));
        assert_eq!(node_group_of(&cfg, "10.0.0.4:4"), Some("订阅B".to_string()));
        // 不在节点列表但被订阅认领：组归属仍按订阅 nodes 判定（过滤时被列表约束）
        assert_eq!(node_group_of(&cfg, "9.9.9.9:9"), None);
    }

    #[test]
    fn filter_nodes_by_group_none_all_manual_and_sub() {
        let cfg = group_fixture();
        let addrs = cfg.node_addrs.clone();
        // None = 全部
        assert_eq!(filter_nodes_by_group(&cfg, &addrs, &None), addrs);
        // Some("manual") = 未被任何订阅认领的手动节点
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some(GROUP_MANUAL.to_string())),
            vec!["10.0.0.1:1".to_string()]
        );
        // Some(订阅名) = 该订阅认领的地址
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some("订阅A".to_string())),
            vec!["10.0.0.2:2".to_string(), "10.0.0.3:3".to_string()]
        );
        // 不存在的组名 = 空列表（UI 侧已回落「全部」，此处仅保证纯函数确定性）
        assert!(filter_nodes_by_group(&cfg, &addrs, &Some("不存在".to_string())).is_empty());
    }

    #[test]
    fn filter_nodes_by_group_empty_config_and_no_subs() {
        // 无订阅配置：全部 = 手动 = 节点列表
        let mut cfg = GuiConfig::default();
        cfg.node_addrs = vec!["1.2.3.4:4433".to_string()];
        let addrs = cfg.node_addrs.clone();
        assert_eq!(filter_nodes_by_group(&cfg, &addrs, &None), addrs);
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some(GROUP_MANUAL.to_string())),
            addrs
        );
        assert!(
            filter_nodes_by_group(&cfg, &addrs, &Some("订阅A".to_string())).is_empty()
        );
        // 空列表
        assert!(filter_nodes_by_group(&cfg, &[], &None).is_empty());
    }

    #[test]
    fn group_summary_counts_online_offline_only_when_checked() {
        let mut status = HashMap::new();
        let mk = |connected: bool| NodeStatusInfo {
            connected,
            last_check: Some(std::time::Instant::now()),
            latency_ms: None,
        };
        status.insert("a".to_string(), mk(true));
        status.insert("b".to_string(), mk(false));
        // 未测（last_check=None）不计入摘要
        status.insert(
            "c".to_string(),
            NodeStatusInfo {
                connected: false,
                last_check: None,
                latency_ms: None,
            },
        );
        // 无记录的 d 同样不计入
        let addrs: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert_eq!(group_summary(&status, &addrs), (1, 1));
        assert_eq!(group_summary(&status, &[]), (0, 0));
    }
}
