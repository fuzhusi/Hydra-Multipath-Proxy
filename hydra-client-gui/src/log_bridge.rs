//! 批次 A1/A4：内核 tracing 事件桥接 + 日志级别热调。
//!
//! 组成（评审硬约束：全进程**唯一** tracing 初始化在 main.rs 完成，本模块
//! 只提供被 registry 组装使用的 Layer 与运行时控制句柄，绝不二次 init）：
//! - [`KernelRingLayer`]：自定义 `Layer<Registry>`，把内核（hydra-core /
//!   hydra-client / hydra-node 库代码）发出的 tracing 事件经字段 Visitor
//!   提取（`message` / `target` / `direction` / 其余 k=v）后推入进程级环形
//!   缓冲（Mutex<VecDeque>，满员丢最旧）。GUI 日志页每帧 drain 到页面缓冲，
//!   推送端只做一次短锁拷贝、绝不阻塞 IO 线程。
//! - [`LEVEL_HANDLE`] / [`FILE_HANDLE`]：`reload::Layer` 句柄，设置页级别
//!   下拉（A4）与「自动保存日志」开关（A3）运行时热调 EnvFilter。
//!
//! 字段化事件经环 Layer 进缓冲有单测覆盖（见 tests）。
//!
//! ── P1-1 硬约束（评审修订）──────────────────────────────────────
//! **GUI 环缓冲永不接收明文目标——内核事件一律字段化 + 掩码**：KernelRingLayer
//! 挂载在同进程 registry 上，hydra-core 等内核库发出的每一条 debug/trace 事件
//! 都会进入本缓冲，因此内核侧任何日志事件禁止以文本形式携带明文目标
//! （host:port / URL / 请求行）；目标仅允许以 `target = %mask_target(...)`
//! 字段（短哈希）出现。新增内核日志时必须遵守本约束；code review 以此核查
//! （docs/review 10 号「内核与日志优化」批次 A 评审 P1-1）。

use crate::LogLevel;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::reload;
use tracing_subscriber::EnvFilter;

/// 环形缓冲容量（与 GUI 日志页 LOG_CAPACITY 同量级：未打开日志页时内核
/// 事件仍被暂存，打开页面即可回看最近 1000 条）
const RING_CAPACITY: usize = 1000;

/// 进程级环形缓冲（内核事件暂存；GUI 日志页 drain 走）
static RING: Mutex<VecDeque<LogEntry>> = Mutex::new(VecDeque::new());

/// A4：全局 EnvFilter 热调句柄（registry 组装后由 main 写入一次）
static LEVEL_HANDLE: OnceLock<reload::Handle<EnvFilter, tracing_subscriber::Registry>> =
    OnceLock::new();

/// A3：GUI 文件日志开关（文件层自身的 Filter 读取；级别跟随全局 EnvFilter，
/// 此处只做开/关门控——关 = 该层不收到任何事件）
static FILE_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// P2-2：RUST_LOG 环境变量优先标记（main 启动时写入一次，之后只读）。
/// true = 设置页级别下拉禁用（hover 提示「RUST_LOG 环境变量优先，热调已跳过」）、
/// 热调调用点跳过 reload——环境变量优先级高于配置持久化，热调无意义且会造成
/// 「UI 显示与实际过滤不一致」的假象。
static RUST_LOG_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// P2-2：main 启动时写入一次（RUST_LOG 是否已设置）
pub(crate) fn set_rust_log_override(on: bool) {
    RUST_LOG_OVERRIDE.store(on, Ordering::Relaxed);
}

/// P2-2：设置页读取（true → 下拉禁用 + 热调调用点跳过 reload）
pub(crate) fn rust_log_override() -> bool {
    RUST_LOG_OVERRIDE.load(Ordering::Relaxed)
}

/// GUI 日志页单条结构化条目（A2：VecDeque 元素从 (LogLevel, String) 升级）
#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    pub level: LogLevel,
    /// 已含时间前缀的展示文本（push 入页面缓冲时统一加 `[HH:MM:SS]`）
    pub text: String,
    /// 内核事件的 direction 字段（"inbound"/"outbound"/"up"/"down"…），GUI 自产日志为 None
    pub direction: Option<String>,
    /// 内核事件掩码后的 target 字段，GUI 自产日志为 None
    pub target: Option<String>,
}

impl LogEntry {
    /// GUI 应用自产日志（无内核字段；仅测试构造用，生产路径走 push_log_full）
    #[cfg(test)]
    pub(crate) fn app(level: LogLevel, text: String) -> Self {
        Self {
            level,
            text,
            direction: None,
            target: None,
        }
    }
}

/// tracing Level → GUI LogLevel 映射（GUI 只有三档：debug/trace 归入信息档，
/// 文本前缀标注原始级别，避免为着色扩展 components 层）。
fn map_level(level: &Level) -> LogLevel {
    match *level {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warn,
        Level::INFO | Level::DEBUG | Level::TRACE => LogLevel::Info,
    }
}

/// debug/trace 级事件的文本前缀（级别降档后仍可辨识原始级别）
fn level_prefix(level: &Level) -> &'static str {
    match *level {
        Level::DEBUG => "[debug] ",
        Level::TRACE => "[trace] ",
        _ => "",
    }
}

/// 字段 Visitor：`message` 为主体，`target`/`direction` 升为结构化字段，
/// 其余字段以 ` k=v` 追加到文本尾部。
struct EventVisitor {
    message: String,
    extra: Vec<(&'static str, String)>,
    direction: Option<String>,
    target: Option<String>,
}

impl EventVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            extra: Vec::new(),
            direction: None,
            target: None,
        }
    }

    fn route(&mut self, name: &'static str, value: String) {
        match name {
            "message" => self.message = value,
            "direction" => self.direction = Some(value),
            "target" => self.target = Some(value),
            _ => self.extra.push((name, value)),
        }
    }
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.route(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.route(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.route(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.route(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.route(field.name(), value.to_string());
    }
}

/// 内核事件 → GUI 环形缓冲 Layer（A1）。
///
/// 挂载位置在全局 EnvFilter（registry 组装时的过滤层）之后：转发级别由
/// EnvFilter 控制，默认 info；GUI 日志页既有的级别/文本过滤照旧叠加。
pub(crate) struct KernelRingLayer;

impl<S: Subscriber> Layer<S> for KernelRingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = EventVisitor::new();
        event.record(&mut visitor);
        let mut text = format!("{}{}", level_prefix(event.metadata().level()), visitor.message);
        for (k, v) in &visitor.extra {
            text.push_str(&format!(" {k}={v}"));
        }
        let entry = LogEntry {
            level: map_level(event.metadata().level()),
            text,
            direction: visitor.direction,
            target: visitor.target,
        };
        // 短锁推送 + 满员丢最旧；绝不阻塞、绝不 panic（锁中毒降级为丢弃）
        if let Ok(mut ring) = RING.lock() {
            if ring.len() >= RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(entry);
        }
    }
}

/// GUI 日志页每帧调用：把环形缓冲中的内核事件搬到页面缓冲
/// （容量由调用方 push 逻辑统一裁剪）。
pub(crate) fn drain_kernel_entries(out: &mut Vec<LogEntry>) {
    if let Ok(mut ring) = RING.lock() {
        out.extend(ring.drain(..));
    }
}

/// A4：运行时热调全局日志级别（设置页下拉）。
/// `level` ∈ error/warn/info/debug/trace（非法返回 Err，不改动当前过滤）。
pub(crate) fn set_level(level: &str) -> Result<(), String> {
    let filter = EnvFilter::try_new(level).map_err(|e| format!("日志级别 {level} 非法: {e}"))?;
    match LEVEL_HANDLE.get() {
        Some(h) => h.reload(filter).map_err(|e| format!("级别热调失败: {e}")),
        None => Err("tracing 尚未初始化（应在 GUI 启动后调用）".to_string()),
    }
}

/// A3：文件日志层门控 Filter（挂在 fmt 文件层上；关 = 层内丢弃全部事件）
pub(crate) struct FileGate;

impl<S: Subscriber> tracing_subscriber::layer::Filter<S> for FileGate {
    fn enabled(
        &self,
        _metadata: &tracing::Metadata<'_>,
        _ctx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        FILE_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A3：运行时开关 GUI 文件日志（开 = 跟随全局级别写 gui.log；关 = 不写）。
/// 级别过滤由全局 EnvFilter 统一承担，此处仅门控文件层自身（无失败路径）。
pub(crate) fn set_file_logging(enabled: bool, _level: &str) {
    FILE_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// 注册热调句柄（main.rs registry 组装后调用一次；重复调用静默忽略——
/// 首次组装者获胜，防御性兜底而非业务分支）。
pub(crate) fn install_handles(level: reload::Handle<EnvFilter, tracing_subscriber::Registry>) {
    let _ = LEVEL_HANDLE.set(level);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;

    /// RING 是进程级全局缓冲：ring 相关用例经此互斥串行化，避免并行测试
    /// 互相 drain 走对方的事件（测试基建，非生产路径）
    static RING_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 新增测试③：字段化 tracing 事件经 KernelRingLayer 进入环形缓冲
    /// （message 主体 + target/direction 结构化字段 + k=v 附加字段）。
    #[test]
    fn test_fieldized_event_reaches_ring_buffer() {
        let _serial = RING_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // 本地组装 registry（不用全局 init：单测进程内可能已有别的 subscriber）
        let subscriber = tracing_subscriber::registry().with(KernelRingLayer);
        with_default(subscriber, || {
            tracing::info!(
                target = "1.2.3.4:443",
                direction = "outbound",
                up_bytes = 128u64,
                down_bytes = 4096u64,
                duration_ms = 42u64,
                "连接关闭"
            );
        });
        let mut drained = Vec::new();
        drain_kernel_entries(&mut drained);
        let hit = drained
            .iter()
            .find(|e| e.text.contains("连接关闭"))
            .expect("字段化事件应进环形缓冲");
        assert_eq!(hit.level, LogLevel::Info);
        assert_eq!(hit.direction.as_deref(), Some("outbound"));
        assert_eq!(hit.target.as_deref(), Some("1.2.3.4:443"));
        assert!(hit.text.contains("up_bytes=128"), "附加字段应拼进文本: {}", hit.text);
        assert!(hit.text.contains("duration_ms=42"), "附加字段应拼进文本: {}", hit.text);
    }

    /// 级别映射：error→Error、warn→Warn、debug→Info（带 [debug] 前缀）
    #[test]
    fn test_level_mapping_and_prefix() {
        let _serial = RING_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let subscriber = tracing_subscriber::registry().with(KernelRingLayer);
        with_default(subscriber, || {
            tracing::warn!(direction = "inbound", "内核告警");
            tracing::debug!("内核调试细节");
        });
        let mut drained = Vec::new();
        drain_kernel_entries(&mut drained);
        let warn = drained.iter().find(|e| e.text.contains("内核告警")).unwrap();
        assert_eq!(warn.level, LogLevel::Warn);
        assert!(warn.direction.as_deref() == Some("inbound"));
        let dbg = drained.iter().find(|e| e.text.contains("内核调试细节")).unwrap();
        assert_eq!(dbg.level, LogLevel::Info);
        assert!(dbg.text.starts_with("[debug] "), "debug 应带级别前缀: {}", dbg.text);
    }

    /// 新增测试②：EnvFilter 热调——reload 句柄切换级别后，先前被过滤的
    /// info 事件开始进入环 Layer（A4 验收：拉到 debug 后内核 debug 事件实时出现）。
    #[test]
    fn test_env_filter_hot_reload() {
        let _serial = RING_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        use tracing_subscriber::layer::SubscriberExt;
        let (filter, handle) = reload::Layer::new(EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry().with(filter).with(KernelRingLayer);
        with_default(subscriber, || {
            tracing::info!(tag = "before", "info 事件（warn 级应被过滤）");
            let mut drained = Vec::new();
            drain_kernel_entries(&mut drained);
            assert!(drained.is_empty(), "warn 级下 info 事件不应进入缓冲");
            // 热调到 info：同一进程内立即生效
            handle.reload(EnvFilter::new("info")).expect("热调应成功");
            tracing::info!(tag = "after", "info 事件（热调后应进入缓冲）");
            drain_kernel_entries(&mut drained);
            assert!(
                drained.iter().any(|e| e.text.contains("after")),
                "热调后 info 事件应进入缓冲: {:?}",
                drained
            );
            assert!(!drained.iter().any(|e| e.text.contains("before")));
        });
    }

    /// set_level 非法级别拒绝且不改动（错误透出，不静默）
    #[test]
    fn test_set_level_rejects_invalid() {
        assert!(crate::log_bridge::set_level("not-a-level").is_err());
    }

    /// 环形缓冲满员丢最旧（容量边界不 panic、不无界增长）
    #[test]
    fn test_ring_capacity_drops_oldest() {
        let _serial = RING_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let subscriber = Arc::new(tracing_subscriber::registry().with(KernelRingLayer));
        with_default(subscriber, || {
            for i in 0..(RING_CAPACITY + 50) {
                tracing::info!(seq = i as u64, "采样事件");
            }
        });
        let mut drained = Vec::new();
        drain_kernel_entries(&mut drained);
        assert_eq!(drained.len(), RING_CAPACITY);
        // 最旧的 seq=0 已被挤出，最新一条保留
        assert!(drained.iter().all(|e| !e.text.contains("seq=0")));
        assert!(drained
            .last()
            .unwrap()
            .text
            .contains(&format!("seq={}", RING_CAPACITY + 49)));
    }
}
