//! Hydra Android 绑定层（uniffi → Kotlin）。
//!
//! 设计约束（docs/design/移动端Android方案-v2.md v2.1）：
//! - **显式参数化**：节点/PSK/证书全部由 Kotlin 传入（R8：PSK 存
//!   EncryptedSharedPreferences，Kotlin 侧解密后以 hex/bytes 交付），本层
//!   零 env 读取、零文件路径依赖。
//! - **R4 防环回**：[`SocketProtect`] 回调接口——引擎每个新出站 socket 在
//!   **建连前**回调 Kotlin 层调 `VpnService.protect(fd)`（09-P1-7 起**全链路
//!   接线**：经 `hydra_core::socket_protect` 钩子在 `TcpSocket` 阶段调用），
//!   回调返回 `false`（protect 失败）时该连接立即中止——放行会被本应用 TUN
//!   捕获回环。iOS 等无 VPN 环回问题的平台传 None。
//! - 引擎生命周期独立 tokio runtime：`start()` 立即返回（绑定监听在后台完成，
//!   经 [`HydraEngine::bound_addr`] 查询），`stop()` 关停全部任务。
//!
//! Kotlin 冒烟单测（android/app）：经绑定构造 → start → 查询监听地址 → stop。

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use hydra_core::{proxy::ProxyServer, tcp_transport::TlsTrust, traffic::TrafficMonitor};
use hydra_protocol::mask_target;

// ── uniffi 导出类型 ─────────────────────────────────────────────────────────

/// 节点描述（addr 形如 "1.2.3.4:443"；IPv6 用 "[::1]:443" 字面量形式）
#[derive(uniffi::Record, Debug, Clone)]
pub struct NodeSpec {
    pub addr: String,
}

/// TLS 信任模式（v2.1 信任双路线）
#[derive(uniffi::Enum, Debug, Clone)]
pub enum TrustMode {
    /// 自签证书 pin：Kotlin 从 EncryptedSharedPreferences/Assets 读 der 传入
    Pinned { cert_der: Vec<Vec<u8>> },
    /// 真证书部署：公共 CA 根 + 域名校验（sni 必填）
    PublicCa,
}

/// 引擎统计快照（进程内 SOCKS 与未来 TUN 通道同一计数面）
#[derive(uniffi::Record, Debug, Clone)]
pub struct EngineStats {
    pub sent: u64,
    pub received: u64,
    pub upload_speed: f64,
    pub download_speed: f64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub uptime_secs: u64,
}

/// R4 防环回：出站 socket 保护回调（Kotlin 实现 → `VpnService.protect(fd)`）。
/// fd 为引擎新建出站 socket 的文件描述符；在任何 connect 之前调用。
/// **返回 protect 是否成功**：false 时引擎中止该连接（放行 = 流量进自身
/// TUN 回环，宁失败不放行）。Kotlin 实现示例：
/// `override fun protect(fd: Long): Boolean = vpnService.protect(fd.toInt())`
#[uniffi::export(callback_interface)]
pub trait SocketProtect: Send + Sync {
    fn protect(&self, fd: i64) -> bool;
}

/// 分享/订阅导入结果（Kotlin 落 EncryptedSharedPreferences）。
/// 密钥/证书字段为空串 = 链接未携带——调用方**不覆盖**已存值。
#[derive(uniffi::Record, Debug, Clone)]
pub struct ParsedShare {
    /// 节点 "addr:port" 列表（IP 字面量；域名节点计入 skipped）
    pub nodes: Vec<String>,
    /// 认证密钥 64 hex（取首个携带密钥的链接）
    pub auth_key_hex: String,
    /// 证书 DER base64（STANDARD；取首个携带证书的链接——分享链接 v2 的
    /// `cc=` 字段自带节点证书，导入后无需再手动选文件）
    pub cert_der_b64: String,
    /// 未能导入的条目数（域名节点/坏行——域名支持随 M2 tun_core）
    pub skipped: u32,
}

/// 解析分享链接 / 订阅文本（hydra:// 多行、逐行或整体 base64 订阅），
/// 汇聚为一份引擎配置（节点列表 + 密钥 + 证书）。任一链接携带的 `k=`（密钥）
/// 与 `cc=`（证书）都会被提取。
#[uniffi::export]
pub fn parse_share_text(text: String) -> Result<ParsedShare, HydraEngineError> {
    let parse = hydra_core::subscription::parse_subscription(&text);
    let mut nodes: Vec<String> = Vec::new();
    let mut auth_key_hex = String::new();
    let mut cert_der_b64 = String::new();
    let mut skipped = parse.errors.len() as u32;
    for link in &parse.links {
        // IP 字面量节点入库；域名节点 M2 前不支持（计数跳过，给出可感知反馈）
        match link.to_node_info() {
            Ok(info) => {
                let addr = info.address.to_string();
                if !nodes.contains(&addr) {
                    nodes.push(addr);
                }
            }
            Err(_) => skipped += 1,
        }
        if auth_key_hex.is_empty() {
            if let Ok(Some(k)) = link.auth_key_bytes() {
                auth_key_hex = hydra_core::share_link::hex_encode_lower(&k);
            }
        }
        if cert_der_b64.is_empty() {
            if let Ok(Some(der)) = link.cert_der_bytes() {
                use base64::Engine as _;
                cert_der_b64 = base64::engine::general_purpose::STANDARD.encode(&der);
            }
        }
    }
    if nodes.is_empty() {
        return Err(HydraEngineError::InvalidConfig {
            msg: format!(
                "未能识别任何可用节点（跳过 {skipped} 条）。支持 hydra:// 分享链接、                 多行链接文本与整体 base64 订阅"
            ),
        });
    }
    Ok(ParsedShare {
        nodes,
        auth_key_hex,
        cert_der_b64,
        skipped,
    })
}

/// 单节点连通性测试结果（§连通性自检：引擎可用 ≠ 节点可达）
#[derive(uniffi::Record, Debug, Clone)]
pub struct TestResult {
    pub ok: bool,
    /// 成功时为完整握手耗时（毫秒）；失败为 0
    pub latency_ms: u64,
    /// 失败原因（用户可读中文）
    pub detail: String,
}

/// 对单个节点发起完整握手探测（TCP+TLS+Noise-PSK，与数据面同路径）。
/// 阻塞调用（内部一次性 runtime，8s 超时）——Kotlin 侧须在 IO 线程调用。
#[uniffi::export]
pub fn test_node_connection(
    node: String,
    auth_key_hex: String,
    trust: TrustMode,
    sni: Option<String>,
) -> TestResult {
    use std::net::SocketAddr;
    let fail = |detail: String| TestResult {
        ok: false,
        latency_ms: 0,
        detail,
    };
    let addr: SocketAddr = match node.parse() {
        Ok(a) => a,
        Err(_) => return fail("节点地址无法解析（须 IP:端口；IPv6 用 [::1]:443 形式）".into()),
    };
    let key = match hydra_core::auth_key_from_hex(&auth_key_hex) {
        Ok(k) => k,
        Err(m) => return fail(format!("认证密钥非法：{m}")),
    };
    let tls = match trust {
        TrustMode::Pinned { cert_der } => hydra_core::tcp_transport::TlsTrust::pinned(cert_der),
        TrustMode::PublicCa => hydra_core::tcp_transport::TlsTrust::public_ca(None),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(format!("探测 runtime 创建失败: {e}")),
    };
    let sni = sni.unwrap_or_else(|| hydra_core::DEFAULT_SNI.to_string());
    let out = runtime.block_on(async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(8),
            hydra_core::speedtest::probe_node_once(addr, &sni, &tls, &key),
        )
        .await
        {
            Ok(Ok(d)) => TestResult {
                ok: true,
                latency_ms: d.as_millis() as u64,
                detail: String::new(),
            },
            Ok(Err(e)) => fail(e),
            Err(_) => fail("探测超时（8s）——节点不可达或网络不通".into()),
        }
    });
    runtime.shutdown_timeout(std::time::Duration::from_millis(200));
    out
}

// ── M2：全局 VPN（VpnService fd → 用户态栈 → 节点隧道）──────────────────────

/// VPN 模式配置（Kotlin 自 SecureStore 组装；地址与 VpnService.Builder 一致）
#[derive(uniffi::Record, Debug, Clone)]
pub struct VpnConfig {
    pub nodes: Vec<String>,
    pub auth_key_hex: String,
    pub trust: TrustMode,
    pub sni: Option<String>,
    pub mtu: u16,
    /// TUN v4 地址（与 Builder.addAddress 一致，默认 10.7.0.1/30）
    pub addr4: String,
    pub prefix4: u8,
    /// TUN v6 网关地址（默认 fd07::1）
    pub addr6: String,
    pub udp_relay: bool,
    /// 智能分流开关（设计 v1 §九）：true = 规则模式（内置 CN 域名/GeoIP 表 +
    /// 可选自定义规则文件）；false = 全局模式（与既有行为逐字节一致，零开销）。
    pub rule_mode: bool,
    /// 规则文件**完整绝对路径**（Kotlin 沙箱 `context.filesDir/rules.txt`——
    /// Rust 不知道安卓沙箱路径）。仅 rule_mode=true 时读取；文件缺失/解析
    /// 失败 → 降级为内置 CN 规则引擎（对齐桌面语义：内置 CN 直连保留，
    /// 自定义规则未加载），**永不因分流断网**。
    pub rule_file: Option<String>,
}

/// VPN 规则降级标记（P2-3）：rule_mode=true 且规则文件不可用、实际使用
/// [`hydra_core::routing_rules::RuleEngine::builtin_cn`] 兜底时置 true；
/// 正常文件引擎或全局模式为 false。`stop_vpn` 复位（未启动 = false）。
static VPN_RULE_DEGRADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 查询当前 VPN 是否处于「规则降级」状态（P2-3）：true = 规则模式开启但
/// 自定义规则文件不可用，正在使用内置 CN 规则兜底（Kotlin 层据此在日志流
/// 中给用户可见提示）。VPN 未启动时恒为 false。
#[uniffi::export]
pub fn vpn_rule_mode_degraded() -> bool {
    VPN_RULE_DEGRADED.load(std::sync::atomic::Ordering::SeqCst)
}

/// 全局 VPN 数据面流量统计快照（Kotlin `HydraVpnService` 每秒轮询）。
/// 与本地端口模式的 [`EngineStats`] 相互独立：本结构只反映 TUN 用户态栈
/// （Rust `run_stack`）的中继字节与 TCP 流数；本地模式统计仍走
/// `HydraEngine::stats()`（SOCKS 侧 TrafficMonitor）。
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct VpnStats {
    /// 上行字节（应用 → 节点隧道，TCP 流字节 + UDP 载荷）
    pub up_bytes: u64,
    /// 下行字节（节点隧道 → 应用，TCP 流字节 + UDP 载荷）
    pub down_bytes: u64,
    /// 当前活动 TCP 流数
    pub active_conns: u64,
    /// 累计建立的 TCP 流数
    pub total_conns: u64,
}

/// 读取全局 VPN 数据面统计（未启动/已停止时全 0）。
/// 每次调用只读 4 个 `Relaxed` 原子——无需加锁，可由 Kotlin 每秒轮询。
#[uniffi::export]
pub fn vpn_stats() -> VpnStats {
    let s = hydra_client::tun::vpn_stats_snapshot();
    VpnStats {
        up_bytes: s.up_bytes,
        down_bytes: s.down_bytes,
        active_conns: s.active_conns,
        total_conns: s.total_conns,
    }
}

// ── 内核日志桥接（A 批：tracing Layer → 环形缓冲 → uniffi 增量拉取）──────────
//
// 设计（docs/design/安卓日志与健康观测方案-v1.md §二.A）：
// - 进程级环形缓冲（Mutex<VecDeque>，容量 500，满员丢最旧）承接内核
//   （hydra-core / hydra-client）全部 tracing 事件；Kotlin 侧每秒以
//   `vpn_logs_since(seq)` 增量拉取，**不依赖任何阻塞回调**；
// - 消息在入环前统一脱敏：目标（URL / IPv4[:端口] / 主机名[:端口] /
//   [IPv6]:端口）替换为 `mask_target` 短哈希（保留端口），与桌面
//   log_bridge 的「明文目标不出内核」纪律一致；
// - 纯内存：不落盘、不上传；`start_vpn` 开启新会话时清空（进程被杀自然清零）。

/// 环形缓冲容量（与 Kotlin `EngineState` 日志上限一致：500 条）
const LOG_RING_CAPACITY: usize = 500;

/// 单条消息最大字符数（异常长事件截断，防单条撑爆内存）
const LOG_MESSAGE_MAX_CHARS: usize = 512;

/// 内核日志条目（uniffi Record → Kotlin `VpnLogEntry`）。
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct VpnLogEntry {
    /// 单调递增序号（进程内唯一；Kotlin 增量拉取游标，重启后继续递增）
    pub seq: u64,
    /// 级别三档：`INFO` / `WARN` / `ERROR`（debug/trace 归入 INFO，消息带前缀）
    pub level: String,
    /// 已脱敏的消息正文（目标为 mask_target 短哈希）
    pub message: String,
    /// Unix 毫秒时间戳（Kotlin 负责格式化为 HH:mm:ss）
    pub ts_ms: u64,
}

/// 环形缓冲 + 序号发生器（同一把锁保护，保证 seq 与入队顺序一致）
struct LogRing {
    entries: VecDeque<VpnLogEntry>,
    next_seq: u64,
}

static LOG_RING: Mutex<LogRing> = Mutex::new(LogRing {
    entries: VecDeque::new(),
    next_seq: 1,
});

/// 入环一条日志（短锁：只做一次 push_back / 可能一次 pop_front；锁中毒降级为丢弃）。
fn push_log_entry(level: &'static str, message: String) {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let Ok(mut ring) = LOG_RING.lock() else {
        return;
    };
    if ring.entries.len() >= LOG_RING_CAPACITY {
        ring.entries.pop_front();
    }
    let seq = ring.next_seq;
    ring.next_seq = ring.next_seq.saturating_add(1);
    ring.entries.push_back(VpnLogEntry {
        seq,
        level: level.to_string(),
        message,
        ts_ms,
    });
}

/// 清空环形缓冲（新会话开始；**保留 next_seq 单调**——Kotlin 侧游标不会因
/// 新会话回退而漏拉日志）。
fn reset_vpn_logs() {
    if let Ok(mut ring) = LOG_RING.lock() {
        ring.entries.clear();
    }
}

/// 增量拉取内核日志：返回 `seq` 之后的所有条目（最多 500 条，按 seq 升序）。
/// Kotlin 每秒轮询一次（与 `vpn_stats()` 同一循环），记录上次最大 seq 作游标。
/// 环形缓冲已丢弃的更早条目自然不可见（UI 上限同为 500 条）。
#[uniffi::export]
pub fn vpn_logs_since(seq: u64) -> Vec<VpnLogEntry> {
    let Ok(ring) = LOG_RING.lock() else {
        return Vec::new();
    };
    ring.entries
        .iter()
        .filter(|e| e.seq > seq)
        .cloned()
        .collect()
}

/// tracing Level → 三档级别标签（GUI/Android 日志页只区分三档着色）
fn log_level_label(level: &tracing::Level) -> &'static str {
    match *level {
        tracing::Level::ERROR => "ERROR",
        tracing::Level::WARN => "WARN",
        _ => "INFO",
    }
}

/// debug/trace 降档为 INFO 后的原文前缀（保留原始级别可辨识性）
fn log_level_prefix(level: &tracing::Level) -> &'static str {
    match *level {
        tracing::Level::DEBUG => "[debug] ",
        tracing::Level::TRACE => "[trace] ",
        _ => "",
    }
}

/// 字段 Visitor：`message` 为正文，其余字段以 ` k=v` 追加（与桌面 log_bridge
/// 同款字段化提取；脱敏在拼接后的整行上统一执行）。
#[derive(Default)]
struct LogVisitor {
    message: String,
    extra: Vec<(&'static str, String)>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let v = format!("{value:?}");
        if name == "message" {
            self.message = v;
        } else {
            self.extra.push((name, v));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = value.to_string();
        } else {
            self.extra.push((name, value.to_string()));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_debug(field, &value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_debug(field, &value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_debug(field, &value);
    }
}

/// 内核事件 → 环形缓冲 Layer（A 批）。
///
/// 过滤级别在层内完成：ERROR/WARN/INFO/DEBUG 入环（丢包、直连决策等内核
/// 诊断在 DEBUG 级——「丢包/中继/DNS 应全部可见」），TRACE 丢弃（噪声/开销）。
struct KernelLogLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for KernelLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = event.metadata().level();
        if *level > tracing::Level::DEBUG {
            return;
        }
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        let mut text = String::with_capacity(visitor.message.len() + 32);
        text.push_str(log_level_prefix(level));
        text.push_str(&visitor.message);
        for (k, v) in &visitor.extra {
            text.push_str(&format!(" {k}={v}"));
        }
        let text = truncate_chars(&sanitize_log_message(&text), LOG_MESSAGE_MAX_CHARS);
        push_log_entry(log_level_label(level), text);
    }
}

/// 字符截断（按 Unicode 字符计；超长追加省略号）
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// 已知顶级域白名单：仅当「a.b.tld」的 tld 命中才按域名打码——避免把
/// `hydra.log` / `rules.txt` 等文件名或 `dev.hydra.vpn` 包名误判为目标。
const KNOWN_TLDS: &[&str] = &[
    "com", "cn", "net", "org", "io", "me", "co", "cc", "tv", "xyz", "top", "info", "dev", "app",
    "cloud", "site", "online", "vip", "uk", "us", "jp", "hk", "tw", "sg", "de", "ru", "au", "ca",
    "fr", "kr", "edu", "gov",
];

/// 主机名字符（用于前后边界判定：避免从长串中间截出「伪域名」）
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// 解析 `a.b.c.d`（每段 0-255，最多 3 位）；返回结束位置。
fn parse_ipv4_at(c: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    for octet in 0..4 {
        let begin = i;
        while i < c.len() && c[i].is_ascii_digit() && i - begin < 3 {
            i += 1;
        }
        if i == begin {
            return None;
        }
        let value: u32 = c[begin..i].iter().collect::<String>().parse().ok()?;
        if value > 255 {
            return None;
        }
        if octet < 3 {
            if i >= c.len() || c[i] != '.' {
                return None;
            }
            i += 1;
        }
    }
    Some(i)
}

/// 主机名（label("."label)+，末段命中 KNOWN_TLDS）；返回结束位置。
fn parse_hostname_at(c: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    let mut labels = 0usize;
    loop {
        let begin = i;
        while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '-') {
            i += 1;
        }
        if i == begin || i - begin > 63 {
            return None;
        }
        labels += 1;
        if i < c.len() && c[i] == '.' {
            // 后续标签必须存在（避免把句末点号当域名分隔）
            if i + 1 >= c.len() || !c[i + 1].is_ascii_alphanumeric() {
                break;
            }
            i += 1;
            continue;
        }
        break;
    }
    if labels < 2 {
        return None;
    }
    let host = &c[start..i];
    let tld_start = host.iter().rposition(|&ch| ch == '.').map(|p| p + 1)?;
    let tld: String = host[tld_start..].iter().collect();
    if !KNOWN_TLDS.contains(&tld.to_ascii_lowercase().as_str()) {
        return None;
    }
    Some(i)
}

/// 可选 `:端口`（1-5 位数字）；返回结束位置。
fn consume_port(c: &[char], start: usize) -> usize {
    if start + 1 >= c.len() || c[start] != ':' || !c[start + 1].is_ascii_digit() {
        return start;
    }
    let mut i = start + 1;
    while i < c.len() && c[i].is_ascii_digit() && i - (start + 1) < 5 {
        i += 1;
    }
    i
}

/// `http://` / `https://` 前缀：authority 整体按 mask_target 打码（保留协议头）。
fn match_url_at(c: &[char], i: usize) -> Option<(usize, String)> {
    let head: String = c[i..c.len().min(i + 8)].iter().collect();
    let (scheme, prefix_len) = if head.starts_with("https://") {
        ("https://", 8)
    } else if head.starts_with("http://") {
        ("http://", 7)
    } else {
        return None;
    };
    let begin = i + prefix_len;
    let mut j = begin;
    while j < c.len()
        && !matches!(
            c[j],
            '/' | '?' | '#' | ' ' | '\t' | '"' | '\'' | ')' | ']' | ',' | ';' | '|'
        )
        && j - begin < 255
    {
        j += 1;
    }
    if j == begin {
        return None;
    }
    let authority: String = c[begin..j].iter().collect();
    let host = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(&authority);
    Some((j, format!("{scheme}{}", mask_target(host))))
}

/// `[IPv6]` / `[IPv6]:端口`：整体按 mask_target 打码。
fn match_bracketed_ipv6_at(c: &[char], i: usize) -> Option<(usize, String)> {
    if i >= c.len() || c[i] != '[' {
        return None;
    }
    let mut j = i + 1;
    while j < c.len() && c[j] != ']' {
        if !(c[j].is_ascii_hexdigit() || c[j] == ':' || c[j] == '.') {
            return None;
        }
        j += 1;
    }
    if j >= c.len() {
        return None;
    }
    let addr: String = c[i + 1..j].iter().collect();
    if !addr.contains(':') {
        return None;
    }
    let end = consume_port(c, j + 1);
    let token: String = c[i..end].iter().collect();
    Some((end, mask_target(&token)))
}

/// 日志正文脱敏：把目标形态 token 替换为 `mask_target` 短哈希（端口保留）。
///
/// 覆盖：URL authority / IPv4[:端口] / 域名[:端口]（KNOWN_TLDS 白名单）/
/// `[IPv6][:端口]`。前端字符、路径、耗时数字、版本号（0.2.8）、文件名
/// （hydra.log）不受影响。裸 IPv6（无方括号）不打码——内核日志按惯例以
/// `mask_target` 字段化输出，本函数是纵深防御。
fn sanitize_log_message(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        // URL 优先（避免随后把 URL 内的域名/IP 单独替换）
        if let Some((end, replacement)) = match_url_at(&chars, i) {
            out.push_str(&replacement);
            i = end;
            continue;
        }
        if let Some((end, replacement)) = match_bracketed_ipv6_at(&chars, i) {
            out.push_str(&replacement);
            i = end;
            continue;
        }
        let at_boundary = i == 0 || !is_host_char(chars[i - 1]);
        if at_boundary && chars[i].is_ascii_digit() {
            if let Some(end) = parse_ipv4_at(&chars, i) {
                let end = consume_port(&chars, end);
                if end == chars.len() || !is_host_char(chars[end]) {
                    let token: String = chars[i..end].iter().collect();
                    out.push_str(&mask_target(&token));
                    i = end;
                    continue;
                }
            }
        }
        if at_boundary && chars[i].is_ascii_alphanumeric() {
            if let Some(end) = parse_hostname_at(&chars, i) {
                let end = consume_port(&chars, end);
                if end == chars.len() || !is_host_char(chars[end]) {
                    let token: String = chars[i..end].iter().collect();
                    out.push_str(&mask_target(&token));
                    i = end;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// 智能分流引擎构建（start_vpn 与单测共用）：`rule_mode=false` → None（全局
/// 模式零开销）；`rule_mode=true` 恒 Some——文件缺失/解析失败降级为内置
/// CN 规则引擎（对齐桌面 hydra-client：内置 CN 直连保留，消除「开关在规则
/// 模式而引擎为全局」的脑裂），并置降级标记；成功 → Arc 包裹（只读共享，
/// 每连接一次 O(log n) 判定）。
fn build_rule_engine(
    cfg: &VpnConfig,
) -> Option<std::sync::Arc<hydra_core::routing_rules::RuleEngine>> {
    if !cfg.rule_mode {
        VPN_RULE_DEGRADED.store(false, std::sync::atomic::Ordering::SeqCst);
        return None;
    }
    let Some(path) = cfg.rule_file.as_deref().filter(|p| !p.trim().is_empty()) else {
        tracing::warn!("规则模式已开启但未提供规则文件路径——降级为内置 CN 规则（自定义规则未加载）");
        VPN_RULE_DEGRADED.store(true, std::sync::atomic::Ordering::SeqCst);
        return Some(std::sync::Arc::new(
            hydra_core::routing_rules::RuleEngine::builtin_cn(),
        ));
    };
    match hydra_core::routing_rules::RuleEngine::from_rule_file(path) {
        Ok(engine) => {
            tracing::info!(
                "规则引擎已加载（{} 条规则，跳过 {} 行非法）：文件 {}",
                engine.domain_rule_count() + engine.port_rule_count(),
                engine.skipped_lines,
                path
            );
            VPN_RULE_DEGRADED.store(false, std::sync::atomic::Ordering::SeqCst);
            Some(std::sync::Arc::new(engine))
        }
        Err(e) => {
            // 安全降级语义（对齐桌面）：规则文件不可用 → 内置 CN 规则兜底，
            // 永不断网；降级对用户可见（vpn_rule_mode_degraded）
            tracing::warn!("规则文件不可用（{e}）——降级为内置 CN 规则（自定义规则未加载）");
            VPN_RULE_DEGRADED.store(true, std::sync::atomic::Ordering::SeqCst);
            Some(std::sync::Arc::new(
                hydra_core::routing_rules::RuleEngine::builtin_cn(),
            ))
        }
    }
}

/// VpnConfig → TunConfig（start_vpn 与单测共用）：规则模式额外联动 DNS 直连
/// （dns_via_proxy=false + dns_direct=true，对齐桌面 R2——DNS 直连出网才能把
/// CN 域名解析到近端 CDN IP，GeoIP 才判得准；安卓侧 Kotlin 同步把
/// VpnBuilder.addDnsServer 换成国内公共 DNS）。**不设 direct_bind_ip**：
/// 安卓直连 = protect 形态（R3 双形态），tun_rule_opener 在 protect 钩子
/// 已安装时放行无 bind 直连（P1-3 守卫既有逻辑自动正确）。
fn build_tun_config(
    cfg: &VpnConfig,
    addr4: std::net::Ipv4Addr,
    addr6: std::net::Ipv6Addr,
    rule_engine: Option<std::sync::Arc<hydra_core::routing_rules::RuleEngine>>,
) -> hydra_client::tun::TunConfig {
    let rule_active = rule_engine.is_some();
    hydra_client::tun::TunConfig {
        addr: addr4,
        prefix: cfg.prefix4,
        mtu: cfg.mtu,
        addr6,
        ipv6_enabled: true,
        udp_relay: cfg.udp_relay,
        // 全局模式：dns_via_proxy=true（与基线逐字节一致）；规则模式：DNS
        // 直连联动（R2），避免「规则模式 + dns_via_proxy=true」的 P2-5 告警
        dns_via_proxy: !rule_active,
        dns_direct: rule_active,
        rule_engine,
        ..Default::default() // direct_bind_ipv4/6 = None：安卓 protect 形态
    }
}

/// fd 包传输（内核优化 #2，评审修正后设计）：VpnService tun fd →
/// PacketTransport。专职读/写线程 + 有界通道替代 spawn_blocking：
/// - 每包开销 15-50μs（spawn_blocking 往返×2-3 + 3 次堆拷贝）→ <2μs；
/// - **结构性修复吞包缺陷**：run_stack 的 10ms tick 丢弃 recv future 后，
///   旧实现的孤儿阻塞任务继续持锁读走下一包且结果被丢弃（稀疏流量下
///   每 tick 吞一包：TCP +1RTT 尖刺，UDP 中继永久丢包）——专职读线程 +
///   通道保序交付后不存在孤儿任务，tick 丢弃的只是取包时机；
/// - 背压：读通道满 = 读线程停读 = 内核 TUN 队列满 = TCP 窗口收缩（语义不变）。
struct FdTransport {
    /// 读线程 → 栈：收到的包（tokio 通道，栈侧 async recv）
    inbound_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// 栈 → 写线程：待发送包（std sync_channel，写线程阻塞 recv）
    outbound_tx: OutboundSender,
    /// 停机原语：关 fd 副本解除读线程阻塞 + drop 写端解除写线程
    stop: Arc<FdStop>,
    /// 写线程 JoinHandle（shutdown 时 join——见 FdStop::shutdown 顺序）
    write_join: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// 读线程 JoinHandle（close fd 后 read 返回，可 join）
    read_join: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// 停机原语（code review P0 修正版）：**dup 的 fd 共享同一 open file
/// description，close 一个副本不会唤醒阻塞在另一副本上的 read()**——
/// "先 close 再 join"不成立。改用 poll(2) 超时轮询：读线程每 100ms 醒来
/// 检查停止位，join 上限一个周期；写线程 recv_timeout 同理。
struct FdStop {
    /// 停止位（AtomicBool：读/写线程每周期检查）
    stopped: std::sync::atomic::AtomicBool,
    /// tun fd 副本：poll 监听用
    raw_fd: std::sync::atomic::AtomicI32,
    /// 写端 File：drop 解除写线程的潜在阻塞写
    w_file: std::sync::Mutex<Option<std::fs::File>>,
}

impl FdStop {
    #[cfg(unix)] // 调用点在读/写线程（unix 专属分支）
    fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 停机：置停止位 + 关 tun fd 副本（poll 立即返回 POLLNVAL 退出）+
    /// drop 写端（潜在阻塞写解除）。之后调用方 join（上限 ~100ms）。
    fn trigger(&self) {
        self.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
        let fd = self.raw_fd.swap(-1, std::sync::atomic::Ordering::SeqCst);
        if fd >= 0 {
            extern "C" {
                fn close(fd: i32) -> i32;
            }
            // Safety：swap 拿到唯一关闭权；poll 循环对 POLLNVAL 退出
            unsafe { close(fd) };
        }
        if let Ok(mut w) = self.w_file.lock() {
            *w = None; // drop 写端 File
        }
    }
}

/// 写线程通道发送端（std sync_channel 薄封装；满 = 阻塞 = 背压语义，
/// 写线程消费速度即 TUN 出站速率，无需丢弃）
#[derive(Clone)]
struct OutboundSender(std::sync::mpsc::SyncSender<Vec<u8>>);

impl OutboundSender {
    fn send(&self, v: Vec<u8>) -> bool {
        self.0.send(v).is_ok()
    }
}

impl FdTransport {
    /// 接管 fd 所有权（Kotlin 侧 detachFd 后交付）并启动专职读/写线程。
    /// Windows 主机构建走 not(unix) 分支返回 Unsupported——该路径仅 Android
    /// 使用，但符号仍需导出（桌面 JVM 冒烟的绑定 checksum 校验要求全符号在库）。
    fn new(fd: i32) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::{FromRawFd, IntoRawFd};
            // Safety：fd 来自 Kotlin `pfd.detachFd()`——所有权唯一移交本侧。
            let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
            let w = f.try_clone()?;
            // fd 独立 dup 副本（close 专用）：File 各持 dup，互不影响
            let fd_dup = w.try_clone()?.into_raw_fd();

            const MTU_MAX: usize = 1504; // TUN MTU 1500 + 余量
            const CHAN_CAP: usize = 256; // 有界：满 = 背压（不丢包）
            let (in_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(CHAN_CAP);
            let (out_tx, out_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(CHAN_CAP);

            let stop = Arc::new(FdStop {
                stopped: std::sync::atomic::AtomicBool::new(false),
                raw_fd: std::sync::atomic::AtomicI32::new(fd_dup),
                w_file: std::sync::Mutex::new(Some(w)),
            });

            // 读线程（code review P0 修正版）：poll(2) 100ms 超时轮询——
            // 不再依赖"close 唤醒阻塞 read"（dup fd 共享 open file
            // description，close 一个副本不唤醒另一副本上的阻塞 read）；
            // 每 100ms 检查停止位，join 上限一个周期
            let stop_r = Arc::clone(&stop);
            let read_join = std::thread::Builder::new()
                .name("hydra-fd-read".into())
                .spawn(move || {
                    use std::io::Read;
                    let mut buf = vec![0u8; MTU_MAX];
                    #[repr(C)]
                    struct PollFd { fd: i32, events: i16, revents: i16 }
                    extern "C" { fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32; }
                    const POLLIN: i16 = 0x0001;
                    const POLLNVAL: i16 = 0x0020;
                    loop {
                        if stop_r.is_stopped() { break; }
                        let fd_cur = stop_r.raw_fd.load(std::sync::atomic::Ordering::SeqCst);
                        if fd_cur < 0 { break; }
                        let mut fds = PollFd { fd: fd_cur, events: POLLIN, revents: 0 };
                        let pr = unsafe { poll(&mut fds as *mut PollFd, 1, 100) };
                        if stop_r.is_stopped() { break; }
                        if pr < 0 {
                            if std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::Interrupted { continue; }
                            break;
                        }
                        if (fds.revents & POLLNVAL) != 0 { break; }
                        if (fds.revents & POLLIN) == 0 { continue; }
                        match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if in_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(_) => break,
                        }
                    }
                    drop(stop_r);
                })?;

            // 写线程（code review P0 修正版）：recv_timeout(100ms) 轮询停止
            // 位——不再依赖"w_file drop 解除阻塞"（原设计 w_file 在 spawn 时
            // 已被 take，close_fd 的置 None 是死代码）
            let stop_w = Arc::clone(&stop);
            let mut w_file = stop.w_file.lock().unwrap().take();
            let write_join = std::thread::Builder::new()
                .name("hydra-fd-write".into())
                .spawn(move || {
                    use std::io::Write;
                    loop {
                        if stop_w.is_stopped() { break; }
                        match out_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok(pkt) => match w_file.as_mut() {
                                Some(f) => {
                                    if f.write_all(&pkt).is_err() { break; }
                                }
                                None => break,
                            },
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    drop(stop_w);
                })?;

            Ok(Self {
                inbound_rx: tokio::sync::Mutex::new(inbound_rx),
                outbound_tx: OutboundSender(out_tx),
                stop,
                write_join: std::sync::Mutex::new(Some(write_join)),
                read_join: std::sync::Mutex::new(Some(read_join)),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "VPN fd 接入仅支持 Android/Unix 平台（桌面 Windows 无此场景）",
            ))
        }
    }

    /// 停机（code review P0 修正版）：置停止位 + 关 fd 副本 + drop 写端，
    /// 然后 join——两线程均为 100ms 轮询循环，join 上限一个周期，永不挂死。
    /// 由 Drop（stop_vpn drop VpnHandle → transport drop）触发。
    fn shutdown(&self) {
        self.stop.trigger();
        if let Ok(mut j) = self.read_join.lock() {
            if let Some(h) = j.take() {
                let _ = h.join();
            }
        }
        if let Ok(mut j) = self.write_join.lock() {
            if let Some(h) = j.take() {
                let _ = h.join();
            }
        }
    }
}

impl Drop for FdTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl hydra_client::tun::PacketTransport for FdTransport {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> hydra_client::tun::BoxFut<'a, std::io::Result<usize>> {
        Box::pin(async move {
            // tick 丢弃本 future 后，包仍安全停在通道里（无孤儿任务）——
            // 下次 recv 取到即交付（吞包缺陷的结构性修复）
            let mut rx = self.inbound_rx.lock().await;
            let pkt = rx.recv().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "fd 读线程已退出（停机）",
                )
            })?;
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        })
    }

    fn send<'a>(&'a self, buf: &'a [u8]) -> hydra_client::tun::BoxFut<'a, std::io::Result<()>> {
        let data = buf.to_vec();
        let tx = self.outbound_tx.clone();
        Box::pin(async move {
            if tx.send(data) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "fd 写线程已退出（停机）",
                ))
            }
        })
    }
}

/// VPN 运行句柄：独立 runtime + 栈任务 + 停机令牌
struct VpnHandle {
    runtime: tokio::runtime::Runtime,
    shutdown: tokio_util::sync::CancellationToken,
}

static VPN_STATE: std::sync::Mutex<Option<VpnHandle>> = std::sync::Mutex::new(None);

/// VPN 数据面退出回调（评审方案 2：数据面死亡感知）——`run_stack` 因任何原因
/// 返回时调用（含正常停止：Kotlin 侧以 userStopRequested/generation 守卫忽略）。
/// **硬约束（评审 P1）**：回调运行在 Rust runtime 工作线程，且 `stop_vpn` 持
/// VPN_STATE 锁执行 shutdown（最长 3s）——回调体内**禁止同步调用本 crate 任何
/// FFI**（死锁面）；Kotlin 侧应只做 `scope.launch` 后返回。
#[uniffi::export(callback_interface)]
pub trait VpnExitCallback: Send + Sync {
    fn on_stack_exit(&self, reason: String);
}

/// 启动全局 VPN 数据面：tun fd → 用户态栈（TCP 任意端口动态接流 + UDP 中继）
/// → 经节点隧道。protect 回调（R4）在每个出站 socket connect 前调用，失败即
/// 中止连接。快速返回（栈任务后台运行，建连异步）。
/// `on_exit`：数据面退出回调（数据面死亡感知——Kotlin 据此触发自动重连；
/// 正常停止也会回调，Kotlin 侧守卫忽略）。
#[uniffi::export]
pub fn start_vpn(
    tun_fd: i32,
    config: VpnConfig,
    protect: Box<dyn SocketProtect>,
    on_exit: Box<dyn VpnExitCallback>,
) -> Result<(), HydraEngineError> {
    let mut guard = VPN_STATE.lock().unwrap_or_else(|p| p.into_inner());

    // 诊断：初始化 tracing → 环形缓冲（→ Kotlin 日志页）+ 应用 filesDir/hydra.log
    // （debug 包可 run-as 读取）。此前无任何 subscriber，内核全部日志被静默丢弃。
    // 唯一一次 init（reload/重启不重复安装；try_init 失败 = 已有 subscriber，
    // 环 Layer 首次安装即生效）。
    {
        use std::io::Write;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        use tracing_subscriber::Layer as _;
        struct LogFile(std::sync::Mutex<std::fs::File>);
        impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for LogFile {
            type Writer = LogFileWriter<'a>;
            fn make_writer(&'a self) -> Self::Writer {
                LogFileWriter(self.0.lock().unwrap_or_else(|p| p.into_inner()))
            }
        }
        struct LogFileWriter<'a>(std::sync::MutexGuard<'a, std::fs::File>);
        impl Write for LogFileWriter<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.0.write(buf) }
            fn flush(&mut self) -> std::io::Result<()> { self.0.flush() }
        }
        // 内核日志环（DEBUG 起：丢包/直连决策等诊断可见，TRACE 丢弃）
        let ring_layer = KernelLogLayer.with_filter(LevelFilter::DEBUG);
        let fmt_level = if cfg!(debug_assertions) { LevelFilter::DEBUG } else { LevelFilter::INFO };
        // Android 无 TMPDIR；debug 诊断固定写应用私有 files 目录
        let path = std::path::PathBuf::from("/data/user/0/dev.hydra.vpn/files/hydra.log");
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = tracing_subscriber::registry()
                .with(ring_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(LogFile(std::sync::Mutex::new(f)))
                        .with_filter(fmt_level),
                )
                .try_init();
        } else {
            // 文件不可用（非 Android 主机/权限异常）：仍安装环 Layer——日志页
            // 是主通道，不能被可选的文件诊断拖累
            let _ = tracing_subscriber::registry()
                .with(ring_layer)
                .try_init();
        }
    }

    // R4：保护钩子进程级安装（首装生效）——出站连接 connect 前回调 protect(fd)
    {
        let cb = std::sync::Arc::new(protect);
        let hook: hydra_core::socket_protect::ProtectHook = Box::new(move |fd| cb.protect(fd));
        let _ = hydra_core::socket_protect::set_socket_protect_hook(hook);
    }

    // fd 接管必须先于一切**可失败路径**（含下方"已在运行"早退）：FdTransport
    // 持有 fd 所有权（drop 关闭），任何 Err 返回都连 fd 一起释放——否则 Kotlin
    // 已 detach 的 fd 无人认领（停止→立即重启竞态下逐次泄漏）
    let transport = FdTransport::new(tun_fd).map_err(|e| HydraEngineError::Start {
        msg: format!("tun fd 接管失败: {e}"),
    })?;
    if guard.is_some() {
        return Err(HydraEngineError::Start {
            msg: "VPN 已在运行".into(),
        });
    }

    // 新会话：日志纯内存——清空上一会话的内核日志（seq 保持单调，Kotlin
    // 游标不会因回退而漏拉；spurious start 在上一检查处已早退，不清）
    reset_vpn_logs();

    let addr4: std::net::Ipv4Addr =
        config
            .addr4
            .parse()
            .map_err(|_| HydraEngineError::InvalidConfig {
                msg: format!("addr4 非法: {}", config.addr4),
            })?;
    let addr6: std::net::Ipv6Addr =
        config
            .addr6
            .parse()
            .map_err(|_| HydraEngineError::InvalidConfig {
                msg: format!("addr6 非法: {}", config.addr6),
            })?;
    if config.nodes.is_empty() {
        return Err(HydraEngineError::InvalidConfig {
            msg: "至少需要一个节点".into(),
        });
    }
    let key = hydra_core::auth_key_from_hex(&config.auth_key_hex)
        .map_err(|m| HydraEngineError::InvalidConfig { msg: m })?;
    let tls = match &config.trust {
        TrustMode::Pinned { cert_der } => {
            if cert_der.is_empty() {
                return Err(HydraEngineError::InvalidConfig {
                    msg: "pin 模式必须提供节点证书".into(),
                });
            }
            hydra_core::tcp_transport::TlsTrust::pinned(cert_der.clone())
        }
        TrustMode::PublicCa => hydra_core::tcp_transport::TlsTrust::public_ca(None),
    };
    let nodes: Vec<std::net::SocketAddr> =
        config.nodes.iter().filter_map(|a| a.parse().ok()).collect();
    if nodes.is_empty() {
        return Err(HydraEngineError::InvalidConfig {
            msg: "节点地址全部无法解析（域名节点 M2 暂不支持）".into(),
        });
    }
    let sni = config
        .sni
        .clone()
        .unwrap_or_else(|| hydra_core::DEFAULT_SNI.into());

    // 智能分流（§九）：规则模式构建引擎（rule_mode=true 恒 Some——文件缺失/
    // 解析失败降级内置 CN 规则，对齐桌面；必须在可失败路径之后、fd 使用之前
    // 语义无冲突——此处仅内存构建）。
    let rule_engine = build_rule_engine(&config);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| HydraEngineError::Start { msg: e.to_string() })?;

    // opener/udp 工厂：复用 ProxyServer 的凭据与调度器（不 start——不监听本地端口）
    let proxy = hydra_core::proxy::ProxyServer::new("127.0.0.1:0".parse().unwrap())
        .with_nodes(nodes)
        .with_auth_key(key)
        .with_trust(tls)
        .with_sni(sni);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown2 = shutdown.clone();
    let on_exit = std::sync::Arc::new(on_exit);

    runtime.spawn(async move {
        proxy.register_nodes().await;
        let opener = match proxy.tun_channel_opener() {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("VPN opener 构建失败: {e}");
                // 死亡感知全覆盖：早退也通知 Kotlin（当前因 auth_key 已校验
                // 而不可达——防未来静默死亡面）
                on_exit.on_stack_exit(format!("opener 构建失败: {e}"));
                return;
            }
        };
        let udp_factory = proxy.tun_udp_channel_factory().ok();
        let tun_cfg = build_tun_config(&config, addr4, addr6, rule_engine);
        if tun_cfg.rule_engine.is_some() {
            tracing::info!("Hydra VPN 规则分流已启用（CN 直连 · 其余走节点）");
        }
        tracing::info!("Hydra VPN 栈启动（fd 模式，mtu={}）", config.mtu);
        let stack_res = hydra_client::tun::run_stack(
            std::sync::Arc::new(transport),
            tun_cfg,
            opener,
            udp_factory,
            shutdown2.clone(),
        )
        .await;
        let reason = match &stack_res {
            Err(e) => format!("错误：{e}"),
            Ok(()) if shutdown2.is_cancelled() => "正常停止".to_string(),
            Ok(()) => "异常退出".to_string(),
        };
        match &stack_res {
            Err(e) => tracing::error!("VPN 栈退出: {e}"),
            Ok(()) => tracing::info!("VPN 栈退出: {reason}"),
        }
        // 数据面死亡感知（评审方案 2）：任何退出都通知 Kotlin（其守卫决定
        // 是否自动重连）；回调由包装任务闭包持有至触发，勿提前丢弃（评审 P2）
        on_exit.on_stack_exit(reason);
    });

    *guard = Some(VpnHandle { runtime, shutdown });
    Ok(())
}

/// 停止 VPN 数据面（幂等）。返回是否有运行中的 VPN 被停止。
#[uniffi::export]
pub fn stop_vpn() -> bool {
    let mut guard = VPN_STATE.lock().unwrap_or_else(|p| p.into_inner());
    match guard.take() {
        Some(h) => {
            h.shutdown.cancel();
            h.runtime
                .shutdown_timeout(std::time::Duration::from_secs(3));
            // P2-3：停止后降级标记复位（未启动 = false）
            VPN_RULE_DEGRADED.store(false, std::sync::atomic::Ordering::SeqCst);
            true
        }
        None => false,
    }
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum HydraEngineError {
    #[error("配置非法: {msg}")]
    InvalidConfig { msg: String },
    #[error("引擎启动失败: {msg}")]
    Start { msg: String },
    #[error("引擎未运行")]
    NotRunning,
}

/// 引擎运行句柄：独立 tokio runtime + ProxyServer 任务
struct EngineHandle {
    runtime: tokio::runtime::Runtime,
    monitor: Arc<TrafficMonitor>,
    bound: Arc<OnceLock<String>>,
    accept_task: tokio::task::JoinHandle<()>,
}

/// Hydra 引擎（进程内 SOCKS5 代理，M1 手机浏览器手动配代理即用此路径；
/// M2 全局 VPN 由 Kotlin VpnService 把 TUN 流量导向本引擎监听端口）。
#[derive(uniffi::Object)]
pub struct HydraEngine {
    state: Mutex<Option<EngineHandle>>,
    nodes: Vec<String>,
    auth_key: Vec<u8>,
    trust: TlsTrust,
    sni: String,
    listen_port: u16,
}

#[uniffi::export]
impl HydraEngine {
    /// 构造引擎（不做网络操作）。
    /// - `auth_key_hex`：64 个 hex 字符（32 字节 PSK，snow NNpsk2 约束）
    /// - `sni`：None = 默认 hydra.node
    /// - `listen_port`：进程内 SOCKS5 监听端口（0 = 系统随机分配）
    #[uniffi::constructor]
    pub fn new(
        nodes: Vec<NodeSpec>,
        auth_key_hex: String,
        trust: TrustMode,
        sni: Option<String>,
        listen_port: u16,
    ) -> Result<Arc<Self>, HydraEngineError> {
        if nodes.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: "至少需要一个节点".to_string(),
            });
        }
        // 09-A-1：节点地址逐条解析校验——此前 `filter_map(parse().ok())` 把
        // 解析失败（典型：域名节点）静默过滤，引擎以 0 节点"成功启动"且无
        // 任何可用出口。域名节点解析需要系统 resolver（且其 socket 同样要过
        // protect），M2 tun_core 一并支持；当前显式报错给出明确原因。
        let mut parsed_nodes = Vec::with_capacity(nodes.len());
        let mut invalid = Vec::new();
        for n in &nodes {
            match n.addr.parse::<std::net::SocketAddr>() {
                Ok(a) => parsed_nodes.push(a),
                Err(_) => invalid.push(n.addr.clone()),
            }
        }
        if parsed_nodes.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: format!(
                    "节点地址全部无法解析为 IP:端口（域名节点暂不支持，M2 接入）：{:?}",
                    invalid
                ),
            });
        }
        if !invalid.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: format!("节点地址无法解析为 IP:端口: {:?}", invalid),
            });
        }
        let auth_key = hydra_core::auth_key_from_hex(&auth_key_hex)
            .map_err(|msg| HydraEngineError::InvalidConfig { msg })?;
        let trust = match trust {
            TrustMode::Pinned { cert_der } => {
                if cert_der.is_empty() {
                    return Err(HydraEngineError::InvalidConfig {
                        msg: "pin 模式必须提供至少一张节点证书（der）".to_string(),
                    });
                }
                TlsTrust::pinned(cert_der)
            }
            TrustMode::PublicCa => {
                // 真证书模式：sni 即校验域名（缺省 hydra.node 为自签约定值，
                // 真证书部署应显式传入）
                TlsTrust::public_ca(None)
            }
        };
        Ok(Arc::new(Self {
            state: Mutex::new(None),
            nodes: parsed_nodes.into_iter().map(|a| a.to_string()).collect(),
            auth_key,
            trust,
            sni: sni.unwrap_or_else(|| hydra_core::DEFAULT_SNI.to_string()),
            listen_port,
        }))
    }

    /// 启动引擎（绑定进程内 SOCKS5 监听并常驻；重复调用报 Start 错误）。
    /// `protect`：R4 出站 socket 保护回调，可传 None（仅调试/直连节点场景）。
    pub fn start(
        self: Arc<Self>,
        protect: Option<Box<dyn SocketProtect>>,
    ) -> Result<(), HydraEngineError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.is_some() {
            return Err(HydraEngineError::Start {
                msg: "引擎已在运行".to_string(),
            });
        }
        // R4 防环回全链路接线（09-P1-7）：把 Kotlin 回调安装为 hydra-core 的
        // 进程级出站 socket 保护钩子——引擎每个新出站连接（节点/直连）在
        // TcpSocket 阶段（connect 前）回调 protect(fd)，失败即中止该连接。
        // 进程级单次安装：重复 start 传新回调时以首次为准（返回 false 不报错）。
        if let Some(cb) = protect {
            let hook: hydra_core::socket_protect::ProtectHook = Box::new(move |fd| cb.protect(fd));
            let _ = hydra_core::socket_protect::set_socket_protect_hook(hook);
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| HydraEngineError::Start { msg: e.to_string() })?;

        let mut server = ProxyServer::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            self.listen_port,
        )))
        .with_nodes(self.nodes.iter().filter_map(|a| a.parse().ok()).collect())
        .with_auth_key(self.auth_key.clone())
        .with_trust(self.trust.clone())
        .with_sni(self.sni.clone());

        let monitor = Arc::new(TrafficMonitor::new());
        server = server.with_traffic_monitor(monitor.clone());

        // OnceLock 的 Clone 是「另起一个空实例」语义，必须套 Arc 才是共享同一槽
        let bound: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let bound_slot = bound.clone();
        let server = Arc::new(server);
        // start() 校验凭据 + 绑定监听后进入 accept 循环；绑定失败即时上抛
        let prep = server.clone();
        let accept_task = runtime.spawn(async move {
            // 先跑 start() 到绑定完成再放行：bound_addr 就绪即可视为已启动
            if let Err(e) = prep.start().await {
                tracing::error!("HydraEngine accept 循环退出: {e}");
            }
        });
        // 等待监听绑定（最多 5s；ProxyServer::start 绑定后即写 bound_addr）
        let srv_for_wait = server.clone();
        let wait = async move {
            for _ in 0..100 {
                if let Some(addr) = srv_for_wait.bound_addr() {
                    let _ = bound_slot.set(addr.to_string());
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(HydraEngineError::Start {
                msg: "5s 内未完成监听绑定".to_string(),
            })
        };
        runtime.block_on(wait)?;

        *state = Some(EngineHandle {
            runtime,
            monitor,
            bound,
            accept_task,
        });
        Ok(())
    }

    /// 停止引擎并回收 runtime（幂等：未运行时为 no-op）
    pub fn stop(&self) {
        if let Some(h) = self.state.lock().unwrap_or_else(|p| p.into_inner()).take() {
            h.accept_task.abort();
            h.runtime.shutdown_timeout(Duration::from_secs(3));
        }
    }

    /// 进程内 SOCKS5 监听地址（形如 "127.0.0.1:1080"；未绑定完成时 None）
    pub fn bound_addr(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|h| h.bound.get().cloned())
    }

    /// 流量统计（引擎未运行时报 NotRunning）
    pub fn stats(&self) -> Result<EngineStats, HydraEngineError> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let h = state.as_ref().ok_or(HydraEngineError::NotRunning)?;
        let s = h.runtime.block_on(h.monitor.get_stats());
        Ok(EngineStats {
            sent: s.bytes_sent,
            received: s.bytes_received,
            upload_speed: s.upload_speed,
            download_speed: s.download_speed,
            active_connections: s.active_connections,
            total_connections: s.total_connections,
            uptime_secs: s.uptime_secs,
        })
    }
}

// uniffi scaffolding（proc-macro 导出风格的收尾宏）
uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "ab";

    fn engine(port: u16) -> Arc<HydraEngine> {
        HydraEngine::new(
            vec![NodeSpec {
                addr: "127.0.0.1:44300".to_string(),
            }],
            HEX.repeat(32),
            TrustMode::Pinned {
                // 占位 der（启动只校验非空，握手期才会真正解析）
                cert_der: vec![vec![0x30u8, 0x00]],
            },
            None,
            port,
        )
        .unwrap()
    }

    #[test]
    fn engine_start_stop_smoke() {
        let e = engine(0);
        // start(self: Arc<Self>) 消费句柄——测试里先克隆一份供断言复用
        let e2 = e.clone();
        let e3 = e.clone();
        e2.start(None)
            .expect("启动应成功（绑定 127.0.0.1 随机端口）");
        let bound = e.bound_addr().expect("启动后应有监听地址");
        assert!(bound.starts_with("127.0.0.1:"), "bound={bound}");
        // 重复启动必须报错
        assert!(e3.start(None).is_err());
        let s = e.stats().expect("运行中 stats 可查");
        assert_eq!(s.total_connections, 0);
        e.stop();
        assert!(e.bound_addr().is_none(), "stop 后监听地址清空");
        assert!(e.stats().is_err(), "stop 后 stats 报 NotRunning");
        // 幂等 stop
        e.stop();
    }

    #[test]
    fn engine_rejects_bad_config() {
        assert!(HydraEngine::new(
            vec![],
            "00".repeat(32),
            TrustMode::Pinned {
                cert_der: vec![vec![0x30]]
            },
            None,
            0
        )
        .is_err());
        assert!(HydraEngine::new(
            vec![NodeSpec {
                addr: "127.0.0.1:443".to_string()
            }],
            "00".repeat(31), // 31 字节：NNpsk2 约束必须 32
            TrustMode::Pinned {
                cert_der: vec![vec![0x30]]
            },
            None,
            0
        )
        .is_err());
        assert!(HydraEngine::new(
            vec![NodeSpec {
                addr: "127.0.0.1:443".to_string()
            }],
            "00".repeat(32),
            TrustMode::Pinned { cert_der: vec![] },
            None,
            0
        )
        .is_err());
    }

    // ── §九：VpnConfig → TunConfig 规则引擎接线三态 ─────────────────────────

    /// VPN_RULE_DEGRADED 是进程级全局标记——涉它的测试必须串行（防止并行
    /// 测试互相重置标记造成竞态假阳性）
    static DEGRADED_FLAG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn vpn_cfg(rule_mode: bool, rule_file: Option<String>) -> VpnConfig {
        VpnConfig {
            nodes: vec!["127.0.0.1:44300".into()],
            auth_key_hex: HEX.repeat(32),
            trust: TrustMode::Pinned {
                cert_der: vec![vec![0x30u8, 0x00]],
            },
            sni: None,
            mtu: 1500,
            addr4: "10.7.0.1".into(),
            prefix4: 30,
            addr6: "fd07::1".into(),
            udp_relay: true,
            rule_mode,
            rule_file,
        }
    }

    #[test]
    fn rule_mode_off_tun_config_has_no_engine() {
        // 进程级降级标记也会被本用例复位——必须与其他涉标记用例串行
        let _g = DEGRADED_FLAG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // 全局模式（开关 OFF）：rule_engine=None 且 DNS 配置与基线逐字节一致
        let cfg = vpn_cfg(false, Some("whatever.txt".into()));
        assert!(build_rule_engine(&cfg).is_none(), "OFF 不得构建引擎");
        let tun = build_tun_config(&cfg, "10.7.0.1".parse().unwrap(), "fd07::1".parse().unwrap(), None);
        assert!(tun.rule_engine.is_none());
        assert!(tun.dns_via_proxy, "全局模式 DNS 语义与基线一致");
        assert!(!tun.dns_direct);
        assert!(tun.direct_bind_ipv4.is_none() && tun.direct_bind_ipv6.is_none(),
            "安卓 protect 形态：不设直连 bind 源 IP");
    }

    #[test]
    fn rule_mode_missing_file_degrades_to_builtin_cn() {
        let _g = DEGRADED_FLAG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // 安全降级（P1-2 对齐桌面）：规则模式 + 文件缺失/解析失败 → 内置 CN
        // 规则引擎（内置 CN 表有效），引擎恒 Some——消除脑裂；不报错不断网
        let cfg = vpn_cfg(true, None);
        let engine = build_rule_engine(&cfg).expect("文件缺失应降级为内置 CN 引擎而非 None");
        assert!(engine.geoip_enabled(), "内置引擎必须启用 GeoIP-CN 表");
        assert!(vpn_rule_mode_degraded(), "降级兜底必须置标记（P2-3）");
        let cfg = vpn_cfg(true, Some("Z:/不存在的路径/rules.txt".into()));
        let engine = build_rule_engine(&cfg).expect("解析失败应降级为内置 CN 引擎而非 None");
        assert!(engine.geoip_enabled(), "内置引擎必须启用 GeoIP-CN 表");
        assert!(vpn_rule_mode_degraded());
        let cfg = vpn_cfg(true, Some("   ".into()));
        let engine = build_rule_engine(&cfg).expect("空白路径视同未提供——同样降级为内置 CN");
        assert!(engine.geoip_enabled());
        // 正常文件引擎不置降级标记
        let dir = std::env::temp_dir().join(format!("hydra_rules_deg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.txt");
        std::fs::write(&path, "GEOIP,CN,DIRECT\n").unwrap();
        let cfg = vpn_cfg(true, Some(path.to_string_lossy().into_owned()));
        build_rule_engine(&cfg).expect("有效规则文件应构建出引擎");
        assert!(!vpn_rule_mode_degraded(), "正常文件引擎不得置降级标记");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rule_mode_valid_file_wires_engine_and_dns_direct() {
        let _g = DEGRADED_FLAG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // 规则模式 + 有效规则文件：引擎接入 TunConfig + DNS 直连联动（R2）
        let dir = std::env::temp_dir().join(format!("hydra_rules_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.txt");
        std::fs::write(&path, "# 注释\nGEOIP,CN,DIRECT\nDOMAIN-SUFFIX,example.com,DIRECT\n")
            .unwrap();
        let cfg = vpn_cfg(true, Some(path.to_string_lossy().into_owned()));
        let engine = build_rule_engine(&cfg).expect("有效规则文件应构建出引擎");
        let tun = build_tun_config(
            &cfg,
            "10.7.0.1".parse().unwrap(),
            "fd07::1".parse().unwrap(),
            Some(engine),
        );
        assert!(tun.rule_engine.is_some(), "规则模式必须接入 TunConfig");
        assert!(!tun.dns_via_proxy && tun.dns_direct, "DNS 直连联动（R2）");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── VPN 数据面统计 FFI（全局 VPN 流量显示）──────────────────────────────

    #[test]
    fn vpn_stats_unstarted_is_zero_and_mapping_consistent() {
        // 未启动（本测试二进制从不跑 run_stack）→ FFI 必须全 0：
        // Kotlin 首轮轮询不会显示上一会话的残留值
        let s = vpn_stats();
        assert_eq!(
            s,
            VpnStats {
                up_bytes: 0,
                down_bytes: 0,
                active_conns: 0,
                total_conns: 0,
            }
        );
        // 映射一致性：FFI 记录逐字段来自 hydra-client 快照（同进程中唯一来源）
        let raw = hydra_client::tun::vpn_stats_snapshot();
        assert_eq!(raw, Default::default());
        assert_eq!(s.up_bytes, raw.up_bytes);
        assert_eq!(s.down_bytes, raw.down_bytes);
        assert_eq!(s.active_conns, raw.active_conns);
        assert_eq!(s.total_conns, raw.total_conns);
    }

    // ── A 批：内核日志桥接（环形缓冲 / 增量拉取 / 脱敏 / 级别映射）──────────

    /// LOG_RING 是进程级全局缓冲：相关用例经此互斥串行，避免并行测试互相
    /// 清空/污染（测试基建，非生产路径）
    static LOG_RING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn log_ring_incremental_pull_and_capacity() {
        let _g = LOG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        reset_vpn_logs();
        for i in 0..3 {
            push_log_entry("INFO", format!("事件 {i}"));
        }
        let all = vpn_logs_since(0);
        assert_eq!(all.len(), 3);
        // seq 严格递增（Kotlin 增量游标的前提）
        assert!(all.windows(2).all(|w| w[0].seq < w[1].seq));
        // 已拉到最新 → 无增量
        let last = all.last().unwrap().seq;
        assert!(vpn_logs_since(last).is_empty());
        // 新增一条 → 只返回该条（增量语义）
        push_log_entry("WARN", "新事件".to_string());
        let newer = vpn_logs_since(last);
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].level, "WARN");
        assert_eq!(newer[0].message, "新事件");
        // 满员丢最旧：容量 500，最旧的 14 条（3+1+10）被挤出
        for i in 0..(LOG_RING_CAPACITY + 10) {
            push_log_entry("INFO", format!("洪峰 {i}"));
        }
        let all = vpn_logs_since(0);
        assert_eq!(all.len(), LOG_RING_CAPACITY);
        assert_eq!(all.first().unwrap().message, "洪峰 10");
    }

    #[test]
    fn log_ring_reset_keeps_seq_monotonic() {
        let _g = LOG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        reset_vpn_logs();
        push_log_entry("INFO", "旧会话".to_string());
        let old_max = vpn_logs_since(0).last().unwrap().seq;
        // 新会话清空内容，但 seq 不回退（Kotlin 旧游标不会漏拉新日志）
        reset_vpn_logs();
        assert!(vpn_logs_since(0).is_empty());
        push_log_entry("INFO", "新会话".to_string());
        let new = vpn_logs_since(old_max);
        assert_eq!(new.len(), 1, "seq 必须继续递增: {new:?}");
        assert_eq!(new[0].seq, old_max + 1);
    }

    #[test]
    fn log_sanitizer_masks_targets_keeps_benign_text() {
        // IPv4[:端口] → mask_target 短哈希（保留端口）
        let ip_masked = sanitize_log_message("连接 1.2.3.4:443 完成");
        assert!(ip_masked.contains(&mask_target("1.2.3.4:443")), "{ip_masked}");
        assert!(!ip_masked.contains("1.2.3.4"), "{ip_masked}");
        // 域名[:端口]（KNOWN_TLDS 白名单）
        let host_masked = sanitize_log_message("解析 www.baidu.com:443 失败");
        assert!(host_masked.contains(&mask_target("www.baidu.com:443")), "{host_masked}");
        assert!(!host_masked.contains("baidu"), "{host_masked}");
        // 无端口域名同样打码
        let bare = sanitize_log_message("目标 www.google.com 不可达");
        assert!(!bare.contains("google"), "{bare}");
        // URL authority 打码，协议头/路径结构保留
        let url = sanitize_log_message("GET http://connect.rom.miui.com/generate_204");
        assert!(url.starts_with("GET http://"), "{url}");
        assert!(url.ends_with("/generate_204"), "{url}");
        assert!(!url.contains("miui"), "{url}");
        // [IPv6]:端口 打码
        let v6 = sanitize_log_message("出站 [fd07::1]:443");
        assert!(!v6.contains("fd07"), "{v6}");
        assert!(v6.ends_with(":443"), "{v6}");
        // 良性文本零改写：耗时/路径/文件名/版本号/包名
        let benign = "duration_ms=42 path=/data/user/0/dev.hydra.vpn/files/hydra.log 版本 0.2.8";
        assert_eq!(sanitize_log_message(benign), benign);
    }

    #[test]
    fn kernel_layer_captures_debug_and_drops_trace() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let _g = LOG_RING_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        reset_vpn_logs();
        let subscriber = tracing_subscriber::registry().with(KernelLogLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target = "www.example.com:443", "连接关闭");
            tracing::warn!("警告：节点 1.2.3.4:443 超时");
            tracing::debug!("丢包：UDP 下行 sid 无流映射");
            tracing::trace!("跟踪噪声不得入环");
        });
        let logs = vpn_logs_since(0);
        assert_eq!(logs.len(), 3, "INFO/WARN/DEBUG 入环、TRACE 丢弃: {logs:?}");
        assert_eq!(logs[0].level, "INFO");
        assert!(logs[0].message.starts_with("连接关闭"), "{}", logs[0].message);
        assert!(logs[0].message.contains("target="), "{}", logs[0].message);
        assert!(!logs[0].message.contains("example.com"), "字段值也须脱敏: {}", logs[0].message);
        assert_eq!(logs[1].level, "WARN");
        assert!(!logs[1].message.contains("1.2.3.4"), "{}", logs[1].message);
        assert_eq!(logs[2].level, "INFO");
        assert!(logs[2].message.starts_with("[debug] "), "{}", logs[2].message);
        assert!(logs[2].message.contains("丢包"));
        assert!(logs.iter().all(|e| e.ts_ms > 0));
    }
}
