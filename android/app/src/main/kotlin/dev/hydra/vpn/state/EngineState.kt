package dev.hydra.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 日志级别三档（徽章着色 / 级别过滤的共同判定源；与 Rust `VpnLogEntry.level` 对应）。 */
enum class LogLevel {
    INFO,
    WARN,
    ERROR,
}

/** 日志上限（与 Rust 内核日志环形缓冲容量一致：500 条，超出丢最旧） */
const val LOG_CAPACITY = 500

/**
 * 引擎运行态 + 事件日志的单一数据源：EngineService 写，MainActivity 订阅。
 * 独立顶层单例（非 Service companion）——Service 销毁重建期间状态不丢。
 *
 * 进程边界（评审 R9）：单例仅限同进程可用——UI 与前台通知同源也仅限同进程；
 * M2 若 VpnService 分进程（`:vpn` 惯例），须换 Binder/AIDL 或服务端广播，
 * 本类只做 UI 侧镜像。
 *
 * 重组性能（R10）：UI 订阅侧拆细——连接状态经 [connPhase]（distinctUntilChanged）
 * 只在状态迁移时变化；流量/时长每秒跳字，由统计带独立 composable 单独收集，
 * 不触发整屏重组。UI 禁止直读单例字段，统一走 StateFlow。
 */
object EngineState {

    data class Ui(
        val running: Boolean = false,
        /** "正在启动…" / 错误消息 / null = 空闲 */
        val transition: String? = null,
        val boundAddr: String? = null,
        val sentBytes: Long = 0,
        val receivedBytes: Long = 0,
        val activeConns: Long = 0,
        val totalConns: Long = 0,
        val uptimeSecs: Long = 0,
        /** 上行速率（B/s；相邻两次采样差/间隔。未连接或计数器归零时为 0） */
        val upSpeedBps: Long = 0,
        /** 下行速率（B/s） */
        val downSpeedBps: Long = 0,
    )

    private val _ui = MutableStateFlow(Ui())
    val ui = _ui.asStateFlow()

    private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs = _logs.asStateFlow()

    /**
     * 连接四态（R10 护栏）：从 [ui] 派生并去重——大按钮/状态环只在本 Flow
     * 变化时重组，流量每秒跳字不再牵动整屏。
     */
    val connPhase: kotlinx.coroutines.flow.Flow<ConnPhase> =
        _ui.map { it.toPhase() }.distinctUntilChanged()

    fun update(transform: (Ui) -> Ui) {
        _ui.value = transform(_ui.value)
    }

    /** 追加一条应用侧事件日志（新条目在前，封顶 [LOG_CAPACITY] 条）。 */
    fun addLog(message: String, level: LogLevel = LogLevel.INFO) {
        val entry = LogEntry(logTimestamp(), message, level)
        synchronized(this) {
            _logs.value = (listOf(entry) + _logs.value).take(LOG_CAPACITY)
        }
    }

    /**
     * 合并内核增量日志（Rust `vpn_logs_since` 每秒拉取一批，按 seq 升序）。
     * 去重（seq 游标 + 集合双保险）、整体倒序（新在前）、封顶 500。
     */
    fun mergeKernelLogs(incoming: List<LogEntry>) {
        if (incoming.isEmpty()) return
        synchronized(this) {
            _logs.value = mergeLogs(_logs.value, incoming, LOG_CAPACITY)
        }
    }

    /** 清空日志（纯内存：点击连接开始新会话 / 服务停止即清空）。 */
    fun clearLogs() {
        synchronized(this) {
            _logs.value = emptyList()
        }
    }
}

/**
 * 单条日志：级别 + 时间 + 正文。
 * [seq] > 0 表示内核日志（增量拉取去重键）；Kotlin 应用侧日志为 0。
 */
data class LogEntry(
    val time: String,
    val message: String,
    val level: LogLevel = LogLevel.INFO,
    val seq: Long = 0,
)

/** 当前时刻 `HH:mm:ss`（日志时间前缀）。 */
internal fun logTimestamp(): String =
    SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())

/** Unix 毫秒 → `HH:mm:ss`（内核日志时间戳格式化；非法值回退当前时刻）。 */
internal fun formatLogTime(epochMillis: Long): String =
    if (epochMillis <= 0L) logTimestamp()
    else SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(epochMillis))

/** Rust 级别字符串 → [LogLevel]（未知值按 INFO 处理，不丢日志）。 */
internal fun logLevelFrom(raw: String): LogLevel = when (raw.uppercase(Locale.ROOT)) {
    "ERROR" -> LogLevel.ERROR
    "WARN" -> LogLevel.WARN
    else -> LogLevel.INFO
}

/**
 * 日志合并（纯函数，单测覆盖）：
 * - seq > 0 的条目按 seq 去重（已存在/批内重复都丢弃）；
 * - [incoming] 按 seq 升序（Rust 保证）→ 整体倒序后新条目在最前；
 * - 结果封顶 [cap] 条（丢最旧）。
 */
internal fun mergeLogs(
    existing: List<LogEntry>,
    incoming: List<LogEntry>,
    cap: Int = LOG_CAPACITY,
): List<LogEntry> {
    val seen = existing.asSequence().filter { it.seq > 0L }.map { it.seq }.toHashSet()
    val fresh = ArrayList<LogEntry>(incoming.size)
    for (entry in incoming) {
        if (entry.seq > 0L && !seen.add(entry.seq)) continue
        fresh += entry
    }
    if (fresh.isEmpty()) return existing
    return (fresh.asReversed() + existing).take(cap)
}

/**
 * 日志过滤（纯函数，单测覆盖）：级别阈值（null = 全部；INFO < WARN < ERROR）
 * + 关键字（忽略大小写，匹配正文）。保持输入顺序（新在前）。
 */
internal fun filterLogs(
    logs: List<LogEntry>,
    minLevel: LogLevel?,
    query: String,
): List<LogEntry> {
    val keyword = query.trim()
    if (minLevel == null && keyword.isEmpty()) return logs
    return logs.filter { entry ->
        (minLevel == null || entry.level.ordinal >= minLevel.ordinal) &&
            (keyword.isEmpty() || entry.message.contains(keyword, ignoreCase = true))
    }
}

/** 连接四态：状态环颜色 / 大按钮文案 / TalkBack 状态描述的共同判定源。 */
enum class ConnPhase {
    /** 已断开（灰环灰字） */
    DISCONNECTED,
    /** 连接中（accent 环旋转）——含 kill switch 重连等待期 */
    CONNECTING,
    /** 已连接（success 环） */
    CONNECTED,
    /** 错误（danger 环 + 横幅） */
    ERROR,
}

/** Ui 快照 → 连接四态（错误优先于进行中；重连中视作连接中）。 */
fun EngineState.Ui.toPhase(): ConnPhase = when {
    running -> ConnPhase.CONNECTED
    transition == null -> ConnPhase.DISCONNECTED
    transition.startsWith("启动失败") || transition.startsWith("✗") -> ConnPhase.ERROR
    else -> ConnPhase.CONNECTING
}

/**
 * 相邻两次采样的速率（B/s）：字节差 ÷ 实际间隔。
 *
 * 防御两种异常：间隔非正（时钟回拨/同一毫秒）→ 0；字节计数回退
 * （新一轮 VPN 会话归零/重连重置）→ 0，绝不产生负速率。
 */
internal fun computeSpeedBps(prevBytes: Long, currBytes: Long, elapsedMs: Long): Long {
    if (elapsedMs <= 0L || currBytes < prevBytes) return 0L
    return (currBytes - prevBytes) * 1000L / elapsedMs
}

/**
 * 全局 VPN 统计轮询的单步状态迁移：**只**更新流量/连接/时长/速率字段，
 * `running` / `transition` / `boundAddr` 等运行态字段原样保留——轮询与
 * 启动/停止/重连路径并发写 UI 时不得互相覆盖（评审：只更新统计字段）。
 */
internal fun EngineState.Ui.withVpnStats(
    sentBytes: Long,
    receivedBytes: Long,
    activeConns: Long,
    totalConns: Long,
    uptimeSecs: Long,
    upSpeedBps: Long,
    downSpeedBps: Long,
): EngineState.Ui = copy(
    sentBytes = sentBytes,
    receivedBytes = receivedBytes,
    activeConns = activeConns,
    totalConns = totalConns,
    uptimeSecs = uptimeSecs,
    upSpeedBps = upSpeedBps,
    downSpeedBps = downSpeedBps,
)
