package dev.hydra.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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

    /** 追加一条事件日志（新条目在前，封顶 100 条；UI 只取前若干条展示）。 */
    fun addLog(message: String) {
        val ts = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        synchronized(this) {
            _logs.value = (listOf(LogEntry(ts, message)) + _logs.value).take(100)
        }
    }
}

data class LogEntry(val time: String, val message: String)

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
