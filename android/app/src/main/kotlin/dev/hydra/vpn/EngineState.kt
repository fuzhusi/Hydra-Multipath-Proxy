package dev.hydra.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 引擎运行态 + 事件日志的单一数据源：EngineService 写，MainActivity 订阅。
 * 独立顶层单例（非 Service companion）——Service 销毁重建期间状态不丢。
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
    )

    private val _ui = MutableStateFlow(Ui())
    val ui = _ui.asStateFlow()

    private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs = _logs.asStateFlow()

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
