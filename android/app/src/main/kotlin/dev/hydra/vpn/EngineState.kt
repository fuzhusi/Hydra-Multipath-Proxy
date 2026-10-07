package dev.hydra.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 引擎运行态的单一数据源：EngineService 写，MainActivity 订阅。
 * 独立顶层单例（非 Service companion）——Service 销毁重建期间状态不丢。
 */
object EngineState {

    data class Ui(
        val running: Boolean = false,
        /** "正在启动…" / 错误消息 / null=空闲 */
        val transition: String? = null,
        val boundAddr: String? = null,
        val sentBytes: Long = 0,
        val receivedBytes: Long = 0,
        val activeConns: Long = 0,
        val totalConns: Long = 0,
        val uptimeSecs: Long = 0,
        val configFromStore: Boolean = false,
    )

    private val _ui = MutableStateFlow(Ui())
    val ui = _ui.asStateFlow()

    fun update(transform: (Ui) -> Ui) {
        _ui.value = transform(_ui.value)
    }
}
