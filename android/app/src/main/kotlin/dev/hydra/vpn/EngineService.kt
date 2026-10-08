package dev.hydra.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.hydra_android.HydraEngine
import uniffi.hydra_android.NodeSpec
import uniffi.hydra_android.TrustMode

/**
 * M1：前台服务持有 HydraEngine。
 *
 * 为什么需要前台服务：Android 11+ 的 Cached App Freezer 会在应用退到后台后
 * 冻结进程——用户切到 Firefox 走本地代理时，若无前台通知保活，引擎会被冻结
 * 失去响应。FGS 让进程保持 oom_adj 可调度状态（M2 换 VpnService 常驻）。
 *
 * 引擎生命周期归本服务：start 在 Dispatchers.IO（uniffi start 内部 block_on
 * 最长 5s，严禁主线程调用）；stop 幂等。R4 protect 在 M1 传 null——无 VPN
 * 环境（VpnService 未运行）不存在环回，钩子留给 M2 接线。
 */
class EngineService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var engine: HydraEngine? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopEngine()
                return START_NOT_STICKY
            }
            else -> {
                // START（含系统重启服务）：已在运行则只刷新通知
                if (engine == null && EngineState.ui.value.transition == null) {
                    startEngineFromStore()
                } else {
                    updateNotification()
                }
                return START_NOT_STICKY
            }
        }
    }

    private fun startEngineFromStore() {
        EngineState.addLog("正在启动引擎…")
        EngineState.update { it.copy(transition = "正在启动引擎…") }
        startAsForeground("Hydra 引擎启动中…")
        scope.launch {
            val cfg = SecureStore(this@EngineService).load()
            val result = runCatching { buildEngine(cfg) }
            result.fold(onSuccess = { eng ->
                try {
                    // M1：无 VpnService 环境，protect 传 null（M2 接线 VpnService.protect）
                    eng.start(null)
                    engine = eng
                    val addr = eng.boundAddr()
                    EngineState.update {
                        it.copy(running = true, transition = null, boundAddr = addr)
                    }
                    EngineState.addLog("✓ 引擎已就绪，监听 ${addr ?: "未知"}")
                    updateNotification()
                    pollStats()
                } catch (e: Exception) {
                    eng.close()
                    EngineState.addLog("✗ 启动失败：${e.message}")
                    EngineState.update {
                        it.copy(running = false, transition = "启动失败：${e.message}")
                    }
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }, onFailure = { e ->
                EngineState.addLog("✗ 启动失败：${e.message}")
                EngineState.update {
                    it.copy(running = false, transition = "启动失败：${e.message}")
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            })
        }
    }

    /** 按存储配置构造引擎（不启动）。配置校验失败抛 HydraEngineException。 */
    private fun buildEngine(cfg: HydraConfig): HydraEngine {
        val nodes = cfg.nodesText.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { NodeSpec(it) }
        val trust = if (cfg.trustMode == SecureStore.TRUST_CA) {
            TrustMode.PublicCa
        } else {
            val der = android.util.Base64.decode(
                cfg.certDerB64.ifEmpty { throw IllegalStateException("pin 模式必须提供节点证书") },
                android.util.Base64.DEFAULT,
            )
            TrustMode.Pinned(listOf(der))
        }
        return HydraEngine(
            nodes = nodes,
            authKeyHex = cfg.authKeyHex,
            trust = trust,
            sni = cfg.sni.ifEmpty { null },
            listenPort = cfg.listenPort.coerceIn(0, UShort.MAX_VALUE.toInt()).toUShort(),
        )
    }

    /** 每秒拉一次统计刷新状态与通知（引擎停止/服务销毁时随 scope 取消）。 */
    private suspend fun pollStats() {
        while (engine != null) {
            delay(1_000)
            val eng = engine ?: break
            try {
                val s = withContext(Dispatchers.IO) { eng.stats() }
                EngineState.update {
                    it.copy(
                        sentBytes = s.sent.toLong(),
                        receivedBytes = s.received.toLong(),
                        activeConns = s.activeConnections.toLong(),
                        totalConns = s.totalConnections.toLong(),
                        uptimeSecs = s.uptimeSecs.toLong(),
                    )
                }
                updateNotification()
            } catch (_: Exception) {
                break // 引擎已停止
            }
        }
    }

    private fun stopEngine() {
        scope.launch(Dispatchers.IO) {
            engine?.let { runCatching { it.stop() }; runCatching { it.close() } }
            engine = null
            EngineState.addLog("■ 引擎已停止")
            EngineState.update {
                it.copy(running = false, transition = null, boundAddr = null, sentBytes = 0,
                    receivedBytes = 0, activeConns = 0, totalConns = 0, uptimeSecs = 0)
            }
            withContext(kotlinx.coroutines.Dispatchers.Main) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    override fun onDestroy() {
        engine?.let { runCatching { it.stop() }; runCatching { it.close() } }
        engine = null
        scope.cancel()
        // 系统回收服务（非用户停止路径）也要复位状态——否则 UI 残留"运行中"
        // 而引擎已死，用户误以为代理仍在工作
        EngineState.update {
            it.copy(
                running = false, transition = null, boundAddr = null,
                sentBytes = 0, receivedBytes = 0, activeConns = 0,
                totalConns = 0, uptimeSecs = 0,
            )
        }
        EngineState.addLog("服务已回收，引擎停止")
        super.onDestroy()
    }

    // ── 通知 ────────────────────────────────────────────────────────────────

    private fun ensureChannel() {
        val ch = NotificationChannel(
            CHANNEL_ID, "Hydra 引擎", NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "本地代理引擎运行状态" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun baseBuilder(text: String): NotificationCompat.Builder =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("Hydra 本地代理")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )

    private fun startAsForeground(text: String) {
        val n: Notification = baseBuilder(text).build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification() {
        val s = EngineState.ui.value
        val text = when {
            s.transition != null -> s.transition
            s.running -> "${s.boundAddr ?: "未绑定"}  ↑${fmt(s.sentBytes)} ↓${fmt(s.receivedBytes)}  活跃 ${s.activeConns}"
            else -> "已停止"
        }
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, baseBuilder(text).build())
    }

    private fun fmt(bytes: Long): String = when {
        bytes >= 1 shl 20 -> "%.1fMB".format(bytes.toDouble() / (1 shl 20))
        bytes >= 1 shl 10 -> "%.1fKB".format(bytes.toDouble() / (1 shl 10))
        else -> "${bytes}B"
    }

    companion object {
        const val ACTION_START = "dev.hydra.vpn.action.START"
        const val ACTION_STOP = "dev.hydra.vpn.action.STOP"
        private const val CHANNEL_ID = "hydra_engine"
        private const val NOTIF_ID = 1
        // 库加载由 uniffi 生成的 UniffiLib 首次访问时自动完成（JNA Native.load，
        // app native 库目录在默认搜索路径内），无需手动注册。
    }
}
