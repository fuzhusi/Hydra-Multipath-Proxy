package dev.hydra.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.hydra_android.SocketProtect
import uniffi.hydra_android.TrustMode
import uniffi.hydra_android.VpnConfig
import uniffi.hydra_android.startVpn
import uniffi.hydra_android.stopVpn
import java.util.Base64

/**
 * M2：全局 VPN（VpnService）。
 *
 * 数据面：establish() 建立 TUN（v4/v6 全接管路由）→ fd 交付 Rust
 * `start_vpn`（用户态栈：TCP 任意端口动态接流 + UDP 中继）→ 出站连接经
 * protect 钩子（R4）标记防回环 → 全部流量加密走节点隧道。
 *
 * 与 EngineService（本地代理模式）互斥使用：由设置页"运行模式"决定启停目标。
 * DNS：系统 DNS（v4/v6）随全局路由进入隧道，经节点解析（加密、无泄漏）。
 */
/**
 * 进程级 protect 委托点：Rust 钩子进程内首装生效——回调对象首次安装后不再
 * 更换，service 实例仅更新此处 handler；实例销毁置空 = fail-closed。
 */
object VpnProtectHolder {
    @Volatile
    var handler: ((Long) -> Boolean)? = null
    fun protect(fd: Long): Boolean = handler?.invoke(fd) ?: false
}

class HydraVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnLocal()
                return START_NOT_STICKY
            }
            // 只有显式 START（或无 action 的默认投递）才启动——未知 action 一律
            // 忽略。此前 else 兜底把任何非 STOP action 都当启动：停止按钮发错
            // action 常量即触发"伪启动 → VPN 已在运行 → 启动失败"且引擎不停
            ACTION_START, null -> {
                startVpnFromStore()
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    private fun startVpnFromStore() {
        EngineState.update {
            it.copy(running = false, transition = "正在建立 VPN 隧道…", boundAddr = null,
                sentBytes = 0, receivedBytes = 0, activeConns = 0,
                totalConns = 0, uptimeSecs = 0)
        }
        EngineState.addLog("正在建立全局 VPN…")
        startAsForeground("VPN 隧道建立中…")

        // 看门狗：establish/FFI pathological 挂起兜底（同 EngineService 设计）
        val gen = generation.incrementAndGet()
        Thread {
            Thread.sleep(20_000)
            if (generation.get() == gen && !EngineState.ui.value.running) {
                runCatching { stopVpn() }
                EngineState.addLog("✗ VPN 启动超时（20s）已中止——请重试")
                EngineState.update {
                    it.copy(running = false, transition = "启动超时（20s）：请重试")
                }
                updateNotification()
            }
        }.apply { isDaemon = true; start() }

        scope.launch {
            EngineState.addLog("① 读取加密配置…")
            val cfg = SecureStore(this@HydraVpnService).load()
            val nodeCount = cfg.nodesText.lines().count { it.isNotBlank() }
            EngineState.addLog(
                "② 配置已加载（$nodeCount 个节点，密钥" +
                    (if (cfg.authKeyHex.isNotEmpty()) "✓" else "✗") + "）"
            )

            EngineState.addLog("③ 建立 TUN 接口…")
            val pfd = establish()
            if (pfd == null) {
                EngineState.addLog("✗ VPN 接口建立失败——请重新授权（设置页再点启动会弹授权）")
                EngineState.update {
                    it.copy(running = false, transition = "启动失败：VPN 接口建立失败（未授权或已占用）")
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return@launch
            }
            val fd = pfd.detachFd() // 所有权移交 Rust（drop 时关闭）

            // R4 防环回：每个出站 socket 在 connect 前回调 protect(fd)，
            // 失败即中止该连接（放行 = 流量被自身 TUN 捕获回环）
            // 更新委托点为当前 service 实例（Rust 侧首装回调会经 holder 转发）
            VpnProtectHolder.handler = { fd ->
                runCatching { this@HydraVpnService.protect(fd.toInt()) }.getOrDefault(false)
            }
            val protect = object : SocketProtect {
                override fun protect(fd: Long): Boolean = VpnProtectHolder.protect(fd)
            }

            EngineState.addLog("④ 启动用户态栈与隧道…")
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    startVpn(fd, cfg.toVpnConfig(), protect)
                }
            }
            result.fold(onSuccess = {
                // 停止竞态守卫：启动期间收到 STOP（generation 已递增）——刚启动的
                // 数据面必须立即终止且不更新 UI（否则僵尸 VPN：UI 显示已停止而
                // 引擎仍在接管全部流量）
                if (generation.get() != gen) {
                    runCatching { stopVpn() }
                    EngineState.addLog("启动期间收到停止请求——本轮启动已作废")
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }
                EngineState.update {
                    it.copy(running = true, transition = null,
                        boundAddr = "全局 VPN（所有应用流量经节点）")
                }
                EngineState.addLog("✓ 全局 VPN 已接管——所有应用流量经节点加密隧道")
                updateNotification()
            }, onFailure = { e ->
                // 过期启动的失败不覆盖新状态（新一轮启动可能已在途）
                if (generation.get() == gen) {
                    EngineState.addLog("✗ 启动失败：${e.message}")
                    EngineState.update {
                        it.copy(running = false, transition = "启动失败：${e.message}")
                    }
                }
                runCatching { stopVpn() }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            })
        }
    }

    /** 建立 TUN 接口（v4/v6 全接管；节点出站连接经 protect 防回环，无需路由豁免） */
    private fun establish(): ParcelFileDescriptor? {
        val cfg = SecureStore(this).load()
        return runCatching {
            Builder()
                .setSession("Hydra 全局代理")
                .setMtu(1500)
                .addAddress("10.7.0.1", 30)
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
                .addAddress("fd07::1", 126)
                .addRoute("::", 1)
                .addRoute("8000::", 1)
                .establish()
        }.getOrElse {
            EngineState.addLog("✗ TUN 建立异常：${it.message}")
            null
        }
    }

    private fun stopVpnLocal() {
        generation.incrementAndGet() // 使在途看门狗失效
        scope.launch(Dispatchers.IO) {
            runCatching { stopVpn() }
            EngineState.addLog("■ 全局 VPN 已停止")
            EngineState.update {
                it.copy(running = false, transition = null, boundAddr = null,
                    sentBytes = 0, receivedBytes = 0, activeConns = 0,
                    totalConns = 0, uptimeSecs = 0)
            }
            withContext(kotlinx.coroutines.Dispatchers.Main) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /** 系统/用户撤销 VPN（设置页关闭、其他 VPN 接管等）：停数据面并收敛 */
    override fun onRevoke() {
        EngineState.addLog("VPN 被系统或用户撤销")
        runCatching { stopVpn() }
        EngineState.update {
            it.copy(running = false, transition = null, boundAddr = null)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        runCatching { stopVpn() }
        scope.cancel()
        VpnProtectHolder.handler = null
        EngineState.update {
            it.copy(running = false, transition = null, boundAddr = null,
                sentBytes = 0, receivedBytes = 0, activeConns = 0,
                totalConns = 0, uptimeSecs = 0)
        }
        super.onDestroy()
    }

    // ── 通知 ────────────────────────────────────────────────────────────────

    private fun ensureChannel() {
        val ch = NotificationChannel(CHANNEL_ID, "Hydra VPN", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "全局 VPN 运行状态" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun baseBuilder(text: String): NotificationCompat.Builder =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentTitle("Hydra 全局 VPN")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            .addAction(
                0, "停止",
                PendingIntent.getService(
                    this, 2,
                    Intent(this, HydraVpnService::class.java).setAction(ACTION_STOP),
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
            s.running -> "已接管全部流量 · ↑${fmt(s.sentBytes)} ↓${fmt(s.receivedBytes)}"
            else -> "已停止"
        }
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, baseBuilder(text).build())
    }

    private fun fmt(bytes: Long): String = when {
        bytes >= 1 shl 20 -> "%.1fMB".format(bytes.toDouble() / (1 shl 20))
        bytes >= 1 shl 10 -> "%.1fKB".format(bytes.toDouble() / (1 shl 10))
        else -> "${bytes}B"
    }

    companion object {
        /** 配置 → Rust VpnConfig（地址与 establish() 的 Builder 严格一致） */
        private fun HydraConfig.toVpnConfig(): VpnConfig = VpnConfig(
            nodes = nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() },
            authKeyHex = authKeyHex,
            trust = if (trustMode == SecureStore.TRUST_CA) TrustMode.PublicCa
            else TrustMode.Pinned(listOf(Base64.getDecoder().decode(certDerB64))),
            sni = sni.ifEmpty { null },
            mtu = 1500.toUShort(),
            addr4 = "10.7.0.1",
            prefix4 = 30.toUByte(),
            addr6 = "fd07::1",
            udpRelay = true,
        )

        const val ACTION_START = "dev.hydra.vpn.action.VPN_START"
        const val ACTION_STOP = "dev.hydra.vpn.action.VPN_STOP"
        private const val CHANNEL_ID = "hydra_vpn"
        private const val NOTIF_ID = 2
        private val generation = java.util.concurrent.atomic.AtomicLong(0)
    }
}
