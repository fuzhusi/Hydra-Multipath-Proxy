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
import kotlinx.coroutines.delay
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

    /** kill switch 重连循环任务（stopVpnLocal 取消以打断退避等待） */
    private var retryJob: kotlinx.coroutines.Job? = null

    /** 用户显式停止标志（区分「停止」与「新一轮启动」两种 gen 失效） */
    @Volatile
    private var userStopRequested = false

    /**
     * kill switch 阻断用黑洞 TUN：隧道中断的退避期间保持全接管路由的 TUN
     * 不被消费——应用出站包进入内核 TUN 队列填满后丢弃 = **流量被阻断、
     * 真实 IP 零泄漏**。下一次真实建立前毫秒级关闭（用户显式停止则恢复直连）。
     */
    @Volatile
    private var holdTun: ParcelFileDescriptor? = null

    private fun releaseHoldTun() {
        holdTun?.let { runCatching { it.close() } }
        holdTun = null
    }

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

        userStopRequested = false
        val gen = generation.incrementAndGet()

        // 看门狗：仅守首轮建立（establish/FFI pathological 挂起兜底——阻塞 JNI
        // 无法被协程取消，只能由独立线程兜底）。kill switch 重连等待（"隧道中断"
        // 态）由重连循环自管退避，看门狗跳过——判定依据是 transition，**不能**
        // 用 retryJob.isActive（首轮挂起时 retryJob 恰是被卡协程，恒 active，
        // 看门狗会因此永不触发）
        Thread {
            Thread.sleep(20_000)
            val t = EngineState.ui.value
            if (generation.get() == gen && !t.running
                && !t.transition.orEmpty().startsWith("隧道中断")) {
                runCatching { stopVpn() }
                EngineState.addLog("✗ VPN 启动超时（20s）已中止——请重试")
                EngineState.update {
                    it.copy(running = false, transition = "启动超时（20s）：请重试")
                }
                updateNotification()
            }
        }.apply { isDaemon = true; start() }

        retryJob?.cancel()
        retryJob = scope.launch {
            EngineState.addLog("① 读取加密配置…")
            val cfg = SecureStore(this@HydraVpnService).load()
            val nodeCount = cfg.nodesText.lines().count { it.isNotBlank() }
            EngineState.addLog(
                "② 配置已加载（$nodeCount 个节点，密钥" +
                    (if (cfg.authKeyHex.isNotEmpty()) "✓" else "✗") +
                    when (cfg.appFilterMode) {
                        SecureStore.APP_FILTER_ALLOW -> "，分应用白名单"
                        SecureStore.APP_FILTER_DISALLOW -> "，分应用黑名单"
                        else -> ""
                    } + "）"
            )

            // 本代黑洞 TUN 的**本地**引用（声明在 try 外——Kotlin finally 不可见
            // try 内局部变量）：finally 只关本代实例——若旧代被取消时新代已写入
            // 共享字段，旧代 finally 关共享字段会误杀新代黑洞（直连泄漏而 UI
            // 声称已阻断）
            var myHold: ParcelFileDescriptor? = null
            try {
                // 配置预校验：配置类错误直接「启动失败」，不进 kill switch 重连
                // （重连修复不了配置错误；且 Rust 校验失败发生在 fd 接管之前，
                //  每轮重试会泄漏 1 个 fd；空配置重试会把设备黑洞在无提示状态）
                validateVpnConfig(cfg)?.let { err ->
                    EngineState.addLog("✗ 启动失败：$err")
                    EngineState.update {
                        it.copy(running = false, transition = "启动失败：$err")
                    }
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                var attempt = 0
                var configFatal = false // Rust InvalidConfig：配置终态，不进重连
                while (true) {
                    if (userStopRequested || generation.get() != gen) return@launch
                    attempt++
                    val first = attempt == 1
                    EngineState.addLog(if (first) "③ 建立 TUN 接口…" else "↻ 第 $attempt 次重连：建立 TUN…")

                    // 建立前释放上一轮黑洞 TUN（毫秒级无隧道窗口，紧接重建）
                    releaseHoldTun()
                    val pfd = establish(cfg)
                    var failMsg: String? = if (pfd == null) {
                        "VPN 接口建立失败（未授权或被其他 VPN 占用）"
                    } else null

                    if (pfd != null) {
                        val fd = pfd.detachFd() // 所有权移交 Rust（drop 时关闭）
                        // R4 防环回：每个出站 socket connect 前回调 protect(fd)，
                        // 失败即中止该连接（放行 = 流量被自身 TUN 捕获回环）
                        VpnProtectHolder.handler = { f ->
                            runCatching { this@HydraVpnService.protect(f.toInt()) }.getOrDefault(false)
                        }
                        val protect = object : SocketProtect {
                            override fun protect(fd: Long): Boolean = VpnProtectHolder.protect(fd)
                        }
                        EngineState.addLog("④ 启动用户态栈与隧道…")
                        runCatching {
                            withContext(Dispatchers.IO) {
                                startVpn(fd, cfg.toVpnConfig(), protect)
                            }
                        }.fold(
                            onSuccess = {
                                // 竞态守卫：成功前收到停止/新一轮启动 → 立即终止
                                // 刚启动的数据面（僵尸 VPN 防护）
                                if (userStopRequested || generation.get() != gen) {
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
                                return@launch
                            },
                            onFailure = { e ->
                                // 取消异常必须穿透（superseded 兜底之外的正确语义）
                                if (e is kotlinx.coroutines.CancellationException) throw e
                                // 配置类错误是**终态**：kill switch 重连修复不了配置
                                // （Rust 解析权威——预校验漏过的域名节点等在此落地）
                                if (e is uniffi.hydra_android.HydraEngineException.InvalidConfig) {
                                    configFatal = true
                                }
                                failMsg = e.message
                            },
                        )
                    }

                    // ── 本轮失败 ──
                    val msg = failMsg ?: "未知错误"
                    EngineState.addLog("✗ 建连失败：$msg")
                    runCatching { stopVpn() } // 清 Rust 态并释放失败尝试的 fd

                    val superseded = userStopRequested || generation.get() != gen
                    if (!cfg.vpnKillSwitch || superseded || configFatal) {
                        if (!superseded) {
                            EngineState.update {
                                it.copy(running = false, transition = "启动失败：$msg")
                            }
                        }
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@launch
                    }

                    // ── kill switch：黑洞 TUN 保持阻断 + 退避重连 ──
                    // 保持全接管路由的 TUN 不被消费 = 应用流量持续被阻断、防真实
                    // IP 泄漏；用户显式停止才恢复直连。
                    // 顺序权衡：先释放旧黑洞再建新黑洞（毫秒级直连窗口）。若反过来
                    // 「先建后放」依赖系统同应用原子替换 VPN，部分 OEM 可能误触发
                    // onRevoke 导致服务被拆——保守取当前顺序，毫秒窗口记为已知边界
                    myHold = establish(cfg)
                    if (myHold == null && cfg.appFilterMode != SecureStore.APP_FILTER_ALL) {
                        // 分应用过滤 TUN 建立失败（如含失效包名）：回退全量阻断
                        // ——kill switch 语义「阻断永不回退到直连」
                        EngineState.addLog("⚠ 分应用过滤建立失败——回退全量阻断（防泄漏优先）")
                        myHold = establish(cfg.copy(appFilterMode = SecureStore.APP_FILTER_ALL))
                    }
                    holdTun = myHold // 停止路径可见（stopVpnLocal 立即关闭恢复直连）
                    val backoff = ((3_000L shl (attempt - 1).coerceAtMost(4))
                        .coerceAtMost(30_000L)) + (0..999L).random()
                    val waitSec = (backoff / 1000).toInt()
                    // UI 写入前复检（失败处理段含 establish/通知等耗时操作，
                    // STOP 可能已落入——服务即将销毁不得把 UI 覆写回重连态）
                    if (!userStopRequested && generation.get() == gen) {
                        EngineState.update {
                            it.copy(
                                running = false,
                                transition = "隧道中断——已阻断全部流量，${waitSec}s 后重连（第 $attempt 次）",
                            )
                        }
                        EngineState.addLog("↻ kill switch：已阻断流量，${waitSec}s 后重连")
                        updateNotification()
                    }
                    delay(backoff)
                }
            } finally {
                // 一切退出路径（成功/停止/取消/新一轮启动）都不得遗留**本代**黑洞：
                // 只关本地引用；共享字段仅在本代仍持有时置空——旧代 finally 不得
                // 误杀新代已写入的黑洞（跨代竞态修复）
                myHold?.let { runCatching { it.close() } }
                if (holdTun === myHold) {
                    holdTun = null
                }
            }
        }
    }

    /** 建立 TUN 接口（v4/v6 全接管；节点出站连接经 protect 防回环，无需路由豁免）。
     *  分应用代理：白名单（仅所选应用走 VPN）/ 黑名单（所选应用直连）。 */
    private fun establish(cfg: HydraConfig): ParcelFileDescriptor? {
        return runCatching {
            val b = Builder()
                .setSession("Hydra 全局代理")
                .setMtu(1500)
                .addAddress("10.7.0.1", 30)
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
                .addAddress("fd07::1", 126)
                .addRoute("::", 1)
                .addRoute("8000::", 1)
            // 分应用代理包名先经 PackageManager 校验——失效包名（已卸载/拼写错）
            // 在部分系统上会使 addAllowed/Disallowed 抛异常 → establish 持续失败
            val pm = packageManager
            val pkgs = cfg.appFilterPkgs.split(',', '\n')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .filter { p -> runCatching { pm.getPackageInfo(p, 0) }.isSuccess }
            when (cfg.appFilterMode) {
                SecureStore.APP_FILTER_ALLOW -> pkgs.forEach { b.addAllowedApplication(it) }
                SecureStore.APP_FILTER_DISALLOW -> pkgs.forEach { b.addDisallowedApplication(it) }
            }
            b.establish()
        }.getOrElse {
            EngineState.addLog("✗ TUN 建立异常：${it.message}")
            null
        }
    }

    /** 配置预校验：返回 null = 可尝试启动；非 null = 用户可修复的错误文案。
     *  配置类错误不进 kill switch 重连（重连修复不了配置；且 Rust 校验失败
     *  发生在 fd 接管之前，重试每轮泄漏 1 个 fd）。
     *  快速路径与 Rust 对齐：v4 用系统正则、v6 必须方括号形态（Rust
     *  SocketAddr 标准解析形态）；**Rust 解析仍是权威**——此处漏过的配置
     *  错误由下方 InvalidConfig 终态兜底（不进重连循环）。 */
    private fun validateVpnConfig(cfg: HydraConfig): String? {
        if (cfg.nodesText.isBlank()) return "未配置节点——请先到「节点」页导入"
        val hasParsableNode = cfg.nodesText.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .any { node ->
                runCatching {
                    val port = node.substringAfterLast(':').toInt()
                    if (port !in 1..65535) return@runCatching false
                    if (node.startsWith("[")) {
                        true // v6 方括号形态（Rust SocketAddr 标准解析）
                    } else {
                        val host = node.substringBeforeLast(':')
                        android.util.Patterns.IP_ADDRESS.matcher(host).matches()
                    }
                }.getOrDefault(false)
            }
        if (!hasParsableNode) {
            return "节点地址均无法解析（M2 暂不支持域名节点，需 IP:port，IPv6 用 [..]:port）"
        }
        val keyOk = cfg.authKeyHex.length == 64 &&
            cfg.authKeyHex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
        if (!keyOk) return "认证密钥非法（须恰好 64 位 hex）"
        if (cfg.trustMode == SecureStore.TRUST_PINNED && cfg.certDerB64.isEmpty()) {
            return "自签 pin 模式未导入节点证书"
        }
        return null
    }

    private fun stopVpnLocal() {
        generation.incrementAndGet() // 使在途看门狗/重连循环/启动结果失效
        userStopRequested = true
        retryJob?.cancel()           // 打断退避等待
        releaseHoldTun()             // 用户显式停止 = 恢复直连（kill switch 不拦用户）
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

    /** 系统/用户撤销 VPN（设置页关闭、其他 VPN 接管等）：停数据面并收敛。
     *  与用户停止同语义：取消重连循环、释放黑洞 TUN，不与之争抢。 */
    override fun onRevoke() {
        EngineState.addLog("VPN 被系统或用户撤销")
        generation.incrementAndGet()
        userStopRequested = true
        retryJob?.cancel()
        releaseHoldTun()
        runCatching { stopVpn() }
        EngineState.update {
            it.copy(running = false, transition = null, boundAddr = null,
                sentBytes = 0, receivedBytes = 0, activeConns = 0,
                totalConns = 0, uptimeSecs = 0)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        runCatching { stopVpn() }
        retryJob?.cancel()
        releaseHoldTun()
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
        when {
            // 34+：specialUse（无 6h 超时、BOOT_COMPLETED 不受限；见 Manifest）
            Build.VERSION.SDK_INT >= 34 ->
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            Build.VERSION.SDK_INT >= 29 ->
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else -> startForeground(NOTIF_ID, n)
        }
    }

    /** Android 15+ FGS 超时兜底（specialUse 类型不应触发；防御性收敛而非静默死亡） */
    override fun onTimeout(startId: Int) {
        EngineState.addLog("⚠ 前台服务被系统超时回收——VPN 已停止（请重新启动）")
        stopVpnLocal()
        super.onTimeout(startId)
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
