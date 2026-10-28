package dev.hydra.vpn

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.ActivityCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.hydra.vpn.ui.HydraTheme
import dev.hydra.vpn.ui.HomeScreen
import dev.hydra.vpn.ui.ImportFeedback
import dev.hydra.vpn.ui.NodesScreen
import dev.hydra.vpn.ui.SettingsScreen
import dev.hydra.vpn.ui.ShareImporter
import dev.hydra.vpn.ui.ThemeMode
import dev.hydra.vpn.ui.ThemePrefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.hydra_android.TrustMode
import uniffi.hydra_android.testNodeConnection

/**
 * Hydra Android：本地 SOCKS5/HTTP 代理 + 全局 VPN（TUN）引擎 + 三页 UI。
 *
 * 本文件只保留「装配」：Activity 生命周期、hydra:// 深链、三 Tab 导航与
 * 状态接线（T4 拆分后 UI 细节在 ui/ 各文件，主题在 ui/Theme.kt）。
 *
 * 使用模型：引擎在本机监听 SOCKS5/HTTP——浏览器手动配代理指向监听地址即可
 * 走节点出网；全局 VPN（VpnService + TUN）模式免配置。
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wanted = buildList {
            if (Build.VERSION.SDK_INT >= 33 &&
                ActivityCompat.checkSelfPermission(this@MainActivity, Manifest.permission.POST_NOTIFICATIONS) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
            // 相机权限**不在此处请求**（真机实测 UX 问题：启动即弹相机授权，
            // 与用户当下意图无关、徒增反感）。扫码入口（onScan）点击时按需请求，
            // 见 requestCameraThenScan。
        }
        if (wanted.isNotEmpty()) {
            requestPermissions(wanted.toTypedArray(), 1)
        }
        handleDeepLink(intent)
        setContent {
            // 主题偏好存 SharedPreferences「hydra_ui」（R2，非 SecureStore），
            // 设置页四选切换即时生效
            val context = LocalContext.current
            var themeMode by remember { mutableStateOf(ThemePrefs.load(context)) }
            HydraTheme(themeMode) {
                HydraApp(
                    themeMode = themeMode,
                    onSetTheme = { mode ->
                        themeMode = mode
                        ThemePrefs.save(context, mode)
                    },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    /** hydra:// 深链：聊天工具/浏览器点开直达导入（设计 §5 输入③）。
     *  评审 P2-3：scope 改 lifecycleScope（随 Activity 销毁自动取消，
     *  原手动 CoroutineScope 永不 cancel = 泄漏） */
    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme != "hydra") return
        val text = data.toString()
        val appCtx = applicationContext
        lifecycleScope.launch {
            // R5：导入反馈不再用静默 Toast——ShareImporter 写 ImportFeedback，
            // 首页 Snackbar「已导入 N 个节点」+ 节点 Tab 徽标消费同一信号
            ShareImporter.import(appCtx, text)
        }
    }
}

private enum class Tab(val label: String) {
    Home("连接"), Nodes("节点"), Settings("设置")
}

/** 装配层：三 Tab 导航 + 配置状态 + 引擎/VPN 服务启停接线。 */
@Composable
private fun HydraApp(themeMode: ThemeMode, onSetTheme: (ThemeMode) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { SecureStore(context) }
    var cfg by remember { mutableStateOf(store.load()) }
    var tab by androidx.compose.runtime.saveable.rememberSaveable { mutableStateOf(Tab.Home) }
    var toast by androidx.compose.runtime.saveable.rememberSaveable { mutableStateOf<String?>(null) }
    val imported by ImportFeedback.importedNodes.collectAsState()
    // 深链导入（handleDeepLink 在 Activity 侧执行）不会触碰本 composable 的
    // cfg 状态——不刷新则 UI 一直显示「尚未配置」，且任何 persist 都会把
    // 导入的数据覆盖掉（真机实测 P0）。导入信号到达即从存储重读。
    LaunchedEffect(imported) {
        if (imported != null) cfg = store.load()
    }
    LaunchedEffect(toast) {
        toast?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            toast = null
        }
    }

    fun persist(c: HydraConfig) {
        // 评审 P1-1：运行中切换运行模式 → 先停**旧模式**的服务。否则旧引擎
        // 成为孤儿：UI 已显示新模式（待启动/已断开），旧服务仍在监听/耗流量
        // （stopCurrentMode 读新模式只能停新服务——孤儿路径的根因）。
        if (EngineState.ui.value.running && cfg.runMode != c.runMode) {
            val oldVpn = cfg.runMode == SecureStore.MODE_VPN
            val stopIntent = Intent(
                context,
                if (oldVpn) HydraVpnService::class.java else EngineService::class.java,
            ).setAction(
                if (oldVpn) HydraVpnService.ACTION_STOP else EngineService.ACTION_STOP,
            )
            context.startService(stopIntent)
            EngineState.addLog("运行模式已切换——原${if (oldVpn) "全局 VPN" else "本地代理"}引擎已停止")
        }
        cfg = c
        store.save(c)
    }

    // ── 分享/订阅导入（粘贴文本或扫码结果共用）──
    suspend fun doImport(text: String): String {
        val msg = ShareImporter.import(context, text)
        cfg = store.load() // 回读最新落库（节点列表即时刷新）
        return msg
    }

    // R1 节点连通性手动测试（完整握手探测，8s 超时；须在 IO 线程）
    val testNode: suspend (String) -> Pair<Boolean, String> = { addr ->
        withContext(Dispatchers.IO) {
            try {
                val cur = store.load()
                val t = if (cur.trustMode == SecureStore.TRUST_CA) {
                    TrustMode.PublicCa
                } else {
                    // 用**被测节点自己的证书**（缺项回落全局）——用别的节点
                    // 证书探测会把证书错配误报成节点故障（ISSUE 安卓多节点证书）
                    val b64 = NodeCerts.certB64For(cur, addr)
                        ?: return@withContext false to "未导入证书——请导入该节点的分享链接或到设置页选择证书 DER"
                    TrustMode.Pinned(listOf(NodeCerts.decodeCert(b64)))
                }
                val r = testNodeConnection(addr, cur.authKeyHex, t, cur.sni.ifEmpty { null })
                if (r.ok) true to "${r.latencyMs}ms" else false to NodeCerts.friendlyError(r.detail)
            } catch (e: Exception) {
                false to NodeCerts.friendlyError(e.message ?: "测试失败")
            }
        }
    }

    // M2 VPN 授权（系统 VpnService.consent 对话框；同意后直接启动 VPN 服务）。
    // R4：launcher 以参数位传给 HomeScreen（vpnPrepareLauncher），VPN 权限流
    // 挂点收敛在大按钮点击链路
    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            // 授权成功：VPN 服务直启（无需再走 consent）
            context.startForegroundService(
                Intent(context, HydraVpnService::class.java)
                    .setAction(HydraVpnService.ACTION_START),
            )
        } else {
            toast = "未授权 VPN——全局代理需要 VPN 权限"
            EngineState.addLog("✗ 用户未授权 VPN 权限")
        }
    }

    /** 按运行模式启动（大按钮「连接」）：vpn 走 prepare/consent/服务，local 走引擎服务 */
    fun startCurrentMode() {
        val c = store.load()
        if (c.runMode == SecureStore.MODE_VPN) {
            val prepare = VpnService.prepare(context)
            if (prepare != null) {
                vpnConsent.launch(prepare)
            } else {
                context.startForegroundService(
                    Intent(context, HydraVpnService::class.java)
                        .setAction(HydraVpnService.ACTION_START),
                )
            }
        } else {
            val intent = Intent(context, EngineService::class.java)
                .setAction(EngineService.ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    /** 按运行模式停止（大按钮「断开」）。
     *  必须用各自服务的 ACTION_STOP 常量——此前统一用
     *  EngineService.ACTION_STOP，HydraVpnService 收到未知 action
     *  被误判为启动：点停止 → 伪启动 → "VPN 已在运行" 启动失败，
     *  而旧引擎从未收到停止指令继续跑（线上真机实测 bug） */
    fun stopCurrentMode() {
        // 评审 P1-1 兜底：**双停**。运行中切模式后 UI 显示的模式可能不是
        // 正在跑的服务（persist 已停旧服务，此处再兜一层）；ACTION_STOP 对
        // 未启动的服务是空操作（onStartCommand 收到即停止自身），无伪启动
        // 风险——早前"伪启动"事故是给错误服务发了未知 action，非双停本身。
        context.startService(
            Intent(context, HydraVpnService::class.java)
                .setAction(HydraVpnService.ACTION_STOP),
        )
        context.startService(
            Intent(context, EngineService::class.java)
                .setAction(EngineService.ACTION_STOP),
        )
    }

    // 扫码导入（桌面端分享二维码 → 手机扫描即完成全部配置）
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents
        if (content != null) {
            scope.launch {
                val msg = doImport(content)
                toast = msg
                if (msg.startsWith("导入成功")) tab = Tab.Nodes
            }
        }
    }

    // 按需相机权限（真机实测 UX 修复）：启动不再请求，点「扫码」时才请求；
    // 授权即启动扫描，拒绝给可操作提示（还有其他导入方式）
    fun launchQrScan() {
        qrLauncher.launch(
            ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("对准桌面端生成的 Hydra 分享二维码")
                .setBeepEnabled(false),
        )
    }
    val cameraPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            launchQrScan()
        } else {
            toast = "未授予相机权限——可改用「粘贴分享链接」导入"
        }
    }

    val nodeSummary = run {
        val n = cfg.nodesText.lines().count { it.isNotBlank() }
        if (n > 0) "$n 个节点已配置" else "尚未配置——去节点页导入分享链接"
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = {
                            tab = t
                            // R5：进入节点页即清徽标（已读）
                            if (t == Tab.Nodes) ImportFeedback.importedNodes.value = null
                        },
                        icon = {
                            if (t == Tab.Nodes && imported != null) {
                                // R5：导入后节点 Tab 徽标高亮
                                BadgedBox(badge = { Badge { Text("${imported}") } }) {
                                    Icon(Icons.AutoMirrored.Outlined.List, contentDescription = t.label)
                                }
                            } else {
                                Icon(
                                    when (t) {
                                        Tab.Home -> Icons.Filled.Home
                                        Tab.Nodes -> Icons.AutoMirrored.Outlined.List
                                        Tab.Settings -> Icons.Filled.Settings
                                    },
                                    contentDescription = t.label,
                                )
                            }
                        },
                        label = { Text(t.label) },
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (tab) {
                Tab.Home -> HomeScreen(
                    runMode = cfg.runMode,
                    nodeSummary = nodeSummary,
                    vpnPrepareLauncher = { intent -> vpnConsent.launch(intent) },
                    onGoNodes = { tab = Tab.Nodes },
                    onConnect = {
                        // 真机实测修复（P0）：此处曾 persist(cfg)——用 UI 缓存的
                        // **陈旧配置**回写存储。深链导入后 UI 缓存未刷新时，
                        // 点连接 = 把导入的节点/密钥/证书整份覆盖清空（实测
                        // prefs 3298B→2562B），服务随即读到 0 节点启动失败。
                        // 改为**先刷新缓存**（从存储重新读）再启动，绝不回写。
                        cfg = store.load()
                        startCurrentMode()
                    },
                    onDisconnect = { stopCurrentMode() },
                    ruleMode = cfg.runRuleMode,
                    // §九 智能分流开关：持久化（启动 VPN 时经 VpnConfig 生效）；
                    // 运行中不热切换——提示重启 VPN 生效（分流字段在启动时读取）
                    onToggleRuleMode = { on ->
                        persist(cfg.copy(runRuleMode = on))
                        if (EngineState.ui.value.running) {
                            toast = "分流已${if (on) "开启" else "关闭"}——重启 VPN 后生效"
                            EngineState.addLog("智能分流已${if (on) "开启" else "关闭"}（重启 VPN 生效）")
                        }
                    },
                )
                Tab.Nodes -> NodesScreen(
                    cfg = cfg,
                    onPersist = ::persist,
                    onImport = { text -> doImport(text) },
                    onScan = {
                        // 按需权限：已授权直接扫，未授权先请求（启动不再弹）
                        if (androidx.core.content.ContextCompat.checkSelfPermission(
                                context,
                                Manifest.permission.CAMERA,
                            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
                        ) {
                            launchQrScan()
                        } else {
                            cameraPermLauncher.launch(Manifest.permission.CAMERA)
                        }
                    },
                    onToast = { toast = it },
                    onTestNode = testNode,
                )
                Tab.Settings -> SettingsScreen(
                    cfg = cfg,
                    themeMode = themeMode,
                    onSetTheme = onSetTheme,
                    onPersist = { c ->
                        persist(c)
                        toast = "配置已加密保存"
                    },
                )
            }
        }
    }
}
