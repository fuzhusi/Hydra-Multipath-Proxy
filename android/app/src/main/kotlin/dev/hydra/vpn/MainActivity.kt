package dev.hydra.vpn

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.List
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Switch
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Shapes
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.hydra_android.TrustMode
import uniffi.hydra_android.parseShareText
import uniffi.hydra_android.testNodeConnection
import java.util.Base64

/**
 * Hydra Android（M1.5）：本地 SOCKS5/HTTP 代理引擎 + 三页 UI。
 *
 * 页面：连接（状态/启停/流量/事件日志）、节点（卡片列表 + 分享链接/二维码/手动导入）、
 * 设置（凭据/证书/高级）。
 *
 * 使用模型：引擎在本机监听 SOCKS5/HTTP——浏览器手动配代理指向监听地址即可
 * 走节点出网；M2 全局 VPN（VpnService + TUN）上线后免配置。
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
            // 扫码导入分享二维码的前置条件（zxing CaptureActivity 不代请求）
            if (ActivityCompat.checkSelfPermission(this@MainActivity, Manifest.permission.CAMERA) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                add(Manifest.permission.CAMERA)
            }
        }
        if (wanted.isNotEmpty()) {
            requestPermissions(wanted.toTypedArray(), 1)
        }
        handleDeepLink(intent)
        setContent { HydraTheme { HydraApp() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    private val deepLinkScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.SupervisorJob() + Dispatchers.Main.immediate
    )

    /** hydra:// 深链：聊天工具/浏览器点开直达导入（设计 §5 输入③） */
    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme != "hydra") return
        val text = data.toString()
        val appCtx = applicationContext
        deepLinkScope.launch {
            val msg = ShareImporter.import(appCtx, text)
            Toast.makeText(appCtx, msg, Toast.LENGTH_LONG).show()
        }
    }
}

/** Material 3 动态配色（Android 12+ 取系统壁纸色；低版本回退默认深色）。 */
@Composable
private fun HydraTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val dark = (ctx.resources.configuration.uiMode and
        android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
        android.content.res.Configuration.UI_MODE_NIGHT_YES
    val scheme = if (Build.VERSION.SDK_INT >= 31) {
        (if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx))
    } else {
        MaterialTheme.colorScheme
    }
    // §4 几何体系：状态主卡 20 / 普通卡与对话框 12 / 按钮 14
    val shapes = Shapes(
        small = RoundedCornerShape(8.dp),
        medium = RoundedCornerShape(12.dp),
        large = RoundedCornerShape(20.dp),
    )
    MaterialTheme(colorScheme = scheme, shapes = shapes, content = content)
}

private enum class Tab(val label: String) {
    Home("连接"), Nodes("节点"), Settings("设置")
}

/** 导入逻辑唯一实现：Activity 深链与 Compose 粘贴/扫码共用。 */
object ShareImporter {
    suspend fun import(context: Context, text: String): String =
        withContext(Dispatchers.IO) {
            try {
                val p = parseShareText(text.trim())
                val store = SecureStore(context)
                val cur = store.load()
                // 合并而非替换：手动添加的节点不因导入丢失；链接节点去重后追加
                val existing = cur.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }
                val mergedNodes = (existing + p.nodes.filter { it !in existing })
                    .joinToString("\n")
                val merged = cur.copy(
                    nodesText = mergedNodes,
                    authKeyHex = p.authKeyHex.ifEmpty { cur.authKeyHex },
                    certDerB64 = p.certDerB64.ifEmpty { cur.certDerB64 },
                )
                store.save(merged)
                val extra = buildString {
                    if (p.authKeyHex.isNotEmpty()) append("，密钥✓")
                    if (p.certDerB64.isNotEmpty()) append("，证书✓")
                    if (p.skipped > 0u) append("（跳过 ${p.skipped} 条：域名节点/坏行）")
                }
                EngineState.addLog("导入成功：${p.nodes.size} 个节点$extra")
                "导入成功：${p.nodes.size} 个节点$extra"
            } catch (e: Exception) {
                EngineState.addLog("导入失败：${e.message}")
                "导入失败：${e.message}"
            }
        }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HydraApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { SecureStore(context) }
    var cfg by remember { mutableStateOf(store.load()) }
    var tab by remember { mutableStateOf(Tab.Home) }
    var toast by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(toast) {
        toast?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            toast = null
        }
    }

    fun persist(c: HydraConfig) {
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
                    uniffi.hydra_android.TrustMode.PublicCa
                } else {
                    uniffi.hydra_android.TrustMode.Pinned(listOf(
                        java.util.Base64.getDecoder().decode(cur.certDerB64)))
                }
                val r = testNodeConnection(addr, cur.authKeyHex, t, cur.sni.ifEmpty { null })
                if (r.ok) true to "${r.latencyMs}ms" else false to r.detail
            } catch (e: Exception) {
                false to (e.message ?: "测试失败")
            }
        }
    }

    // M2 VPN 授权（系统 VpnService.consent 对话框；同意后直接启动 VPN 服务）
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

    /** 按运行模式启动（Home 启动按钮）：vpn 走 consent/服务，local 走引擎服务 */
    fun startCurrentMode(context: Context) {
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

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = {
                            Icon(
                                when (t) {
                                    Tab.Home -> Icons.Filled.Home
                                    Tab.Nodes -> Icons.Outlined.List
                                    Tab.Settings -> Icons.Filled.Settings
                                },
                                contentDescription = t.label,
                            )
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
                    cfg = cfg,
                    onGoNodes = { tab = Tab.Nodes },
                    onStart = {
                        persist(cfg)
                        startCurrentMode(context)
                    },
                    onStop = {
                        // 按运行模式停止（vpn = HydraVpnService；local = EngineService）。
                        // 必须用各自服务的 ACTION_STOP 常量——此前统一用
                        // EngineService.ACTION_STOP，HydraVpnService 收到未知 action
                        // 被误判为启动：点停止 → 伪启动 → "VPN 已在运行" 启动失败，
                        // 而旧引擎从未收到停止指令继续跑（线上真机实测 bug）
                        if (cfg.runMode == SecureStore.MODE_VPN) {
                            context.startService(
                                Intent(context, HydraVpnService::class.java)
                                    .setAction(HydraVpnService.ACTION_STOP),
                            )
                        } else {
                            context.startService(
                                Intent(context, EngineService::class.java)
                                    .setAction(EngineService.ACTION_STOP),
                            )
                        }
                    },
                )
                Tab.Nodes -> NodesScreen(
                    cfg = cfg,
                    onPersist = ::persist,
                    onImport = { text -> doImport(text) },
                    onScan = {
                        qrLauncher.launch(
                            ScanOptions()
                                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt("对准桌面端生成的 Hydra 分享二维码")
                                .setBeepEnabled(false),
                        )
                    },
                    onToast = { toast = it },
                    onTestNode = testNode,
                )
                Tab.Settings -> SettingsScreen(
                    cfg = cfg,
                    onPersist = { c ->
                        persist(c)
                        toast = "配置已加密保存"
                    },
                )
            }
        }
    }
}

// ── 连接页 ──────────────────────────────────────────────────────────────────

@Composable
private fun HomeScreen(
    cfg: HydraConfig,
    onGoNodes: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val ui by EngineState.ui.collectAsState()
    val logs by EngineState.logs.collectAsState()
    val context = LocalContext.current
    val nodeCount = cfg.nodesText.lines().count { it.isNotBlank() }
    var showAllLogs by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ── 状态主卡 ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(
                containerColor = when {
                    ui.transition?.startsWith("启动失败") == true ->
                        MaterialTheme.colorScheme.errorContainer
                    ui.running -> MaterialTheme.colorScheme.tertiaryContainer
                    else -> MaterialTheme.colorScheme.surfaceVariant
                },
            ),
        ) {
            Column(
                Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .background(
                            when {
                                ui.running -> MaterialTheme.colorScheme.tertiary
                                ui.transition != null -> MaterialTheme.colorScheme.primary
                                else -> MaterialTheme.colorScheme.outline
                            },
                            CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    if (ui.transition != null && !ui.running) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(36.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    } else {
                        Text(if (ui.running) "ON" else "OFF", fontSize = 20.sp,
                            color = MaterialTheme.colorScheme.onTertiary, fontFamily = FontFamily.Monospace)
                    }
                }
                Text(
                    when {
                    ui.running -> "运行中"
                    ui.transition?.startsWith("隧道中断") == true -> "重连中"
                    ui.transition?.startsWith("启动失败") == true -> "启动失败"
                        ui.transition != null -> "启动中…"
                        else -> "已停止"
                    },
                    style = MaterialTheme.typography.titleLarge,
                )
                ui.transition?.takeIf { it.startsWith("启动失败") || it.startsWith("✗") }?.let {
                    Text(it, color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall)
                }
                // kill switch 中断态：阻断/重试详情在首页可见（不仅通知栏）
                ui.transition?.takeIf { it.startsWith("隧道中断") }?.let {
                    Text(it, color = MaterialTheme.colorScheme.primary,
                        style = MaterialTheme.typography.bodySmall)
                }
                if (ui.running) {
                    Text(
                        "运行 ${formatDuration(ui.uptimeSecs)} · 活跃 ${ui.activeConns} · 累计 ${ui.totalConns}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                    )
                } else if (nodeCount > 0) {
                    Text("已配置 $nodeCount 个节点", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        // ── 启停按钮 ──
        val busy = ui.running || (ui.transition != null && !ui.transition!!.startsWith("启动失败"))
        // kill switch 重连等待期：必须保持「停止」可达（用户停止 = 结束重连恢复直连）
        val retrying = ui.transition?.startsWith("隧道中断") == true
        if (ui.running || retrying) {
            Button(
                onClick = onStop,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(14.dp),
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                ),
            ) {
                Text(
                    if (retrying) "■ 停止代理（重连中）" else "■ 停止代理",
                    fontSize = 16.sp,
                )
            }
        } else {
            Button(
                onClick = onStart,
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(14.dp),
            ) { Text("▶ 启动代理", fontSize = 16.sp) }
        }

        // ── 监听地址 / 模式说明 ──
        val bound = ui.boundAddr
        if (ui.running && cfg.runMode == SecureStore.MODE_VPN) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("全局 VPN 模式", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "已接管所有应用流量（含 DNS），无需任何手动配置；如个别应用异常可在设置页切回「本地端口」模式",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else if (ui.running && bound != null) {
            Card(Modifier.fillMaxWidth()) {
                Row(
                    Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("本地监听（浏览器代理填这个）",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(bound, fontFamily = FontFamily.Monospace)
                    }
                    TextButton(onClick = {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("hydra", bound))
                        Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                    }) { Text("复制") }
                }
            }
            // 流量两格
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatTile("↑ 发送", fmt(ui.sentBytes), Modifier.weight(1f))
                StatTile("↓ 接收", fmt(ui.receivedBytes), Modifier.weight(1f))
            }
        }

        // ── 节点摘要 ──
        Card(onClick = onGoNodes, modifier = Modifier.fillMaxWidth()) {
            Row(
                Modifier.padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("节点", style = MaterialTheme.typography.titleSmall)
                    Text(
                        if (nodeCount > 0) "$nodeCount 个节点已配置" else "尚未配置——去节点页导入分享链接",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("›", fontSize = 22.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // ── 事件日志（§9：最近 8 条 + "全部"对话框 + 一键复制）──
        if (logs.isNotEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("事件", style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f))
                        TextButton(onClick = { showAllLogs = true }) { Text("全部（${logs.size}）") }
                    }
                    logs.take(8).forEach { e ->
                        Text(
                            "${e.time}  ${e.message}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }

    if (showAllLogs) {
        AlertDialog(
            onDismissRequest = { showAllLogs = false },
            title = { Text("事件（${logs.size} 条）") },
            text = {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(420.dp),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    items(logs) { e ->
                        Text(
                            "${e.time}  ${e.message}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText(
                        "hydra-logs", logs.joinToString("\n") { "${it.time} ${it.message}" }))
                    Toast.makeText(context, "已复制全部事件", Toast.LENGTH_SHORT).show()
                }) { Text("复制全部") }
            },
            dismissButton = {
                TextButton(onClick = { showAllLogs = false }) { Text("关闭") }
            },
        )
    }
}

@Composable
private fun StatTile(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier) {
        Column(Modifier.padding(12.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.titleMedium)
        }
    }
}

// ── 节点页 ──────────────────────────────────────────────────────────────────

@Composable
private fun NodesScreen(
    cfg: HydraConfig,
    onPersist: (HydraConfig) -> Unit,
    onImport: suspend (String) -> String,
    onScan: () -> Unit,
    onToast: (String) -> Unit,
    onTestNode: suspend (String) -> Pair<Boolean, String>,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showImport by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var clipHint by remember { mutableStateOf<String?>(null) }
    // R3 剪贴板预填：打开导入时检测 hydra:// 链接自动填入（省一步粘贴）
    LaunchedEffect(showImport) {
        if (showImport && importText.isBlank()) {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = cm.primaryClip?.getItemAt(0)?.text?.toString().orEmpty()
            if (clip.contains("hydra://")) {
                importText = clip
                clipHint = "已从剪贴板填入分享链接"
            }
        }
    }
    var importBusy by remember { mutableStateOf(false) }
    var importError by remember { mutableStateOf<String?>(null) }
    var showManual by remember { mutableStateOf(false) }
    var manualAddr by remember { mutableStateOf("") }
    var manualPort by remember { mutableStateOf("443") }
    var deleteTarget by remember { mutableStateOf<String?>(null) }
    // R1 手动连通性测试：addr → "✓ 123ms" / "✗ 原因"
    val testResults = remember { androidx.compose.runtime.mutableStateMapOf<String, String>() }
    var testingAddr by remember { mutableStateOf<String?>(null) }

    val nodes = cfg.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }

    Scaffold(
        floatingActionButton = {
            Button(onClick = { showImport = true; importError = null }) {
                Icon(Icons.Filled.Add, null); Spacer(Modifier.size(4.dp)); Text("导入节点")
            }
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            Text(
                "节点", style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
            )
            if (nodes.isEmpty()) {
                Column(
                    Modifier.fillMaxWidth().padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        Icons.Outlined.List, null,
                        modifier = Modifier.size(48.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text("还没有节点", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "点击右下角「导入节点」：\n· 扫描桌面端分享二维码\n· 粘贴 hydra:// 分享链接\n· 手动输入 IP:端口",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(nodes) { node ->
                        Card(Modifier.fillMaxWidth()) {
                            Row(
                                Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Box(
                                    Modifier.size(8.dp).background(
                                        MaterialTheme.colorScheme.tertiary, CircleShape,
                                    )
                                )
                                Spacer(Modifier.size(10.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(node, fontFamily = FontFamily.Monospace)
                                    testResults[node]?.let { r ->
                                        Text(
                                            r, fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = if (r.startsWith("✓"))
                                                MaterialTheme.colorScheme.tertiary
                                            else MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                                TextButton(
                                    onClick = {
                                        if (testingAddr == null) {
                                            testingAddr = node
                                            scope.launch {
                                                val (ok, detail) = onTestNode(node)
                                                testResults[node] =
                                                    (if (ok) "✓ " else "✗ ") + detail
                                                testingAddr = null
                                            }
                                        }
                                    },
                                    enabled = testingAddr == null,
                                ) {
                                    Text(if (testingAddr == node) "测试中" else "测试")
                                }
                                IconButton(onClick = { deleteTarget = node }) {
                                    Icon(Icons.Filled.Delete, "删除",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── 导入对话框 ──
    if (showImport) {
        AlertDialog(
            onDismissRequest = { if (!importBusy) showImport = false },
            title = { Text("导入节点") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        "支持：桌面端分享二维码 / hydra:// 链接（可含密钥与证书）/ 订阅文本",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onScan) { Text("📷 扫码") }
                        Button(
                            onClick = {
                                if (importText.isBlank()) {
                                    importError = "请先粘贴分享链接"
                                } else {
                                    importBusy = true
                                    scope.launch {
                                        val msg = onImport(importText)
                                        importBusy = false
                                        if (msg.startsWith("导入成功")) {
                                            showImport = false
                                            onToast(msg)
                                        } else {
                                            importError = msg
                                        }
                                    }
                                }
                            },
                            enabled = !importBusy,
                        ) {
                            if (importBusy) {
                                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.size(6.dp))
                            }
                            Text("导入")
                        }
                    }
                    OutlinedTextField(
                        value = importText,
                        onValueChange = { importText = it },
                        label = { Text("粘贴分享链接 / 订阅内容") },
                        placeholder = { Text("hydra://1.2.3.4:443?k=…&cc=…") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                    )
                    clipHint?.let {
                        Text(it, color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    importError?.let {
                        Text(it, color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { showImport = false; showManual = true }) {
                        Text("或手动输入 IP:端口 ›")
                    }
                }
            },
            confirmButton = {},
            dismissButton = {},
        )
    }

    // ── 手动添加对话框 ──
    if (showManual) {
        AlertDialog(
            onDismissRequest = { showManual = false },
            title = { Text("手动添加节点") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = manualAddr,
                        onValueChange = { manualAddr = it.trim() },
                        label = { Text("IP 地址") },
                        placeholder = { Text("1.2.3.4（IPv6 用 [::1]）") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = manualPort,
                        onValueChange = { manualPort = it.filter(Char::isDigit).take(5) },
                        label = { Text("端口") },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    val a = manualAddr.removePrefix("[").removeSuffix("]")
                    if (a.isEmpty() || manualPort.toIntOrNull() == null) {
                        onToast("请填写 IP 与端口")
                        return@Button
                    }
                    val node = "${a}:${manualPort}"
                    val list = cfg.nodesText.lines().map { it.trim() }
                        .filter { it.isNotEmpty() }.toMutableList()
                    if (!list.contains(node)) list.add(node)
                    onPersist(cfg.copy(nodesText = list.joinToString("\n")))
                    showManual = false
                    manualAddr = ""; manualPort = "443"
                }) { Text("添加") }
            },
            dismissButton = {
                TextButton(onClick = { showManual = false }) { Text("取消") }
            },
        )
    }

    // ── 删除确认 ──
    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("删除节点") },
            text = { Text("确定删除 $target ？") },
            confirmButton = {
                TextButton(onClick = {
                    val list = nodes.filter { it != target }
                    onPersist(cfg.copy(nodesText = list.joinToString("\n")))
                    deleteTarget = null
                }) { Text("删除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("取消") }
            },
        )
    }
}

// ── 设置页 ──────────────────────────────────────────────────────────────────

@Composable
private fun SettingsScreen(cfg: HydraConfig, onPersist: (HydraConfig) -> Unit) {
    val context = LocalContext.current
    var authKey by remember(cfg.authKeyHex) { mutableStateOf(cfg.authKeyHex) }
    var sni by remember(cfg.sni) { mutableStateOf(cfg.sni) }
    var trustMode by remember(cfg.trustMode) { mutableStateOf(cfg.trustMode) }
    var certB64 by remember(cfg.certDerB64) { mutableStateOf(cfg.certDerB64) }
    var listenPort by remember {
        mutableStateOf(cfg.listenPort.takeIf { it != 0 }?.toString() ?: SecureStore.DEFAULT_PORT.toString())
    }
    var showKey by remember { mutableStateOf(false) }
    var showAppPicker by remember { mutableStateOf(false) }

    val certPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            context.contentResolver.openInputStream(uri)?.use { ins ->
                val der = ins.readBytes()
                certB64 = Base64.getEncoder().encodeToString(der)
                Toast.makeText(context, "证书已导入（${der.size} 字节）", Toast.LENGTH_SHORT).show()
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("设置", style = MaterialTheme.typography.headlineSmall)

        Section("凭据") {
            OutlinedTextField(
                value = authKey,
                onValueChange = { authKey = it.trim() },
                label = { Text("认证密钥（64 hex）") },
                supportingText = {
                    Text(
                        when {
                            authKey.isEmpty() -> "未设置——请从分享链接导入或手动填写"
                            authKey.length != 64 -> "长度 ${authKey.length}/64（须恰好 64 个 hex 字符）"
                            else -> "✓ 已设置"
                        }
                    )
                },
                isError = authKey.isNotEmpty() && authKey.length != 64,
                visualTransformation = if (showKey) VisualTransformation.None
                else PasswordVisualTransformation(),
                trailingIcon = {
                    TextButton(onClick = { showKey = !showKey }) {
                        Text(if (showKey) "隐藏" else "显示")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = trustMode == SecureStore.TRUST_PINNED,
                    onClick = { trustMode = SecureStore.TRUST_PINNED },
                    label = { Text("自签 pin") },
                )
                FilterChip(
                    selected = trustMode == SecureStore.TRUST_CA,
                    onClick = { trustMode = SecureStore.TRUST_CA },
                    label = { Text("真证书 CA") },
                )
            }
            if (trustMode == SecureStore.TRUST_PINNED) {
                OutlinedButton(onClick = { certPicker.launch(arrayOf("*/*")) }) {
                    Text(
                        if (certB64.isEmpty()) "导入节点证书 DER"
                        else {
                            val size = runCatching {
                                Base64.getDecoder().decode(certB64).size
                            }.getOrDefault(0)
                            "已导入证书 ✓（$size 字节，重新选）"
                        }
                    )
                }
                if (certB64.isEmpty()) {
                    Text(
                        "提示：分享链接携带证书（cc=）时导入链接即可，无需手动选文件",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        Section("运行模式") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = cfg.runMode == SecureStore.MODE_VPN,
                    onClick = {
                        onPersist(cfg.copy(runMode = SecureStore.MODE_VPN))
                    },
                    label = { Text("全局 VPN") },
                )
                FilterChip(
                    selected = cfg.runMode == SecureStore.MODE_LOCAL,
                    onClick = {
                        onPersist(cfg.copy(runMode = SecureStore.MODE_LOCAL))
                    },
                    label = { Text("本地端口") },
                )
            }
            Text(
                if (cfg.runMode == SecureStore.MODE_VPN)
                    "全局 VPN：无需任何配置，所有应用流量经节点（首次启动需授权）"
                else
                    "本地端口：仅浏览器等手动配置代理的应用经节点（连接页复制监听地址）",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // ── VPN 保护（M2.1：kill switch / 开机自启 / 分应用代理）──
        if (cfg.runMode == SecureStore.MODE_VPN) {
            Section("VPN 保护") {
                SettingSwitchRow(
                    title = "断线阻断（kill switch）",
                    desc = "隧道中断时保持接管路由阻断全部流量并自动重连，防真实 IP 泄漏（推荐开启）",
                    checked = cfg.vpnKillSwitch,
                    onChange = { onPersist(cfg.copy(vpnKillSwitch = it)) },
                )
                SettingSwitchRow(
                    title = "开机自动启动 VPN",
                    desc = "重启后自动连接（需已授权过 VPN）。Android 15+ 可能限制自启，可靠方案是下方系统 Always-on",
                    checked = cfg.vpnBootStart,
                    onChange = { onPersist(cfg.copy(vpnBootStart = it)) },
                )
                OutlinedButton(onClick = {
                    // 系统级 Always-on（免疫一切自启限制，OS 强制执行阻断）：
                    // 深链到系统 VPN 设置页，用户开启「始终开启 + 屏蔽无 VPN 网络」
                    runCatching {
                        context.startActivity(
                            Intent("android.net.vpn.SETTINGS")
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }.recoverCatching {
                        context.startActivity(
                            Intent("android.settings.VPN_SETTINGS")
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }.onFailure {
                        Toast.makeText(context, "请到系统设置 → VPN 手动开启", Toast.LENGTH_LONG).show()
                    }
                }) { Text("系统 Always-on 设置（推荐开启）") }

                Text("分应用代理", style = MaterialTheme.typography.titleSmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = cfg.appFilterMode == SecureStore.APP_FILTER_ALL,
                        onClick = { onPersist(cfg.copy(appFilterMode = SecureStore.APP_FILTER_ALL)) },
                        label = { Text("全部") },
                    )
                    FilterChip(
                        selected = cfg.appFilterMode == SecureStore.APP_FILTER_ALLOW,
                        onClick = { onPersist(cfg.copy(appFilterMode = SecureStore.APP_FILTER_ALLOW)) },
                        label = { Text("白名单") },
                    )
                    FilterChip(
                        selected = cfg.appFilterMode == SecureStore.APP_FILTER_DISALLOW,
                        onClick = { onPersist(cfg.copy(appFilterMode = SecureStore.APP_FILTER_DISALLOW)) },
                        label = { Text("黑名单") },
                    )
                }
                if (cfg.appFilterMode != SecureStore.APP_FILTER_ALL) {
                    val pkgCount = cfg.appFilterPkgs.split('\n', ',').count { it.isNotBlank() }
                    val allowEmpty = cfg.appFilterMode == SecureStore.APP_FILTER_ALLOW && pkgCount == 0
                    Text(
                        when {
                            allowEmpty -> "⚠ 白名单为空：不会有任何应用流量走 VPN——请先「选择应用」"
                            pkgCount > 0 -> "已选 $pkgCount 个应用"
                            else -> "尚未选择应用"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (allowEmpty) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(onClick = { showAppPicker = true }) { Text("选择应用") }
                }
            }
        }

        Section("高级") {
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it },
                label = { Text("SNI（留空 = hydra.node）") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = listenPort,
                onValueChange = { listenPort = it.filter(Char::isDigit).take(5) },
                label = { Text("本地监听端口（1080）") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        Button(
            onClick = {
                onPersist(
                    cfg.copy(
                        authKeyHex = authKey,
                        sni = sni,
                        trustMode = trustMode,
                        certDerB64 = certB64,
                        listenPort = listenPort.toIntOrNull() ?: SecureStore.DEFAULT_PORT,
                    ),
                )
            },
            enabled = authKey.isEmpty() || authKey.length == 64,
            modifier = Modifier.fillMaxWidth().height(48.dp),
        ) { Text("保存配置（加密存储）") }

        Text(
            "Hydra v0.2.2 · 配置经 Android Keystore 加密存储，不进云备份\n" +
                "浏览器代理指向「连接」页的监听地址即可使用",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    // 分应用代理选择器（白/黑名单模式共享）：选择期仅改内存，「完成」一次持久化
    if (showAppPicker) {
        val selectedPkgs = cfg.appFilterPkgs.split('\n', ',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()
        AppPickerDialog(
            mode = cfg.appFilterMode,
            initialPkgs = selectedPkgs,
            onDone = { pkgs ->
                onPersist(cfg.copy(appFilterPkgs = pkgs.sorted().joinToString("\n")))
                showAppPicker = false
            },
            onDismiss = { showAppPicker = false },
        )
    }
}

/** 开关行：标题 + 说明居左，Switch 居右（VPN 保护区专用） */
@Composable
private fun SettingSwitchRow(
    title: String,
    desc: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                desc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/** 分应用代理应用选择器：列出有启动入口的用户应用（排除自身）；
 *  选择期间仅改内存草稿，「完成」一次性持久化（避免逐项加密写盘）。 */
@Composable
private fun AppPickerDialog(
    mode: Int,
    initialPkgs: Set<String>,
    onDone: (Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<Pair<String, String>>?>(null) } // null = 加载中
    var draft by remember { mutableStateOf(initialPkgs) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            runCatching {
                pm.getInstalledPackages(0).mapNotNull { pi ->
                    val pkg = pi.packageName
                    // 排除自身与无启动入口的系统组件（分应用语义只对真实应用有意义）
                    if (pkg == context.packageName) return@mapNotNull null
                    if (pm.getLaunchIntentForPackage(pkg) == null) return@mapNotNull null
                    val label = runCatching {
                        pi.applicationInfo?.loadLabel(pm).toString()
                    }.getOrDefault(pkg)
                    pkg to label
                }.sortedBy { it.second }
            }.getOrDefault(emptyList())
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                if (mode == SecureStore.APP_FILTER_ALLOW) "选择走 VPN 的应用"
                else "选择不走 VPN 的应用",
            )
        },
        text = {
            when {
                apps == null -> Text("正在加载应用列表…", Modifier.padding(24.dp))
                apps!!.isEmpty() -> Text(
                    "未读到应用列表（系统包可见性受限）——已通过 Manifest queries 声明，" +
                        "若仍为空请反馈机型",
                    Modifier.padding(24.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
                else -> LazyColumn(Modifier.height(420.dp)) {
                    items(apps!!, key = { it.first }) { app ->
                        val (pkg, label) = app
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable {
                                    draft = if (pkg in draft) draft - pkg else draft + pkg
                                }
                                .padding(horizontal = 4.dp, vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = pkg in draft,
                                onCheckedChange = {
                                    draft = if (pkg in draft) draft - pkg else draft + pkg
                                },
                            )
                            Text(
                                label,
                                Modifier.weight(1f),
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 1,
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onDone(draft) }) { Text("完成") }
        },
    )
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            content()
        }
    }
}

private fun fmt(bytes: Long): String = when {
    bytes >= 1 shl 20 -> "%.1f MB".format(bytes.toDouble() / (1 shl 20))
    bytes >= 1 shl 10 -> "%.1f KB".format(bytes.toDouble() / (1 shl 10))
    else -> "$bytes B"
}

private fun formatDuration(secs: Long): String = when {
    secs >= 3600 -> "%d:%02d:%02d".format(secs / 3600, (secs % 3600) / 60, secs % 60)
    else -> "%d:%02d".format(secs / 60, secs % 60)
}
