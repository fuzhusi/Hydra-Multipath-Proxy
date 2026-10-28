package dev.hydra.vpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.hydra.vpn.HydraConfig
import dev.hydra.vpn.NodeCerts
import dev.hydra.vpn.SecureStore
import kotlinx.coroutines.launch

/*
 * 节点页（T4 拆分平移，逻辑不变）：卡片列表 + 分享链接/扫码/手动导入。
 * R11：列表 item 用节点地址本身做稳定 key（导入合并后只重组受影响项）。
 * ISSUE 安卓多节点证书：节点行显示自身证书指纹（SHA-256 前 16 位，与分享
 * 链接 cf= 同算法）——多节点各持独立证书时用于识别"导入错了证书/证书漂移"。
 */

@Composable
fun NodesScreen(
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
            val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                as android.content.ClipboardManager
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
    val testResults = remember { mutableStateMapOf<String, String>() }
    var testingAddr by remember { mutableStateOf<String?>(null) }

    val nodes = cfg.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }

    // 每节点证书指纹行（cfg 变化才重算；CA 模式不 pin 显示 null = 不渲染）。
    // pin 模式下节点无任何证书（独立与全局均无）→ 明确提示连接将失败
    val certLines = remember(cfg) {
        val pin = cfg.trustMode != SecureStore.TRUST_CA
        nodes.associateWith { node ->
            if (!pin) {
                null
            } else {
                NodeCerts.certB64For(cfg, node)?.let { b64 ->
                    runCatching {
                        "证书 ${NodeCerts.fingerprint(NodeCerts.decodeCert(b64)).take(16)}…"
                    }.getOrNull()
                } ?: "未导入证书——连接将失败"
            }
        }
    }

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
                        Icons.AutoMirrored.Outlined.List, null,
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
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    // 稳定 key：导入/删除只重组受影响项（评审 §五.2）。
                    // 评审 P3-1：历史数据可能含重复行，key=内容 遇重复直接
                    // IllegalArgumentException 崩溃——回退位置 key（唯一稳定，
                    // 代价是仅删除中间项时尾部全量重组，可接受）
                    items(nodes) { node ->
                        NodeCard(
                            node = node,
                            certLine = certLines[node],
                            testResult = testResults[node],
                            testing = testingAddr == node,
                            busy = testingAddr != null,
                            onTest = {
                                if (testingAddr == null) {
                                    testingAddr = node
                                    scope.launch {
                                        val (ok, detail) = onTestNode(node)
                                        testResults[node] = (if (ok) "✓ " else "✗ ") + detail
                                        testingAddr = null
                                    }
                                }
                            },
                            onDelete = { deleteTarget = node },
                        )
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
                    onPersist(
                        cfg.copy(
                            nodesText = list.joinToString("\n"),
                            // 同步清掉该节点的证书条目：残留会让此后手动添加的
                            // 同地址节点被旧证书抢先接管信任（回落全局失效）
                            nodeCertB64Map = cfg.nodeCertB64Map - target,
                        ),
                    )
                    deleteTarget = null
                }) { Text("删除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun NodeCard(
    node: String,
    certLine: String?,
    testResult: String?,
    testing: Boolean,
    busy: Boolean,
    onTest: () -> Unit,
    onDelete: () -> Unit,
) {
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
                certLine?.let { c ->
                    Text(
                        c, fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = if (c.startsWith("证书"))
                            MaterialTheme.colorScheme.onSurfaceVariant
                        else MaterialTheme.colorScheme.error,
                    )
                }
                testResult?.let { r ->
                    Text(
                        r, fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = if (r.startsWith("✓"))
                            MaterialTheme.colorScheme.tertiary
                        else MaterialTheme.colorScheme.error,
                    )
                }
            }
            TextButton(onClick = onTest, enabled = !busy) {
                Text(if (testing) "测试中" else "测试")
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, "删除",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
