package dev.hydra.vpn.ui

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.hydra.vpn.HEALTH_PROBE_OPTIONS
import dev.hydra.vpn.HydraConfig
import dev.hydra.vpn.SecureStore
import dev.hydra.vpn.normalizeProbeSecs
import dev.hydra.vpn.probeIntervalLabel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Base64

/*
 * 设置页（T4 拆分平移 + T3 主题四选）：
 * - 凭据 / 运行模式 / VPN 保护 / 高级（原逻辑不变）
 * - 新增「外观」：跟随系统/深色/浅色/深海 四选，写 SharedPreferences「hydra_ui」
 *   即时生效（R2：主题走普通存储，非 SecureStore）
 */

@Composable
fun SettingsScreen(
    cfg: HydraConfig,
    themeMode: ThemeMode,
    onSetTheme: (ThemeMode) -> Unit,
    onPersist: (HydraConfig) -> Unit,
) {
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
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    // ── 智能分流（§九）：规则文件（filesDir/rules.txt）状态与 SAF 导入 ──
    val ruleFile = remember { java.io.File(context.filesDir, "rules.txt") }
    // exist 在导入后刷新（@Volatile 计数器驱动 recompose 即可，stat 开销微小）
    var ruleFileStamp by remember { mutableStateOf(0) }
    val rulePicker = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch(Dispatchers.IO) {
                // 安全约束（§九）：content:// 只读复制进应用沙箱，不持久化
                // URI 权限；限 1MB（规则文件上限，防超大输入撑爆内存）。
                // 评审一轮 P2-1：流式限界读取——先读到 1MB+1 判超限（超限即
                // 失败、不落盘），≤1MB 才写入 rules.txt；禁止 readBytes() 全量读
                val result = runCatching {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        val max = 1 shl 20
                        val buf = ByteArray(64 * 1024)
                        var total = 0
                        val collected = java.io.ByteArrayOutputStream(max)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            total += n
                            check(total <= max) { "规则文件超过 1MB" }
                            collected.write(buf, 0, n)
                        }
                        val bytes = collected.toByteArray()
                        check(bytes.isNotEmpty()) { "文件为空" }
                        ruleFile.writeBytes(bytes)
                        bytes.size
                    } ?: error("无法读取所选文件")
                }
                withContext(Dispatchers.Main) {
                    ruleFileStamp++
                    result.fold(
                        onSuccess = { size ->
                            Toast.makeText(context, "规则已导入（$size 字节，重启 VPN 生效）", Toast.LENGTH_SHORT).show()
                        },
                        onFailure = { e ->
                            // 超限给明确文案（P2-1：限界读取失败不落盘）
                            val msg = if (e.message?.contains("1MB") == true) "规则文件超过 1MB"
                            else "规则导入失败：${e.message}"
                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                        },
                    )
                }
            }
        }
    }

    val certPicker = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri != null) {
            // 评审 P1-2：SAF 读取（云盘提供方可阻塞数秒）移入 IO 线程防主线程
            // ANR；结果回主线程写状态
            scope.launch(Dispatchers.IO) {
                val der = runCatching {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                }.getOrNull()
                withContext(Dispatchers.Main) {
                    if (der != null) {
                        certB64 = Base64.getEncoder().encodeToString(der)
                        Toast.makeText(context, "证书已导入（${der.size} 字节）", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "证书读取失败", Toast.LENGTH_SHORT).show()
                    }
                }
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

        // ── 外观（T3）：四选单选行，选择即写 SharedPreferences 并即时生效 ──
        Section("外观") {
            ThemeMode.entries.forEach { mode ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        // 行高 ≥48dp 触摸目标（§3.3 组件规范）
                        .heightIn(min = 48.dp)
                        .clickable { onSetTheme(mode) }
                        .padding(horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = themeMode == mode, onClick = { onSetTheme(mode) })
                    Text(mode.label, style = MaterialTheme.typography.bodyLarge)
                }
            }
            Text(
                "「跟随系统」在 Android 12+ 使用 Material You 动态取色；深海为品牌深海主题",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

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
                    desc = "重启后自动连接（需已授权过 VPN）。更可靠的是下方系统 Always-on（OS 级强制，含屏蔽无 VPN 网络）",
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
                            allowEmpty -> "⚠ 白名单为空：当前等同全部应用走 VPN——请「选择应用」以收敛范围"
                            pkgCount > 0 -> "已选 $pkgCount 个应用（已卸载的应用自动剔除）"
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

        // ── 健康检查（B 批）：间隔可配（1m/3m/5m/10m/关，默认 300s）──
        if (cfg.runMode == SecureStore.MODE_VPN) {
            Section("健康检查") {
                Text(
                    "检查间隔（连接建立与网络切换瞬间各额外即时检查一次）",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    HEALTH_PROBE_OPTIONS.forEach { secs ->
                        FilterChip(
                            selected = normalizeProbeSecs(cfg.healthProbeSecs) == secs,
                            onClick = { onPersist(cfg.copy(healthProbeSecs = secs)) },
                            label = { Text(probeIntervalLabel(secs)) },
                        )
                    }
                }
                Text(
                    "三项独立计时：节点 TCP 直连 · 隧道内 DNS 查询 · HTTP 204。" +
                        "连续 2 次失败 → 日志 warn + 通知栏「网络异常」；连续 5 次 → 建议手动" +
                        "切换节点/网络。只告警，不自动切节点。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // ── 分流规则（§九）：规则文件导入（SAF，text/*，≤1MB → 沙箱 rules.txt）──
        if (cfg.runMode == SecureStore.MODE_VPN) {
            Section("分流规则") {
                Text(
                    "配合连接页「分流：CN 直连」开关使用：自定义规则叠加在内置 " +
                        "CN 域名/GeoIP 表之上（GEOIP,CN,DIRECT / DOMAIN-SUFFIX,… 语法），" +
                        "文件不可用时自动退化为全局代理",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                run {
                    val exists = remember(ruleFileStamp) { ruleFile.exists() }
                    Text(
                        if (exists) {
                            val size = runCatching { ruleFile.length() }.getOrDefault(0L)
                            "规则文件：${ruleFile.absolutePath}\n已导入 ✓（$size 字节，导入即覆盖）"
                        } else {
                            "规则文件：${ruleFile.absolutePath}\n尚未导入——仅使用内置 CN 直连表"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                OutlinedButton(onClick = { rulePicker.launch(arrayOf("text/*")) }) {
                    Text("导入规则文件（≤1MB）")
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
