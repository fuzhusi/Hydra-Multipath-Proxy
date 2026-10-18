package dev.hydra.vpn.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.hydra.vpn.ConnPhase
import dev.hydra.vpn.EngineState
import dev.hydra.vpn.SecureStore
import dev.hydra.vpn.toPhase
import kotlinx.coroutines.launch

/*
 * 连接主页（设计 §3.2 大按钮形态）：
 * - 112dp 大圆钮 + 状态外环四态（灰/accent 旋转/success/danger）
 * - 状态大字 28sp + 节点摘要行 + 统计带 + 最近日志 2 行
 * - R4：vpnPrepareLauncher 参数位预留（VPN 权限流 M2 挂点）
 * - R5：导入成功 Snackbar 反馈（经 ImportFeedback 总线）
 * - R6：宽 ≥600dp 两栏 Row；内容列宽上限 480dp；verticalScroll 滚动降级
 * - R7：大按钮/状态胶囊 contentDescription 随状态 + liveRegion
 * - R8：旋转动画 rememberInfiniteTransition 条件挂载；系统动画缩放 0 时静止
 * - R10：统计带独立 composable，内部自行收集 EngineState.ui，每秒跳字不
 *   触发本页其余部分重组；连接状态走 EngineState.connPhase（去重派生）
 */

// R6 宽屏断点：非 const（Dp 非原语类型）
private val WIDE_BREAKPOINT = 600.dp

@Composable
fun HomeScreen(
    /** 运行模式（SecureStore.MODE_VPN / MODE_LOCAL）：决定大按钮双模文案 */
    runMode: String,
    /** 节点摘要行（如「3 个节点已配置」），由装配层从配置生成 */
    nodeSummary: String,
    /**
     * R4 预留：VpnService.prepare 返回的授权 Intent 的启动器。
     * VPN 模式点击大按钮时若为 null → Unsupported 占位提示（M2 接线）。
     */
    vpnPrepareLauncher: ((Intent) -> Unit)?,
    onGoNodes: () -> Unit,
    /** 本地模式：启停 EngineService；VPN 模式：装配层 prepare/consent 分流 */
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    /** 智能分流开关当前值（SecureStore.runRuleMode，§九） */
    ruleMode: Boolean = false,
    /** 切换智能分流（持久化由装配层完成；运行中切换 → 提示重启 VPN 生效） */
    onToggleRuleMode: (Boolean) -> Unit = {},
) {
    val context = LocalContext.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val isVpn = runMode == SecureStore.MODE_VPN

    // 连接四态：只在状态迁移时重组（R10）
    val phase by EngineState.connPhase.collectAsState(ConnPhase.DISCONNECTED)
    val logs by EngineState.logs.collectAsState()
    var showAllLogs by remember { mutableStateOf(false) }

    // R5：深链/粘贴导入成功 → Snackbar 反馈（展示一次即消费）
    val snackbar = remember { SnackbarHostState() }
    val imported by dev.hydra.vpn.ui.ImportFeedback.importedNodes.collectAsState()
    LaunchedEffect(imported) {
        imported?.let {
            snackbar.showSnackbar("已导入 $it 个节点")
            ImportFeedback.importedNodes.value = null
        }
    }

    val vpnUnsupportedHint = "VPN 模式连接将在 M2 接入（VpnService 授权流占位）"
    fun onBigButtonClick() {
        when {
            phase == ConnPhase.CONNECTED || phase == ConnPhase.CONNECTING -> onDisconnect()
            isVpn && vpnPrepareLauncher == null -> {
                // R4 占位：launcher 未接线时明确回 Unsupported，而非静默失败
                scope.launch { snackbar.showSnackbar(vpnUnsupportedHint) }
                EngineState.addLog(vpnUnsupportedHint)
            }
            else -> onConnect()
        }
    }

    // R6：宽屏（≥600dp）两栏；窄屏单列。内容包 verticalScroll（小屏降级）
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val wide = maxWidth >= WIDE_BREAKPOINT
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // 顶栏：品牌名 + 状态胶囊（与 EngineState 同源，R7 语义标签）
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Hydra",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(phase)
            }

            if (wide) {
                // R6：大按钮居左、统计带 + 日志居右
                Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                    Column(
                        Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        BigButtonSection(phase, isVpn, ::onBigButtonClick, nodeSummary)
                    }
                    Column(
                        Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        RuleModeCard(isVpn, ruleMode, onToggleRuleMode)
                        StatBand()
                        ErrorBanner(phase)
                        RecentLogs(logs.take(2)) { showAllLogs = true }
                        NodeSummaryCard(nodeSummary, onGoNodes)
                    }
                }
            } else {
                Column(
                    Modifier
                        .widthIn(max = 480.dp)
                        .fillMaxWidth()
                        .align(Alignment.CenterHorizontally),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    BigButtonSection(phase, isVpn, ::onBigButtonClick, nodeSummary)
                    RuleModeCard(isVpn, ruleMode, onToggleRuleMode)
                    ErrorBanner(phase)
                }
                StatBand()
                RecentLogs(logs.take(2)) { showAllLogs = true }
                NodeSummaryCard(nodeSummary, onGoNodes)
            }
        }

        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter))
    }

    if (showAllLogs) {
        LogsScreen(logs) { showAllLogs = false }
    }
}

// ── 状态胶囊 ────────────────────────────────────────────────────────────────

@Composable
private fun StatusPill(phase: ConnPhase) {
    val hc = hydraColors
    val color = phaseRingColor(phase)
    val label = phaseLabel(phase)
    Card(
        shape = RoundedCornerShape(50),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 10.dp, vertical = 5.dp)
                .semantics {
                    // R7：胶囊可被 TalkBack 完整读出，状态变化即播报
                    contentDescription = "连接状态：$label"
                    liveRegion = LiveRegionMode.Polite
                },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(8.dp).background(color, CircleShape))
            Spacer(Modifier.size(6.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = color)
        }
    }
}

// ── 大按钮区（按钮 + 状态大字 + 节点摘要行） ────────────────────────────────

@Composable
private fun BigButtonSection(
    phase: ConnPhase,
    isVpn: Boolean,
    onClick: () -> Unit,
    nodeSummary: String,
) {
    Spacer(Modifier.size(8.dp))
    BigConnectButton(phase, isVpn, onClick)
    // 状态大字 28sp（字阶 §3.3）
    Text(
        phaseLabel(phase),
        fontSize = 28.sp,
        color = if (phase == ConnPhase.DISCONNECTED) MaterialTheme.colorScheme.onSurfaceVariant
        else phaseRingColor(phase),
    )
    Text(
        nodeSummary,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.size(8.dp))
}

/**
 * 112dp 大圆钮：内圆 = 动作文案（深字，R1）；外环 = 状态色（R8 动画护栏）。
 * R7：role=Button + 动态 contentDescription + stateDescription + liveRegion。
 */
@Composable
private fun BigConnectButton(phase: ConnPhase, isVpn: Boolean, onClick: () -> Unit) {
    val hc = hydraColors
    val connecting = phase == ConnPhase.CONNECTING
    // R8 条件挂载 + 系统动画缩放为 0 时静止：不空转浪费电
    val animationsEnabled = rememberAnimationsEnabled()
    val transition = rememberInfiniteTransition(label = "statusRing")
    val angleState = if (connecting && animationsEnabled) {
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(1000, easing = LinearEasing)),
            label = "ringAngle",
        )
    } else null

    val innerColor = when (phase) {
        ConnPhase.CONNECTED -> hc.ringConnected
        ConnPhase.ERROR -> hc.ringError
        else -> hc.accent
    }
    val connectingNow = phase == ConnPhase.CONNECTING
    val actionText = when {
        connectingNow -> if (isVpn) "连接中…" else "启动中…"
        phase == ConnPhase.CONNECTED -> if (isVpn) "断开 VPN" else "停止代理"
        phase == ConnPhase.ERROR -> if (isVpn) "重连 VPN" else "重试启动"
        else -> if (isVpn) "连接 VPN" else "启动代理"
    }
    val stateLabel = phaseLabel(phase)
    // 状态环色在组合期取定（drawBehind 非组合上下文，不能调 @Composable）
    val ringColor = phaseRingColor(phase)

    Box(
        modifier = Modifier
            .size(112.dp)
            // R7：TalkBack——外环动画信息读不到，语义整体挂在 Box 上
            .semantics {
                role = Role.Button
                contentDescription = "$actionText（当前状态：$stateLabel）"
                stateDescription = stateLabel
                liveRegion = LiveRegionMode.Polite
            }
            .clickable(onClickLabel = actionText) { onClick() },
        contentAlignment = Alignment.Center,
    ) {
        // 状态外环：drawBehind 只画环不转内文（评审 §三.2）
        Box(
            modifier = Modifier
                .fillMaxSize()
                .drawBehind {
                    val stroke = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                    val inset = stroke.width / 2 + 1.dp.toPx()
                    val arcSize = androidx.compose.ui.geometry.Size(size.width - inset * 2, size.height - inset * 2)
                    val topLeft = androidx.compose.ui.geometry.Offset(inset, inset)
                    val spinning = angleState != null
                    when {
                        // 连接中：accent 弧段旋转（动画关闭 → 完整静止环）
                        spinning -> {
                            drawArc(ringColor.copy(alpha = 0.25f), 0f, 360f, false, topLeft, arcSize, style = stroke)
                            // 绘制阶段读值：每帧只重绘外环，不重组组件树
                            drawArc(ringColor, angleState!!.value, 90f, false, topLeft, arcSize, style = stroke)
                        }
                        else -> {
                            // 断开环弱化、连接/错误环完整
                            val alpha = if (phase == ConnPhase.DISCONNECTED) 0.7f else 1f
                            drawArc(ringColor.copy(alpha = alpha), 0f, 360f, false, topLeft, arcSize, style = stroke)
                        }
                    }
                },
        )
        // 内圆：accent 底（R12：深色下加 1dp accent 描边防与卡底融合）
        Box(
            modifier = Modifier
                .size(84.dp)
                .background(innerColor, CircleShape)
                .then(
                    if (phase == ConnPhase.DISCONNECTED || connectingNow) {
                        Modifier.border(1.dp, hc.accent, CircleShape)
                    } else Modifier
                ),
            contentAlignment = Alignment.Center,
        ) {
            if (connectingNow) {
                CircularProgressIndicator(
                    modifier = Modifier.size(32.dp),
                    color = hc.onAccent,
                    strokeWidth = 3.dp,
                )
            } else {
                Text(
                    when (phase) {
                        ConnPhase.CONNECTED -> "ON"
                        ConnPhase.ERROR -> "✗"
                        else -> if (isVpn) "VPN" else "GO"
                    },
                    fontSize = 22.sp,
                    fontFamily = FontFamily.Monospace,
                    // R1：accent/success/danger 内圆上一律品牌深字（白字不达标）
                    color = hc.onAccent,
                )
            }
        }
    }
}

// ── 智能分流卡片（§九，美观重点）：VPN 卡片下「分流：CN 直连」开关 ─────────
// 主题令牌约束：颜色只取 MaterialTheme.colorScheme / hydraColors（四主题模式
// 全兼容），文字层级走既有 typography，间距对齐 12dp rhythm。

@Composable
private fun RuleModeCard(isVpn: Boolean, ruleMode: Boolean, onToggle: (Boolean) -> Unit) {
    if (!isVpn) return // 仅 VPN 模式可见（本地端口无分流语义）
    // 独立收集连接态（R10 护栏：distinctUntilChanged，迁移时才重组本卡片）
    val phase by EngineState.connPhase.collectAsState(ConnPhase.DISCONNECTED)
    val runningOrConnecting = phase == ConnPhase.CONNECTED || phase == ConnPhase.CONNECTING
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // 状态点：主题令牌（开 = success / 关 = ringDisconnected），
                    // 禁硬编码色值——四主题（深/浅/Abyss/动态取色）自动适配
                    Box(
                        Modifier
                            .size(8.dp)
                            .background(
                                if (ruleMode) hydraColors.success else hydraColors.ringDisconnected,
                                CircleShape,
                            ),
                    )
                    Spacer(Modifier.size(8.dp))
                    Text("分流：CN 直连", style = MaterialTheme.typography.titleSmall)
                }
                Text(
                    "命中 CN 规则直连 · 其余走节点" +
                        if (runningOrConnecting) "（切换后重启 VPN 生效）" else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = ruleMode,
                onCheckedChange = onToggle,
                modifier = Modifier.semantics {
                    // TalkBack：开关状态 + 副标题语义可完整读出（既有无障碍基线）
                    contentDescription = "智能分流开关：命中 CN 规则直连，其余走节点" +
                        if (ruleMode) "，已开启" else "，已关闭"
                },
            )
        }
    }
}

// ── 统计带（R10：独立 composable + 独立收集，每秒跳字只重组本组件） ──────────

@Composable
private fun StatBand() {
    val ui by EngineState.ui.collectAsState()
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        StatCell(
            "发送", fmtBytes(ui.sentBytes), Modifier.weight(1f),
            speed = "↑${fmtSpeed(ui.upSpeedBps)}",
        )
        StatCell(
            "接收", fmtBytes(ui.receivedBytes), Modifier.weight(1f),
            speed = "↓${fmtSpeed(ui.downSpeedBps)}",
        )
        StatCell("运行时长", formatDuration(ui.uptimeSecs), Modifier.weight(1f), speed = "本会话")
        StatCell(
            "活跃连接", ui.activeConns.toString(), Modifier.weight(1f),
            speed = "累计 ${ui.totalConns}",
        )
    }
}

/**
 * 单格：参数全为基本类型/String，流量跳字被 strong-skip 收敛在本格内。
 * [speed] 为第二行小字（全局 VPN 速率 / 累计连接数等），四格都渲染以保持
 * 卡片等高（空串也占一行）。
 */
@Composable
private fun StatCell(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    speed: String = "",
) {
    Card(modifier) {
        Column(Modifier.padding(10.dp)) {
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                // R7/G4：统计带每格有标签（label 即读法）
            )
            Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
            Text(
                speed,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ── 错误横幅 / 节点摘要 / 日志 ──────────────────────────────────────────────

@Composable
private fun ErrorBanner(phase: ConnPhase) {
    if (phase != ConnPhase.ERROR) return
    // 仅错误态收集：transition 此刻静止，不引入每秒重组
    val ui by EngineState.ui.collectAsState()
    val msg = ui.transition ?: "启动失败"
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Text(
            msg,
            Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NodeSummaryCard(nodeSummary: String, onGoNodes: () -> Unit) {
    Card(
        onClick = onGoNodes,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("节点", style = MaterialTheme.typography.titleSmall)
                Text(
                    nodeSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text("›", fontSize = 22.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun RecentLogs(recent: List<dev.hydra.vpn.LogEntry>, onShowAll: () -> Unit) {
    if (recent.isEmpty()) return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("最近日志", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                TextButton(onClick = onShowAll) { Text("全部") }
            }
            recent.forEach { e ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    LevelDot(e.level)
                    Spacer(Modifier.size(4.dp))
                    Text(
                        "${e.time}  ${e.message}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

/** R8：系统「移除动画/动画缩放 0」→ 无限循环动画静止。 */
@Composable
private fun rememberAnimationsEnabled(): Boolean {
    val ctx = LocalContext.current
    return remember {
        runCatching {
            Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
        }.getOrDefault(1f) > 0f
    }
}

@Composable
private fun phaseRingColor(phase: ConnPhase): Color {
    val hc = hydraColors
    return when (phase) {
        ConnPhase.DISCONNECTED -> hc.ringDisconnected
        ConnPhase.CONNECTING -> hc.ringConnecting
        ConnPhase.CONNECTED -> hc.ringConnected
        ConnPhase.ERROR -> hc.ringError
    }
}

@Composable
private fun phaseLabel(phase: ConnPhase): String = when (phase) {
    ConnPhase.DISCONNECTED -> "已断开"
    ConnPhase.CONNECTING -> "连接中…"
    ConnPhase.CONNECTED -> "已连接"
    ConnPhase.ERROR -> "连接失败"
}

internal fun fmtBytes(bytes: Long): String = when {
    bytes >= 1L shl 30 -> "%.1f GB".format(bytes.toDouble() / (1L shl 30))
    bytes >= 1L shl 20 -> "%.1f MB".format(bytes.toDouble() / (1L shl 20))
    bytes >= 1L shl 10 -> "%.1f KB".format(bytes.toDouble() / (1L shl 10))
    else -> "$bytes B"
}

/** 速率（B/s）：复用 [fmtBytes] 换算，只补 /s 后缀（总量与速率不混用）。 */
internal fun fmtSpeed(bps: Long): String = "${fmtBytes(bps)}/s"

internal fun formatDuration(secs: Long): String = when {
    secs >= 3600 -> "%d:%02d:%02d".format(secs / 3600, (secs % 3600) / 60, secs % 60)
    else -> "%d:%02d".format(secs / 60, secs % 60)
}
