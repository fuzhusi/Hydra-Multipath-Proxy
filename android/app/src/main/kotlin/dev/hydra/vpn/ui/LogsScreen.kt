package dev.hydra.vpn.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.hydra.vpn.EngineState
import dev.hydra.vpn.LogEntry
import dev.hydra.vpn.LogLevel
import dev.hydra.vpn.filterLogs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/*
 * 日志页（D 批）：
 * - 级别徽章着色（INFO/WARN/ERROR）+ 级别阈值过滤 + 关键字搜索；
 * - 自动滚动到最新（新日志在顶）开关，排障时可看历史；
 * - 导出：写 files/exports/ 后复制到剪贴板 / 分享纯文本；清空即时生效；
 * - 纯内存日志：仅本机、不上传；进程被杀/服务停止即清空（方案 §五）。
 * - 颜色全部取 HydraTheme 令牌（四主题兼容），关键控件带 TalkBack 语义。
 */

@Composable
fun LogsScreen(logs: List<LogEntry>, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var minLevel by remember { mutableStateOf<LogLevel?>(null) }
    var query by remember { mutableStateOf("") }
    var autoScroll by remember { mutableStateOf(true) }
    val filtered = remember(logs, minLevel, query) { filterLogs(logs, minLevel, query) }
    // 展示顺序：时间正序（新日志在底）——排障时从最新往回看
    val visible = remember(filtered) { filtered.asReversed() }

    // 自动滚动：新日志在底（index = lastIndex），日志数变化或重新开启时滚到最新
    LaunchedEffect(visible.size, autoScroll) {
        if (autoScroll && visible.isNotEmpty()) listState.animateScrollToItem(visible.lastIndex)
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "日志（${logs.size} 条）",
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = onDismiss) { Text("关闭") }
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("搜索关键字（如 健康检查 / DNS / 丢弃）") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { contentDescription = "日志关键字搜索" },
                )
                // 级别过滤：全部 / 信息+（含警告错误）/ 警告+ / 仅错误
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = minLevel == null,
                        onClick = { minLevel = null },
                        label = { Text("全部") },
                    )
                    FilterChip(
                        selected = minLevel == LogLevel.INFO,
                        onClick = { minLevel = LogLevel.INFO },
                        label = { Text("信息+") },
                    )
                    FilterChip(
                        selected = minLevel == LogLevel.WARN,
                        onClick = { minLevel = LogLevel.WARN },
                        label = { Text("警告+") },
                    )
                    FilterChip(
                        selected = minLevel == LogLevel.ERROR,
                        onClick = { minLevel = LogLevel.ERROR },
                        label = { Text("错误") },
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = {
                        EngineState.clearLogs()
                    }) { Text("清空") }
                    TextButton(onClick = {
                        scope.launch {
                            val file = withContext(Dispatchers.IO) {
                                writeLogsToFile(context, logs)
                            }
                            copyLogsToClipboard(context, logs)
                            Toast.makeText(
                                context,
                                if (file != null) "已导出到 ${file.absolutePath}（并复制到剪贴板）"
                                else "导出失败：无法写入应用目录",
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                    }) { Text("导出") }
                    TextButton(onClick = { shareLogs(context, logs) }) { Text("分享") }
                    Spacer(Modifier.weight(1f))
                    Text(
                        "自动滚动",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Switch(
                        checked = autoScroll,
                        onCheckedChange = { autoScroll = it },
                        modifier = Modifier.semantics {
                            contentDescription = "日志自动滚动到最新：" +
                                if (autoScroll) "已开启" else "已关闭"
                        },
                    )
                }
                if (visible.isEmpty()) {
                    Box(
                        Modifier.fillMaxWidth().weight(1f),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            if (logs.isEmpty()) "暂无日志——连接 VPN 后内核事件会实时出现在这里"
                            else "没有匹配的日志（调整级别/关键字）",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        items(visible) { entry -> LogRow(entry) }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogRow(entry: LogEntry) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        LevelBadge(entry.level)
        Spacer(Modifier.width(8.dp))
        Text(
            "${entry.time}  ${entry.message}",
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

/** 级别徽章（着色 + 中文级别语义，TalkBack 可读）。 */
@Composable
private fun LevelBadge(level: LogLevel) {
    val color = logLevelColor(level)
    val text = when (level) {
        LogLevel.INFO -> "INFO"
        LogLevel.WARN -> "WARN"
        LogLevel.ERROR -> "ERROR"
    }
    val spoken = when (level) {
        LogLevel.INFO -> "信息"
        LogLevel.WARN -> "警告"
        LogLevel.ERROR -> "错误"
    }
    Text(
        text,
        color = color,
        fontSize = 9.sp,
        fontFamily = FontFamily.Monospace,
        modifier = Modifier
            .background(color.copy(alpha = 0.16f), RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
            .semantics { contentDescription = "级别：$spoken" },
    )
}

/** 级别 → 主题令牌色（INFO 用次要文字色，WARN/ERROR 用品牌语义色）。 */
@Composable
internal fun logLevelColor(level: LogLevel): Color = when (level) {
    LogLevel.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
    LogLevel.WARN -> hydraColors.warning
    LogLevel.ERROR -> hydraColors.danger
}

/** 级别小圆点（首页「最近日志」两行摘要用，避免占用横向空间）。 */
@Composable
internal fun LevelDot(level: LogLevel) {
    Box(Modifier.size(6.dp).background(logLevelColor(level), CircleShape))
}

/**
 * 导出文本（纯函数，单测覆盖）：按时间正序（最旧在前）逐行
 * `HH:mm:ss [LEVEL] message`，首部为隐私说明。
 */
internal fun formatLogsForExport(logs: List<LogEntry>): String = buildString {
    appendLine("# Hydra 安卓日志导出")
    appendLine("# 导出时间：${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
    appendLine("# 条数：${logs.size}；日志为连接期纯内存采集，本文件由用户手动导出（不上传）")
    logs.asReversed().forEach { entry ->
        appendLine("${entry.time} [${entry.level.name}] ${entry.message}")
    }
}

/** 写导出文件（files/exports/hydra-logs-<时间>.txt）；失败返回 null。 */
internal fun writeLogsToFile(context: Context, logs: List<LogEntry>): File? = runCatching {
    val dir = File(context.filesDir, "exports").apply { mkdirs() }
    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    val file = File(dir, "hydra-logs-$stamp.txt")
    file.writeText(formatLogsForExport(logs))
    file
}.getOrNull()

/** 复制完整日志到剪贴板（导出兜底通道；不依赖 FileProvider）。 */
internal fun copyLogsToClipboard(context: Context, logs: List<LogEntry>) {
    runCatching {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("hydra-logs", formatLogsForExport(logs)))
    }
}

/** 系统分享纯文本日志（无需 FileProvider；用户可选任意目标应用）。 */
internal fun shareLogs(context: Context, logs: List<LogEntry>) {
    runCatching {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "Hydra 安卓日志")
            putExtra(Intent.EXTRA_TEXT, formatLogsForExport(logs))
        }
        context.startActivity(
            Intent.createChooser(send, "分享日志").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }
}
