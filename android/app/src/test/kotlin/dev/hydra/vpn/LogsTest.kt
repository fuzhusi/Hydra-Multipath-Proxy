package dev.hydra.vpn

import dev.hydra.vpn.ui.formatLogsForExport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 日志合并/去重/过滤/导出（纯 JVM 单测，不依赖 Android 框架）：
 * 覆盖 A 批「Kotlin 1s 轮询增量拉取 → EngineState 合并」与 D 批「级别过滤 +
 * 导出」的核心纯逻辑。
 */
class LogsTest {

    private fun kernel(
        seq: Long,
        message: String,
        level: LogLevel = LogLevel.INFO,
    ) = LogEntry("10:00:00", message, level, seq)

    private fun app(message: String, level: LogLevel = LogLevel.INFO) =
        LogEntry("10:00:00", message, level)

    @Test
    fun mergeDedupesBySeqAndKeepsNewestFirst() {
        val existing = listOf(kernel(5, "e5"), kernel(4, "e4"))
        // Rust 增量返回按 seq 升序；批内可能含已消费过的条目（游标重拉/竞态）
        val incoming = listOf(kernel(4, "e4"), kernel(5, "e5"), kernel(6, "e6"), kernel(7, "e7"))
        val merged = mergeLogs(existing, incoming)
        assertEquals(
            "新条目在前、seq 去重、已存在条目不得重复",
            listOf("e7", "e6", "e5", "e4"),
            merged.map { it.message },
        )
        // 同一批再合并一次：幂等（Kotlin 侧 lastSeq 游标失效时的兜底）
        assertEquals(merged, mergeLogs(merged, incoming))
    }

    @Test
    fun mergeKeepsAppLogsAndCapsOldest() {
        // 应用侧日志 seq=0 不参与去重（两条同文案也各自保留）
        val existing = listOf(app("正在建立全局 VPN…"), kernel(1, "规则引擎已加载"))
        val merged = mergeLogs(existing, listOf(app("正在建立全局 VPN…"), kernel(2, "TUN 已接管")))
        assertEquals(4, merged.size)
        // 容量上限：超出丢弃最旧
        val many = (1..10).map { kernel(it.toLong(), "e$it") }
        val capped = mergeLogs(emptyList(), many, cap = 5)
        assertEquals(5, capped.size)
        assertEquals(listOf("e10", "e9", "e8", "e7", "e6"), capped.map { it.message })
    }

    @Test
    fun filterByLevelThresholdAndKeyword() {
        val logs = listOf(
            kernel(3, "健康检查失败（节点 超时）", LogLevel.WARN),
            kernel(2, "DNS 查询完成"),
            kernel(1, "TUN 丢弃 UDP 包", LogLevel.ERROR),
        )
        // null = 全部
        assertEquals(3, filterLogs(logs, null, "").size)
        // 信息+ 含警告/错误
        assertEquals(3, filterLogs(logs, LogLevel.INFO, "").size)
        // 警告+：WARN/ERROR
        assertEquals(
            listOf("健康检查失败（节点 超时）", "TUN 丢弃 UDP 包"),
            filterLogs(logs, LogLevel.WARN, "").map { it.message },
        )
        // 仅错误
        assertEquals(listOf("TUN 丢弃 UDP 包"), filterLogs(logs, LogLevel.ERROR, "").map { it.message })
        // 关键字：忽略大小写、前后空白
        assertEquals(listOf("DNS 查询完成"), filterLogs(logs, null, "  dns  ").map { it.message })
        assertEquals(1, filterLogs(logs, LogLevel.WARN, "失败").size)
    }

    @Test
    fun levelStringMappingIsLossless() {
        assertEquals(LogLevel.ERROR, logLevelFrom("ERROR"))
        assertEquals(LogLevel.WARN, logLevelFrom("warn"))
        assertEquals(LogLevel.INFO, logLevelFrom("INFO"))
        // 未知级别不丢日志（按 INFO 呈现）
        assertEquals(LogLevel.INFO, logLevelFrom("DEBUG"))
    }

    @Test
    fun exportIsChronologicalWithLevelTags() {
        val logs = listOf(
            kernel(2, "新日志", LogLevel.WARN),
            kernel(1, "旧日志"),
        )
        val text = formatLogsForExport(logs)
        val body = text.lines().filter { it.isNotBlank() && !it.startsWith("#") }
        assertEquals(2, body.size)
        // 导出按时间正序（最旧在前），带级别标签
        assertTrue(body[0].contains("旧日志"))
        assertTrue(body[0].contains("[INFO]"))
        assertTrue(body[1].contains("新日志"))
        assertTrue(body[1].contains("[WARN]"))
        // 首部说明隐私边界（不上传）
        assertTrue(text.contains("不上传"))
        assertFalse(body[0].contains("[WARN]"))
    }
}
