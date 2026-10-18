package dev.hydra.vpn

/*
 * 周期健康探测（方案 §二.B 定稿）：
 * - 三项**独立计时**：① 节点 TCP 直连（物理路径，protect 后绕过 TUN）
 *   ② 隧道内 DNS 查询（未 protect 的 DatagramSocket → TUN → 中继 → 返回；
 *   真实测隧道全链路）③ 可选 HTTP 204（隧道内 best-effort，1.5s 超时）；
 * - 本条文件只放**纯逻辑**（结果类型 / 日志格式化 / 告警分级 / DNS 报文编解码 /
 *   配置归一化）——Android 侧真实探测在 HydraVpnService（需要 VpnService.protect），
 *   纯逻辑全部可在桌面 JVM 单测（不依赖 Android 框架）。
 * - 失败处理：连续 2 次 → warn + 通知栏「网络异常」；连续 5 次 → 建议手动
 *   切换节点/网络；**不自动切节点**（留给调度层）。
 */

/** 探测间隔可选值（秒；0 = 关闭）。默认 300s（对齐 Clash url-test 默认）。 */
val HEALTH_PROBE_OPTIONS: List<Int> = listOf(60, 180, 300, 600, 0)

/** 默认探测间隔：300s（方案已定稿） */
const val HEALTH_PROBE_DEFAULT_SECS = 300

/** 连续失败升级阈值：2 次 → warn + 通知；5 次 → 建议手动切换节点/网络 */
const val HEALTH_WARN_STREAK = 2
const val HEALTH_ADVICE_STREAK = 5

/** 三项超时（毫秒）：节点 TCP 2s / 隧道 DNS 2s / HTTP 1.5s（方案 §二.B） */
const val HEALTH_NODE_TIMEOUT_MS = 2_000
const val HEALTH_DNS_TIMEOUT_MS = 2_000
const val HEALTH_HTTP_TIMEOUT_MS = 1_500

/** 隧道 DNS 探测目标（国内公共 DNS；查询名用稳定国内域名，仅测链路不解析结果） */
const val HEALTH_DNS_SERVER = "223.5.5.5"
const val HEALTH_DNS_PROBE_NAME = "www.baidu.com"

/** HTTP 204 探测端点（国内可达；不用 gstatic——墙内必失败造成误报） */
const val HEALTH_HTTP_204_URL = "http://connect.rom.miui.com/generate_204"

/** 单项探测状态（OK / 超时 / 失败——日志文案与告警分级共用） */
enum class ProbeStatus {
    OK,
    TIMEOUT,
    FAILED,
}

/** 单项探测结果：成功携带耗时（毫秒），失败为 0。 */
data class ProbeItem(val status: ProbeStatus, val ms: Long = 0L) {
    val ok: Boolean get() = status == ProbeStatus.OK

    companion object {
        fun ok(ms: Long): ProbeItem = ProbeItem(ProbeStatus.OK, ms)
        fun timeout(): ProbeItem = ProbeItem(ProbeStatus.TIMEOUT)
        fun failed(): ProbeItem = ProbeItem(ProbeStatus.FAILED)
    }
}

/**
 * 一轮三项探测结果。
 *
 * 整体失败判定：**节点直连与隧道 DNS 两项独立证据同时失败**——单项失败
 * （如 HTTP 204 端点被运营商拦截、节点 IP 被临时限速）不误判整体。
 */
data class HealthReport(
    val node: ProbeItem,
    val dns: ProbeItem,
    val http: ProbeItem,
) {
    val ok: Boolean get() = node.ok || dns.ok
    val failed: Boolean get() = !ok
}

/** 连续失败升级档位（只触发一次：达到阈值的当轮）。 */
enum class HealthAlert {
    /** 连续 2 次：warn 日志 + 通知栏「网络异常」 */
    WARN,

    /** 连续 5 次：建议手动切换节点/网络（不自动切） */
    ADVICE,
}

/**
 * 连续失败次数 → 当轮告警档位（纯函数，单测覆盖）。
 *
 * 仅在**恰好**达到阈值时返回非 null——3/4/6+ 次不重复刷通知与日志。
 */
fun healthAlertFor(streak: Int): HealthAlert? = when (streak) {
    HEALTH_WARN_STREAK -> HealthAlert.WARN
    HEALTH_ADVICE_STREAK -> HealthAlert.ADVICE
    else -> null
}

/** 单项 → 日志片段：`节点 89ms` / `节点 超时` / `节点 失败`。 */
private fun probeText(label: String, item: ProbeItem): String = when (item.status) {
    ProbeStatus.OK -> "$label ${item.ms}ms"
    ProbeStatus.TIMEOUT -> "$label 超时"
    ProbeStatus.FAILED -> "$label 失败"
}

/**
 * 健康检查日志行（方案定稿格式）：
 * - 通过：`✓ 健康检查（节点 89ms · 隧道DNS 12ms · HTTP 204 320ms）`
 * - 失败：`✗ 健康检查失败（节点 超时 · 隧道DNS 失败）`（只列失败项）
 */
fun formatHealthLog(report: HealthReport): String {
    val items = listOf(
        "节点" to report.node,
        "隧道DNS" to report.dns,
        "HTTP 204" to report.http,
    )
    return if (report.ok) {
        "✓ 健康检查（${items.joinToString(" · ") { probeText(it.first, it.second) }}）"
    } else {
        "✗ 健康检查失败（${items.filter { !it.second.ok }
            .joinToString(" · ") { probeText(it.first, it.second) }}）"
    }
}

/** 探测间隔归一化：非法值回退默认 300s（持久化脏数据不产生 0 间隔风暴）。 */
fun normalizeProbeSecs(raw: Int): Int =
    if (raw in HEALTH_PROBE_OPTIONS) raw else HEALTH_PROBE_DEFAULT_SECS

/** 间隔 → 设置页文案（关闭 / 1 分钟 / 3 分钟 / 5 分钟 / 10 分钟）。 */
fun probeIntervalLabel(secs: Int): String = when (normalizeProbeSecs(secs)) {
    0 -> "关闭"
    60 -> "1 分钟"
    180 -> "3 分钟"
    600 -> "10 分钟"
    else -> "5 分钟"
}

/**
 * 构造最小 DNS A 查询报文（RD=1，QTYPE=A，QCLASS=IN）。
 * 纯函数 → 单测可直接断言字节布局（不联网）。
 */
fun buildDnsQuery(id: Int, name: String): ByteArray {
    val labels = name.split('.').filter { it.isNotEmpty() }
    val qnameLen = labels.sumOf { 1 + it.length } + 1
    val buf = ByteArray(12 + qnameLen + 4)
    fun put16(offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }
    put16(0, id and 0xFFFF)   // ID
    put16(2, 0x0100)          // Flags：RD=1
    put16(4, 1)               // QDCOUNT
    var off = 12
    for (label in labels) {
        val bytes = label.toByteArray(Charsets.US_ASCII)
        if (bytes.isEmpty() || bytes.size > 63) continue
        buf[off++] = bytes.size.toByte()
        bytes.copyInto(buf, off)
        off += bytes.size
    }
    buf[off++] = 0            // QNAME 终止
    put16(off, 1)             // QTYPE = A
    put16(off + 2, 1)         // QCLASS = IN
    return buf
}

/**
 * DNS 响应是否有效（纯函数）：ID 匹配 + QR=1 + RCODE=0 + ANCOUNT>0。
 * 只判「隧道把查询送达并取回答案」，不解析具体记录（探测语义是链路连通）。
 */
fun isDnsResponseOk(packet: ByteArray, length: Int, id: Int): Boolean {
    if (length < 12 || packet.size < 12) return false
    val respId = ((packet[0].toInt() and 0xFF) shl 8) or (packet[1].toInt() and 0xFF)
    if (respId != (id and 0xFFFF)) return false
    val flags = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
    if (flags and 0x8000 == 0) return false // QR = 0：仍是查询，不是响应
    if (flags and 0x000F != 0) return false // RCODE != 0：NXDOMAIN/SERVFAIL
    val ancount = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
    return ancount > 0
}

/** 探针执行线程名（单测/日志排查用；避免硬编码散落）。 */
internal fun healthThreadName(): String = "hydra-health"
