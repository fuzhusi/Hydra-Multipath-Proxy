package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 健康探测纯逻辑单测（B 批）：结果格式化（方案定稿文案）、整体失败判定
 * （单项失败不误判）、告警分级、DNS 报文编解码、间隔配置归一化/持久化往返。
 * 全部不联网、不依赖 Android 框架（真实探测在 HydraVpnService，需 VpnService.protect）。
 */
class HealthProbeTest {

    private fun sampleConfig(healthProbeSecs: Int = HEALTH_PROBE_DEFAULT_SECS) = HydraConfig(
        nodesText = "1.2.3.4:443",
        authKeyHex = "ab".repeat(32),
        sni = "",
        trustMode = SecureStore.TRUST_PINNED,
        certDerB64 = "",
        listenPort = SecureStore.DEFAULT_PORT,
        runMode = SecureStore.MODE_VPN,
        healthProbeSecs = healthProbeSecs,
    )

    @Test
    fun formatsSuccessfulProbeWithThreeTimings() {
        val report = HealthReport(
            node = ProbeItem.ok(89),
            dns = ProbeItem.ok(12),
            http = ProbeItem.ok(320),
        )
        assertTrue(report.ok)
        assertEquals(
            "✓ 健康检查（节点 89ms · 隧道DNS 12ms · HTTP 204 320ms）",
            formatHealthLog(report),
        )
    }

    @Test
    fun formatsFailedProbeWithFailedItemsOnly() {
        // 方案定稿失败样例：节点超时 + 隧道 DNS 失败（HTTP best-effort 成功不列出）
        val report = HealthReport(
            node = ProbeItem.timeout(),
            dns = ProbeItem.failed(),
            http = ProbeItem.ok(300),
        )
        assertTrue("节点+隧道DNS 同时失败 → 整体失败", report.failed)
        assertEquals(
            "✗ 健康检查失败（节点 超时 · 隧道DNS 失败）",
            formatHealthLog(report),
        )
    }

    @Test
    fun singleItemFailureDoesNotFailOverall() {
        // HTTP 204 端点被拦截：隧道本身可用（DNS 成功）→ 不误判整体失败
        assertFalse(HealthReport(ProbeItem.ok(10), ProbeItem.ok(20), ProbeItem.failed()).failed)
        // 节点直连被运营商拦截但隧道可用：不误判
        assertFalse(HealthReport(ProbeItem.failed(), ProbeItem.ok(20), ProbeItem.failed()).failed)
        // 隧道 DNS 失败但 HTTP 成功：隧道仍通
        assertFalse(HealthReport(ProbeItem.timeout(), ProbeItem.ok(5), ProbeItem.ok(200)).failed)
    }

    @Test
    fun alertEscalatesOnlyAtThresholds() {
        assertNull(healthAlertFor(0))
        assertNull(healthAlertFor(1))
        assertEquals("连续 2 次 → warn + 通知栏", HealthAlert.WARN, healthAlertFor(2))
        assertNull("3/4 次不重复刷告警", healthAlertFor(3))
        assertNull(healthAlertFor(4))
        assertEquals("连续 5 次 → 建议手动切换", HealthAlert.ADVICE, healthAlertFor(5))
        assertNull(healthAlertFor(6))
    }

    @Test
    fun probeIntervalConfigNormalizesAndPersists() {
        // 默认 300s（方案定稿）；可选值 1m/3m/5m/10m/关
        assertEquals(300, HEALTH_PROBE_DEFAULT_SECS)
        assertEquals(listOf(60, 180, 300, 600, 0), HEALTH_PROBE_OPTIONS)
        assertEquals(300, sampleConfig().healthProbeSecs)
        // 非法持久化脏数据归一化到默认（不产生 0 间隔风暴 / 负数延迟）
        assertEquals(300, normalizeProbeSecs(42))
        assertEquals(300, normalizeProbeSecs(-1))
        assertEquals(0, normalizeProbeSecs(0))
        assertEquals(600, normalizeProbeSecs(600))
        // copy 往返保留其余字段（SecureStore.save/load 的字段映射契约）
        val changed = sampleConfig().copy(healthProbeSecs = 60)
        assertEquals(60, changed.healthProbeSecs)
        assertEquals("1.2.3.4:443", changed.nodesText)
        assertEquals(SecureStore.MODE_VPN, changed.runMode)
        // 设置页文案
        assertEquals("关闭", probeIntervalLabel(0))
        assertEquals("1 分钟", probeIntervalLabel(60))
        assertEquals("3 分钟", probeIntervalLabel(180))
        assertEquals("5 分钟", probeIntervalLabel(300))
        assertEquals("10 分钟", probeIntervalLabel(600))
    }

    @Test
    fun dnsQueryEncodesAndResponseParses() {
        val id = 0x1234
        val query = buildDnsQuery(id, HEALTH_DNS_PROBE_NAME)
        assertEquals("ID 高字节", 0x12, query[0].toInt() and 0xFF)
        assertEquals("ID 低字节", 0x34, query[1].toInt() and 0xFF)
        assertEquals("RD=1", 0x01, query[2].toInt() and 0xFF)
        assertEquals(
            "QDCOUNT=1",
            1,
            ((query[4].toInt() and 0xFF) shl 8) or (query[5].toInt() and 0xFF),
        )
        // QNAME 首标签 "www"（长度 3）
        assertEquals(3, query[12].toInt() and 0xFF)

        // 构造响应：ID 匹配 + QR=1 + RCODE=0 + ANCOUNT=1
        val response = ByteArray(32)
        response[0] = 0x12
        response[1] = 0x34
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[7] = 1
        assertTrue(isDnsResponseOk(response, response.size, id))
        assertFalse("长度不足", isDnsResponseOk(response, 11, id))
        assertFalse("ID 不匹配（迟到/串包响应）", isDnsResponseOk(response, response.size, 0x9999))
        response[3] = 0x03 // RCODE=3 NXDOMAIN
        assertFalse("RCODE != 0", isDnsResponseOk(response, response.size, id))
        response[3] = 0x80.toByte()
        response[7] = 0 // ANCOUNT=0
        assertFalse("无应答记录", isDnsResponseOk(response, response.size, id))
    }
}
