package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.hydra_android.HydraEngine
import uniffi.hydra_android.NodeSpec
import uniffi.hydra_android.TrustMode
import uniffi.hydra_android.vpnStats

/**
 * 全局 VPN 流量统计（uniffi `vpnStats()` 每秒轮询）的纯函数单测：
 *
 * 1. [EngineState.Ui.withVpnStats] 只更新流量/连接/时长/速率字段，运行态字段
 *    （running / transition / boundAddr）原样保留——轮询与启动/停止/重连路径
 *    并发写 EngineState 时不得互相覆盖（本任务的核心约束）；
 * 2. [computeSpeedBps] 的间隔换算与异常防御（时钟回拨/新会话计数器归零）；
 * 3. Ui 新增速率字段默认 0，不改变既有状态机语义（[EngineState.Ui.toPhase]）。
 *
 * 沿用 RuleModeTest 的纯 JVM 风格（不依赖 Android 框架，无需 Robolectric）。
 */
class VpnStatsTest {

    private fun runningUi() = EngineState.Ui(
        running = true,
        transition = null,
        boundAddr = "全局 VPN（所有应用流量经节点）",
        sentBytes = 11,
        receivedBytes = 22,
        activeConns = 3,
        totalConns = 4,
        uptimeSecs = 5,
        upSpeedBps = 6,
        downSpeedBps = 7,
    )

    @Test
    fun statsUpdateKeepsRuntimeFields() {
        val next = runningUi().withVpnStats(
            sentBytes = 1024,
            receivedBytes = 2048,
            activeConns = 2,
            totalConns = 9,
            uptimeSecs = 42,
            upSpeedBps = 100,
            downSpeedBps = 200,
        )
        // 统计字段全部来自本次采样
        assertEquals(1024L, next.sentBytes)
        assertEquals(2048L, next.receivedBytes)
        assertEquals(2L, next.activeConns)
        assertEquals(9L, next.totalConns)
        assertEquals(42L, next.uptimeSecs)
        assertEquals(100L, next.upSpeedBps)
        assertEquals(200L, next.downSpeedBps)
        // 运行态字段逐字段保留（轮询不得覆盖启动/停止结果）
        assertTrue("running 不得被统计轮询改写", next.running)
        assertNull("transition 不得被统计轮询改写", next.transition)
        assertEquals("boundAddr 不得被统计轮询改写", "全局 VPN（所有应用流量经节点）", next.boundAddr)
        assertEquals("连接四态不受统计字段影响", ConnPhase.CONNECTED, next.toPhase())
    }

    @Test
    fun statsUpdateKeepsReconnectingState() {
        // kill switch 重连等待期：running=false + transition=隧道中断
        val waiting = EngineState.Ui(
            running = false,
            transition = "隧道中断——已阻断全部流量，5s 后重连（第 1 次）",
        )
        val next = waiting.withVpnStats(
            sentBytes = 0,
            receivedBytes = 0,
            activeConns = 0,
            totalConns = 0,
            uptimeSecs = 3,
            upSpeedBps = 0,
            downSpeedBps = 0,
        )
        assertFalse("重连等待期间不得被轮询改成运行中", next.running)
        assertEquals(waiting.transition, next.transition)
        assertEquals(ConnPhase.CONNECTING, next.toPhase())
    }

    @Test
    fun speedIsDeltaOverInterval() {
        // 1000 字节 / 1000ms = 1000 B/s；500ms 内 1000 字节 = 2000 B/s
        assertEquals(1000L, computeSpeedBps(0, 1000, 1000))
        assertEquals(2000L, computeSpeedBps(1000, 2000, 500))
        // 无新增流量 → 0
        assertEquals(0L, computeSpeedBps(4096, 4096, 1000))
    }

    @Test
    fun speedDefendsAgainstResetAndBadInterval() {
        // 计数器回退（新会话归零/重连重置）不得产生负速率
        assertEquals(0L, computeSpeedBps(5000, 0, 1000))
        // 间隔非正（时钟回拨/同一毫秒）不得除零
        assertEquals(0L, computeSpeedBps(0, 1000, 0))
        assertEquals(0L, computeSpeedBps(0, 1000, -1))
    }

    @Test
    fun speedFieldsDefaultToZero() {
        // 默认 Ui（未连接）：速率字段为 0，既有字段默认值不变
        val ui = EngineState.Ui()
        assertEquals(0L, ui.upSpeedBps)
        assertEquals(0L, ui.downSpeedBps)
        assertEquals(0L, ui.sentBytes)
        assertEquals(ConnPhase.DISCONNECTED, ui.toPhase())
    }

    @Test
    fun vpnStatsFfiIsZeroAndLocalModeDoesNotPolluteIt() {
        // 未启动 TUN 数据面：FFI 全 0（Kotlin 首轮轮询不显示残留值）
        assertEquals(0uL, vpnStats().upBytes)
        assertEquals(0uL, vpnStats().downBytes)
        assertEquals(0uL, vpnStats().activeConns)
        assertEquals(0uL, vpnStats().totalConns)

        // 本地端口模式（SOCKS 引擎）启停不写 VPN 计数器：两条统计面独立
        val engine = HydraEngine(
            nodes = listOf(NodeSpec(addr = "127.0.0.1:44300")),
            authKeyHex = "ab".repeat(32),
            nodeAuthKeys = emptyMap(),
        trust = TrustMode.Pinned(certDer = listOf(byteArrayOf(0x30, 0x00))),
            sni = null,
            listenPort = 0u,
        )
        engine.start(protect = null)
        try {
            val s = vpnStats()
            assertEquals("本地模式不得污染 VPN 上行统计", 0uL, s.upBytes)
            assertEquals("本地模式不得污染 VPN 下行统计", 0uL, s.downBytes)
            assertEquals(0uL, s.activeConns)
            assertEquals(0uL, s.totalConns)
        } finally {
            engine.stop()
        }
    }
}
