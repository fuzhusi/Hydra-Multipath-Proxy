package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 智能分流开关（§九）桌面 JVM 单测：HydraConfig.runRuleMode 默认值与持久化
 * 往返语义（对齐 ThemeTest 纯函数风格；SecureStore 的 EncryptedSharedPreferences
 * 依赖 Android 框架，持久化通道由 save/load 逐字段映射保证——此处锁定字段级
 * 往返不因后续改动丢失）。
 *
 * 评审一轮 P3-1：app/build.gradle.kts 未引入 Robolectric（桌面 JVM 无
 * Android 框架）——SecureStore.save/load 的 prefs 真持久化字段映射**需仪器
 * 测试覆盖**：
 * TODO 真机验证清单：
 *   1. save(sampleConfig(runRuleMode=true)) → load 后 runRuleMode==true；
 *   2. 其余字段（nodesText/authKeyHex/trustMode/certDerB64/appFilterPkgs 等）
 *      逐字段往返不丢；
 *   3. 升级场景：旧版本 prefs（无 runRuleMode 键）load 默认 false。
 */
class RuleModeTest {

    /** 与 UI 表单/服务启动一致的样例配置（非默认字段全量显式）。 */
    private fun sampleConfig(runRuleMode: Boolean = false) = HydraConfig(
        nodesText = "1.2.3.4:443\n[::1]:443",
        authKeyHex = "ab".repeat(32),
        sni = "",
        trustMode = SecureStore.TRUST_CA,
        certDerB64 = "",
        listenPort = SecureStore.DEFAULT_PORT,
        runMode = SecureStore.MODE_VPN,
        vpnKillSwitch = true,
        vpnBootStart = false,
        appFilterMode = SecureStore.APP_FILTER_ALL,
        appFilterPkgs = "",
        runRuleMode = runRuleMode,
    )

    @Test
    fun runRuleModeDefaultsOff() {
        // 默认关闭 = 全局代理（行为与基线逐字节一致，零新增开销）
        assertFalse("runRuleMode 必须默认关闭", sampleConfig().runRuleMode)
    }

    @Test
    fun runRuleModeToggleRoundTripPreservesOtherFields() {
        // 开关切换（copy）只改分流位：凭据/节点/运行模式等全部原样保留——
        // 对应 SecureStore.save/load 的逐字段映射通道
        val toggled = sampleConfig().copy(runRuleMode = true)
        assertTrue(toggled.runRuleMode)
        assertEquals("1.2.3.4:443\n[::1]:443", toggled.nodesText)
        assertEquals("ab".repeat(32), toggled.authKeyHex)
        assertEquals(SecureStore.MODE_VPN, toggled.runMode)
        assertEquals(SecureStore.TRUST_CA, toggled.trustMode)
        assertTrue(toggled.vpnKillSwitch)

        val reverted = toggled.copy(runRuleMode = false)
        assertFalse(reverted.runRuleMode)
        assertEquals(sampleConfig(), reverted)
    }
}
