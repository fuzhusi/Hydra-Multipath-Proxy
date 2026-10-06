package dev.hydra.vpn

import uniffi.hydra_android.HydraEngine
import uniffi.hydra_android.NodeSpec
import uniffi.hydra_android.TrustMode
import java.io.File
import org.junit.Assert.assertContains
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * M0 验收冒烟（设计 v2.1 §5）：Kotlin 经 uniffi 绑定启停 HydraEngine。
 *
 * 运行机制：桌面 JVM 单测，按 java.library.path（app/build.gradle.kts 注入
 * 仓库 target/debug）加载 host 架构的 hydra_android 动态库（Windows dll /
 * Linux so / macOS dylib，`cargo build -p hydra-android` 产出）。
 * 无需设备/模拟器；真机交叉编译 .so 的装包验证随 M1。
 */
class EngineSmokeTest {

    private fun newEngine(): HydraEngine {
        // 占位节点/证书：start() 只校验参数合法性与监听绑定，不做出站连接
        return HydraEngine.new(
            nodes = listOf(NodeSpec(addr = "127.0.0.1:44300")),
            authKeyHex = "ab".repeat(32),
            trust = TrustMode.Pinned(certDer = listOf(byteArrayOf(0x30, 0x00))),
            sni = null,
            listenPort = 0u,
        )
    }

    @Test
    fun startStopViaUniffi() {
        val engine = newEngine()
        engine.start(protect = null)
        try {
            val bound = assertNotNull(engine.boundAddr, "启动后应有进程内 SOCKS 监听地址")
            assertContains(bound, "127.0.0.1:")
            val stats = engine.stats()
            assertEquals(0uL, stats.totalConnections)
        } finally {
            engine.stop()
        }
        assertEquals(null, engine.boundAddr, "stop 后监听地址应清空")
    }

    @Test
    fun rejectsInvalidConfig() {
        val badKey = runCatching {
            HydraEngine.new(
                nodes = listOf(NodeSpec(addr = "127.0.0.1:443")),
                authKeyHex = "ab".repeat(31), // NNpsk2 要求恰好 32 字节
                trust = TrustMode.Pinned(certDer = listOf(byteArrayOf(0x30))),
                sni = null,
                listenPort = 0u,
            )
        }
        assertTrue(badKey.isFailure, "31 字节 PSK 必须被拒绝")
    }

    /** 诊断辅助：确认 java.library.path 注入与库文件存在（失败时输出可读原因） */
    @Test
    fun nativeLibraryPresent() {
        val path = System.getProperty("java.library.path") ?: ""
        assertTrue(path.isNotEmpty(), "java.library.path 未注入")
        val dir = File(path)
        val found = dir.listFiles { f ->
            f.name.startsWith("hydra_android.") || f.name == "libhydra_android.so"
        } ?: emptyArray()
        assertTrue(found.isNotEmpty(), "target/debug 下未找到 hydra_android 动态库（先 cargo build -p hydra-android）: $path")
    }
}
