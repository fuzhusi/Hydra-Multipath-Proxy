package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.hydra_android.HydraEngine
import uniffi.hydra_android.NodeSpec
import uniffi.hydra_android.TrustMode
import java.io.File

/**
 * M0 验收冒烟（设计 v2.1 §5）：Kotlin 经 uniffi 绑定启停 HydraEngine。
 *
 * 运行机制：桌面 JVM 单测，按 java.library.path（app/build.gradle.kts 注入
 * 仓库 target/debug）经 JNA 加载 host 架构的 hydra_android 动态库
 * （Windows dll / Linux so / macOS dylib，`cargo build -p hydra-android` 产出）。
 * 无需设备/模拟器；真机交叉编译 .so 的装包验证随 M1。
 */
class EngineSmokeTest {

    private fun newEngine(): HydraEngine = HydraEngine(
        nodes = listOf(NodeSpec(addr = "127.0.0.1:44300")),
        authKeyHex = "ab".repeat(32),
        trust = TrustMode.Pinned(certDer = listOf(byteArrayOf(0x30, 0x00))),
        sni = null,
        listenPort = 0u,
    )

    @Test
    fun startStopViaUniffi() {
        val engine = newEngine()
        engine.start(protect = null)
        try {
            val bound = engine.boundAddr()
            assertNotNull("启动后应有进程内 SOCKS 监听地址", bound)
            assertTrue("监听地址异常: $bound", bound!!.contains("127.0.0.1:"))
            val stats = engine.stats()
            assertEquals(0uL, stats.totalConnections)
        } finally {
            engine.stop()
        }
        assertEquals("stop 后监听地址应清空", null, engine.boundAddr())
    }

    @Test
    fun rejectsInvalidConfig() {
        val badKey = runCatching {
            HydraEngine(
                nodes = listOf(NodeSpec(addr = "127.0.0.1:443")),
                authKeyHex = "ab".repeat(31), // NNpsk2 要求恰好 32 字节
                trust = TrustMode.Pinned(certDer = listOf(byteArrayOf(0x30))),
                sni = null,
                listenPort = 0u,
            )
        }
        assertTrue("31 字节 PSK 必须被拒绝", badKey.isFailure)
    }

    /** 诊断辅助：确认库搜索路径注入与库文件存在（失败时输出可读原因） */
    @Test
    fun nativeLibraryPresent() {
        // JVM 启动后 java.library.path 属性可能与实际搜索路径不同步，
        // 因此以 jna.library.path（JNA 主查找属性）为准，java.library.path 兜底
        val path = System.getProperty("jna.library.path")
            ?: System.getProperty("java.library.path") ?: ""
        assertTrue("库搜索路径未注入", path.isNotEmpty())
        val dir = File(path)
        val found = dir.listFiles { f ->
            f.name.startsWith("hydra_android.")
        } ?: emptyArray()
        assertTrue(
            "target/debug 下未找到 hydra_android 动态库（先 cargo build -p hydra-android）: $path",
            found.isNotEmpty(),
        )
    }
}
