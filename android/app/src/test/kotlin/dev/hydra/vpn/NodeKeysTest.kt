package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 按节点独立认证密钥纯逻辑（NodeKeys）的桌面 JVM 单测
 * （v0.2.9.3 实测：多节点各持 PSK，全局单密钥被后导入覆盖 →
 * 其余节点 Noise msg2 解密必败）。
 */
class NodeKeysTest {

    private val keyA = "ab".repeat(32)
    private val keyB = "cd".repeat(32)

    private fun cfg(
        nodes: String = "",
        globalKey: String = "",
        nodeKeys: Map<String, String> = emptyMap(),
    ) = HydraConfig(
        nodesText = nodes,
        authKeyHex = globalKey,
        sni = "",
        trustMode = SecureStore.TRUST_PINNED,
        certDerB64 = "",
        nodeAuthKeyMap = nodeKeys,
        listenPort = SecureStore.DEFAULT_PORT,
        runMode = SecureStore.MODE_VPN,
    )

    @Test
    fun authKeyFor_prefers_per_node_entry() {
        val c = cfg(nodes = "10.0.0.1:443", globalKey = keyB, nodeKeys = mapOf("10.0.0.1:443" to keyA))
        assertEquals(keyA, NodeKeys.authKeyHexFor(c, "10.0.0.1:443"))
    }

    @Test
    fun authKeyFor_falls_back_to_global() {
        val c = cfg(nodes = "10.0.0.1:443", globalKey = keyB)
        assertEquals(keyB, NodeKeys.authKeyHexFor(c, "10.0.0.1:443"))
        // 非法长度（残缺）独立条目视同缺失，回落全局
        val c2 = cfg(nodes = "10.0.0.1:443", globalKey = keyB, nodeKeys = mapOf("10.0.0.1:443" to "ab"))
        assertEquals(keyB, NodeKeys.authKeyHexFor(c2, "10.0.0.1:443"))
    }

    @Test
    fun authKeyFor_null_when_neither() {
        assertEquals(null, NodeKeys.authKeyHexFor(cfg(nodes = "10.0.0.1:443"), "10.0.0.1:443"))
    }

    @Test
    fun missingKeyNodes_empty_when_global_valid() {
        val c = cfg(nodes = "10.0.0.1:443\n10.0.0.2:443", globalKey = keyA)
        assertTrue(NodeKeys.missingKeyNodes(c).isEmpty())
    }

    @Test
    fun missingKeyNodes_empty_when_per_node_covers_all() {
        // 全局密钥为空、按节点全覆盖——多节点各持 PSK 的目标形态
        val c = cfg(
            nodes = "10.0.0.1:443\n10.0.0.2:443",
            nodeKeys = mapOf("10.0.0.1:443" to keyA, "10.0.0.2:443" to keyB),
        )
        assertTrue(NodeKeys.missingKeyNodes(c).isEmpty())
    }

    @Test
    fun missingKeyNodes_lists_uncovered_nodes() {
        val c = cfg(
            nodes = "10.0.0.1:443\n10.0.0.2:443",
            nodeKeys = mapOf("10.0.0.1:443" to keyA),
        )
        assertEquals(listOf("10.0.0.2:443"), NodeKeys.missingKeyNodes(c))
    }

    @Test
    fun missingKeyNodes_lists_all_when_nothing() {
        val c = cfg(nodes = "10.0.0.1:443\n10.0.0.2:443")
        assertEquals(listOf("10.0.0.1:443", "10.0.0.2:443"), NodeKeys.missingKeyNodes(c))
    }
}
