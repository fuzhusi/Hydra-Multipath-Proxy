package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * 按节点独立证书纯逻辑（NodeCerts + node_certs 序列化）的桌面 JVM 单测
 * （ISSUE 安卓多节点证书）：不触 Android 框架，直接覆盖信任池/指纹/错误映射。
 */
class NodeCertsTest {

    private val certA = Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3))
    private val certB = Base64.getEncoder().encodeToString(byteArrayOf(4, 5, 6))

    private fun cfg(
        nodes: String = "",
        cert: String = "",
        nodeCerts: Map<String, String> = emptyMap(),
        trustMode: String = SecureStore.TRUST_PINNED,
    ) = HydraConfig(
        nodesText = nodes,
        authKeyHex = "ab".repeat(32),
        sni = "",
        trustMode = trustMode,
        certDerB64 = cert,
        nodeCertB64Map = nodeCerts,
        listenPort = SecureStore.DEFAULT_PORT,
        runMode = SecureStore.MODE_VPN,
    )

    // ── 单节点证书取用 ─────────────────────────────────────────────────────

    @Test
    fun certB64For_prefers_per_node_entry() {
        val c = cfg(nodes = "10.0.0.1:443", cert = certB, nodeCerts = mapOf("10.0.0.1:443" to certA))
        assertEquals(certA, NodeCerts.certB64For(c, "10.0.0.1:443"))
    }

    @Test
    fun certB64For_falls_back_to_global() {
        val c = cfg(nodes = "10.0.0.1:443", cert = certB)
        assertEquals(certB, NodeCerts.certB64For(c, "10.0.0.1:443"))
        // 空白条目视同缺失，同样回落全局
        val c2 = cfg(nodes = "10.0.0.1:443", cert = certB, nodeCerts = mapOf("10.0.0.1:443" to "  "))
        assertEquals(certB, NodeCerts.certB64For(c2, "10.0.0.1:443"))
    }

    @Test
    fun certB64For_null_when_neither() {
        val c = cfg(nodes = "10.0.0.1:443")
        assertEquals(null, NodeCerts.certB64For(c, "10.0.0.1:443"))
    }

    // ── 信任根池 ───────────────────────────────────────────────────────────

    // JUnit 的 List/ByteArray equals 按引用比较——池断言统一转 base64 字符串
    private fun List<ByteArray>.b64() = map { Base64.getEncoder().encodeToString(it) }

    @Test
    fun pool_unions_per_node_and_global_with_dedup() {
        val c = cfg(
            nodes = "10.0.0.1:443\n10.0.0.2:443",
            cert = certB,
            nodeCerts = mapOf("10.0.0.1:443" to certA),
        )
        val pool = NodeCerts.certPool(c)
        // 10.0.0.1 → certA；10.0.0.2 → 回落 certB；全局 certB 去重不重复计
        assertEquals(setOf(certA, certB), pool.b64().toSet())
        assertEquals(2, pool.size)
    }

    @Test
    fun pool_excludes_deleted_nodes_certs() {
        // 已删除节点的证书不再进池（随节点列表收敛，天然吊销）
        val c = cfg(
            nodes = "10.0.0.1:443",
            nodeCerts = mapOf("10.0.0.1:443" to certA, "10.0.0.9:443" to certB),
        )
        assertEquals(listOf(certA), NodeCerts.certPool(c).b64())
    }

    @Test
    fun pool_skips_malformed_and_empty_entries() {
        val c = cfg(
            nodes = "10.0.0.1:443\n10.0.0.2:443",
            nodeCerts = mapOf("10.0.0.1:443" to "!!!"),
            cert = certA,
        )
        // "!!!" Mime 解码为空数组（非字母表全忽略）——滤除；10.0.0.2 回落全局
        assertEquals(listOf(certA), NodeCerts.certPool(c).b64())
    }

    @Test
    fun pool_empty_when_no_cert_anywhere() {
        assertEquals(emptyList<ByteArray>(), NodeCerts.certPool(cfg(nodes = "10.0.0.1:443")))
    }

    // ── 指纹（SHA-256，与分享链接 cf= 同算法） ──────────────────────────────

    @Test
    fun fingerprint_matches_sha256_vector() {
        // SHA-256("") 标准测试向量
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            NodeCerts.fingerprint(ByteArray(0)),
        )
        // SHA-256("abc") 标准测试向量
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            NodeCerts.fingerprint("abc".toByteArray()),
        )
    }

    @Test
    fun decodeCert_tolerates_whitespace() {
        val wrapped = certA.chunked(2).joinToString("\n")
        assertTrue(NodeCerts.decodeCert(wrapped).contentEquals(byteArrayOf(1, 2, 3)))
    }

    // ── BadSignature → 用户可读映射 ────────────────────────────────────────

    @Test
    fun friendlyError_maps_bad_signature() {
        val raw = "TLS handshake with 1.2.3.4:11534 failed: invalid peer certificate: BadSignature"
        val mapped = NodeCerts.friendlyError(raw)
        assertTrue(mapped.contains("证书不匹配"))
        assertTrue(mapped.contains("重新导入"))
        assertTrue("原文应保留供排障", mapped.contains(raw))
    }

    @Test
    fun friendlyError_maps_invalid_peer_certificate_without_marker() {
        assertTrue(NodeCerts.friendlyError("invalid peer certificate: UnknownIssuer").contains("证书不匹配"))
    }

    @Test
    fun friendlyError_passthrough_other_errors() {
        assertEquals("探测超时（8s）——节点不可达或网络不通",
            NodeCerts.friendlyError("探测超时（8s）——节点不可达或网络不通"))
        assertEquals("", NodeCerts.friendlyError(null))
    }

    // ── node_certs 表序列化（tab 分隔行） ───────────────────────────────────

    @Test
    fun node_certs_round_trip_with_v6_addr() {
        val m = mapOf(
            "118.193.33.251:11534" to certA,
            "[::1]:443" to certB,
        )
        assertEquals(m, parseNodeCerts(encodeNodeCerts(m)))
    }

    @Test
    fun node_certs_parse_skips_malformed_lines() {
        val text = "10.0.0.1:443\t$certA\n坏行无tab\n\t$certB\n10.0.0.2:443\t\n$certA"
        val parsed = parseNodeCerts(text)
        assertEquals(mapOf("10.0.0.1:443" to certA), parsed)
    }

    @Test
    fun node_certs_parse_empty() {
        assertEquals(emptyMap<String, String>(), parseNodeCerts(""))
        assertEquals(emptyMap<String, String>(), parseNodeCerts("\n\n"))
    }
}
