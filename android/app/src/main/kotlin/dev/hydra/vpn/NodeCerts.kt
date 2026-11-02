package dev.hydra.vpn

import java.security.MessageDigest
import java.util.Base64

/**
 * 按节点独立证书的纯逻辑助手（ISSUE 安卓多节点证书）。
 *
 * 信任语义（与桌面 GUI node_cert_paths、Rust 信任根池一致）：pin 模式的信任根
 * 池 = 各已配置节点自己的证书（node_certs 表，缺项回落全局 cert_der_b64）∪
 * 全局证书。rustls 把池内每张证书都加入 RootCertStore——多节点各持独立证书时
 * 池内齐备即握手成功，不再"后导入覆盖先前"；已删除节点的证书不再进池
 * （随节点列表收敛，天然吊销）。
 *
 * 只用 JVM 标准库（java.util.Base64/MessageDigest），桌面 JVM 单测可直接覆盖。
 */
object NodeCerts {

    /** 单节点应使用的证书 DER base64：按节点条目优先，缺项回落全局；均无 → null。 */
    fun certB64For(cfg: HydraConfig, node: String): String? =
        cfg.nodeCertB64Map[node]?.takeIf { it.isNotBlank() }
            ?: cfg.certDerB64.takeIf { it.isNotBlank() }

    /**
     * 节点行证书状态（UI 显示与漂移诊断用）：
     * - [Status.HAS_CERT]：节点有可用的证书本体（独立条目，或回落全局；
     *   若链接 `cf=` 同时存在且与全局一致，fingerprint16 即确认后的指纹）
     * - [Status.FP_MISMATCH]：节点将回落全局证书，但链接 `cf=` 与全局证书
     *   SHA-256 不符——握手将失败（BadSignature），证书漂移/导入错证书的
     *   精准诊断
     * - [Status.FP_ONLY]：仅有链接指纹，本地无任何证书本体——需导入
     * - [Status.NONE]：无任何证书信息
     */
    data class NodeCertStatus(val status: Status, val fingerprint16: String?) {
        enum class Status { HAS_CERT, FP_MISMATCH, FP_ONLY, NONE }
    }

    fun statusFor(cfg: HydraConfig, node: String): NodeCertStatus {
        if (cfg.trustMode == SecureStore.TRUST_CA) return NodeCertStatus(NodeCertStatus.Status.NONE, null)
        // 本节点实际会用的证书本体（独立条目优先，缺项回落全局）。
        // [K 修复] 非 X.509 垃圾本体视同无证书（此前算出假指纹显示 HAS_CERT，
        // 误导排障；实际信任池在 certPool 已剔除该条目）
        val effectiveB64 = certB64For(cfg, node)
        val effectiveFp = effectiveB64?.let { b64 ->
            runCatching {
                val der = decodeCert(b64)
                if (isWellFormedX509(der)) fingerprint(der) else null
            }.getOrNull()
        }
        val nodeFp = cfg.nodeCertFpMap[node]?.takeIf { it.isNotBlank() }?.lowercase()
        return when {
            effectiveFp != null ->
                if (nodeFp == null || nodeFp == effectiveFp) {
                    // 有本体；cf 存在且一致 = "这就是节点证书"的确认
                    NodeCertStatus(NodeCertStatus.Status.HAS_CERT, effectiveFp.take(16))
                } else {
                    // 本体与链接指纹不符：独立条目=旧证书漂移；回落=握手将失败
                    NodeCertStatus(NodeCertStatus.Status.FP_MISMATCH, nodeFp.take(16))
                }
            nodeFp != null ->
                // 无任何本体，仅有链接指纹——紧凑链接待导入
                NodeCertStatus(NodeCertStatus.Status.FP_ONLY, nodeFp.take(16))
            else ->
                NodeCertStatus(NodeCertStatus.Status.NONE, null)
        }
    }

    private val x509Factory: java.security.cert.CertificateFactory by lazy {
        java.security.cert.CertificateFactory.getInstance("X.509")
    }

    /** [K 修复] X.509 语法预过滤：MimeDecoder 对垃圾不抛异常（非字母表字符
     *  静默忽略、合法 base64 的垃圾字节原样产出），垃圾 DER 混入池会让 rustls
     *  roots.add 整池失败（一张坏证书打死全部节点）。仅 JVM 标准库，可单测。 */
    fun isWellFormedX509(der: ByteArray): Boolean = der.isNotEmpty() && runCatching {
        x509Factory.generateCertificate(der.inputStream())
    }.isSuccess

    /**
     * 引擎信任根池：全部已配置节点的独立证书（缺项回落全局）+ 全局证书，
     * 按 base64 文本去重（保持首次出现顺序）。坏条目跳过不致命（[K 修复]
     * 起按 X.509 语法预过滤——此前垃圾 DER 混入池会让整池报错）；空池 =
     * pin 模式不可启动，调用方负责报错。需要告警细节用 [certPoolWithWarnings]。
     */
    fun certPool(cfg: HydraConfig): List<ByteArray> = certPoolWithWarnings(cfg).first

    /** [K 修复] 信任池 + 坏条目告警（UI 日志展示用）：空 base64 / 非 X.509
     *  条目剔除并给出可读的修复指引。 */
    fun certPoolWithWarnings(cfg: HydraConfig): Pair<List<ByteArray>, List<String>> {
        val b64s = LinkedHashSet<String>()
        for (node in cfg.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
            certB64For(cfg, node)?.let { b64s.add(it) }
        }
        cfg.certDerB64.takeIf { it.isNotBlank() }?.let { b64s.add(it) }
        val pool = ArrayList<ByteArray>()
        val warnings = ArrayList<String>()
        for (b64 in b64s) {
            val der = runCatching { decodeCert(b64) }.getOrNull() ?: ByteArray(0)
            when {
                der.isEmpty() -> warnings.add("有 1 条证书无法 base64 解码，已跳过")
                !isWellFormedX509(der) -> warnings.add(
                    "有 1 条证书不是有效 X.509（指纹前 16 位 " +
                        "${fingerprint(der).take(16)}），已跳过——请重新导入对应节点的分享链接",
                )
                else -> pool.add(der)
            }
        }
        return pool to warnings
    }

    /** 证书 DER base64 → DER 字节（Mime 解码：容忍换行/空白等手工粘贴形态）。 */
    fun decodeCert(b64: String): ByteArray =
        Base64.getMimeDecoder().decode(b64.filterNot { it.isWhitespace() })

    /** 证书 DER 的 SHA-256 指纹（64 位小写 hex，与分享链接 `cf=` 字段同算法）。 */
    fun fingerprint(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der)
            .joinToString("") { "%02x".format(it) }

    /**
     * TLS 握手错误的用户可读映射：自签证书 Subject/Issuer 全部同名
     * （rcgen self signed cert），rustls 匹配到同名信任根后签名比对失败，
     * 只报 `BadSignature` 而非"证书不匹配"——用户无法自行定位。此处显式
     * 指向修复路径（重新导入该节点的分享链接）。其余错误原样透传。
     */
    fun friendlyError(msg: String?): String {
        val m = msg ?: return ""
        return if (m.contains("BadSignature") || m.contains("invalid peer certificate")) {
            "证书不匹配——该节点的证书已更换或导入错了证书，请重新导入该节点的分享链接（原文：$m）"
        } else {
            m
        }
    }
}
