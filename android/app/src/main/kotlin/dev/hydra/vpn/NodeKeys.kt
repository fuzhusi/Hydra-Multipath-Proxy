package dev.hydra.vpn

/**
 * 按节点独立认证密钥的纯逻辑助手（v0.2.9.3 实测：多节点各自部署各持 PSK，
 * 全局单密钥被后导入节点覆盖 → 其余节点 Noise msg2 解密必败）。
 *
 * 语义与 [NodeCerts] 同构：按节点条目优先，缺项回落全局 authKeyHex。
 * 只用 JVM 标准库，桌面 JVM 单测可直接覆盖。
 */
object NodeKeys {

    /** 单节点应使用的认证密钥 hex：按节点条目优先，缺项回落全局；均无/非法 → null。 */
    fun authKeyHexFor(cfg: HydraConfig, node: String): String? =
        cfg.nodeAuthKeyMap[node]?.takeIf { it.length == 64 }
            ?: cfg.authKeyHex.takeIf { it.length == 64 }

    /**
     * 凭据就绪判定（VPN 启动预校验用）：全局密钥合法，或全部已配置节点
     * 都有独立密钥。返回缺失密钥的节点列表（空 = 就绪）。
     */
    fun missingKeyNodes(cfg: HydraConfig): List<String> {
        if (cfg.authKeyHex.length == 64) return emptyList()
        return cfg.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }
            .filter { authKeyHexFor(cfg, it) == null }
    }
}
