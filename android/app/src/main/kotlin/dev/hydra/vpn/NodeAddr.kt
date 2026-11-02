package dev.hydra.vpn

/**
 * 节点串接纯逻辑（L 修复）：手动添加输入 → nodesText 行。
 * IPv6 一律输出 `[host]:port` 方括号字面量形态（Rust SocketAddr 标准解析
 * 形态，与分享链接/NodeSpec/节点表键约定一致）；裸 v6 自动包方括号。
 * 只用 JVM 标准库，桌面 JVM 单测可直接覆盖。
 */
object NodeAddr {

    /** 归一化：返回 null = 输入无效（空地址/端口越界/括号不闭合等）。 */
    fun normalizeManual(addrRaw: String, portText: String): String? {
        val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val addr = addrRaw.trim()
        if (addr.isEmpty()) return null
        return if (addr.contains(':')) {
            // IPv6（用户按占位提示可能带或不带方括号）→ 统一 [host]:port
            val body = addr.removePrefix("[").removeSuffix("]")
            if (body.isEmpty() || body.any { it == '[' || it == ']' }) null
            else "[$body]:$port"
        } else {
            if (addr.any { it == '[' || it == ']' }) null else "$addr:$port"
        }
    }
}
