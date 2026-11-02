package dev.hydra.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** [L 修复] 手动添加节点地址归一化的桌面 JVM 单测。 */
class NodeAddrTest {

    @Test
    fun ipv4_passes_through() {
        assertEquals("1.2.3.4:443", NodeAddr.normalizeManual("1.2.3.4", "443"))
    }

    @Test
    fun bare_ipv6_gets_brackets() {
        // 主回归：裸 v6 此前产出 "::1:443"（非法，双端拒绝）
        assertEquals("[::1]:443", NodeAddr.normalizeManual("::1", "443"))
    }

    @Test
    fun bracketed_ipv6_idempotent() {
        assertEquals("[::1]:443", NodeAddr.normalizeManual("[::1]", "443"))
        assertEquals("[2001:db8::1]:443", NodeAddr.normalizeManual("[2001:db8::1]", "443"))
    }

    @Test
    fun invalid_inputs_rejected() {
        assertNull(NodeAddr.normalizeManual("", "443"))
        assertNull(NodeAddr.normalizeManual("1.2.3.4", "0"))
        assertNull(NodeAddr.normalizeManual("1.2.3.4", "70000"))
        assertNull(NodeAddr.normalizeManual("1.2.3.4", "abc"))
        // 未闭合括号宽容归一化：用户意图明确（[::1]）→ 自动补全为合法形态
        assertEquals("[::1]:443", NodeAddr.normalizeManual("[::1", "443"))
        assertNull("v4 夹括号", NodeAddr.normalizeManual("1.2.3[4]", "443"))
    }
}
