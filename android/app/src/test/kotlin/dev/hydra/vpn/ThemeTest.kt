package dev.hydra.vpn

import dev.hydra.vpn.ui.DarkColorScheme
import dev.hydra.vpn.ui.AbyssColorScheme
import dev.hydra.vpn.ui.LightColorScheme
import dev.hydra.vpn.ui.SemanticAbyss
import dev.hydra.vpn.ui.SemanticDark
import dev.hydra.vpn.ui.SemanticLight
import dev.hydra.vpn.ui.ThemeMode
import dev.hydra.vpn.ui.themeModeFrom
import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 主题模块桌面 JVM 单测（T1/T5 验收）：ThemeMode 持久化往返 + 品牌色板锚点断言。
 * 色值源头：docs/design/安卓端UI重设计方案-v1.md §3.1（桌面 v4.1 令牌）。
 */
class ThemeTest {

    // ── ThemeMode 往返（SharedPreferences 只存枚举名字符串） ──

    @Test
    fun themeModeRoundTrip() {
        ThemeMode.entries.forEach { mode ->
            assertEquals("枚举名应能无损还原: $mode", mode, themeModeFrom(mode.name))
        }
    }

    @Test
    fun themeModeDefaultsToSystemOnUnknownOrNull() {
        // R2：存储未知值/缺失值必须回退「跟随系统」（默认动态取色）
        assertEquals(ThemeMode.System, themeModeFrom(null))
        assertEquals(ThemeMode.System, themeModeFrom(""))
        assertEquals(ThemeMode.System, themeModeFrom("material_you_x"))
        assertEquals(ThemeMode.System, themeModeFrom("dark ")) // 大小写敏感防呆：非法即回退
    }

    @Test
    fun themeModeLabels() {
        // 设置页四选行文案（§3.1 表）
        assertEquals("跟随系统", ThemeMode.System.label)
        assertEquals("深色", ThemeMode.Dark.label)
        assertEquals("浅色", ThemeMode.Light.label)
        assertEquals("深海", ThemeMode.Abyss.label)
        assertEquals(4, ThemeMode.entries.size)
    }

    // ── 品牌色板锚点（对齐桌面 v4.1 令牌） ──

    @Test
    fun darkPaletteAnchors() {
        assertEquals(0xFF12141C, DarkColorScheme.background.toArgbBits())
        assertEquals(0xFF1A1D29, DarkColorScheme.surfaceVariant.toArgbBits())
        assertEquals(0xFF4C8DFF, DarkColorScheme.primary.toArgbBits())
        assertEquals(0xFFE8EAF2, DarkColorScheme.onBackground.toArgbBits())
    }

    @Test
    fun abyssPaletteAnchors() {
        assertEquals(0xFF0A1220, AbyssColorScheme.background.toArgbBits())
        assertEquals(0xFF101B2E, AbyssColorScheme.surfaceVariant.toArgbBits())
        assertEquals(0xFF2DD4BF, AbyssColorScheme.primary.toArgbBits())
        assertEquals(0xFFD8E4F0, AbyssColorScheme.onBackground.toArgbBits())
    }

    @Test
    fun lightPaletteAnchors() {
        assertEquals(0xFFF5F6FA, LightColorScheme.background.toArgbBits())
        assertEquals(0xFF2563EB, LightColorScheme.primary.toArgbBits())
    }

    @Test
    fun semanticColorsRespectContrastRulings() {
        // R1：大按钮内文字一律品牌深字（白字对比度不达标被否决）
        assertEquals(0xFF0A1220, SemanticAbyss.onAccent.toArgbBits())
        assertEquals(0xFF12141C, SemanticDark.onAccent.toArgbBits())
        // R2：Light warning 锚定桌面修正值 #B45309（4.65:1），非旧表 #D97706
        assertEquals(0xFFB45309, SemanticLight.warning.toArgbBits())
        // 状态环四态色（连接中 = 各主题 accent）
        assertEquals(SemanticAbyss.accent, SemanticAbyss.ringConnecting)
        assertEquals(SemanticLight.accent, SemanticLight.ringConnecting)
    }

    /** Color.value 的 ARGB 打包在 ULong 高 32 位，取出为 0xAARRGGBB Long。 */
    private fun Color.toArgbBits(): Long = ((value shr 32).toLong() and 0xFFFFFFFFL)
}
