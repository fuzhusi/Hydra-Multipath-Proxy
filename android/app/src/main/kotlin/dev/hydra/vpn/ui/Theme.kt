package dev.hydra.vpn.ui

import android.content.Context
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/*
 * 品牌主题（设计 §3.1 / 评审 R1-R3、R6）：
 * - 四模式：跟随系统（Android 12+ 动态取色）/ 深色 / 浅色 / 深海 Abyss。
 * - 色值与桌面端 v4.1 令牌锚定（同一套语义令牌，各自实现）：
 *   Dark  bg #12141C / card #1A1D29 / accent #4C8DFF / text #E8EAF2
 *   Abyss bg #0A1220 / card #101B2E / accent #2DD4BF / accent2 #8B5CF6 / text #D8E4F0
 *   Light bg #F5F6FA / card #FFFFFF  / accent #2563EB / text #1A1D29
 * - R1：大按钮内文字一律深字（Abyss #0A1220 = 11.22:1；Dark #12141C = 5.74:1），
 *   白字方案否决（1.67:1 / 3.20:1）；Light accent 上白字 5.17:1 达标可保留。
 * - R2：Light warning 锚定桌面修正值 #B45309（4.65:1），不用令牌表旧值 #D97706（2.95:1）。
 * - R3：语义色（success/warning/danger/状态环色）经 staticCompositionLocalOf 注入，
 *   只换 MaterialTheme.colorScheme 不够。
 * - R2/R3（存储）：主题偏好非敏感 → 普通 SharedPreferences「hydra_ui」，
 *   不进 SecureStore（避免 Keystore IO 与凭据耦合）。
 */

/** 主题模式四选（D1：动态取色为默认，尊重平台惯例；三品牌板对齐桌面端）。 */
enum class ThemeMode(val label: String) {
    System("跟随系统"),
    Dark("深色"),
    Light("浅色"),
    Abyss("深海"),
}

/** 存储字符串 → ThemeMode（未知值回退跟随系统；供持久化往返与单测）。 */
fun themeModeFrom(name: String?): ThemeMode =
    ThemeMode.entries.firstOrNull { it.name == name } ?: ThemeMode.System

/** 主题偏好存储：普通 SharedPreferences（R2，非 SecureStore）。 */
object ThemePrefs {
    private const val PREFS_NAME = "hydra_ui"
    private const val KEY_THEME = "ui_theme"

    fun load(context: Context): ThemeMode =
        themeModeFrom(
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_THEME, null),
        )

    fun save(context: Context, mode: ThemeMode) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString(KEY_THEME, mode.name).apply()
    }
}

/**
 * 品牌语义色（R3）：colorScheme 装不下的语义色统一从这里取。
 * 大按钮状态环色也在此收敛——动态取色模式下组件统一取 [accent]（回退
 * colorScheme.primary），避免四模式视觉漂移（评审 §一.1）。
 */
data class HydraColors(
    /** 主强调色（状态环 / 大按钮 / 链接） */
    val accent: Color,
    /** 次强调色（Abyss 紫 #8B5CF6；仅大字与装饰，评审 §二对比度注记） */
    val accent2: Color,
    val success: Color,
    val warning: Color,
    val danger: Color,
    /** 状态环四态色：已断开（灰）/ 连接中（accent）/ 已连接 / 错误 */
    val ringDisconnected: Color,
    val ringConnecting: Color,
    val ringConnected: Color,
    val ringError: Color,
    /** 大按钮内文字色（R1：深色系主题必须深字） */
    val onAccent: Color,
)

/** 语义色经此读取（静态注入：主题整体替换场景，static 开销更低）。 */
val LocalHydraColors = staticCompositionLocalOf<HydraColors> { ABYSS_HYDRA_COLORS }

/** 组件层统一取值口：非 @Composable 上下文不可用，优先 MaterialTheme 附近读取。 */
val hydraColors: HydraColors
    @Composable @ReadOnlyComposable get() = LocalHydraColors.current

// ── 语义色板（深色系 / 浅色系两套；Light success #059669 仅限状态大字，R13） ──

internal val SemanticDark = HydraColors(
    accent = Color(0xFF4C8DFF),
    accent2 = Color(0xFF8B5CF6),
    success = Color(0xFF34D399),
    warning = Color(0xFFFBBF24),
    danger = Color(0xFFF87171),
    ringDisconnected = Color(0xFF6B7280),
    ringConnecting = Color(0xFF4C8DFF),
    ringConnected = Color(0xFF34D399),
    ringError = Color(0xFFF87171),
    onAccent = Color(0xFF12141C), // R1：Dark accent 上深墨字（5.74:1）
)

internal val SemanticAbyss = SemanticDark.copy(
    accent = Color(0xFF2DD4BF),
    accent2 = Color(0xFF8B5CF6),
    ringConnecting = Color(0xFF2DD4BF),
    ringConnected = Color(0xFF34D399),
    onAccent = Color(0xFF0A1220), // R1：Abyss accent 上深字 #0A1220（11.22:1，白字 1.67 否决）
)

internal val SemanticLight = HydraColors(
    accent = Color(0xFF2563EB),
    accent2 = Color(0xFF7C3AED),
    success = Color(0xFF059669), // 3.49:1——仅限 28sp 状态大字，禁用于 14sp 正文（R13）
    warning = Color(0xFFB45309), // R2：桌面修正值（4.65:1；#D97706 仅 2.95 否决）
    danger = Color(0xFFDC2626),  // 4.47:1——限大字/横幅底（R13）
    ringDisconnected = Color(0xFF9CA3AF),
    ringConnecting = Color(0xFF2563EB),
    ringConnected = Color(0xFF059669),
    ringError = Color(0xFFDC2626),
    onAccent = Color(0xFFFFFFFF), // Light accent 上白字 5.17:1 达标
)

/** 供静态注入默认值与单测断言（品牌板对外只读）。 */
val ABYSS_HYDRA_COLORS = SemanticAbyss

// ── Material3 完整 ColorScheme（各主题一块，对齐桌面令牌） ──

/** 品牌深色板（= 桌面 Dark 令牌的 Android 映射）。 */
val DarkColorScheme: ColorScheme = darkColorScheme(
    primary = Color(0xFF4C8DFF),
    onPrimary = Color(0xFF12141C), // R1：深墨字
    primaryContainer = Color(0xFF1E2A45),
    onPrimaryContainer = Color(0xFFD6E3FF),
    secondary = Color(0xFF8B5CF6),
    onSecondary = Color(0xFF12141C),
    secondaryContainer = Color(0xFF241B3A),
    onSecondaryContainer = Color(0xFFE2D9FF),
    tertiary = Color(0xFF34D399),
    onTertiary = Color(0xFF0C1F17),
    tertiaryContainer = Color(0xFF143226),
    onTertiaryContainer = Color(0xFFB9F1DA),
    error = Color(0xFFF87171),
    onError = Color(0xFF2A0B0D),
    errorContainer = Color(0xFF3A1519),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF12141C),
    onBackground = Color(0xFFE8EAF2),
    surface = Color(0xFF12141C),
    onSurface = Color(0xFFE8EAF2),
    surfaceVariant = Color(0xFF1A1D29), // 卡片底
    onSurfaceVariant = Color(0xFFA7ADC0),
    outline = Color(0xFF4A5064),
    outlineVariant = Color(0xFF2A2E3D),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFFE8EAF2),
    inverseOnSurface = Color(0xFF12141C),
    inversePrimary = Color(0xFF2563EB),
    surfaceDim = Color(0xFF0D0F16),
    surfaceBright = Color(0xFF232634),
    surfaceContainerLowest = Color(0xFF10121A),
    surfaceContainerLow = Color(0xFF171A24),
    surfaceContainer = Color(0xFF1A1D29),
    surfaceContainerHigh = Color(0xFF21242F),
    surfaceContainerHighest = Color(0xFF282C39),
)

/** 品牌深海板（= 桌面 Abyss：bg #0A1220 / card #101B2E / accent 青绿 #2DD4BF）。 */
val AbyssColorScheme: ColorScheme = DarkColorScheme.copy(
    primary = Color(0xFF2DD4BF),
    onPrimary = Color(0xFF0A1220), // R1：深字（11.22:1）
    primaryContainer = Color(0xFF0E2E33),
    onPrimaryContainer = Color(0xFFB8F1EA),
    tertiary = Color(0xFF34D399),
    background = Color(0xFF0A1220),
    onBackground = Color(0xFFD8E4F0),
    surface = Color(0xFF0A1220),
    onSurface = Color(0xFFD8E4F0),
    surfaceVariant = Color(0xFF101B2E), // 卡片底
    onSurfaceVariant = Color(0xFF93A4BE),
    outline = Color(0xFF3D4C66),
    outlineVariant = Color(0xFF223050),
    surfaceDim = Color(0xFF060C17),
    surfaceBright = Color(0xFF1B2740),
    surfaceContainerLowest = Color(0xFF08101C),
    surfaceContainerLow = Color(0xFF0E1727),
    surfaceContainer = Color(0xFF101B2E),
    surfaceContainerHigh = Color(0xFF16223A),
    surfaceContainerHighest = Color(0xFF1C2A46),
)

/** 品牌浅色板（= 桌面 Light；warning 锚定 R2 修正值 #B45309）。 */
val LightColorScheme: ColorScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color(0xFFFFFFFF), // 5.17:1 达标（评审 §二 Light 表）
    primaryContainer = Color(0xFFD9E5FF),
    onPrimaryContainer = Color(0xFF0E2A66),
    secondary = Color(0xFF7C3AED),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFEDE4FF),
    onSecondaryContainer = Color(0xFF33176E),
    tertiary = Color(0xFF059669), // 仅大字（R13）
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFD3F3E4),
    onTertiaryContainer = Color(0xFF06342A),
    error = Color(0xFFDC2626),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFCD9D7),
    onErrorContainer = Color(0xFF4A0B08),
    background = Color(0xFFF5F6FA),
    onBackground = Color(0xFF1A1D29),
    surface = Color(0xFFF5F6FA),
    onSurface = Color(0xFF1A1D29),
    surfaceVariant = Color(0xFFFFFFFF), // 卡片底：浅色下卡片用白
    onSurfaceVariant = Color(0xFF5B6272),
    outline = Color(0xFFC3C8D4),
    outlineVariant = Color(0xFFE2E5EC),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFF1A1D29),
    inverseOnSurface = Color(0xFFF1F2F8),
    inversePrimary = Color(0xFF4C8DFF),
    surfaceDim = Color(0xFFDBDDE5),
    surfaceBright = Color(0xFFFBFCFE),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF7F8FC),
    surfaceContainer = Color(0xFFF2F4F9),
    surfaceContainerHigh = Color(0xFFECEEF5),
    surfaceContainerHighest = Color(0xFFE6E9F0),
)

// ── HydraTheme ──────────────────────────────────────────────────────────────

/** §4 几何体系（随 Theme.kt 走，避免两处定义）：主卡 20 / 卡与对话框 12 / 按钮 14。 */
private val HydraShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(20.dp),
)

/**
 * 品牌主题入口。
 * System：API≥31 Material You 动态取色（深浅随系统）；<31 用品牌深色中性板
 * （评审 §一.1：不得回落默认紫色板）。三品牌模式给静态板。
 * 语义色经 LocalHydraColors 下发（R3）；动态模式下语义色取当前深浅的
 * 品牌语义板，accent 回退 colorScheme.primary 统一取值口（评审 §一.1）。
 */
@Composable
fun HydraTheme(
    mode: ThemeMode = ThemeMode.System,
    content: @Composable () -> Unit,
) {
    val ctx = LocalContext.current
    val systemDark = isSystemInDarkTheme()
    val scheme: ColorScheme
    val hydra: HydraColors
    when (mode) {
        ThemeMode.System -> {
            if (Build.VERSION.SDK_INT >= 31) {
                scheme = if (systemDark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
                // 动态板：语义色沿用品牌语义板，accent 回退壁纸 primary（一处收敛）
                hydra = (if (systemDark) SemanticDark else SemanticLight).copy(
                    accent = scheme.primary,
                    ringConnecting = scheme.primary,
                )
            } else {
                // <31 中性蓝灰板 = 品牌深色板（评审：明确静态板而非默认紫）
                scheme = DarkColorScheme
                hydra = SemanticDark
            }
        }
        ThemeMode.Dark -> { scheme = DarkColorScheme; hydra = SemanticDark }
        ThemeMode.Light -> { scheme = LightColorScheme; hydra = SemanticLight }
        ThemeMode.Abyss -> { scheme = AbyssColorScheme; hydra = SemanticAbyss }
    }
    CompositionLocalProvider(LocalHydraColors provides hydra) {
        MaterialTheme(colorScheme = scheme, shapes = HydraShapes, content = content)
    }
}
