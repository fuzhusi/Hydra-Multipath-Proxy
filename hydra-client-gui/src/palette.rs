//! 运行时三主题色板（UI 重设计 v4.1 / 评审 R11 零锁方案）。
//!
//! 架构：`UiTheme`（三主题种类）+ 三套 `const Palette` 预设 +
//! `static THEME_KIND: AtomicU8`。每字段一个零成本取值函数（`palette::bg_card()`
//! 等），内部按原子读到的主题种类 match 返回 `&'static` 预设字段——
//! 无 RwLock、无 clone，每帧数百次取色成本可忽略。
//!
//! 色值依据：《桌面端UI重设计方案-v4.md》§3.1 三主题色板表 + 评审 R1-R4 修正：
//! - R1：text_faint 三主题重定（Dark #9AA3B2 / Light #767676 / Abyss #6E86A8）；
//! - R2：Light warning 加深 #B45309；
//! - R3：补全现行全部令牌 + 新增 text_disabled/splitter/shadow/accent_hover/
//!   accent_pressed/chart_up/chart_down/chart_grid；
//! - R4：text_on_accent 按主题显式（Dark/Light 深墨 #0D1522，Abyss #0A1220）。
//!
//! 机械替换约定：全仓 `palette::XXX` → `palette::xxx()`（字段名转 snake_case）；
//! FONT_*/SPACING_*/RADIUS_* 是尺寸常量，保留 const 不参与替换。

use eframe::egui::{self, Color32};

// ── 主题种类 ──

/// 三主题种类（Copy 枚举，存入 AtomicU8 的唯一事实来源）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UiTheme {
    /// 深色（默认）
    Dark,
    /// 浅色
    Light,
    /// 深海（Hydra 品牌：深蓝黑底 + 青绿主色 + 紫点缀）
    Abyss,
}

impl UiTheme {
    /// 全部主题（设置页三选卡下一批次接入时消费；当前仅供测试与文档）
    #[allow(dead_code)]
    pub const ALL: [UiTheme; 3] = [UiTheme::Dark, UiTheme::Light, UiTheme::Abyss];

    /// 中文名
    pub fn label(self) -> &'static str {
        match self {
            UiTheme::Dark => "深色",
            UiTheme::Light => "浅色",
            UiTheme::Abyss => "深海",
        }
    }

    /// 循环切换的下一个主题（侧栏 ◐ 点按顺序）
    pub fn next(self) -> UiTheme {
        match self {
            UiTheme::Dark => UiTheme::Light,
            UiTheme::Light => UiTheme::Abyss,
            UiTheme::Abyss => UiTheme::Dark,
        }
    }

    /// 持久化字符串（config.ui_theme 字段取值）
    pub fn as_config_str(self) -> &'static str {
        match self {
            UiTheme::Dark => "dark",
            UiTheme::Light => "light",
            UiTheme::Abyss => "abyss",
        }
    }

    /// 从持久化字符串解析；None/空串/未知值 → None（回落默认主题）
    pub fn from_config_str(s: &str) -> Option<UiTheme> {
        match s.trim() {
            "dark" => Some(UiTheme::Dark),
            "light" => Some(UiTheme::Light),
            "abyss" => Some(UiTheme::Abyss),
            _ => None,
        }
    }

    /// 切换图标（◐ 一枚，随主题含义由 tooltip 说明）
    pub fn icon(self) -> &'static str {
        match self {
            UiTheme::Dark => "🌙",
            UiTheme::Light => "☀",
            UiTheme::Abyss => "🌊",
        }
    }
}

// ── 色板结构 ──

/// 一套完整色板（R3 令牌全集；所有字段 Color32，结构体 Copy 可零成本传栈）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// 应用/面板底（侧栏与内容区；设计表 bg_app）
    pub bg_panel: Color32,
    /// 卡片底（设计表 bg_card）
    pub bg_card: Color32,
    /// 卡片 hover 底
    pub bg_card_hover: Color32,
    /// 输入框/极端底
    pub bg_extreme: Color32,
    /// 斑马纹/弱分隔底
    pub bg_faint: Color32,
    /// 侧栏底（比面板更深一档）
    pub bg_sidebar: Color32,
    /// 卡片描边/分隔线
    pub border: Color32,
    /// 强描边（焦点环/危险边框）
    pub border_strong: Color32,
    /// 主强调色（选中/主按钮/链接）
    pub accent: Color32,
    /// 强调色 hover 态
    pub accent_hover: Color32,
    /// 强调色按压态
    pub accent_pressed: Color32,
    /// 第二强调色（仅点缀：Abyss 连接页徽标；Dark/Light 与 accent 同值）
    pub accent2: Color32,
    /// 成功 / 低延迟（<200ms）
    pub success: Color32,
    /// 警告 / 中延迟（200–500ms）
    pub warning: Color32,
    /// 危险 / 高延迟（≥500ms）与错误
    pub danger: Color32,
    /// 信息（中性提示）
    pub info: Color32,
    /// 危险横幅底（横幅 = 语义底 + 同系前景双通道）
    pub danger_bg: Color32,
    /// 警告横幅底
    pub warning_bg: Color32,
    /// 成功横幅底
    pub success_bg: Color32,
    /// 信息横幅底
    pub info_bg: Color32,
    /// 强调色之上的文字（R4：按主题显式深墨，禁用白字兜底）
    pub text_on_accent: Color32,
    /// 一级文本：正文/标题
    pub text: Color32,
    /// 二级文本：次要说明（ui.small 同级）
    pub text_weak: Color32,
    /// 三级文本：占位/未验证状态点（R1 修正色）
    pub text_faint: Color32,
    /// 控件禁用态前景（add_enabled(false) 场景走 Visuals inactive fg_stroke）
    pub text_disabled: Color32,
    /// 分隔线（ui.separator()，走 Visuals widgets.noninteractive.bg_stroke）
    pub splitter: Color32,
    /// 窗口/弹层阴影色（Light 下调淡防显脏）
    pub shadow: Color32,
    /// 图表上行曲线
    pub chart_up: Color32,
    /// 图表下行曲线
    pub chart_down: Color32,
    /// 图表网格线（R6：与 bg_card 亮度相对差 ≥1.15，肉眼可辨）
    pub chart_grid: Color32,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

// 注：Color32::from_rgba_unmultiplied 非 const；带透明度的令牌（shadow）用
// const 的 from_black_alpha / from_rgba_premultiplied 直接给预乘分量。

/// 深色（默认主题；色值 = 设计 §3.1 Dark 列 + R1/R4 修正）
pub const DARK: Palette = Palette {
    bg_panel: rgb(0x12, 0x14, 0x1C),
    bg_card: rgb(0x1A, 0x1D, 0x29),
    bg_card_hover: rgb(0x20, 0x24, 0x36),
    bg_extreme: rgb(0x0E, 0x10, 0x16),
    bg_faint: rgb(0x23, 0x27, 0x36),
    bg_sidebar: rgb(0x0E, 0x10, 0x16),
    border: rgb(0x2A, 0x2E, 0x40),
    border_strong: rgb(0x4C, 0x8D, 0xFF),
    accent: rgb(0x4C, 0x8D, 0xFF),
    accent_hover: rgb(0x6B, 0xA1, 0xFF),
    accent_pressed: rgb(0x3A, 0x73, 0xD9),
    accent2: rgb(0x4C, 0x8D, 0xFF),
    success: rgb(0x34, 0xD3, 0x99),
    warning: rgb(0xFB, 0xBF, 0x24),
    danger: rgb(0xF8, 0x71, 0x71),
    info: rgb(0x8A, 0xC8, 0xE8),
    danger_bg: rgb(0x3A, 0x22, 0x24),
    warning_bg: rgb(0x3A, 0x32, 0x1E),
    success_bg: rgb(0x1E, 0x32, 0x26),
    info_bg: rgb(0x1E, 0x2A, 0x38),
    text_on_accent: rgb(0x0D, 0x15, 0x22),
    text: rgb(0xE8, 0xEA, 0xF2),
    text_weak: rgb(0x9A, 0xA0, 0xB5),
    text_faint: rgb(0x9A, 0xA3, 0xB2), // R1：提亮至对 bg_card ≥3:1
    text_disabled: rgb(0x6E, 0x76, 0x87),
    splitter: rgb(0x34, 0x3A, 0x4D),
    shadow: Color32::from_black_alpha(96),
    chart_up: rgb(0x34, 0xD3, 0x99),
    chart_down: rgb(0x4C, 0x8D, 0xFF),
    chart_grid: rgb(0x2E, 0x33, 0x45), // R6：与 bg_card 相对差 1.33
};

/// 浅色（色值 = 设计 §3.1 Light 列 + R1/R2/R4 修正）
pub const LIGHT: Palette = Palette {
    bg_panel: rgb(0xF5, 0xF6, 0xFA),
    bg_card: rgb(0xFF, 0xFF, 0xFF),
    bg_card_hover: rgb(0xF0, 0xF2, 0xF8),
    bg_extreme: rgb(0xF0, 0xF2, 0xF8),
    bg_faint: rgb(0xEE, 0xF0, 0xF6),
    bg_sidebar: rgb(0xFF, 0xFF, 0xFF),
    border: rgb(0xE2, 0xE5, 0xEF),
    border_strong: rgb(0x25, 0x63, 0xEB),
    accent: rgb(0x25, 0x63, 0xEB),
    accent_hover: rgb(0x3B, 0x82, 0xF6),
    accent_pressed: rgb(0x1E, 0x40, 0xAF),
    accent2: rgb(0x25, 0x63, 0xEB),
    success: rgb(0x04, 0x78, 0x57), // R2：正文级达标
    warning: rgb(0xB4, 0x53, 0x09), // R2：加深至 on bg_app ≥3:1
    danger: rgb(0xDC, 0x26, 0x26),
    info: rgb(0x03, 0x69, 0xA1),
    danger_bg: rgb(0xFE, 0xE2, 0xE2),
    warning_bg: rgb(0xFE, 0xF3, 0xC7),
    success_bg: rgb(0xD1, 0xFA, 0xE5),
    info_bg: rgb(0xE0, 0xF2, 0xFE),
    text_on_accent: rgb(0x0D, 0x15, 0x22),
    text: rgb(0x1A, 0x1D, 0x29),
    text_weak: rgb(0x6B, 0x72, 0x80),
    text_faint: rgb(0x76, 0x76, 0x76), // R1：加深至 ≥3:1
    text_disabled: rgb(0x9C, 0xA3, 0xAF),
    splitter: rgb(0xE2, 0xE5, 0xEF),
    shadow: Color32::from_rgba_premultiplied(2, 3, 6, 40), // R5 附件：Light 阴影调淡
    chart_up: rgb(0x05, 0x96, 0x69),
    chart_down: rgb(0x25, 0x63, 0xEB),
    chart_grid: rgb(0xEC, 0xED, 0xF3), // R6：与 bg_card 相对差 ≈1.16
};

/// 深海「Abyss」（Hydra 品牌：深蓝黑底 + 青绿主色；紫 #8B5CF6 仅作点缀）
pub const ABYSS: Palette = Palette {
    bg_panel: rgb(0x0A, 0x12, 0x20),
    bg_card: rgb(0x10, 0x1B, 0x2E),
    bg_card_hover: rgb(0x16, 0x23, 0x3C),
    bg_extreme: rgb(0x08, 0x10, 0x20),
    bg_faint: rgb(0x16, 0x23, 0x3C),
    bg_sidebar: rgb(0x08, 0x10, 0x20),
    border: rgb(0x1E, 0x30, 0x50),
    border_strong: rgb(0x2D, 0xD4, 0xBF),
    accent: rgb(0x2D, 0xD4, 0xBF),
    accent_hover: rgb(0x5E, 0xEA, 0xD4),
    accent_pressed: rgb(0x14, 0xB8, 0xA6),
    accent2: rgb(0x8B, 0x5C, 0xF6), // 紫：仅点缀（连接页徽标），不作正文
    success: rgb(0x34, 0xD3, 0x99),
    warning: rgb(0xFB, 0xBF, 0x24),
    danger: rgb(0xF8, 0x71, 0x71),
    info: rgb(0x7D, 0xD3, 0xFC),
    danger_bg: rgb(0x3A, 0x22, 0x24),
    warning_bg: rgb(0x3A, 0x32, 0x1E),
    success_bg: rgb(0x1E, 0x32, 0x26),
    info_bg: rgb(0x1E, 0x2A, 0x38),
    text_on_accent: rgb(0x0A, 0x12, 0x20), // R4：accent×白仅 1.86，必须深字
    text: rgb(0xD8, 0xE4, 0xF0),
    text_weak: rgb(0x7C, 0x93, 0xB5),
    text_faint: rgb(0x6E, 0x86, 0xA8), // R1：提亮至 ≥3:1
    text_disabled: rgb(0x55, 0x68, 0x8A),
    splitter: rgb(0x24, 0x3A, 0x5E),
    shadow: Color32::from_black_alpha(110),
    chart_up: rgb(0x34, 0xD3, 0x99),
    chart_down: rgb(0x2D, 0xD4, 0xBF),
    chart_grid: rgb(0x1C, 0x2C, 0x4A), // R6：与 bg_card 相对差 ≥1.15
};

// ── 零锁全局主题（R11）──

/// 主题种类原子量（0=Dark 1=Light 2=Abyss；与 UiTheme::ALL 下标一致）
static THEME_KIND: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn kind_to_theme(kind: u8) -> UiTheme {
    match kind % 3 {
        1 => UiTheme::Light,
        2 => UiTheme::Abyss,
        _ => UiTheme::Dark,
    }
}

fn kind_index(t: UiTheme) -> u8 {
    match t {
        UiTheme::Dark => 0,
        UiTheme::Light => 1,
        UiTheme::Abyss => 2,
    }
}

/// 切换全局主题（只切内存；config 持久化由调用方负责——评审 R12）
pub fn set_theme(t: UiTheme) {
    THEME_KIND.store(kind_index(t), std::sync::atomic::Ordering::Relaxed);
}

/// 当前主题种类
pub fn current_theme() -> UiTheme {
    kind_to_theme(THEME_KIND.load(std::sync::atomic::Ordering::Relaxed))
}

/// 当前主题预设（内部查表用；对外一律走下方零成本取值函数）
fn current() -> &'static Palette {
    match current_theme() {
        UiTheme::Dark => &DARK,
        UiTheme::Light => &LIGHT,
        UiTheme::Abyss => &ABYSS,
    }
}

// ── 每字段零成本取值函数（机械替换目标：palette::XXX → palette::xxx()）──

/// 应用/面板底
pub fn bg_panel() -> Color32 {
    current().bg_panel
}
/// 卡片底
pub fn bg_card() -> Color32 {
    current().bg_card
}
/// 卡片 hover 底
pub fn bg_card_hover() -> Color32 {
    current().bg_card_hover
}
/// 输入框/极端底
pub fn bg_extreme() -> Color32 {
    current().bg_extreme
}
/// 斑马纹/弱分隔底
pub fn bg_faint() -> Color32 {
    current().bg_faint
}
/// 侧栏底
pub fn bg_sidebar() -> Color32 {
    current().bg_sidebar
}
/// 卡片描边/分隔线
pub fn border() -> Color32 {
    current().border
}
/// 强描边（焦点环/危险边框）
pub fn border_strong() -> Color32 {
    current().border_strong
}
/// 主强调色
pub fn accent() -> Color32 {
    current().accent
}
/// 强调色 hover 态
pub fn accent_hover() -> Color32 {
    current().accent_hover
}
/// 强调色按压态
pub fn accent_pressed() -> Color32 {
    current().accent_pressed
}
/// 第二强调色（仅点缀）
/// （v4 预留：Abyss 连接页徽标消费，下一批次接入；Dark/Light 与 accent 同值）
#[allow(dead_code)]
pub fn accent2() -> Color32 {
    current().accent2
}
/// 成功语义色
pub fn success() -> Color32 {
    current().success
}
/// 警告语义色
pub fn warning() -> Color32 {
    current().warning
}
/// 危险语义色
pub fn danger() -> Color32 {
    current().danger
}
/// 信息语义色
pub fn info() -> Color32 {
    current().info
}
/// 危险横幅底
pub fn danger_bg() -> Color32 {
    current().danger_bg
}
/// 警告横幅底
pub fn warning_bg() -> Color32 {
    current().warning_bg
}
/// 成功横幅底
pub fn success_bg() -> Color32 {
    current().success_bg
}
/// 信息横幅底
pub fn info_bg() -> Color32 {
    current().info_bg
}
/// 强调色上的文字（R4）
pub fn text_on_accent() -> Color32 {
    current().text_on_accent
}
/// 一级文本
pub fn text() -> Color32 {
    current().text
}
/// 二级文本
pub fn text_weak() -> Color32 {
    current().text_weak
}
/// 三级文本（R1 修正色）
pub fn text_faint() -> Color32 {
    current().text_faint
}
/// 禁用态前景
pub fn text_disabled() -> Color32 {
    current().text_disabled
}
/// 分隔线
pub fn splitter() -> Color32 {
    current().splitter
}
/// 阴影色
pub fn shadow() -> Color32 {
    current().shadow
}
/// 图表上行曲线
pub fn chart_up() -> Color32 {
    current().chart_up
}
/// 图表下行曲线
pub fn chart_down() -> Color32 {
    current().chart_down
}
/// 图表网格线
/// （v4 预留：egui_plot 0.27 网格色派生自 text_color，无法直连本令牌——
/// 留作 M3 自绘图表/图例样式时消费，见评审 §三）
#[allow(dead_code)]
pub fn chart_grid() -> Color32 {
    current().chart_grid
}

// ── 字号层级（全局统一，五级 + v4.1 六档新增 22px 数据值档；尺寸常量保留 const）──
/// 页面标题
pub const FONT_HEADING: f32 = 18.0;
/// 数据值大字（统计卡主数值/状态字，R10 新增第 6 档）
pub const FONT_DATA: f32 = 22.0;
/// 卡片标题/节点名
pub const FONT_TITLE: f32 = 15.0;
/// 正文
pub const FONT_BODY: f32 = 13.0;
/// 次要文字/标签（最小可读字号下限）
pub const FONT_SECONDARY: f32 = 12.0;
/// 徽标（五级中最小；最小字号下限）
pub const FONT_BADGE: f32 = 11.0;

// ── 间距节奏（4px 基准，尺寸常量保留 const）──
/// 特小间距：行内元素间 / 卡片外边距
pub const SPACING_XS: f32 = 4.0;
/// 小间距：卡片间 / 表单行距
pub const SPACING_SM: f32 = 8.0;
/// 中间距：卡片内边距 / 网格列距
pub const SPACING_MD: f32 = 12.0;
/// 大间距：区块间距
pub const SPACING_LG: f32 = 16.0;
/// 特大间距：页面级分区
pub const SPACING_XL: f32 = 24.0;

// ── 圆角规范（尺寸常量保留 const）──
/// 卡片圆角
pub const RADIUS_CARD: f32 = 8.0;
/// 控件圆角（按钮/输入框/徽标）
pub const RADIUS_CTRL: f32 = 6.0;

/// 节点健康五态（状态三通道编码的单点判定——颜色/字形/文案词共用同一枚举，
/// 消灭"色相单通道"的 P0 可访问性问题）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHealth {
    /// 从未测速
    Untested,
    /// 测速进行中
    Testing,
    /// 在线（握手通过且延迟 <500ms）
    Online,
    /// 劣化（在线但延迟 ≥500ms）
    Degraded,
    /// 离线（测过但失败）
    Offline,
}

/// 单点判定：节点健康态（connected/checked/latency_ms 三参数来自节点条目）
pub fn node_health(connected: bool, checked: bool, latency_ms: Option<u64>) -> NodeHealth {
    if !checked {
        NodeHealth::Untested
    } else if connected {
        if latency_ms.is_some_and(|ms| ms >= 500) {
            NodeHealth::Degraded
        } else {
            NodeHealth::Online
        }
    } else {
        NodeHealth::Offline
    }
}

/// 健康态 → 语义色
pub fn health_color(health: NodeHealth) -> egui::Color32 {
    match health {
        NodeHealth::Untested => text_faint(),
        NodeHealth::Testing => info(),
        NodeHealth::Online => success(),
        NodeHealth::Degraded => warning(),
        NodeHealth::Offline => danger(),
    }
}

/// 健康态 → 字形（色盲通道：○未测 ◐测速中 ●在线 ◐劣化 ✕离线）
pub fn health_symbol(health: NodeHealth) -> &'static str {
    match health {
        NodeHealth::Untested => "○",
        NodeHealth::Testing => "◐",
        NodeHealth::Online => "●",
        NodeHealth::Degraded => "◐",
        NodeHealth::Offline => "✕",
    }
}

/// 健康态 → 文案词（文字通道）
pub fn health_label(health: NodeHealth) -> &'static str {
    match health {
        NodeHealth::Untested => "未验证",
        NodeHealth::Testing => "测速中",
        NodeHealth::Online => "在线",
        NodeHealth::Degraded => "劣化",
        NodeHealth::Offline => "离线",
    }
}

/// 延迟色标：<200ms 绿 / <500ms 黄 / 其余红；None（未测）= 灰。
/// 与 v3 设计文档 §交互细节 的色阶一致。
pub fn latency_color(latency_ms: Option<u64>) -> egui::Color32 {
    match latency_ms {
        None => text_faint(),
        Some(ms) if ms < 200 => success(),
        Some(ms) if ms < 500 => warning(),
        Some(_) => danger(),
    }
}

/// 节点状态色点（经 [`node_health`] 单点判定 + [`health_color`] 着色。
/// 薄封装，暂仅供测试与 P1 页面接入期使用）
#[allow(dead_code)]
pub fn status_color(connected: bool, checked: bool, latency_ms: Option<u64>) -> egui::Color32 {
    health_color(node_health(connected, checked, latency_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// set_theme 是全局态：串行化涉及切主题的测试，避免并行互踩
    static THEME_LOCK: Mutex<()> = Mutex::new(());

    /// WCAG 2.x 相对亮度
    fn rel_lum(c: Color32) -> f64 {
        let lin = |v: u8| -> f64 {
            let s = v as f64 / 255.0;
            if s <= 0.03928 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(c.r()) + 0.7152 * lin(c.g()) + 0.0722 * lin(c.b())
    }

    /// WCAG 对比度（大值在前）
    fn contrast(a: Color32, b: Color32) -> f64 {
        let (hi, lo) = if rel_lum(a) >= rel_lum(b) {
            (rel_lum(a), rel_lum(b))
        } else {
            (rel_lum(b), rel_lum(a))
        };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn latency_color_thresholds() {
        // 延迟色标：None=灰 / <200 绿 / 200-500 黄 / ≥500 红（v4 原有回归项）
        // （取值函数走全局主题，需与切主题测试串行）
        let _g = THEME_LOCK.lock().unwrap();
        assert_eq!(latency_color(None), text_faint());
        assert_eq!(latency_color(Some(0)), success());
        assert_eq!(latency_color(Some(199)), success());
        assert_eq!(latency_color(Some(200)), warning());
        assert_eq!(latency_color(Some(499)), warning());
        assert_eq!(latency_color(Some(500)), danger());
        assert_eq!(latency_color(Some(2000)), danger());
    }

    #[test]
    fn node_status_color_states() {
        // 节点状态三通道判定（v4 原有回归项，经 node_health + health_color 通路）
        let _g = THEME_LOCK.lock().unwrap();
        assert_eq!(health_color(node_health(false, false, None)), text_faint());
        assert_eq!(health_color(node_health(true, true, Some(45))), success());
        assert_eq!(health_color(node_health(true, true, Some(800))), warning());
        assert_eq!(health_color(node_health(false, true, None)), danger());
    }

    #[test]
    fn theme_switch_changes_values() {
        let _g = THEME_LOCK.lock().unwrap();
        // 三主题切换后取值随动（零锁查表通路验证）
        set_theme(UiTheme::Dark);
        assert_eq!(bg_panel(), DARK.bg_panel);
        assert_eq!(current_theme(), UiTheme::Dark);
        set_theme(UiTheme::Light);
        assert_eq!(bg_card(), LIGHT.bg_card);
        assert_ne!(bg_card(), DARK.bg_card);
        set_theme(UiTheme::Abyss);
        assert_eq!(accent(), ABYSS.accent);
        assert_ne!(bg_panel(), LIGHT.bg_panel);
        set_theme(UiTheme::Dark);
        assert_eq!(bg_panel(), DARK.bg_panel);
    }

    #[test]
    fn contrast_key_pairs_all_themes() {
        // R1：三主题 text/text_faint 对 bg_card 达标；R2：Light warning on bg_panel ≥3
        // R4：text_on_accent 对 accent ≥3
        for t in UiTheme::ALL {
            set_theme(t);
            let p = current();
            assert!(
                contrast(p.text, p.bg_card) >= 4.5,
                "{:?} text×bg_card = {:.2}",
                t,
                contrast(p.text, p.bg_card)
            );
            assert!(
                contrast(p.text_faint, p.bg_card) >= 3.0,
                "{:?} faint×bg_card = {:.2}",
                t,
                contrast(p.text_faint, p.bg_card)
            );
            assert!(
                contrast(p.text_on_accent, p.accent) >= 3.0,
                "{:?} on_accent×accent = {:.2}",
                t,
                contrast(p.text_on_accent, p.accent)
            );
        }
        set_theme(UiTheme::Light);
        assert!(
            contrast(LIGHT.warning, LIGHT.bg_panel) >= 3.0,
            "R2: Light warning×bg_panel = {:.2}",
            contrast(LIGHT.warning, LIGHT.bg_panel)
        );
        // R6：三主题 chart_grid 对 bg_card 亮度相对差 ≥1.15
        for t in UiTheme::ALL {
            set_theme(t);
            let p = current();
            assert!(
                contrast(p.chart_grid, p.bg_card) >= 1.15,
                "{:?} grid×card = {:.2}",
                t,
                contrast(p.chart_grid, p.bg_card)
            );
        }
        set_theme(UiTheme::Dark);
    }

    #[test]
    fn ui_theme_roundtrip_and_labels() {
        // 持久化字符串往返 + 中文标签 + ALL/next 完备性
        assert_eq!(UiTheme::from_config_str("dark"), Some(UiTheme::Dark));
        assert_eq!(UiTheme::from_config_str("abyss"), Some(UiTheme::Abyss));
        assert_eq!(UiTheme::from_config_str(" 深色 "), None);
        for t in UiTheme::ALL {
            assert_eq!(UiTheme::from_config_str(t.as_config_str()), Some(t));
            assert!(!t.label().is_empty());
        }
        // 循环切换闭环：Dark→Light→Abyss→Dark
        let mut t = UiTheme::Dark;
        for _ in 0..3 {
            t = t.next();
        }
        assert_eq!(t, UiTheme::Dark);
    }

    #[test]
    fn three_presets_are_distinct() {
        // 三套预设互不相同（防止复制粘贴同色值）
        assert_ne!(DARK, LIGHT);
        assert_ne!(LIGHT, ABYSS);
        assert_ne!(DARK, ABYSS);
        // Abyss 双 accent 特色：accent2 紫仅点缀，与主 accent 不同
        assert_ne!(ABYSS.accent, ABYSS.accent2);
        assert_eq!(DARK.accent2, DARK.accent);
    }

    #[test]
    fn all_tokens_have_accessors() {
        // 全部 30 个取值函数与当前预设字段一一对应（机械替换正确性的兜底断言）
        let p = current();
        assert_eq!(bg_panel(), p.bg_panel);
        assert_eq!(bg_card(), p.bg_card);
        assert_eq!(bg_card_hover(), p.bg_card_hover);
        assert_eq!(bg_extreme(), p.bg_extreme);
        assert_eq!(bg_faint(), p.bg_faint);
        assert_eq!(bg_sidebar(), p.bg_sidebar);
        assert_eq!(border(), p.border);
        assert_eq!(border_strong(), p.border_strong);
        assert_eq!(accent(), p.accent);
        assert_eq!(accent_hover(), p.accent_hover);
        assert_eq!(accent_pressed(), p.accent_pressed);
        assert_eq!(accent2(), p.accent2);
        assert_eq!(success(), p.success);
        assert_eq!(warning(), p.warning);
        assert_eq!(danger(), p.danger);
        assert_eq!(info(), p.info);
        assert_eq!(danger_bg(), p.danger_bg);
        assert_eq!(warning_bg(), p.warning_bg);
        assert_eq!(success_bg(), p.success_bg);
        assert_eq!(info_bg(), p.info_bg);
        assert_eq!(text_on_accent(), p.text_on_accent);
        assert_eq!(text(), p.text);
        assert_eq!(text_weak(), p.text_weak);
        assert_eq!(text_faint(), p.text_faint);
        assert_eq!(text_disabled(), p.text_disabled);
        assert_eq!(splitter(), p.splitter);
        assert_eq!(shadow(), p.shadow);
        assert_eq!(chart_up(), p.chart_up);
        assert_eq!(chart_down(), p.chart_down);
        assert_eq!(chart_grid(), p.chart_grid);
    }
}
