//! 视觉规范装配：自定义字体装载、统一深色主题、统一卡片 Frame。

use crate::palette;
use eframe::egui;

/// UI 重设计第三批：统一卡片 Frame 规范——卡片底色 + 1px 描边 + 圆角 8 + 内边距 MD、
/// 外边距 XS（视觉规范收口：所有新卡片走本函数，不再散落 Frame::group）。
pub(crate) fn card_frame(_ui: &egui::Ui) -> egui::Frame {
    egui::Frame::none()
        .fill(palette::BG_CARD)
        .stroke(egui::Stroke::new(1.0_f32, palette::BORDER))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(palette::SPACING_MD))
        .outer_margin(egui::Margin::same(palette::SPACING_XS))
}

pub(crate) fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 添加中文字体支持
    // 尝试加载Noto Sans CJK字体
    let font_data = include_bytes!("../fonts/NotoSansCJK-Regular.ttc");
    fonts.font_data.insert(
        "noto_sans_cjk".to_owned(),
        egui::FontData::from_owned(font_data.to_vec()),
    );

    // 将中文字体添加到字体族中
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("noto_sans_cjk".to_owned());

    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("noto_sans_cjk".to_owned());

    ctx.set_fonts(fonts);
}

/// Team-UI：统一深色主题。
///
/// 根因说明：旧版 `apply_dark_theme` 从 egui 默认 style（**浅色 Visuals**）出发，
/// 只改了圆角/选中色/个别 fg_stroke，从未设置 `Visuals::dark()`——
/// 因此面板背景保持白色，而按深底设计的淡灰文字落在白底上不可读。
/// 修复：以 `Visuals::dark()` 为基底整体替换，再叠加高对比配色与圆角/间距；
/// SidePanel/CentralPanel/Window 均未单独设置 fill，全部走 visuals，一处生效全局生效。
///
/// 对比度清单（正文对各自背景，WCAG 相对亮度计算）：
/// - 正文 TEXT   #E8EAED（相对亮度≈0.79）on 面板底 #1B1E24（≈0.012）→ ≈13.5:1
/// - 次要 WEAK   #A8B0BC（≈0.43）on #1B1E24 → ≈7.7:1（ui.small/来源标记仍达标）
/// - 强调 ACCENT #7AB3FF（≈0.44）on #1B1E24 → ≈7.9:1
/// - 成功 GREEN  #7DE297（≈0.63）on #1B1E24 → ≈11:1
/// - 警告 YELLOW #FFD666（≈0.70）on #1B1E24 → ≈12:1
/// - 错误 RED    #FF8A80（≈0.42）on #1B1E24 → ≈7.6:1
/// - 输入框文字  #E8EAED on 输入框底 #121418（≈0.006）→ ≈14.6:1
pub(crate) fn apply_dark_theme(ctx: &egui::Context) {
    // 视觉规范化第一步：颜色全部取自集中式色板 palette（本函数只做 Visuals 装配）
    let bg_panel = palette::BG_PANEL;
    let bg_window = palette::BG_CARD;
    let bg_extreme = palette::BG_EXTREME;
    let text = palette::TEXT;
    let weak = palette::TEXT_WEAK;
    let accent = palette::ACCENT;

    let mut style = (*ctx.style()).clone();
    // 关键修复：以深色 Visuals 为基底（默认是 light = 白底）
    style.visuals = egui::Visuals::dark();
    let vis = &mut style.visuals;
    // 面板/窗口/输入框背景统一深色
    vis.panel_fill = bg_panel;
    vis.window_fill = bg_window;
    vis.extreme_bg_color = bg_extreme; // TextEdit / 折叠区背景
    vis.faint_bg_color = palette::BG_FAINT; // 斑马纹/弱分隔
                                            // 文字：正文高对比，次要文字（ui.small / weak）仍 ≥7:1
    vis.override_text_color = Some(text);
    vis.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, weak); // 分隔线文字等
    vis.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, text);
    vis.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, accent);
    vis.widgets.active.fg_stroke = egui::Stroke::new(1.5_f32, accent);
    vis.widgets.open.fg_stroke = egui::Stroke::new(1.0_f32, accent);
    vis.hyperlink_color = accent;
    // 选中态
    vis.selection.bg_fill = accent.gamma_multiply(0.45);
    vis.selection.stroke = egui::Stroke::new(1.0_f32, accent);
    // 圆角 / 行间距
    vis.window_rounding = egui::Rounding::same(6.0);
    vis.menu_rounding = egui::Rounding::same(6.0);
    // 全局元素间距：统一从 palette 间距常量取（水平/垂直同为 sm=8）
    style.spacing.item_spacing = egui::vec2(palette::SPACING_SM, palette::SPACING_SM);
    ctx.set_style(style);
}
