//! 视觉规范装配：自定义字体装载、三主题 Visuals 完整重写、统一卡片 Frame。
//!
//! R5（评审）：`apply_theme(ctx)` 按当前 [`crate::palette::current_theme`]
//! 重写**完整** egui::Visuals——widgets 三态/selection/separator/shadow/popup/
//! window fill/图例轴样式全部取 `palette::xxx()` 运行时值，切换主题后任何
//! 原生控件不得残留上一主题配色。

use crate::palette;
use eframe::egui;

/// UI 重设计第三批：统一卡片 Frame 规范——卡片底色 + 1px 描边 + 圆角 8 + 内边距 MD、
/// 外边距 XS（视觉规范收口：所有新卡片走本函数，不再散落 Frame::group）。
pub(crate) fn card_frame(_ui: &egui::Ui) -> egui::Frame {
    egui::Frame::none()
        .fill(palette::bg_card())
        .stroke(egui::Stroke::new(1.0_f32, palette::border()))
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

/// 按当前主题装配完整 Visuals（评审 R5 验收项）。
///
/// 前置：先 `palette::set_theme`，再调用本函数（启动首帧前 / 侧栏切换入口处）。
/// 要点：
/// - 全部颜色取 `palette::xxx()` 运行时值，不残留编译期常量；
/// - widgets 五态（noninteractive/inactive/hovered/active/open）前景、底色、描边
///   全量覆盖；
/// - selection / separator / shadow / popup / window fill / 图例轴样式一并重写；
/// - 间距/圆角从 palette 尺寸常量取（与主题无关，统一节奏）。
pub(crate) fn apply_theme(ctx: &egui::Context) {
    let text = palette::text();
    let weak = palette::text_weak();
    let accent = palette::accent();
    let bg_panel = palette::bg_panel();
    let bg_card = palette::bg_card();
    let bg_extreme = palette::bg_extreme();
    let border = palette::border();
    let splitter = palette::splitter();
    let shadow_color = palette::shadow();

    let mut style = (*ctx.style()).clone();
    // 以深/浅 Visuals 为基底（保留 egui 对阴影偏移等非颜色的合理默认），
    // 再全量覆盖颜色——Light 基底自带更轻的阴影语义，避免 Dark 残留
    style.visuals = match palette::current_theme() {
        palette::UiTheme::Light => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };
    let vis = &mut style.visuals;

    // ── 面板/窗口/弹层背景 ──
    vis.panel_fill = bg_panel;
    vis.window_fill = bg_card;
    vis.extreme_bg_color = bg_extreme; // TextEdit / 折叠区 / Plot 图例底
    vis.faint_bg_color = palette::bg_faint(); // 斑马纹/弱分隔
    vis.window_stroke = egui::Stroke::new(1.0_f32, border);
    vis.window_rounding = egui::Rounding::same(6.0);
    vis.menu_rounding = egui::Rounding::same(6.0);

    // ── 阴影（R5 附件：Light 下调淡防显脏；颜色取 shadow 令牌）──
    let shadow_base = vis.window_shadow;
    vis.window_shadow = egui::epaint::Shadow {
        color: shadow_color,
        ..shadow_base
    };
    let popup_base = vis.popup_shadow;
    vis.popup_shadow = egui::epaint::Shadow {
        color: shadow_color,
        ..popup_base
    };

    // ── 文字：正文高对比，三级层次显式 ──
    vis.override_text_color = Some(text);
    vis.hyperlink_color = accent;

    // ── widgets 全态覆盖（disabled 走 text_disabled，R3 新令牌）──
    // 注意：Button/SmallButton/SelectableLabel 的底色取 weak_bg_fill 而非
    // bg_fill（企业评审 P1-2）——两槽必须成对覆盖，否则原生按钮残留
    // egui 基底灰、主题令牌对最高频控件不生效。
    let w = &mut vis.widgets;
    // noninteractive：分隔线/网格/面板文字
    w.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, weak);
    w.noninteractive.bg_stroke = egui::Stroke::new(0.5_f32, splitter); // ui.separator()
    w.noninteractive.bg_fill = bg_card;
    w.noninteractive.weak_bg_fill = bg_card;
    // inactive：控件默认态（含禁用前景 text_disabled）
    w.inactive.fg_stroke = egui::Stroke::new(1.0_f32, text);
    w.inactive.bg_fill = palette::bg_card_hover();
    w.inactive.weak_bg_fill = palette::bg_card_hover();
    w.inactive.bg_stroke = egui::Stroke::new(1.0_f32, border);
    // hovered：hover 前景/描边取 accent_hover（v4 新增 hover 态令牌）
    w.hovered.fg_stroke = egui::Stroke::new(1.0_f32, palette::accent_hover());
    w.hovered.bg_fill = palette::bg_card_hover();
    w.hovered.weak_bg_fill = palette::bg_card_hover();
    w.hovered.bg_stroke = egui::Stroke::new(1.0_f32, palette::border_strong());
    // active（按压）
    // ⚠ 关键：egui 的 `strong()` 文字取色 = `widgets.active.text_color()`
    // （style.rs: strong_text_color() → widgets.active.fg_stroke.color）。
    // 这里必须是**正文亮色**——曾误设为 text_on_accent（#0D1522 近黑，本意
    // 是 accent 按钮上的文字），导致深色主题下所有 strong 标签（页面标题/
    // 卡片标题）几乎与背景同色不可见（像素实测亮度 21 vs 正常 160）。
    // 主按钮的 text_on_accent 由其 RichText 显式指定，不依赖此处。
    w.active.fg_stroke = egui::Stroke::new(1.5_f32, text);
    w.active.bg_fill = palette::accent_pressed();
    w.active.weak_bg_fill = palette::accent_pressed();
    w.active.bg_stroke = egui::Stroke::new(1.0_f32, accent);
    // open（展开的可折叠区）
    w.open.fg_stroke = egui::Stroke::new(1.0_f32, accent);
    w.open.bg_fill = palette::bg_card_hover();
    w.open.weak_bg_fill = palette::bg_card_hover();
    w.open.bg_stroke = egui::Stroke::new(1.0_f32, border);
    // 注：egui 0.27 无独立 disabled 视觉态——禁用控件回落 widgets.inactive，
    // 文字由 WidgetText 按 inactive 前景自动降透明度（R3 的 text_disabled 令牌
    // 保留在色板中，供自绘禁用组件显式取用）。

    // ── 选中态 / 焦点环（focus ring 色取 border_strong，R3 令牌）──
    vis.selection.bg_fill = accent.gamma_multiply(0.45);
    vis.selection.stroke = egui::Stroke::new(1.0_f32, palette::border_strong());

    // 全局元素间距：统一从 palette 间距常量取（水平/垂直同为 sm=8）
    style.spacing.item_spacing = egui::vec2(palette::SPACING_SM, palette::SPACING_SM);
    ctx.set_style(style);
}
