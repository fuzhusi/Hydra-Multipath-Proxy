use eframe::egui;

// ── 底色（暗色优先）──
/// 面板底（侧栏/内容区）
pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x1B, 0x1E, 0x24);
/// 卡片底
pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(0x22, 0x26, 0x2E);
/// 输入框/极端底
pub const BG_EXTREME: egui::Color32 = egui::Color32::from_rgb(0x12, 0x14, 0x18);
/// 斑马纹/弱分隔底
pub const BG_FAINT: egui::Color32 = egui::Color32::from_rgb(0x24, 0x28, 0x30);
/// 卡片描边/分隔线
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(0x2E, 0x33, 0x3D);

// ── 语义色 ──
/// 主强调色（选中/主按钮/链接）
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);
/// 成功 / 低延迟（<200ms）
pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(0x7D, 0xE2, 0x97);
/// 警告 / 中延迟（200–500ms）
pub const WARNING: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xD6, 0x66);
/// 危险 / 高延迟（≥500ms）与错误
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x8A, 0x80);

// ── 文本三级 ──
/// 一级：正文/标题
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE8, 0xEA, 0xED);
/// 二级：次要说明（ui.small 同级）
pub const TEXT_WEAK: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB0, 0xBC);
/// 三级：占位/未验证状态点
pub const TEXT_FAINT: egui::Color32 = egui::Color32::from_rgb(0x7A, 0x82, 0x8F);

// ── 字号层级（全局统一，五级）──
/// 页面标题
pub const FONT_HEADING: f32 = 18.0;
/// 卡片标题/节点名
pub const FONT_TITLE: f32 = 15.0;
/// 正文
pub const FONT_BODY: f32 = 13.0;
/// 次要文字/标签
pub const FONT_SECONDARY: f32 = 11.5;
/// 徽标（来源标记/计数徽标，五级中最小）
pub const FONT_BADGE: f32 = 10.5;

// ── 间距节奏（4px 基准，frontend-design 理念落地：全部间距从常量取）──
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

/// 延迟色标：<200ms 绿 / <500ms 黄 / 其余红；None（未测）= 灰。
/// 与 v3 设计文档 §交互细节 的色阶一致。
pub fn latency_color(latency_ms: Option<u64>) -> egui::Color32 {
    match latency_ms {
        None => TEXT_FAINT,
        Some(ms) if ms < 200 => SUCCESS,
        Some(ms) if ms < 500 => WARNING,
        Some(_) => DANGER,
    }
}

/// 节点状态色点：绿=Online / 黄=Degraded（在线但延迟 ≥500ms）/
/// 红=Offline（测过但失败）/ 灰=未验证（从未测速）。
pub fn status_color(connected: bool, checked: bool, latency_ms: Option<u64>) -> egui::Color32 {
    if !checked {
        TEXT_FAINT // 未验证
    } else if connected {
        if latency_ms.is_some_and(|ms| ms >= 500) {
            WARNING // Degraded：握手通过但延迟过高
        } else {
            SUCCESS // Online
        }
    } else {
        DANGER // Offline
    }
}

#[cfg(test)]
mod tests {
    // ── 视觉规范化第一步：延迟色标 / 节点状态色点 ──

    #[test]
    fn latency_color_thresholds() {
        use super::latency_color;
        // 未测 = 灰
        assert_eq!(latency_color(None), super::TEXT_FAINT);
        // <200ms 绿
        assert_eq!(latency_color(Some(0)), super::SUCCESS);
        assert_eq!(latency_color(Some(199)), super::SUCCESS);
        // 200–500ms 黄
        assert_eq!(latency_color(Some(200)), super::WARNING);
        assert_eq!(latency_color(Some(499)), super::WARNING);
        // ≥500ms 红（老板实测节点 319-451ms 属黄区间）
        assert_eq!(latency_color(Some(500)), super::DANGER);
        assert_eq!(latency_color(Some(2000)), super::DANGER);
    }

    #[test]
    fn node_status_color_states() {
        use super::status_color;
        // 未验证（从未测速）= 灰
        assert_eq!(status_color(false, false, None), super::TEXT_FAINT);
        // Online = 绿
        assert_eq!(status_color(true, true, Some(45)), super::SUCCESS);
        // Degraded（在线但延迟 ≥500ms）= 黄
        assert_eq!(status_color(true, true, Some(800)), super::WARNING);
        // Offline（测过但失败）= 红
        assert_eq!(status_color(false, true, None), super::DANGER);
    }
}
