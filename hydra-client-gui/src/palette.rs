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
/// 强描边（焦点环/危险边框，v4 新增）
#[allow(dead_code)]
pub const BORDER_STRONG: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);
/// 侧栏底（比面板更深一档，v4 新增）
#[allow(dead_code)]
pub const BG_SIDEBAR: egui::Color32 = egui::Color32::from_rgb(0x16, 0x19, 0x1F);

// ── 语义色 ──
/// 主强调色（选中/主按钮/链接）
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);
/// 成功 / 低延迟（<200ms）
pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(0x7D, 0xE2, 0x97);
/// 警告 / 中延迟（200–500ms）
pub const WARNING: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xD6, 0x66);
/// 危险 / 高延迟（≥500ms）与错误
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x8A, 0x80);
/// 信息（中性提示，v4 新增）
pub const INFO: egui::Color32 = egui::Color32::from_rgb(0x8A, 0xC8, 0xE8);
/// 危险横幅底（v4：横幅 = 语义底 + 同系前景双通道）
pub const DANGER_BG: egui::Color32 = egui::Color32::from_rgb(0x3A, 0x22, 0x24);
/// 警告横幅底
pub const WARNING_BG: egui::Color32 = egui::Color32::from_rgb(0x3A, 0x32, 0x1E);
/// 成功横幅底
pub const SUCCESS_BG: egui::Color32 = egui::Color32::from_rgb(0x1E, 0x32, 0x26);
/// 信息横幅底
pub const INFO_BG: egui::Color32 = egui::Color32::from_rgb(0x1E, 0x2A, 0x38);
/// 强调色之上的文字（深墨——ACCENT 上白字仅 2.72:1 不达标，v4 新增）
/// （v4 组件库预留：主按钮文字色——当前主按钮用默认样式，P1 接入）
#[allow(dead_code)]
pub const TEXT_ON_ACCENT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x15, 0x22);

// ── 文本三级 ──
/// 一级：正文/标题
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE8, 0xEA, 0xED);
/// 二级：次要说明（ui.small 同级）
pub const TEXT_WEAK: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB0, 0xBC);
/// 三级：占位/未验证状态点（v4：提亮至 4.52:1 对比度达标）
pub const TEXT_FAINT: egui::Color32 = egui::Color32::from_rgb(0x84, 0x8D, 0x9A);

// ── 字号层级（全局统一，五级）──
/// 页面标题
pub const FONT_HEADING: f32 = 18.0;
/// 卡片标题/节点名
pub const FONT_TITLE: f32 = 15.0;
/// 正文
pub const FONT_BODY: f32 = 13.0;
/// 次要文字/标签（v4：11.5→12.0，最小可读字号下限对齐）
pub const FONT_SECONDARY: f32 = 12.0;
/// 徽标（来源标记/计数徽标，五级中最小；v4：10.5→11.0 最小字号下限）
pub const FONT_BADGE: f32 = 11.0;

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

// ── 圆角规范（v4 新增：双档圆角取代散点数值）──
/// 卡片圆角
pub const RADIUS_CARD: f32 = 8.0;
/// 控件圆角（按钮/输入框/徽标）
pub const RADIUS_CTRL: f32 = 6.0;

/// 节点健康五态（v4 新增：状态三通道编码的单点判定——颜色/字形/文案词
/// 共用同一枚举，消灭"色相单通道"的 P0 可访问性问题）
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
        NodeHealth::Untested => TEXT_FAINT,
        NodeHealth::Testing => INFO,
        NodeHealth::Online => SUCCESS,
        NodeHealth::Degraded => WARNING,
        NodeHealth::Offline => DANGER,
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
        None => TEXT_FAINT,
        Some(ms) if ms < 200 => SUCCESS,
        Some(ms) if ms < 500 => WARNING,
        Some(_) => DANGER,
    }
}

/// 节点状态色点（v4：经 [`node_health`] 单点判定 + [`health_color`] 着色。
/// 薄封装，暂仅供测试与 P1 页面接入期使用）
#[allow(dead_code)]
pub fn status_color(connected: bool, checked: bool, latency_ms: Option<u64>) -> egui::Color32 {
    health_color(node_health(connected, checked, latency_ms))
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
        // v4：经 node_health + health_color 通路断言（status_color 为薄封装）
        use super::{health_color, node_health};
        assert_eq!(health_color(node_health(false, false, None)), super::TEXT_FAINT);
        assert_eq!(health_color(node_health(true, true, Some(45))), super::SUCCESS);
        assert_eq!(health_color(node_health(true, true, Some(800))), super::WARNING);
        assert_eq!(health_color(node_health(false, true, None)), super::DANGER);
    }
}
