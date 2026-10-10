//! 公共组件库（UI v4 / 企业级）：状态徽章、确认对话框、横幅、空态——
//! 六页散点实现的单点收敛（设计评审修正后清单第 3 项）。
//!
//! - 状态**三通道编码**（颜色 + 字形 + 文字）：色盲可辨，P0 ND-01 的根治；
//! - `ConfirmAction` + [`draw_confirm_dialog`]：破坏性操作统一确认
//!   （分级形态：级联删除/退出 = 对话框；普通删除 = 两段式按钮，由调用方实现）；
//! - Esc = 取消（`dialog_keys` 由 ui_shell 提供全局接线）。

use crate::HydraApp;
use crate::LogLevel;
use crate::palette::{self, NodeHealth};
use eframe::egui;

/// 状态点：健康态圆形色点 + 字形（双通道；size 含字形）
/// （v4 组件库预留：ui_nodes 卡片用 painter 定制版；P1 页面接入时消费）
#[allow(dead_code)]
pub fn status_dot(ui: &mut egui::Ui, health: NodeHealth, size: f32) {
    let color = palette::health_color(health);
    let symbol = palette::health_symbol(health);
    ui.label(
        egui::RichText::new(format!("{symbol} "))
            .size(size)
            .color(color)
            .strong(),
    );
}

/// 状态徽章：圆角底 + 字形 + 文字（三通道齐全；hover 显示文案词）
pub fn status_pill(ui: &mut egui::Ui, health: NodeHealth, text: &str) {
    let color = palette::health_color(health);
    let symbol = palette::health_symbol(health);
    egui::Frame::none()
        .fill(color.gamma_multiply(0.18))
        .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(symbol)
                        .size(palette::FONT_SECONDARY)
                        .color(color)
                        .strong(),
                );
                ui.label(
                    egui::RichText::new(text)
                        .size(palette::FONT_SECONDARY)
                        .color(color),
                );
            });
        })
        .response
        .on_hover_text(palette::health_label(health));
}

/// 延迟徽章：按健康态着色（劣化=WARNING 而非 DANGER——修 ND-02「超时灰字
/// 与红点矛盾」的根因：着色不再走 latency_color 的 ≥500ms→红）
/// （v4 组件库预留：节点卡延迟已按健康态直着色；P1 曲线 hover 接入）
#[allow(dead_code)]
pub fn latency_badge(ui: &mut egui::Ui, health: NodeHealth, latency: Option<u64>) {
    let text = match latency {
        Some(ms) => format!("{}ms", ms),
        None => "—".to_string(),
    };
    ui.label(
        egui::RichText::new(text)
            .size(palette::FONT_SECONDARY)
            .color(palette::health_color(health))
            .monospace(),
    );
}

/// 横幅类别（决定底色/前景色对）
/// 横幅类别（Danger 当前被首页启动失败横幅消费；其余随 P1/P2 页面接入）
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerKind {
    Danger,
    Warning,
    Success,
    Info,
}

/// 应用内横幅（G-02：反馈通道不再只有日志页）
pub fn banner(ui: &mut egui::Ui, kind: BannerKind, text: &str) {
    let (fg, bg) = match kind {
        BannerKind::Danger => (palette::DANGER, palette::DANGER_BG),
        BannerKind::Warning => (palette::WARNING, palette::WARNING_BG),
        BannerKind::Success => (palette::SUCCESS, palette::SUCCESS_BG),
        BannerKind::Info => (palette::INFO, palette::INFO_BG),
    };
    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(palette::FONT_BODY).color(fg));
        });
}

/// 空态动作（标题 + 触发回调）
pub type EmptyAction<'a> = (&'a str, Box<dyn FnOnce(&mut egui::Ui) + 'a>);

/// 空态：标题 + 提示 + 可选动作按钮（垂直居中三件套）
pub fn empty_state(
    ui: &mut egui::Ui,
    title: &str,
    hint: &str,
    action: Option<EmptyAction<'_>>,
) {
    ui.vertical_centered(|ui| {
        ui.add_space(palette::SPACING_XL);
        ui.label(
            egui::RichText::new(title)
                .size(palette::FONT_TITLE)
                .color(palette::TEXT_WEAK),
        );
        ui.label(
            egui::RichText::new(hint)
                .size(palette::FONT_SECONDARY)
                .color(palette::TEXT_FAINT),
        );
        if let Some((label, on_click)) = action {
            ui.add_space(palette::SPACING_SM);
            if ui.button(label).clicked() {
                on_click(ui);
            }
        }
        ui.add_space(palette::SPACING_XL);
    });
}

/// 日志级别着色（LG-01：结构化级别 + 过滤）
pub fn log_color(level: LogLevel) -> egui::Color32 {
    match level {
        LogLevel::Info => palette::TEXT,
        LogLevel::Warn => palette::WARNING,
        LogLevel::Error => palette::DANGER,
    }
}

/// 破坏性操作确认状态（app.rs 持有；[draw_confirm_dialog] 绘制与执行）
#[derive(Debug, Clone)]
pub enum ConfirmAction {
    /// 删除节点（地址）
    DeleteNode(String),
    /// 删除订阅（索引/名称/级联节点数/是否本地粘贴导入——级联 + 本地文本
    /// 原文不可重拉时用红字强提示，SB-01）
    DeleteSubscription {
        idx: usize,
        name: String,
        cascade: usize,
        is_local_text: bool,
    },
    /// 清空日志
    ClearLogs,
    /// 退出应用（托盘外入口的破坏性确认；当前托盘退出直接走 TrayCommand::Quit）
    #[allow(dead_code)]
    QuitApp,
}

/// 确认对话框（Esc=取消；Enter=确认；级联删除红字说明——SB-01）。
/// 调用方在 update 末尾调用一次：`components::draw_confirm_dialog(self, ctx)`。
pub fn draw_confirm_dialog(app: &mut HydraApp, ctx: &egui::Context) {
    let Some(action) = app.confirm_state.clone() else {
        return;
    };
    let (title, body, confirm_label, danger) = match &action {
        ConfirmAction::DeleteNode(addr) => (
            "删除节点".to_string(),
            format!("确定删除节点 {addr} 吗？备注与独立证书路径将一并清理。"),
            "删除".to_string(),
            true,
        ),
        ConfirmAction::DeleteSubscription {
            idx: _,
            name,
            cascade,
            is_local_text,
        } => {
            let cascade_note = if *cascade > 0 {
                format!(
                    "\n⚠ 该订阅独占 {} 个节点，删除将连带移除（不可恢复）。\
                     本地导入的链接原文无法重新拉取。",
                    cascade
                )
            } else {
                String::new()
            };
            let local_note = if *is_local_text {
                String::from("\n⚠ 该订阅为本地粘贴导入，删除后原文永久丢失。")
            } else {
                String::new()
            };
            (
                "删除订阅".to_string(),
                format!("确定删除订阅「{name}」吗？{cascade_note}{local_note}"),
                "删除".to_string(),
                *cascade > 0 || *is_local_text,
            )
        }
        ConfirmAction::ClearLogs => (
            "清空日志".to_string(),
            "确定清空全部运行日志吗？".to_string(),
            "清空".to_string(),
            false,
        ),
        ConfirmAction::QuitApp => (
            "退出应用".to_string(),
            "确定退出 Hydra 吗？代理将停止，系统代理设置将还原。".to_string(),
            "退出".to_string(),
            true,
        ),
    };

    let mut execute = false;
    let mut cancel = false;
    let mut dummy_open = true;
    egui::Window::new(
        egui::RichText::new(&title).color(if danger {
            palette::DANGER
        } else {
            palette::TEXT
        }),
    )
    .open(&mut dummy_open)
    .collapsible(false)
    .resizable(false)
    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
    .show(ctx, |ui| {
        ui.set_min_width(320.0);
        ui.label(&body);
        ui.add_space(palette::SPACING_SM);
        ui.separator();
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button(egui::RichText::new(&confirm_label).color(if danger {
                    palette::DANGER
                } else {
                    palette::TEXT
                }))
                .clicked()
            {
                execute = true;
            }
            if ui.button("取消").clicked() {
                cancel = true;
            }
        });
    });
    // Esc = 取消（ui_shell 的 dialog_keys 置 app.dialog_cancel_requested）
    if app.dialog_cancel_requested {
        cancel = true;
        app.dialog_cancel_requested = false;
    }
    if cancel {
        app.confirm_state = None;
        return;
    }
    if !execute {
        return;
    }
    app.confirm_state = None;
    match action {
        ConfirmAction::DeleteNode(addr) => app.execute_delete_node(&addr),
        ConfirmAction::DeleteSubscription { idx, .. } => app.delete_subscription(idx),
        ConfirmAction::ClearLogs => app.logs.clear(),
        ConfirmAction::QuitApp => {
            app.really_quit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}
