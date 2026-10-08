//! 日志页：运行日志自动滚动 + 清空/刷新。

use eframe::egui;
use crate::palette;
use crate::HydraApp;

impl HydraApp {

    /// 运行日志（保留自动滚动 + 清空/刷新）
    pub(crate) fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("运行日志")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.separator();

        // 日志显示区域（stick_to_bottom：新日志自动滚动到底）
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for log in &self.logs {
                    ui.label(log);
                }
            });

        ui.separator();

        // 底部控制栏
        ui.horizontal(|ui| {
            // 破坏性操作用危险色文案
            if ui
                .button(egui::RichText::new("清空日志").color(palette::DANGER))
                .clicked()
            {
                self.logs.clear();
            }
            if ui.button("刷新").clicked() {
                ui.ctx().request_repaint();
            }
        });
    }
}
