//! 日志页：结构化级别（着色/过滤/等宽）+ 导出 + 清空确认（LG-01/02/03/04 + P2-4）。

use crate::palette;
use crate::HydraApp;
use crate::LogLevel;
use eframe::egui;

impl HydraApp {
    /// 运行日志：级别过滤 + 着色 + 等宽 + 自动滚动 + 导出 + 清空确认
    pub(crate) fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("运行日志")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.separator();

        // 级别过滤（LG-01）
        let mut show_info = self.log_show_info;
        let mut show_warn = self.log_show_warn;
        let mut show_error = self.log_show_error;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("显示:").size(palette::FONT_SECONDARY));
            ui.checkbox(&mut show_info, "信息");
            ui.checkbox(&mut show_warn, "警告");
            ui.checkbox(&mut show_error, "错误");
        });
        self.log_show_info = show_info;
        self.log_show_warn = show_warn;
        self.log_show_error = show_error;

        // 日志显示区域（等宽 + 级别着色；stick_to_bottom 自动滚动）
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (level, log) in &self.logs {
                    let visible = match level {
                        LogLevel::Info => self.log_show_info,
                        LogLevel::Warn => self.log_show_warn,
                        LogLevel::Error => self.log_show_error,
                    };
                    if !visible {
                        continue;
                    }
                    ui.label(
                        egui::RichText::new(log)
                            .monospace()
                            .size(palette::FONT_SECONDARY)
                            .color(crate::components::log_color(*level)),
                    );
                }
            });

        ui.separator();

        // 底部控制栏：导出 / 清空（确认）；「刷新」按钮已删（LG-03：egui 每帧
        // 重绘，刷新无意义）
        ui.horizontal(|ui| {
            if ui.button("导出到文件").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("hydra-logs.txt")
                    .save_file()
                {
                    let lines: Vec<String> = self
                        .logs
                        .iter()
                        .map(|(_, l)| l.clone())
                        .collect();
                    let body = lines.join("
");
                    if let Err(e) = std::fs::write(&path, body) {
                        self.add_error(format!("日志导出失败: {e}"));
                    } else {
                        self.add_log(format!("日志已导出到 {}", path.display()));
                    }
                }
            }
            if ui
                .button(egui::RichText::new("清空日志").color(palette::danger()))
                .clicked()
            {
                // 两段式确认（LG-04）：经 ConfirmAction::ClearLogs 对话框
                self.confirm_state = Some(crate::components::ConfirmAction::ClearLogs);
            }
        });
    }
}