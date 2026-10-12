//! 日志页：结构化级别（着色/过滤/等宽）+ 导出 + 清空确认（LG-01/02/03/04 + P2-4）。
//! 批次 A 增量：A1 内核事件 drain 进页面缓冲；A2 VecDeque 迭代（新在上）；
//! 筛选增强——「包含文本」过滤框（对整行不区分大小写 substring，纯 UI 过滤）
//! 与 direction 字段筛选（字段化内核事件具备该字段，GUI 自产日志在指定方向
//! 筛选时隐藏）。

use crate::log_bridge::LogEntry;
use crate::palette;
use crate::HydraApp;
use crate::LogLevel;
use eframe::egui;

impl HydraApp {
    /// 运行日志：级别过滤 + 文本/方向筛选 + 着色 + 等宽 + 自动滚动 + 导出 + 清空确认
    pub(crate) fn ui_logs(&mut self, ui: &mut egui::Ui) {
        // A1：先把环形缓冲中的内核事件搬进页面缓冲（每帧 drain；未开页时
        // 事件暂存于环形缓冲，容量 1000 满员丢最旧）
        self.drain_kernel_logs();

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

        // 筛选增强：包含文本（不区分大小写 substring，纯 UI 过滤）+ 方向
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("包含文本:").size(palette::FONT_SECONDARY));
            ui.add(
                egui::TextEdit::singleline(&mut self.log_text_filter)
                    .desired_width(220.0)
                    .hint_text("如 443 / direct / 连接关闭"),
            );
            ui.checkbox(&mut self.log_direction_all, "全部");
            ui.add_enabled(
                !self.log_direction_all,
                egui::Checkbox::new(&mut self.log_direction_inbound, "入站"),
            );
            ui.add_enabled(
                !self.log_direction_all,
                egui::Checkbox::new(&mut self.log_direction_outbound, "出站"),
            );
        });
        // 小写缓存避免每行重复 to_lowercase（筛选框为空 = 不过滤）
        let needle = self.log_text_filter.trim().to_lowercase();
        let dir_all = self.log_direction_all;
        let dir_in = self.log_direction_inbound;
        let dir_out = self.log_direction_outbound;

        // 日志显示区域（等宽 + 级别着色）。A2 适配：迭代序翻转（.rev()）保持
        // 「新在上」有序读取；stick_to_bottom 保留（自动滚动语义不变）。
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for entry in self.logs.iter().rev() {
                    if !Self::log_entry_visible(
                        entry,
                        &needle,
                        show_info,
                        show_warn,
                        show_error,
                        dir_all,
                        dir_in,
                        dir_out,
                    ) {
                        continue;
                    }
                    ui.label(
                        egui::RichText::new(&entry.text)
                            .monospace()
                            .size(palette::FONT_SECONDARY)
                            .color(crate::components::log_color(entry.level)),
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
                    let lines: Vec<String> = self.logs.iter().map(|e| e.text.clone()).collect();
                    let body = lines.join("\n");
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

    /// 单条日志可见性判定（级别 + 文本 + 方向三重过滤；纯函数供 UI 与单测共用）
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn log_entry_visible(
        entry: &LogEntry,
        needle_lower: &str,
        show_info: bool,
        show_warn: bool,
        show_error: bool,
        dir_all: bool,
        dir_in: bool,
        dir_out: bool,
    ) -> bool {
        // ① 级别过滤（LG-01 语义不变：debug/trace 内核事件归入信息档）
        let level_ok = match entry.level {
            LogLevel::Info => show_info,
            LogLevel::Warn => show_warn,
            LogLevel::Error => show_error,
        };
        // ② 文本过滤：空串 = 不过滤；对整行不区分大小写 substring
        // （needle 在此处统一小写，调用方传原始大小写亦可）
        let text_ok = needle_lower.is_empty()
            || entry.text.to_lowercase().contains(&needle_lower.to_lowercase());
        // ③ 方向过滤：勾「全部」= 不筛；否则按 direction 字段命中（无方向字段
        // 的 GUI 自产日志在仅勾一个方向时隐藏，两个方向都勾 = 等价全部）
        let dir_ok = dir_all
            || match entry.direction.as_deref() {
                Some("inbound") => dir_in,
                Some("outbound") => dir_out,
                _ => dir_in && dir_out,
            };
        level_ok && text_ok && dir_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: LogLevel, text: &str, direction: Option<&str>) -> LogEntry {
        LogEntry {
            level,
            text: text.to_string(),
            direction: direction.map(|d| d.to_string()),
            target: None,
        }
    }

    /// 筛选增强：包含文本过滤（不区分大小写 substring）
    #[test]
    fn test_text_filter_case_insensitive() {
        let e = entry(LogLevel::Info, "[12:00:00] 连接关闭 target=a1b2****8f90", Some("outbound"));
        assert!(HydraApp::log_entry_visible(&e, "", true, true, true, true, true, true));
        assert!(HydraApp::log_entry_visible(&e, "连接关闭", true, true, true, true, true, true));
        assert!(HydraApp::log_entry_visible(&e, "A1B2", true, true, true, true, true, true));
        assert!(!HydraApp::log_entry_visible(&e, "不存在的子串", true, true, true, true, true, true));
    }

    /// 方向过滤：全部 = 不筛；指定方向按字段命中；无方向字段在指定方向时隐藏
    #[test]
    fn test_direction_filter() {
        let out = entry(LogLevel::Info, "内核事件 outbound", Some("outbound"));
        let gui = entry(LogLevel::Info, "GUI 自产日志", None);
        // 「全部」勾选：方向字段不参与
        assert!(HydraApp::log_entry_visible(&out, "", true, true, true, true, false, false));
        assert!(HydraApp::log_entry_visible(&gui, "", true, true, true, true, false, false));
        // 取消全部、只勾出站：outbound 命中、GUI 自产隐藏
        assert!(HydraApp::log_entry_visible(&out, "", true, true, true, false, false, true));
        assert!(!HydraApp::log_entry_visible(&gui, "", true, true, true, false, false, true));
        // 两个方向都勾 = 等价全部（无方向字段可见）
        assert!(HydraApp::log_entry_visible(&gui, "", true, true, true, false, true, true));
    }

    /// 级别过滤语义保持（LG-01）：级别勾选取消后对应条目隐藏
    #[test]
    fn test_level_filter_kept() {
        let warn = entry(LogLevel::Warn, "告警", None);
        assert!(HydraApp::log_entry_visible(&warn, "", true, true, true, true, true, true));
        assert!(!HydraApp::log_entry_visible(&warn, "", true, false, true, true, true, true));
    }
}
