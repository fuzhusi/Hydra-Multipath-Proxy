//! 连接页：经代理的活跃连接表格（500ms 节流快照 + 差分速率）。

use crate::palette;
use crate::theme::card_frame;
use crate::HydraApp;
use eframe::egui;
use hydra_client::{format_bytes, format_duration, format_speed};
use std::collections::HashMap;

// ── 连接页：注册表快照刷新 + 表格渲染（与流量页同范式：500ms 节流拉取，
//    UI 帧只读本地缓存，不在渲染路径触碰注册表锁）──
impl HydraApp {
    /// 拉取注册表快照并差分推算每连接速率（500ms 节流；仅连接页激活时调用）。
    /// 速率 = 相邻两次快照的字节增量 / 时间差（与 TrafficMonitor 5s 窗口差分
    /// 同思路，窗口更短以匹配连接级粒度；首帧无基准不显示速率）。
    pub(crate) fn refresh_connections(&mut self) {
        let now = std::time::Instant::now();
        if let Some(last) = self.conn_last_refresh {
            if now.duration_since(last) < std::time::Duration::from_millis(500) {
                return;
            }
        }
        self.conn_last_refresh = Some(now);
        let snap = hydra_client::connections::connections_registry().snapshot();
        let mut rates: HashMap<u64, (f64, f64)> = HashMap::new();
        let mut prev: HashMap<u64, (u64, u64, std::time::Instant)> = HashMap::new();
        for c in &snap {
            if let Some(&(pu, pd, t)) = self.conn_prev.get(&c.id) {
                let dt = now.duration_since(t).as_secs_f64();
                if dt > 0.05 {
                    rates.insert(
                        c.id,
                        (
                            c.bytes_up.saturating_sub(pu) as f64 / dt,
                            c.bytes_down.saturating_sub(pd) as f64 / dt,
                        ),
                    );
                }
            }
            prev.insert(c.id, (c.bytes_up, c.bytes_down, now));
        }
        self.conn_rates = rates;
        self.conn_prev = prev;
        self.conn_snapshot = snap;
    }

    /// 连接行排序（纯函数，UI 与单测共用）：活跃优先；活跃按开始时间新→旧
    /// （最近活跃在前），已关闭按关闭时间新→旧。
    pub(crate) fn sorted_connections(snap: &[hydra_client::connections::ConnInfo]) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..snap.len()).collect();
        idx.sort_by_key(|&i| {
            let c = &snap[i];
            (
                !c.active, // 活跃在前
                std::cmp::Reverse(c.started_at),
                std::cmp::Reverse(c.closed_at),
            )
        });
        idx
    }

    /// 连接页主渲染
    pub(crate) fn ui_connections(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("连接")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.add_space(palette::SPACING_XS);

        // ── 帧首快照：活跃/最近关闭计数 + 排序下标一次性算好 ──
        let snap = self.conn_snapshot.clone();
        let active_n = snap.iter().filter(|c| c.active).count();
        let closed_n = snap.len() - active_n;
        let order = Self::sorted_connections(&snap);

        // ── 顶部汇总卡：活跃 n / 最近关闭 m ──
        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("活跃连接 {active_n}"))
                        .size(palette::FONT_TITLE + 3.0)
                        .color(if active_n > 0 {
                            palette::SUCCESS
                        } else {
                            palette::TEXT
                        })
                        .strong(),
                );
                ui.add_space(palette::SPACING_LG);
                ui.label(
                    egui::RichText::new(format!("最近关闭 {closed_n}"))
                        .size(palette::FONT_TITLE)
                        .color(palette::TEXT_WEAK),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small("每 500ms 自动刷新；已关闭条目保留 60s");
                });
            });
        });

        // ── 连接表格卡 ──
        ui.add_space(palette::SPACING_SM);
        card_frame(ui).show(ui, |ui| {
            if order.is_empty() {
                // 空态：诚实文案（代理未启动 / 尚无流量）
                ui.vertical_centered(|ui| {
                    ui.add_space(palette::SPACING_LG);
                    ui.label(
                        egui::RichText::new("暂无连接")
                            .size(palette::FONT_TITLE)
                            .color(palette::TEXT_WEAK),
                    );
                    ui.small(if self.proxy_running {
                        "代理运行中——经代理发起的连接将实时显示在这里"
                    } else {
                        "代理未运行——启动代理后，经代理的连接会显示在这里"
                    });
                    ui.add_space(palette::SPACING_LG);
                });
                return;
            }
            egui::Grid::new("connections_table")
                .num_columns(7)
                .spacing([palette::SPACING_MD, palette::SPACING_XS])
                .striped(true)
                .show(ui, |ui| {
                    // 表头
                    ui.weak("目标");
                    ui.weak("节点");
                    ui.weak("↑ 速率");
                    ui.weak("↓ 速率");
                    ui.weak("累计");
                    ui.weak("时长");
                    ui.weak("状态");
                    ui.end_row();

                    for i in order {
                        let c = &snap[i];
                        // 目标（注册表内已脱敏：短哈希:端口，hover 可复制排查）
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&c.target)
                                    .monospace()
                                    .size(palette::FONT_BODY),
                            )
                            .truncate(true),
                        );
                        // 节点名（0.0.0.0:0 = CN 分流直连；否则按备注名/地址显示）
                        let node_str = c.node.to_string();
                        let node_label = if c.node.ip().is_unspecified() {
                            "直连".to_string()
                        } else {
                            self.config.node_display_name(&node_str)
                        };
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(node_label).size(palette::FONT_BODY),
                            )
                            .truncate(true),
                        )
                        .on_hover_text(node_str);
                        // 速率（差分推算；首帧或无新数据显示 0）
                        let (up, down) = self.conn_rates.get(&c.id).copied().unwrap_or((0.0, 0.0));
                        ui.label(
                            egui::RichText::new(format_speed(up))
                                .monospace()
                                .size(palette::FONT_BODY)
                                .color(palette::SUCCESS),
                        );
                        ui.label(
                            egui::RichText::new(format_speed(down))
                                .monospace()
                                .size(palette::FONT_BODY)
                                .color(palette::ACCENT),
                        );
                        // 累计流量
                        ui.label(
                            egui::RichText::new(format!(
                                "↑{} ↓{}",
                                format_bytes(c.bytes_up),
                                format_bytes(c.bytes_down)
                            ))
                            .monospace()
                            .size(palette::FONT_BODY),
                        );
                        // 时长：活跃 = 至今；已关闭 = 存续区间
                        let secs = match c.closed_at {
                            Some(closed) => closed.duration_since(c.started_at).as_secs(),
                            None => c.started_at.elapsed().as_secs(),
                        };
                        ui.label(
                            egui::RichText::new(format_duration(secs))
                                .monospace()
                                .size(palette::FONT_BODY),
                        );
                        // 状态
                        ui.label(if c.active {
                            egui::RichText::new("● 活跃")
                                .size(palette::FONT_SECONDARY)
                                .color(palette::SUCCESS)
                        } else {
                            egui::RichText::new("○ 已关闭")
                                .size(palette::FONT_SECONDARY)
                                .color(palette::TEXT_FAINT)
                        });
                        ui.end_row();
                    }
                });
            ui.add_space(palette::SPACING_XS);
            ui.small(format!(
                "共 {} 条（活跃 {} / 已关闭 {}）",
                snap.len(),
                active_n,
                closed_n
            ));
        });
    }
}
