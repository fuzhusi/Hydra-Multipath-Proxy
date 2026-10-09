//! 首页：统计卡（运行状态/当前节点/今日流量/活跃节点）+
//! 实时速率双曲线仪表盘（egui_plot）+ 快捷入口卡。

use crate::app::start_button_state;
use crate::nodes::{best_online_node, median_online_latency, Tab};
use crate::palette;
use crate::theme::card_frame;
use crate::HydraApp;
use eframe::egui;
use hydra_client::{format_bytes, format_speed};

impl HydraApp {
    /// 首页（UI 重设计第三批：卡片式仪表盘，v3 方案 P1 §首页仪表盘）：
    /// - 顶部四张统计卡：运行状态（含启停大按钮）/ 当前节点（调度参考）/
    ///   今日流量上下行 / 活跃节点数与延迟中位；
    /// - 下方大号实时速率曲线卡（egui_plot 双曲线，最近 120 个采样点 = 60s 窗口）；
    /// - 快捷入口卡：「全部节点测试」「TUN 开关」「系统代理开关」+ 最近日志摘要。
    ///
    /// 本页无配置项；配置修改仍在「⚙ 设置」页。
    pub(crate) fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("首页")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.add_space(palette::SPACING_XS);

        // ── 帧首快照：流量统计缓存与历史序列一次性读出（锁内只做 clone）──
        let stats = self.traffic_stats_cache.lock().ok().and_then(|g| g.clone());
        let (up_series, down_series, daily_up, daily_down) = self
            .traffic_history
            .lock()
            .map(|h| (h.up_series(), h.down_series(), h.daily_up, h.daily_down))
            .unwrap_or((Vec::new(), Vec::new(), 0, 0));
        let online = self.node_status.values().filter(|s| s.connected).count();
        let total = self.config.node_addrs.len();
        let median_latency = median_online_latency(&self.node_status);
        let best_node = best_online_node(&self.config, &self.node_status);

        // ── 顶部四张统计卡：固定 2×2 网格（确定性布局——任何窗口宽度下四张卡
        //    都完整可见；卡宽 = 可用宽度均分，钳制 130..=320，极窄窗口整行收缩）──
        ui.add_space(palette::SPACING_LG);
        let avail_w = ui.available_width();
        let stat_cols = 2usize;
        let card_w = (avail_w - palette::SPACING_SM * (stat_cols + 1) as f32) / stat_cols as f32;
        let card_w = card_w.clamp(130.0, 320.0);
        // card_w 是含 Frame 边距的整卡宽度；内容区需再扣除 内边距MD×2 + 外边距XS×2 = 32px，
        // 否则两张卡的 Frame 总宽超出可用宽度，第二列被窗口右缘裁掉（卡内文字被截断）
        // 卡内长文本均已 truncate(true)，内容可随窗口收缩——不设可读性下限，
        // 否则极窄窗口下 120px 下限会重新引入二列水平溢出（审查批次 C-1）
        let card_inner_w = (card_w - (palette::SPACING_MD + palette::SPACING_XS) * 2.0).max(1.0);
        egui::Grid::new("dashboard_stat_cards")
            .num_columns(stat_cols)
            .spacing([palette::SPACING_SM, palette::SPACING_SM])
            .show(ui, |ui| {
                // ① 运行状态卡：状态色点三态 + 启停大按钮
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(card_inner_w);
                    ui.set_max_width(card_inner_w);
                    ui.label(
                        egui::RichText::new("运行状态")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::TEXT_WEAK),
                    );
                    let (status_text, status_color) = if self.proxy_running {
                        ("● 运行中", palette::SUCCESS)
                    } else if self.proxy_starting {
                        ("◐ 启动中…", palette::WARNING)
                    } else {
                        ("○ 已停止", palette::TEXT_FAINT)
                    };
                    ui.label(
                        egui::RichText::new(status_text)
                            .size(palette::FONT_TITLE + 3.0)
                            .color(status_color)
                            .strong(),
                    );
                    // 启停大按钮（按钮文字/可用性走 start_button_state 状态机，见其单测）
                    let (btn_text, btn_enabled) =
                        start_button_state(self.proxy_running, self.proxy_starting);
                    let resp = ui.add_enabled(
                        btn_enabled,
                        egui::Button::new(egui::RichText::new(btn_text).size(palette::FONT_BODY)),
                    );
                    if resp.clicked() {
                        if self.proxy_running {
                            self.stop_proxy();
                        } else {
                            self.start_proxy();
                        }
                    }
                    // 长地址超卡宽会触发「组件超出」告警：截断 + hover 显示全量
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("监听 {}", self.config.proxy_listen_addr))
                                .size(palette::FONT_SECONDARY),
                        )
                        .truncate(true),
                    );
                });
                // ② 当前节点卡：在线节点中延迟最低者（调度参考语义，诚实标注）
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(card_inner_w);
                    ui.set_max_width(card_inner_w);
                    ui.label(
                        egui::RichText::new("当前节点（调度参考）")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::TEXT_WEAK),
                    );
                    match &best_node {
                        Some((addr, ms)) => {
                            // 节点备注/地址超卡宽：截断 + hover 全量
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(self.config.node_display_name(addr))
                                        .size(palette::FONT_TITLE + 3.0)
                                        .strong(),
                                )
                                .truncate(true),
                            )
                            .on_hover_text(addr);
                            ui.label(
                                egui::RichText::new(format!("{}ms", ms))
                                    .size(palette::FONT_BODY)
                                    .color(palette::latency_color(Some(*ms))),
                            );
                        }
                        None => {
                            ui.label(
                                egui::RichText::new("—")
                                    .size(palette::FONT_TITLE + 3.0)
                                    .color(palette::TEXT_FAINT),
                            );
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(if total == 0 {
                                        "暂无节点"
                                    } else {
                                        "无在线节点"
                                    })
                                    .size(palette::FONT_SECONDARY),
                                )
                                .truncate(true),
                            );
                        }
                    }
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new("自动按最低延迟调度")
                                .size(palette::FONT_SECONDARY)
                                .color(palette::TEXT_WEAK),
                        )
                        .truncate(true),
                    );
                });
                // egui Grid 不会自动换行：2 列布局下每 2 张卡必须显式 end_row，
                // 否则 ③④ 两张卡排到屏幕外（本轮「今日流量看不到」的根因）
                ui.end_row();
                // ③ 今日流量卡：上下行当日累计（差分自采样序列；重启不跨日不清零）
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(card_inner_w);
                    ui.set_max_width(card_inner_w);
                    ui.label(
                        egui::RichText::new("今日流量")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::TEXT_WEAK),
                    );
                    ui.label(
                        egui::RichText::new(format!("⬇ {}", format_bytes(daily_down)))
                            .size(palette::FONT_TITLE + 3.0)
                            .color(palette::ACCENT)
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new(format!("⬆ {}", format_bytes(daily_up)))
                            .size(palette::FONT_TITLE + 3.0)
                            .color(palette::SUCCESS)
                            .strong(),
                    );
                    if let Some(s) = &stats {
                        ui.small(format!("速率 ⬇ {}/s", format_speed(s.download_speed)));
                    }
                });
                // ④ 活跃节点卡：在线数/总数 + 在线节点延迟中位数
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(card_inner_w);
                    ui.set_max_width(card_inner_w);
                    ui.label(
                        egui::RichText::new("活跃节点")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::TEXT_WEAK),
                    );
                    ui.label(
                        egui::RichText::new(format!("{}/{}", online, total))
                            .size(palette::FONT_TITLE + 3.0)
                            .strong(),
                    );
                    ui.label(match median_latency {
                        Some(ms) => egui::RichText::new(format!("延迟中位 {}ms", ms))
                            .size(palette::FONT_BODY)
                            .color(palette::latency_color(Some(ms))),
                        None => egui::RichText::new("延迟中位 —")
                            .size(palette::FONT_BODY)
                            .color(palette::TEXT_FAINT),
                    });
                    if let Some(s) = &stats {
                        ui.small(format!("活跃连接 {}", s.active_connections));
                    }
                });
                ui.end_row();
            });

        // ── 实时速率曲线卡（egui_plot 双曲线：上行=SUCCESS 绿 / 下行=ACCENT 主色；
        //    数据源 = 采样线程维护的最近 120 点历史，UI 帧只读快照零阻塞）──
        ui.add_space(palette::SPACING_SM);
        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("实时速率")
                        .size(palette::FONT_TITLE)
                        .strong(),
                );
                ui.colored_label(
                    palette::SUCCESS,
                    format!(
                        "⬆ {}/s",
                        format_speed(up_series.last().copied().unwrap_or(0.0))
                    ),
                );
                ui.colored_label(
                    palette::ACCENT,
                    format!(
                        "⬇ {}/s",
                        format_speed(down_series.last().copied().unwrap_or(0.0))
                    ),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small("最近 120 个采样点（500ms/点）");
                });
            });
            // 固定高度的大号曲线区（180px）：审查批次 C-2——allocate_exact_size
            // 只会留 180px 空白带且 Plot 高度失控（吃掉剩余可用高度）；改用
            // allocate_ui 给 Plot 一个确定大小的 rect
            ui.allocate_ui(egui::vec2(ui.available_width(), 180.0), |ui| {
                egui_plot::Plot::new("dashboard_speed_plot")
                    // 仪表盘装饰性图表：禁用全部交互（拖动/缩放/平移/双击重置）——
                    // 此前可被拖得找不到图；悬停坐标读数也一并关闭
                    .allow_zoom(false)
                    .allow_drag(false)
                    .allow_scroll(false)
                    .allow_boxed_zoom(false)
                    .allow_double_click_reset(false)
                    .coordinates_formatter(
                        egui_plot::Corner::RightBottom,
                        egui_plot::CoordinatesFormatter::new(|_pt, _bounds| String::new()),
                    )
                    // 图例与坐标轴/网格配置在 Plot 构造器上（egui_plot 0.27 API）
                    .legend(egui_plot::Legend::default())
                    .show_axes(false)
                    .show_grid(false)
                    .show(ui, |plot| {
                        // 曲线纵轴自适应，不显示坐标轴刻度（仪表盘装饰性图表）
                        let up_points: egui_plot::PlotPoints = up_series
                            .iter()
                            .enumerate()
                            .map(|(i, v)| [i as f64, *v])
                            .collect();
                        let down_points: egui_plot::PlotPoints = down_series
                            .iter()
                            .enumerate()
                            .map(|(i, v)| [i as f64, *v])
                            .collect();
                        plot.line(
                            egui_plot::Line::new(up_points)
                                .name("上行")
                                .color(palette::SUCCESS)
                                .width(2.0_f32),
                        );
                        plot.line(
                            egui_plot::Line::new(down_points)
                                .name("下行")
                                .color(palette::ACCENT)
                                .width(2.0_f32),
                        );
                    });
            });
            if !self.proxy_running {
                ui.colored_label(
                    palette::TEXT_FAINT,
                    "代理未运行——启动代理后开始记录速率曲线",
                );
            }
        });

        // ── 快捷入口卡：全部节点测试 / TUN 开关 / 系统代理开关 + 最近日志摘要 ──
        ui.add_space(palette::SPACING_SM);
        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("快捷操作")
                        .size(palette::FONT_TITLE)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("查看全部日志 →").clicked() {
                        self.current_tab = Tab::Logs;
                    }
                });
            });
            ui.add_space(palette::SPACING_XS);
            ui.horizontal(|ui| {
                // 全部节点测试（与节点页同一入口，进度/结果经健康检查通道落地）
                if self.health_check_receiver.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label("全部测速中…");
                } else if ui.button("⚡ 全部节点测试").clicked() {
                    self.test_all_nodes();
                }
                // TUN 快捷开关（写入配置，下次启动代理生效，与设置页同一字段）
                if ui
                    .checkbox(&mut self.config.tun_enabled, "TUN 模式")
                    .on_hover_text(
                        "TUN 透明代理（需管理员/root；下次启动代理生效；详细设置见「⚙ 设置」页）",
                    )
                    .changed()
                {
                    self.add_log(if self.config.tun_enabled {
                        "TUN 透明代理：已开启（下次启动代理生效）".to_string()
                    } else {
                        "TUN 透明代理：已关闭（下次启动代理生效）".to_string()
                    });
                    #[cfg(windows)]
                    if self.config.tun_enabled {
                        self.sys_proxy_check_cache = None;
                    }
                }
                // 系统代理快捷开关：代理运行且未开 TUN 时可手动开/关（TUN 全接管时无需叠加）
                let tun_on = self.config.tun_enabled;
                let sys_on = self.system_proxy_on_cached();
                let toggle_text = if sys_on {
                    "系统代理：开 ✓"
                } else {
                    "系统代理：关"
                };
                let resp = ui
                    .add_enabled(
                        self.proxy_running && !tun_on,
                        egui::Button::new(
                            egui::RichText::new(toggle_text).size(palette::FONT_BODY),
                        ),
                    )
                    .on_hover_text(match (self.proxy_running, tun_on) {
                        (false, _) => "先启动代理后可用",
                        (true, true) => "TUN 模式已全局接管流量，无需系统代理",
                        (true, false) => "开关 Windows/桌面系统代理（指向本地 SOCKS 监听）",
                    });
                if resp.clicked() {
                    if sys_on {
                        Self::remove_system_proxy_static();
                        self.add_log("已关闭系统代理".to_string());
                    } else {
                        let url = format!("socks5://{}", self.config.proxy_listen_addr.trim());
                        self.set_system_proxy(&url);
                        self.add_log(format!("已开启系统代理 → {}", url));
                    }
                }
            });
            ui.add_space(palette::SPACING_XS);
            // 最近日志摘要（最近 3 条，与原总览一致）
            ui.separator();
            let start = self.logs.len().saturating_sub(3);
            if start == self.logs.len() {
                ui.weak("暂无日志");
            }
            for line in &self.logs[start..] {
                ui.small(line);
            }
        });
    }

    /// 系统代理开关按钮所依据的状态：Windows 用后台检测缓存（缺省视为关）；
    /// 非 Windows 无检测缓存，按「运行中默认已设置」的近似语义返回 proxy_running。
    /// 只影响按钮文案，误判可再点一次纠正（幂等 enable/disable）。
    #[allow(unused_variables)]
    pub(crate) fn system_proxy_on_cached(&self) -> bool {
        #[cfg(windows)]
        {
            self.sys_proxy_check_cache
                .map(|(_, on)| on)
                .unwrap_or(false)
        }
        #[cfg(not(windows))]
        {
            self.proxy_running
        }
    }
}
