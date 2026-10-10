//! 首页（v4.1 重排，评审 R6-R10）：Hero 状态条 + 三数据卡（22px 数值主角）+
//! 快捷操作单行条 + 实时速率图（网格/坐标/30% 单色填充/图例/空态）。

use crate::app::start_button_state;
use crate::nodes::{best_online_node, median_online_latency, Tab};
use crate::palette;
use crate::theme::card_frame;
use crate::HydraApp;
use eframe::egui::{self};
use hydra_client::{format_bytes, format_speed};

impl HydraApp {
    /// 首页信息架构（设计 §3.5）：
    /// ① Hero 条（状态三通道 + 主操作按钮 + 监听摘要，描边随状态——R7）
    /// ② 启动失败横幅（DANGER_BG 组件）与未配置节点引导卡（异常态，R7）
    /// ③ 三数据卡（今日流量 / 活跃节点 / 当前节点，22px 数值主角——R10；
    ///    当前节点整卡可点跳节点页，hover 描边 accent——R8）
    /// ④ 快捷操作单行条（R9：置于三卡与图表之间）
    /// ⑤ 实时速率图（R6：透明底/网格/Y 轴刻度/单色 30% 填充/图例半透明底）
    pub(crate) fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("首页")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.add_space(palette::SPACING_XS);

        // ── ① Hero 条（一级卡）：描边随状态（运行 success / 启动中 warning /
        //    停止 border），左侧状态三通道大字，中部主操作按钮，右侧监听摘要 ──
        let (state_symbol, state_text, state_color, hero_stroke) = if self.proxy_running {
            ("●", "运行中", palette::success(), palette::success())
        } else if self.proxy_starting {
            ("◐", "启动中…", palette::warning(), palette::warning())
        } else {
            ("○", "已停止", palette::text_faint(), palette::border())
        };
        egui::Frame::none()
            .fill(palette::bg_card())
            .stroke(egui::Stroke::new(1.5_f32, hero_stroke))
            .rounding(egui::Rounding::same(palette::RADIUS_CARD))
            .inner_margin(egui::Margin::same(palette::SPACING_LG))
            .outer_margin(egui::Margin::same(palette::SPACING_XS))
            .show(ui, |ui| {
                // Hero 整体高度 ≥72px（上下内边距 LG×2 + 内容行 ≥40px）；
                // horizontal 布局默认交叉轴居中（状态大字与按钮垂直居中——审美验收第 4 条）
                ui.horizontal(|ui| {
                    ui.set_min_height(40.0);
                    // 左：状态三通道（大圆点字形 + 22px 大字状态，R10 数据值档）
                    ui.label(
                        egui::RichText::new(state_symbol)
                            .size(palette::FONT_DATA)
                            .color(state_color)
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new(state_text)
                            .size(palette::FONT_DATA)
                            .color(state_color)
                            .strong(),
                    );
                    // 中：主操作按钮（R7 三态 + 审美验收第 2 条：正规主按钮——
                    // 最小 120×32、圆角 RADIUS_CTRL；停止态 = danger 描边幽灵按钮）
                    let (btn_text, btn_enabled) =
                        start_button_state(self.proxy_running, self.proxy_starting);
                    let btn = if !btn_enabled {
                        // 启动中：禁用（bg_faint 底 + text_disabled 前景，R3 令牌）
                        egui::Button::new(
                            egui::RichText::new(btn_text)
                                .size(palette::FONT_BODY)
                                .color(palette::text_disabled()),
                        )
                        .fill(palette::bg_faint())
                        .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
                    } else if self.proxy_running {
                        // 运行态：danger 描边幽灵按钮（透明底 + danger 文字）
                        egui::Button::new(
                            egui::RichText::new(btn_text)
                                .size(palette::FONT_BODY)
                                .color(palette::danger())
                                .strong(),
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .stroke(egui::Stroke::new(1.0_f32, palette::danger()))
                        .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
                    } else {
                        // 停止态：accent 主按钮（text_on_accent 深墨文字，R4）
                        egui::Button::new(
                            egui::RichText::new(btn_text)
                                .size(palette::FONT_BODY)
                                .color(palette::text_on_accent())
                                .strong(),
                        )
                        .fill(palette::accent())
                        .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
                    };
                    let resp = ui.add_sized([120.0, 32.0], btn);
                    if resp.clicked() {
                        if self.proxy_running {
                            self.stop_proxy();
                        } else {
                            self.start_proxy();
                        }
                    }
                    // 右：监听摘要小字（长地址截断 + hover 全量）
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!(
                                    "监听 {}",
                                    self.config.proxy_listen_addr
                                ))
                                .size(palette::FONT_SECONDARY)
                                .color(palette::text_weak()),
                            )
                            .truncate(true),
                        );
                    });
                });
            });

        // ── ② 异常态（R7）：启动失败横幅（DANGER_BG）置于 Hero 下 ──
        if !self.proxy_running && !self.proxy_starting {
            if let Some((_, line)) = self
                .logs
                .iter()
                .rev()
                .find(|(_, l)| l.contains("启动失败") || l.contains("启动超时"))
            {
                crate::components::banner(
                    ui,
                    crate::components::BannerKind::Danger,
                    line,
                );
                ui.add_space(palette::SPACING_XS);
            }
        }

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

        // 三数据卡内容先算成纯数据（渲染闭包只依赖本地量，可安全复用两套布局）
        let flow_main = format!("⬇ {}", format_bytes(daily_down));
        let flow_sub = match &stats {
            Some(s) => format!(
                "⬆ {} · 速率 ⬇ {}/s",
                format_bytes(daily_up),
                format_speed(s.download_speed)
            ),
            None => format!("⬆ {}", format_bytes(daily_up)),
        };
        let active_main = format!("{}/{}", online, total);
        let active_sub = match median_latency {
            Some(ms) => (
                format!("延迟中位 {}ms", ms),
                palette::latency_color(Some(ms)),
            ),
            None => ("延迟中位 —".to_string(), palette::text_faint()),
        };
        let (node_main, node_sub, node_addr, node_clickable) = match &best_node {
            Some((addr, ms)) => (
                self.config.node_display_name(addr),
                format!("{}ms", ms),
                Some(addr.clone()),
                true,
            ),
            None => (
                "—".to_string(),
                if total == 0 {
                    "暂无节点".to_string()
                } else {
                    "无在线节点".to_string()
                },
                None,
                false,
            ),
        };
        // 未配置节点引导（审美验收第 3 条）：空态只替换「当前节点」一张卡的
        // 内容——三卡横排 / 快捷条 / 图表卡结构始终渲染，不再整卡吞掉
        let no_nodes = total == 0;

        // ── ③ 三数据卡（22px 数值主角，标签 12px 上置）：
        //    宽窗口三卡一行，窄窗口纵向堆叠（确定性布局不溢出）──
        ui.add_space(palette::SPACING_LG);
        let avail_w = ui.available_width();
        // 数据卡渲染体（含 hover 描边反馈的可点卡处理在外层做）
        let flow_card = |ui: &mut egui::Ui| {
            stat_label(ui, "今日流量");
            ui.label(
                egui::RichText::new(&flow_main)
                    .size(palette::FONT_DATA)
                    .color(palette::accent())
                    .strong(),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&flow_sub)
                        .size(palette::FONT_SECONDARY)
                        .color(palette::text_weak()),
                )
                .truncate(true),
            );
        };
        let active_card = |ui: &mut egui::Ui| {
            stat_label(ui, "活跃节点");
            ui.label(
                egui::RichText::new(&active_main)
                    .size(palette::FONT_DATA)
                    .strong(),
            );
            ui.colored_label(active_sub.1, &active_sub.0);
        };
        let node_card = |ui: &mut egui::Ui| {
            if no_nodes {
                // 未配置节点：引导内容占位（与数据卡同构，结构不塌）。
                // 文案从简（右列窄卡：长句+按钮会双重截断，审美验收 B-2）
                stat_label(ui, "当前节点");
                ui.label(
                    egui::RichText::new("尚未配置")
                        .size(palette::FONT_TITLE)
                        .color(palette::text_weak())
                        .strong(),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new("前往「节点」页添加")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::text_faint()),
                    )
                    .truncate(true),
                );
                ui.add_space(palette::SPACING_XS);
                if ui.small_button("前往节点页 →").clicked() {
                    // 闭包拿不到 self：点击写入 ctx 内存，外层读取后切页
                    ui.ctx().data_mut(|d| {
                        d.insert_temp(egui::Id::new("goto_nodes"), true);
                    });
                }
                return;
            }
            stat_label(ui, "当前节点（调度参考）");
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&node_main)
                        .size(palette::FONT_DATA)
                        .strong(),
                )
                .truncate(true),
            )
            .on_hover_text(node_addr.clone().unwrap_or_default());
            // truncate(true)：卡宽固定，副标题必须随卡收缩（否则溢出卡框/窗口）
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&node_sub)
                        .size(palette::FONT_SECONDARY)
                        .color(if node_addr.is_some() {
                            palette::text_weak()
                        } else {
                            palette::text_faint()
                        }),
                )
                .truncate(true),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(if node_clickable {
                        "自动按最低延迟调度 · 点击前往节点页 →"
                    } else {
                        "自动按最低延迟调度"
                    })
                    .size(palette::FONT_SECONDARY)
                    .color(palette::text_weak()),
                )
                .truncate(true),
            );
        };

        let mut goto_nodes = false;
        // 三数据卡：始终横排三列等宽（审美验收第 1 条——去掉宽窄分支与一切
        // 宽度钳制残留；每卡宽度 = (可用宽 − 2×间距)/3，窄窗口靠 truncate 收缩）
        let gap = palette::SPACING_SM;
        let card_w = (avail_w - gap * 4.0) / 3.0;
        // 卡内容区宽度 = 整卡宽 − 内边距 MD×2 − 外边距 XS×2
        let inner_w = (card_w - (palette::SPACING_MD + palette::SPACING_XS) * 2.0).max(1.0);
        egui::Grid::new("overview_stat_cards")
            .num_columns(3)
            .spacing([gap, gap])
            .show(ui, |ui| {
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(inner_w);
                    ui.set_max_width(inner_w);
                    flow_card(ui);
                });
                card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(inner_w);
                    ui.set_max_width(inner_w);
                    active_card(ui);
                });
                // 当前节点卡：整卡可点跳节点页（R8），hover 描边 accent
                let node_frame = card_frame(ui).show(ui, |ui| {
                    ui.set_min_width(inner_w);
                    ui.set_max_width(inner_w);
                    node_card(ui);
                });
                let resp = ui
                    .interact(
                        node_frame.response.rect,
                        egui::Id::new("overview_node_card"),
                        egui::Sense::click(),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if node_clickable && resp.hovered() {
                    // hover 反馈：accent 描边覆盖在 Frame 之上（R8）
                    ui.painter().rect_stroke(
                        resp.rect,
                        egui::Rounding::same(palette::RADIUS_CARD),
                        egui::Stroke::new(1.5_f32, palette::accent()),
                    );
                }
                if resp.clicked() && node_clickable {
                    goto_nodes = true;
                }
                ui.end_row();
            });
        // 引导卡按钮经 ctx 内存中转切页（闭包拿不到 self）
        if ui.ctx().data_mut(|d| d.get_temp::<bool>(egui::Id::new("goto_nodes")) == Some(true)) {
            ui.ctx().data_mut(|d| {
                d.remove_temp::<bool>(egui::Id::new("goto_nodes"));
            });
            goto_nodes = true;
        }
        if goto_nodes {
            self.current_tab = Tab::Nodes;
        }

        // ── ④ 快捷操作单行条（R9：单行横排非卡片，置于三卡与图表之间）──
        ui.add_space(palette::SPACING_SM);
        egui::Frame::none()
            .fill(palette::bg_faint())
            .rounding(egui::Rounding::same(palette::RADIUS_CTRL))
            .inner_margin(egui::Margin::symmetric(palette::SPACING_MD, palette::SPACING_SM))
            .outer_margin(egui::Margin::same(palette::SPACING_XS))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("快捷操作")
                            .size(palette::FONT_SECONDARY)
                            .color(palette::text_weak())
                            .strong(),
                    );
                    // 全部节点测试（与节点页同一入口）
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
                    // 系统代理快捷开关：代理运行且未开 TUN 时可手动开/关
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
                            let url =
                                format!("socks5://{}", self.config.proxy_listen_addr.trim());
                            self.set_system_proxy(&url);
                            self.add_log(format!("已开启系统代理 → {}", url));
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("查看全部日志 →").clicked() {
                            self.current_tab = Tab::Logs;
                        }
                    });
                });
            });

        // ── ⑤ 实时速率图卡（R6：背景透明同卡底、chart_grid 网格、Y 轴刻度、
        //    上行 chart_up / 下行 chart_down 2px + 单色 30% alpha 填充、
        //    图例半透明底、空态居中提示 + 次按钮；交互保持禁用）──
        ui.add_space(palette::SPACING_SM);
        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("实时速率")
                        .size(palette::FONT_TITLE)
                        .strong(),
                );
                ui.colored_label(
                    palette::chart_up(),
                    format!(
                        "⬆ {}/s",
                        format_speed(up_series.last().copied().unwrap_or(0.0))
                    ),
                );
                ui.colored_label(
                    palette::chart_down(),
                    format!(
                        "⬇ {}/s",
                        format_speed(down_series.last().copied().unwrap_or(0.0))
                    ),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small("最近 120 个采样点（500ms/点）");
                });
            });
            let has_data = !up_series.is_empty() || !down_series.is_empty();
            // 固定高度曲线区（180px）：给 Plot / 空态一个确定大小的 rect
            ui.allocate_ui(egui::vec2(ui.available_width(), 180.0), |ui| {
                if has_data {
                    egui_plot::Plot::new("dashboard_speed_plot")
                        // 仪表盘装饰性图表：禁用全部交互与悬停读数（R6 显式约定）
                        .allow_zoom(false)
                        .allow_drag(false)
                        .allow_scroll(false)
                        .allow_boxed_zoom(false)
                        .allow_double_click_reset(false)
                        .coordinates_formatter(
                            egui_plot::Corner::RightBottom,
                            egui_plot::CoordinatesFormatter::new(|_pt, _bounds| String::new()),
                        )
                        // R6：背景透明（同卡底）；网格/坐标轴取 Visuals + chart_grid
                        .show_background(false)
                        .show_grid(true)
                        .show_axes([false, true])
                        // 图例内嵌**右下角**（审美验收 B-3：LeftTop 的半透明底
                        // 会叠在卡片标题「实时速率」上，Dark/Abyss 下把标题压暗）
                        .legend(
                            egui_plot::Legend::default()
                                .position(egui_plot::Corner::RightBottom)
                                .background_alpha(0.6),
                        )
                        // Y 轴刻度标签：速率自动单位格式化（KB/s → MB/s…）
                        .custom_y_axes(vec![
                            egui_plot::AxisHints::new_y()
                                .formatter(|mark, _digits, _range| format_speed(mark.value)),
                        ])
                        .show(ui, |plot| {
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
                            // 面积填充（企业评审 P1-1 修复）：egui_plot 0.27 的
                            // Line::fill 参数是「Y 基线坐标」而非透明度，且填充
                            // alpha 库内写死 0.05——改用 Polygon 自绘封闭区域
                            // （曲线点 + 基线两角）实现真 30% 面积填充；描边
                            // 透明，曲线本体仍由下方 Line 绘制
                            if !up_series.is_empty() {
                                let n = up_series.len() as f64 - 1.0;
                                let area: egui_plot::PlotPoints = up_series
                                    .iter()
                                    .enumerate()
                                    .map(|(i, v)| [i as f64, *v])
                                    .chain(std::iter::once([n, 0.0]))
                                    .chain(std::iter::once([0.0_f64, 0.0]))
                                    .collect();
                                plot.polygon(
                                    egui_plot::Polygon::new(area)
                                        .fill_color(palette::chart_up().gamma_multiply(0.3))
                                        .stroke(egui::Stroke::NONE),
                                );
                            }
                            if !down_series.is_empty() {
                                let n = down_series.len() as f64 - 1.0;
                                let area: egui_plot::PlotPoints = down_series
                                    .iter()
                                    .enumerate()
                                    .map(|(i, v)| [i as f64, *v])
                                    .chain(std::iter::once([n, 0.0]))
                                    .chain(std::iter::once([0.0_f64, 0.0]))
                                    .collect();
                                plot.polygon(
                                    egui_plot::Polygon::new(area)
                                        .fill_color(palette::chart_down().gamma_multiply(0.3))
                                        .stroke(egui::Stroke::NONE),
                                );
                            }
                            plot.line(
                                egui_plot::Line::new(up_points)
                                    .name("上行")
                                    .color(palette::chart_up())
                                    .width(2.0_f32),
                            );
                            plot.line(
                                egui_plot::Line::new(down_points)
                                    .name("下行")
                                    .color(palette::chart_down())
                                    .width(2.0_f32),
                            );
                        });
                } else {
                    // 空态：居中图标式提示 + 次按钮引导（设计 §3.4）
                    ui.vertical_centered(|ui| {
                        ui.add_space(48.0);
                        ui.colored_label(
                            palette::text_faint(),
                            "📡 启动代理后，这里会实时显示上下行速率",
                        );
                        ui.add_space(palette::SPACING_SM);
                        let (_, enabled) =
                            start_button_state(self.proxy_running, self.proxy_starting);
                        if ui.add_enabled(enabled, egui::Button::new("▶ 启动代理")).clicked() {
                            self.start_proxy();
                        }
                    });
                }
            });
        });

        // ── 最近日志摘要（最近 3 条；原先快捷卡内信息随卡片改条后垫底）──
        ui.add_space(palette::SPACING_SM);
        let start = self.logs.len().saturating_sub(3);
        if start == self.logs.len() {
            ui.weak("暂无日志");
        }
        for (_, line) in &self.logs[start..] {
            ui.small(line);
        }
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

/// 数据卡标签（12px 上置 + 弱色，R10）。
/// truncate(true)：卡宽固定，标签必须随卡收缩——否则长标签（如
/// 「当前节点（调度参考）」）会把文本推出卡框乃至窗口右缘（实测验收发现）
fn stat_label(ui: &mut egui::Ui, label: &str) {
    ui.add(
        egui::Label::new(
            egui::RichText::new(label)
                .size(palette::FONT_SECONDARY)
                .color(palette::text_weak()),
        )
        .truncate(true),
    );
}
