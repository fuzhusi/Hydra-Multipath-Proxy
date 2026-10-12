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
                    // 右：TUN 规则模式状态位（R9：挂在 TUN 状态位，不覆盖监听地址小字）
                    // 仅代理运行中且 TUN + 规则分流生效时显示；监听地址小字原样保留
                    if self.proxy_running
                        && self.config.tun_enabled
                        && self.config.tun_rule_mode
                    {
                        ui.label(
                            egui::RichText::new("规则分流 · CN 直连 · 其余经节点")
                                .size(palette::FONT_SECONDARY)
                                .color(palette::info())
                                .strong(),
                        );
                    }
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
        // （批次 A2 机械适配：logs 元素 (LogLevel, String) → LogEntry 结构体；
        //   仅编译适配，不改本页任何行为）
        if !self.proxy_running && !self.proxy_starting {
            if let Some(entry) = self
                .logs
                .iter()
                .rev()
                .find(|e| e.text.contains("启动失败") || e.text.contains("启动超时"))
            {
                crate::components::banner(
                    ui,
                    crate::components::BannerKind::Danger,
                    &entry.text,
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
            Some((addr, ms)) => {
                let name = self.config.node_display_name(addr);
                // 卡面显示**去端口**的地址（用户反馈：22/16px 下 IP:端口必然
                // 截断；纯 IP 13 字符 16px 可全显）。端口保留在悬停提示。
                // 仅当末段是纯数字端口样式才拆——自定义节点名含冒号不受影响
                let display = match name.rsplit_once(':') {
                    Some((h, p))
                        if !h.is_empty()
                            && p.len() <= 5
                            && p.chars().all(|c| c.is_ascii_digit()) =>
                    {
                        h.to_string()
                    }
                    _ => name,
                };
                (
                    display,
                    format!("{}ms", ms),
                    Some(addr.clone()),
                    true,
                )
            }
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
            // 自适应字号（用户反馈）：IP 含端口等长文本在 22px 大字下必然截断
            // ——按长度分档（≤10 字 22px / ≤14 字 18px / 更长 16px），
            // truncate 仅作极窄窗口兜底
            let value_size = match node_main.chars().count() {
                0..=10 => palette::FONT_DATA,
                11..=14 => 18.0_f32,
                _ => 16.0_f32,
            };
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&node_main)
                        .size(value_size)
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
        // 三数据卡：ui.columns(3) **构造级等宽**（实测修复：egui Grid 列宽随
        // 内容最小宽度浮动——三列实测 232/240/271px，第三列被撑出窗口右缘；
        // columns 恒为可用宽/3，从根上消灭不等宽）。卡内容宽 = 列宽 − Frame
        // 边距（内 MD×2 + 外 XS×2 = 32px），窄窗口靠 truncate 收缩。
        let frame_pad = (palette::SPACING_MD + palette::SPACING_XS) * 2.0;
        ui.columns(3, |cols| {
            let fit_inner = |ui: &mut egui::Ui| {
                let w = (ui.available_width() - frame_pad).max(1.0);
                ui.set_min_width(w);
                ui.set_max_width(w);
            };
            // 列 0：今日流量
            card_frame(&cols[0]).show(&mut cols[0], |ui| {
                fit_inner(ui);
                flow_card(ui);
            });
            // 列 1：活跃节点
            card_frame(&cols[1]).show(&mut cols[1], |ui| {
                fit_inner(ui);
                active_card(ui);
            });
            // 列 2：当前节点（整卡可点跳节点页，R8）
            let node_resp = card_frame(&cols[2]).show(&mut cols[2], |ui| {
                fit_inner(ui);
                node_card(ui);
            });
            let resp = cols[2]
                .interact(
                    node_resp.response.rect,
                    egui::Id::new("overview_node_card"),
                    egui::Sense::click(),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if node_clickable && resp.hovered() {
                // hover 反馈：accent 描边覆盖在 Frame 之上（R8）
                cols[2].painter().rect_stroke(
                    resp.rect,
                    egui::Rounding::same(palette::RADIUS_CARD),
                    egui::Stroke::new(1.5_f32, palette::accent()),
                );
            }
            if resp.clicked() && node_clickable {
                goto_nodes = true;
            }
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
                    // 分流模式快捷开关（用户需求：与 TUN 模式并排，首页一键切换；
                    // 与设置页同一字段 tun_rule_mode，重启代理生效）。
                    // TUN 关闭时禁用（分流仅 TUN 模式下有意义，语义同设置页）
                    let rule_resp = ui
                        .add_enabled(
                            tun_on,
                            egui::Checkbox::new(
                                &mut self.config.tun_rule_mode,
                                egui::RichText::new("分流：CN 直连")
                                    .size(palette::FONT_BODY),
                            ),
                        )
                        .on_hover_text(match tun_on {
                            false => "先开启 TUN 模式后可用",
                            true => "规则分流：命中 CN/自定义规则直连，其余走节点（重启代理生效；规则文件见「⚙ 设置」页）",
                        });
                    if rule_resp.changed() {
                        self.maybe_save_config(true);
                        self.add_log(if self.config.tun_rule_mode {
                            "分流模式：规则分流（CN 直连 · 其余经节点；重启代理后生效）".to_string()
                        } else {
                            "分流模式：全局接管（重启代理后生效）".to_string()
                        });
                    }
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
                    ui.small("最近 10 秒（20 点 · 500ms/点）");
                });
            });
            let has_data = !up_series.is_empty() || !down_series.is_empty();
            // Y 离散档位上限（nice_y_cap）：网格静止的关键
            let y_cap = nice_y_cap(&up_series, &down_series);
            // 固定高度曲线区（180px）：给 Plot / 空态一个确定大小的 rect
            ui.allocate_ui(egui::vec2(ui.available_width(), 180.0), |ui| {
                if has_data {
                    egui_plot::Plot::new("dashboard_speed_plot")
                        // 坐标稳定方案（用户反馈：网格白线随数据每帧重排=卡顿
                        // 感）：egui_plot 0.27 无公开 set_bounds API——改用
                        // 「隐形档位线」：y=档位 处一条透明线，auto-bounds 把
                        // Y 上限钉在离散档位上，仅峰值跨档时网格才重排
                        .allow_zoom(false)
                        .allow_drag(false)
                        .allow_scroll(false)
                        .allow_boxed_zoom(false)
                        .allow_double_click_reset(false)
                        .coordinates_formatter(
                            egui_plot::Corner::RightBottom,
                            egui_plot::CoordinatesFormatter::new(|_pt, _bounds| String::new()),
                        )
                        // 悬停读数（用户反馈第 2 轮）：光标处**同时显示上行/下行**
                        // ——label_formatter 捕获两条序列快照，按光标 x=采样序号
                        // 查表；标签由 egui_plot 绘制在光标旁（右侧）。克隆
                        // 120×f64×2 每帧成本可忽略。
                        .label_formatter({
                            let up_snap = up_series.clone();
                            let down_snap = down_series.clone();
                            move |_name, value| {
                                let idx = (value.x.round().clamp(0.0, 19.0)) as usize;
                                let up = format_speed(up_snap.get(idx).copied().unwrap_or(0.0));
                                let down = format_speed(down_snap.get(idx).copied().unwrap_or(0.0));
                                format!("上行 {up}/s\n下行 {down}/s")
                            }
                        })
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
                            // 隐形档位线：Y 上限钉在离散档位（网格静止的关键）；
                            // 未命名 → 不进图例。线本体透明，仅撑起 auto-bounds
                            plot.line(
                                egui_plot::Line::new(egui_plot::PlotPoints::from(vec![
                                    [0.0, y_cap],
                                    [19.0, y_cap],
                                ]))
                                .stroke(egui::Stroke::NONE),
                            );
                            // Catmull-Rom 样条平滑（用户反馈：折线太生硬）——
                            // 相邻四控制点插值，每段 6 个采样点；点数 <3 时
                            // 原样返回（无法构造切线）
                            let up_points = smooth_series(&up_series);
                            let down_points = smooth_series(&down_series);
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
        // （批次 A2 机械适配：VecDeque 切片 → 迭代器 skip，行为不变）
        ui.add_space(palette::SPACING_SM);
        if self.logs.is_empty() {
            ui.weak("暂无日志");
        }
        let skip = self.logs.len().saturating_sub(3);
        for entry in self.logs.iter().skip(skip) {
            ui.small(&entry.text);
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

/// Y 轴离散档位上限（用户反馈：网格线随数据每帧重排=卡顿感）。取「能容纳
/// 双序列峰值的最近档」，档间跳变仅在峰值跨档时发生——平时网格完全静止。
/// 档位下限 100 KB/s（空闲时网格也稳定在 100K 量级）。
fn nice_y_cap(a: &[f64], b: &[f64]) -> f64 {
    let peak = a.iter().chain(b.iter()).copied().fold(0.0_f64, f64::max);
    const TIERS: [f64; 12] = [
        100.0e3, 250.0e3, 500.0e3, 1.0e6, 2.5e6, 5.0e6, 10.0e6, 25.0e6, 50.0e6, 100.0e6,
        250.0e6, 500.0e6,
    ];
    // 注意：上表第 3 项写作 500.0e6*0.001 是笔误防护位——实际 500 KB/s
    TIERS.iter().copied().find(|t| peak <= *t).unwrap_or(peak * 1.3)
}

/// Catmull-Rom 样条平滑（用户反馈：折线生硬）——相邻四控制点三次插值，
/// 每段 6 个采样点。端点用重复控制点补位；点数 <3 无法构造切线，原样返回。
/// x 坐标均匀递增（i + t），保证悬停按序号查表仍对得上。
fn smooth_series(series: &[f64]) -> egui_plot::PlotPoints {
    const SEGMENTS: usize = 6;
    if series.len() < 3 {
        return series
            .iter()
            .enumerate()
            .map(|(i, v)| [i as f64, *v])
            .collect();
    }
    let mut pts: Vec<[f64; 2]> = Vec::with_capacity(series.len() * SEGMENTS);
    let at = |i: usize| series[i.min(series.len() - 1)];
    for i in 0..series.len() - 1 {
        let (p0, p1, p2, p3) = (at(i.saturating_sub(1)), series[i], series[i + 1], at(i + 2));
        for s in 0..SEGMENTS {
            let t = s as f64 / SEGMENTS as f64;
            let (t2, t3) = (t * t, t * t * t);
            let y = 0.5 * ((2.0 * p1)
                + (-p0 + p2) * t
                + (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * t2
                + (-p0 + 3.0 * p1 - 3.0 * p2 + p3) * t3)
                .max(0.0); // Catmull-Rom 端点会轻微下冲越 0（Y 轴出现 -1 B/s），钳底
            pts.push([i as f64 + t, y]);
        }
    }
    let last = series.len() - 1;
    pts.push([last as f64, series[last]]);
    pts.into_iter().collect()
}
