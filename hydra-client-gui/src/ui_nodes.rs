//! 节点页：节点卡片列表 + 组视图 tabs + 「＋」四个对话框
//!（分享链接导入 / 手动添加 / 分享选择）集中渲染。

use crate::config;
use crate::nodes::{filter_nodes_by_group, group_summary, node_group_of, Tab, GROUP_MANUAL};
use crate::palette;
use crate::HydraApp;
use eframe::egui;

impl HydraApp {
    /// 节点页（UI 重设计第一批，按老板构想重做）：
    /// - 页面主体 = 节点卡片列表（状态色点/名称/地址/延迟色标/操作按钮）；
    /// - 右上角固定「＋」按钮 → 下拉四项：从分享链接导入 / 扫描二维码导入 /
    ///   手动添加节点 / 分享节点（分享与导入全部收进菜单，不再平铺占页面）；
    /// - 全局凭据（认证密钥/证书）移出本页，收敛到「⚙ 设置」页「全局凭据」区，
    ///   本页仅在缺失时显示一条窄横幅提示并跳转；
    /// - 页尾订阅快捷管理区移除（完整生命周期全部在「📡 订阅」页，功能零丢失）。
    pub(crate) fn ui_nodes(&mut self, ui: &mut egui::Ui) {
        // ── 页头：标题 + 右侧「分享节点」+「全部测速」──
        // （UI 重设计第二批：「＋」菜单及其对话框入口整体迁往「📡 订阅」页「＋ 新建」；
        //   分享节点（含批量导出）不是"新建"动作，保留在节点页页头）
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("节点")
                    .size(palette::FONT_HEADING)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // 全部测速（测速进行中显示 spinner + 进度提示）
                if self.health_check_receiver.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label("全部测速中…");
                }
                // 09-G-3：测速进行中禁用按钮（防重入覆盖 health_check_receiver，
                // 上一批结果通道被弃、重复探测）
                let speedtest_busy = self.health_check_receiver.is_some();
                let speedtest_btn = egui::Button::new("⚡ 全部测速");
                let speedtest_resp = if speedtest_busy {
                    ui.add_enabled(false, speedtest_btn)
                } else {
                    ui.add(speedtest_btn)
                };
                if speedtest_resp.clicked() {
                    self.test_all_nodes();
                }
                if ui
                    .button("🔗 分享节点")
                    .on_hover_text("按节点分享（二维码/完整/紧凑链接），或批量导出分享链接")
                    .clicked()
                {
                    self.share_pick_open = true;
                }
            });
        });
        ui.separator();

        // ── 全局凭据缺失横幅（凭据编辑已收敛到「⚙ 设置」页，此处只提示不编辑）──
        let key_missing = self.config.auth_key.trim().is_empty();
        let cert_missing =
            self.config.cert_path.trim().is_empty() && self.config.cert_der_b64.trim().is_empty();
        if key_missing || cert_missing {
            egui::Frame::none()
                .fill(palette::BG_CARD)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(
                    palette::SPACING_MD,
                    palette::SPACING_XS + 2.0,
                ))
                .outer_margin(egui::Margin::symmetric(0.0_f32, palette::SPACING_XS))
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    palette::WARNING.gamma_multiply(0.5),
                ))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            palette::WARNING,
                            "⚠ 全局凭据未配置（认证密钥或节点证书缺失），代理无法启动",
                        );
                        if ui.small_button("前往设置 →").clicked() {
                            self.current_tab = Tab::Settings;
                        }
                    });
                });
        }

        // ── 组视图（复刻 Clash Meta 代理组 tabs）──
        // 组 = 数据来源过滤：全部 / 手动认领 / 某订阅认领的地址（与 GuiConfig 认领机制一致）。
        // 选中的订阅组已被删除时回落「全部」（订阅在「📡 订阅」页删除的场景）
        if let Some(g) = &self.node_group {
            if g != GROUP_MANUAL && !self.config.subscriptions.iter().any(|s| &s.name == g) {
                self.node_group = None;
            }
        }
        ui.add_space(palette::SPACING_XS);

        // ── 顶部组标签行：横排可滚动按钮组，选中高亮，含成员数量徽标 ──
        let all_count = self.config.node_addrs.len();
        let manual_count = self
            .config
            .node_addrs
            .iter()
            .filter(|a| node_group_of(&self.config, a).is_none())
            .count();
        let mut tabs: Vec<(Option<String>, String)> = Vec::new();
        tabs.push((None, format!("全部 · {}", all_count)));
        tabs.push((
            Some(GROUP_MANUAL.to_string()),
            format!("✏️ 手动 · {}", manual_count),
        ));
        for sub in &self.config.subscriptions {
            let cnt = self
                .config
                .node_addrs
                .iter()
                .filter(|a| node_group_of(&self.config, a).as_deref() == Some(sub.name.as_str()))
                .count();
            tabs.push((Some(sub.name.clone()), format!("📡 {} · {}", sub.name, cnt)));
        }
        egui::ScrollArea::new([true, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                for (key, label) in &tabs {
                    let selected = self.node_group.as_deref() == key.as_deref();
                    if ui
                        .selectable_label(
                            selected,
                            egui::RichText::new(label).size(palette::FONT_BODY),
                        )
                        .clicked()
                    {
                        self.node_group = key.clone();
                    }
                }
            });
        });
        ui.separator();

        // ── 组头栏：组名 + 节点数 + 在线/离线摘要 +「⚡ 全部测速（本组）」──
        let members =
            filter_nodes_by_group(&self.config, &self.config.node_addrs, &self.node_group);
        let (online, offline) = group_summary(&self.node_status, &members);
        let group_name = match &self.node_group {
            None => "全部节点".to_string(),
            Some(g) if g == GROUP_MANUAL => "✏️ 手动节点".to_string(),
            Some(name) => format!("📡 {}", name),
        };
        egui::Frame::none()
            .fill(palette::BG_CARD)
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::symmetric(
                palette::SPACING_MD,
                palette::SPACING_XS + 2.0,
            ))
            .outer_margin(egui::Margin::symmetric(0.0_f32, palette::SPACING_XS))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&group_name)
                            .size(palette::FONT_TITLE)
                            .strong(),
                    );
                    ui.colored_label(
                        palette::TEXT_WEAK,
                        format!(
                            "{} 节点 ｜ 在线 {} / 离线 {}",
                            members.len(),
                            online,
                            offline
                        ),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button("⚡ 全部测速（本组）")
                            .on_hover_text("对本组成员逐个发起握手测速（串行，复用单测通道）")
                            .clicked()
                        {
                            self.start_group_test(members.clone());
                        }
                    });
                });
            });

        // ── 组内节点卡片（紧凑双列/三列自适应网格，沿用第一批卡片元素）──
        if self.config.node_addrs.is_empty() {
            egui::Frame::none()
                .fill(palette::BG_CARD)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::same(palette::SPACING_MD))
                .outer_margin(egui::Margin::symmetric(0.0_f32, palette::SPACING_XS))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("还没有节点。")
                            .size(palette::FONT_BODY)
                            .color(palette::TEXT_WEAK),
                    );
                    ui.small("多个节点自动更新 → 「📡 订阅」页右上「＋ 新建」添加订阅源；单个节点 → 从分享链接导入");
                });
        } else if members.is_empty() {
            ui.add_space(palette::SPACING_XS);
            ui.colored_label(palette::TEXT_WEAK, "（本组暂无节点）");
        }
        let mut indices_to_remove = Vec::new();
        let mut edit_target: Option<String> = None;
        let mut manual_target: Option<String> = None;
        let node_addrs_clone = self.config.node_addrs.clone();
        // 组成员（按原列表顺序保留原始下标，供删除与操作定位）
        let entries: Vec<(usize, String)> = node_addrs_clone
            .iter()
            .enumerate()
            .filter(|(_, a)| members.contains(a))
            .map(|(i, a)| (i, a.clone()))
            .collect();
        // 紧凑化：按可用宽度自适应 1–3 列（卡宽约 300px 起）
        let card_min = 300.0_f32;
        let cols = ((ui.available_width() / card_min).floor() as usize).clamp(1, 3);
        // 列距 = SPACING_MD（与上方 Grid spacing 一致，卡片净宽相应扣减）
        let cell_width = ((ui.available_width() - palette::SPACING_MD * (cols as f32 - 1.0))
            / cols as f32
            - palette::SPACING_MD)
            .max(220.0);
        egui::Grid::new("node_group_grid")
            .num_columns(cols)
            .spacing([palette::SPACING_MD, palette::SPACING_SM])
            .show(ui, |ui| {
                for chunk in entries.chunks(cols) {
                    for (i, node_addr) in chunk {
                        let node_addr = node_addr.as_str();
                        // 状态三态：绿=Online / 黄=Degraded（在线但延迟≥500ms）/
                        // 红=Offline / 灰=未验证
                        let (connected, checked, latency) =
                            match self.node_status.get(node_addr) {
                                Some(s) => (s.connected, s.last_check.is_some(), s.latency_ms),
                                None => (false, false, None),
                            };
                        let dot = palette::status_color(connected, checked, latency);
                        let name = self.config.node_display_name(node_addr);
                        let source = self.config.node_source_label(node_addr);
                        let is_manual = source == config::NODE_SOURCE_MANUAL;
                        let latency_text = match latency {
                            Some(ms) => format!("{}ms", ms),
                            None if checked => "超时".to_string(),
                            None => "未测试".to_string(),
                        };
                        let testing_this =
                            self.node_testing_addr.as_deref() == Some(node_addr);
                        // ── 紧凑节点卡片：圆角 + 统一内边距，宽度锁定为网格列宽 ──
                        egui::Frame::none()
                            .fill(palette::BG_CARD)
                            .rounding(egui::Rounding::same(8.0))
                                                        .inner_margin(egui::Margin::same(palette::SPACING_MD))
                            .outer_margin(egui::Margin::same(2.0))
                            .stroke(egui::Stroke::new(1.0_f32, palette::BORDER))
                            .show(ui, |ui| {
                                ui.set_min_width(cell_width);
                                // 第一行：状态色点 + 名称/地址 + 延迟色标（来源已由组标签表达）
                                ui.horizontal(|ui| {
                                    let (rect, _) = ui
                                        .allocate_exact_size(
                                            egui::vec2(10.0, 10.0),
                                            egui::Sense::hover(),
                                        );
                                    ui.painter().circle_filled(rect.center(), 5.0, dot);
                                    if name == node_addr {
                                        ui.label(
                                            egui::RichText::new(node_addr)
                                                .size(palette::FONT_TITLE)
                                                .strong(),
                                        );
                                    } else {
                                        ui.label(
                                            egui::RichText::new(&name)
                                                .size(palette::FONT_TITLE)
                                                .strong(),
                                        )
                                        .on_hover_text(node_addr);
                                    }
                                    // 「全部」组里来源混合，补小组来源徽标（badge 字号）；组内已由标签行表达
                                    if self.node_group.is_none() {
                                        ui.label(
                                            egui::RichText::new(format!("[{}]", source))
                                                .size(palette::FONT_BADGE)
                                                .color(if is_manual {
                                                    palette::TEXT_FAINT
                                                } else {
                                                    palette::ACCENT
                                                }),
                                        );
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new(latency_text.as_str())
                                                    .size(palette::FONT_BODY)
                                                    .color(palette::latency_color(latency)),
                                            );
                                        },
                                    );
                                });
                                // 第二行：操作按钮（测速/分享/编辑（或另存为手动）/删除）
                                ui.horizontal(|ui| {
                                    if testing_this {
                                        ui.add(egui::Spinner::new().size(14.0));
                                        ui.label(
                                            egui::RichText::new("测速中…")
                                                .size(palette::FONT_SECONDARY)
                                                .color(palette::TEXT_WEAK),
                                        );
                                    } else if ui.small_button("⚡").on_hover_text("测速（完整握手）").clicked() {
                                        self.start_node_test(node_addr.to_string());
                                    }
                                    if ui.small_button("🔗").on_hover_text("分享").clicked() {
                                        self.open_share_dialog(node_addr.to_string());
                                    }
                                    // 订阅节点默认只读（地址/凭据随订阅更新覆盖），不提供编辑；
                                    // 可「另存为手动」解除认领后再改
                                    if is_manual {
                                        if ui.small_button("✏").on_hover_text("编辑").clicked() {
                                            edit_target = Some(node_addr.to_string());
                                        }
                                    } else if ui
                                        .small_button("⇥")
                                        .on_hover_text(
                                            "另存为手动：解除订阅认领，变为可编辑的手动节点（后续订阅更新不再覆盖/认领它）",
                                        )
                                        .clicked()
                                    {
                                        manual_target = Some(node_addr.to_string());
                                    }
                                    // 破坏性操作用危险色文案（frontend-design 交互反馈约定）
                                    if ui
                                        .small_button(
                                            egui::RichText::new("🗑").color(palette::DANGER),
                                        )
                                        .on_hover_text("删除节点")
                                        .clicked()
                                    {
                                        indices_to_remove.push(*i);
                                    }
                                });
                            });
                    }
                    // 末行补空位，保持网格对齐
                    for _ in chunk.len()..cols {
                        ui.label("");
                    }
                    ui.end_row();
                }
            });

        // 删除节点并添加日志
        for &i in indices_to_remove.iter().rev() {
            let removed = self.config.node_addrs.remove(i);
            self.node_status.remove(&removed);
            // 审查修复：备注名 + 独立证书路径一并清理（remove_node_state 收口），
            // 防止同地址复用节点时旧证书静默生效
            self.config.remove_node_state(&removed);
            self.add_log(format!("已删除节点: {}", removed));
        }
        if let Some(addr) = edit_target {
            self.open_node_edit(&addr);
        }
        if let Some(addr) = manual_target {
            if self.config.save_subscription_node_as_manual(&addr) {
                self.add_log(format!("节点 {} 已另存为手动节点（不再随订阅更新）", addr));
            }
        }

        // （导入/手动添加/分享选择对话框已集中到 update() 统一渲染：
        //   入口在「📡 订阅」页「＋ 新建」下拉与节点页「🔗 分享节点」，跨页不丢窗口）

        // 提示：订阅源的完整管理（增删改/更新/展开归属节点）在「📡 订阅」页
        ui.add_space(palette::SPACING_XS);
        ui.small("订阅来源拉取的节点自动进入上方列表（来源标记为订阅名）；订阅源的添加与更新见「📡 订阅」页右上「＋ 新建」");
    }

    /// 节点/订阅共用的三个对话框窗口（UI 重设计第一批迁入，第二批起集中渲染）：
    /// ① 从分享链接导入（粘贴版：多行粘贴 / 链接文件 → 创建命名分组「分享导入N」）
    /// ② 手动添加节点（表单：分组名称/地址/端口/证书 → 创建命名分组「手动节点N」）
    /// ③ 分享节点（按节点选择打开分享对话框；批量导出 v1 也在其中）
    /// 改为直接持 ctx 渲染（跨页窗口不丢失），由 update() 每帧统一调用
    pub(crate) fn ui_nodes_dialogs(&mut self, ctx: &egui::Context) {
        // ① 从分享链接导入（保持粘贴版：多行粘贴 hydra:// 链接 / base64 订阅文本 / 链接文件，
        //    → import_share_links_as_group 创建命名分组「分享导入N」）
        if self.import_dialog_open {
            let mut import_clicked = false;
            let mut load_file_clicked = false;
            egui::Window::new("📋 从分享链接导入")
                .collapsible(false)
                .resizable(false)
                .default_width(520.0)
                .show(ctx, |ui| {
                    egui::Grid::new("import_paste_grid")
                        .num_columns(2)
                        .spacing([palette::SPACING_SM, palette::SPACING_SM])
                        .show(ui, |ui| {
                            // 分组名称（打开对话框时预填「分享导入N」避重；重名提交时报错不关窗）
                            ui.label("分组名称：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.import_group_name)
                                    .desired_width(260.0)
                                    .hint_text("分享导入1"),
                            );
                            ui.end_row();
                            // 分享链接文本（多行粘贴）
                            ui.label("分享链接：");
                            ui.vertical(|ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.import_paste_text)
                                        .desired_width(360.0)
                                        .desired_rows(6)
                                        .hint_text(
                                            "每行一条 hydra:// 分享链接，\n或整段 base64 订阅文本",
                                        ),
                                );
                                ui.horizontal(|ui| {
                                    if ui.small_button("从链接文件导入...").clicked() {
                                        load_file_clicked = true;
                                    }
                                    ui.small(".txt：每行一条 hydra:// 链接，或整体 base64");
                                });
                            });
                            ui.end_row();
                        });
                    ui.add_space(palette::SPACING_XS);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("📥 导入（创建分组）").strong(),
                            ))
                            .clicked()
                        {
                            import_clicked = true;
                        }
                        if ui.button("关闭").clicked() {
                            self.import_dialog_open = false;
                        }
                    });
                    if let Some((ok, msg)) = &self.import_status {
                        ui.colored_label(
                            if *ok { palette::SUCCESS } else { palette::DANGER },
                            format!("{} {}", if *ok { "✓" } else { "✗" }, msg),
                        );
                    }
                    ui.small("ℹ 创建命名分组：条目出现在「📡 订阅」列表、节点进入同名组标签；该分组的「立即更新」会重新解析粘贴文本");
                });
            if load_file_clicked {
                self.import_paste_load_file();
            }
            if import_clicked {
                self.import_paste_submit();
            }
        }

        // ② 手动添加节点（表单 = 分组名称/地址/端口/证书文件 → 构造链接 → 创建命名分组；
        //    校验失败红字提示不关窗，成功才关窗并清空表单）
        if self.manual_add_open {
            let mut add_clicked = false;
            egui::Window::new("✏️ 手动添加节点")
                .collapsible(false)
                .resizable(false)
                .default_width(480.0)
                .show(ctx, |ui| {
                    egui::Grid::new("manual_add_grid")
                        .num_columns(2)
                        .spacing([palette::SPACING_SM, palette::SPACING_SM])
                        .show(ui, |ui| {
                            // 分组名称（打开对话框时预填「手动节点N」避重；重名提交时报错不关窗）
                            ui.label("分组名称：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.manual_group_name)
                                    .desired_width(260.0)
                                    .hint_text("手动节点1"),
                            );
                            ui.end_row();
                            // 服务器地址（IP 或域名均可）
                            ui.label("服务器地址：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.manual_form_addr)
                                    .desired_width(260.0)
                                    .hint_text("IP 或域名，如 43.133.91.218"),
                            );
                            ui.end_row();
                            // 端口（默认 443，提交时按 1..=65535 校验）
                            ui.label("端口：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.manual_form_port)
                                    .desired_width(260.0)
                                    .hint_text("443"),
                            );
                            ui.end_row();
                            // 证书文件：浏览选择；留空 = 不带证书（回落全局证书）
                            ui.label("证书文件：");
                            ui.horizontal(|ui| {
                                if ui.button("浏览...").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("证书文件", &["der", "crt", "cer"])
                                        .add_filter("全部文件", &["*"])
                                        .pick_file()
                                    {
                                        self.manual_form_cert_path = path.display().to_string();
                                    }
                                }
                                // 单行显示路径（超宽横向滚动，不换行膨胀）
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.manual_form_cert_path)
                                        .desired_width(180.0)
                                        .hint_text("可选；留空 = 用全局证书"),
                                );
                            });
                            ui.end_row();
                        });
                    ui.add_space(palette::SPACING_XS);
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(
                                egui::RichText::new("➕ 添加（创建分组）").strong(),
                            ))
                            .clicked()
                        {
                            add_clicked = true;
                        }
                        if ui.button("取消").clicked() {
                            self.manual_add_open = false;
                        }
                    });
                    if let Some((ok, msg)) = &self.manual_add_status {
                        ui.colored_label(
                            if *ok { palette::SUCCESS } else { palette::DANGER },
                            format!("{} {}", if *ok { "✓" } else { "✗" }, msg),
                        );
                    }
                    ui.small("ℹ 创建命名分组：条目出现在「📡 订阅」列表、节点进入同名组标签；证书路径按节点独立保存（写入 node_cert_paths）");
                });
            if add_clicked {
                self.manual_add_submit();
            }
        }

        // ③ 分享节点（按节点选择；批量导出 v1 也在此，功能零丢失）
        if self.share_pick_open {
            egui::Window::new("🔗 分享节点")
                .collapsible(false)
                .resizable(true)
                .default_width(460.0)
                .show(ctx, |ui| {
                    ui.label("选择要分享的节点：");
                    let addrs = self.config.node_addrs.clone();
                    if addrs.is_empty() {
                        ui.colored_label(palette::TEXT_WEAK, "（暂无节点可分享）");
                    }
                    for addr in &addrs {
                        ui.horizontal(|ui| {
                            ui.label(self.config.node_display_name(addr));
                            ui.small(addr);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("分享").clicked() {
                                        // 打开现有分享对话框（二维码 + 完整/紧凑链接）
                                        self.open_share_dialog(addr.clone());
                                        self.share_pick_open = false;
                                    }
                                },
                            );
                        });
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("批量导出分享链接（v1，仅地址）").clicked() {
                            self.export_share_links();
                            self.share_pick_open = false;
                        }
                        if ui.button("关闭").clicked() {
                            self.share_pick_open = false;
                        }
                    });
                    ui.small("• 单节点分享可生成二维码与完整/紧凑链接");
                    ui.small("• 完整链接含认证密钥与证书，对方导入即用；仅限可信渠道发送");
                    ui.small("• 紧凑链接仅含证书指纹，需另行发送证书文件");
                });
        }
    }
}
