//! 订阅页：订阅源生命周期（增/改/更新/删除）+ 归属节点展开 +
//! 「添加订阅源」对话框。

use crate::groups::{next_import_group_name, next_manual_group_name, subscription_source_label};
use crate::palette;
use crate::HydraApp;
use eframe::egui;

impl HydraApp {
    /// 订阅页（v2 方案 §2.3）：只管订阅源的生命周期（增/改/更新/删除）。
    /// 每条订阅可展开查看归属节点（只读标记 + 「另存为手动」）；
    /// 节点的统一列表与来源标记见「🛰 节点」页。
    pub(crate) fn ui_subscriptions(&mut self, ui: &mut egui::Ui) {
        // ── 页头：标题 + 右侧「更新全部订阅」+「＋ 新建」下拉（复刻 Clash Profiles 新建入口）──
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("订阅")
                    .size(palette::FONT_HEADING)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // 「＋ 新建」：四种创建/导入入口统一收纳（原节点页「＋」整体迁来）
                ui.menu_button(
                    egui::RichText::new("＋ 新建").size(palette::FONT_TITLE),
                    |ui| {
                        if ui.button("📡 添加订阅源").clicked() {
                            // 展开添加对话框（交互选定：对话框比内联展开少一次布局跳动）
                            self.new_sub_name.clear();
                            self.new_sub_source.clear();
                            self.sub_add_open = true;
                            ui.close_menu();
                        }
                        if ui.button("📋 从分享链接导入").clicked() {
                            // 打开时重置粘贴版表单：预生成默认分组名（避重）、清空粘贴文本与提示
                            self.import_group_name =
                                next_import_group_name(&self.config.subscriptions);
                            self.import_paste_text.clear();
                            self.import_status = None;
                            self.import_dialog_open = true;
                            ui.close_menu();
                        }
                        if ui.button("📷 扫描二维码导入").clicked() {
                            // 复用现有二维码文件识别（后台解码，结果经通道回收）
                            self.import_from_qr_image();
                            ui.close_menu();
                        }
                        if ui.button("✏️ 手动添加节点").clicked() {
                            // 打开时重置表单：预生成默认分组名（避重）、端口默认 443、清空其余字段与提示
                            self.manual_group_name =
                                next_manual_group_name(&self.config.subscriptions);
                            self.manual_form_addr.clear();
                            self.manual_form_port = "443".to_string();
                            self.manual_form_cert_path.clear();
                            self.manual_add_status = None;
                            self.manual_add_open = true;
                            ui.close_menu();
                        }
                    },
                )
                .response
                .on_hover_text("添加订阅源 / 从分享链接导入 / 扫描二维码导入 / 手动添加节点");
                if self.sub_update_receiver.is_some() {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label("更新中...");
                }
                if ui.button("🔄 更新全部订阅").clicked() {
                    self.update_all_subscriptions();
                }
            });
        });
        ui.add_space(2.0);
        ui.small("节点分两种归属：订阅节点由订阅源拉取、随订阅更新自动覆盖（只读，可「另存为手动」解除认领）；手动节点通过「＋ 新建」导入/添加、可自由编辑且不受订阅影响。节点页顶部组标签按下方订阅动态分组");
        ui.separator();

        // 订阅列表：名称 / 来源 / 更新时间 / 节点数 + 立即更新 / 展开节点 / 编辑 / 删除
        let subs_clone = self.config.subscriptions.clone();
        for (i, sub) in subs_clone.iter().enumerate() {
            let updated = sub
                .last_updated_secs
                .and_then(|s| chrono::DateTime::from_timestamp(s as i64, 0))
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string()
                })
                .unwrap_or_else(|| "从未".to_string());
            let expanded = self.expanded_sub.as_deref() == Some(sub.name.as_str());
            ui.horizontal(|ui| {
                ui.strong(&sub.name);
                ui.colored_label(palette::TEXT_WEAK, format!("{} 节点", sub.nodes.len()));
                ui.weak(format!("更新于 {}", updated));
                if ui.small_button("立即更新").clicked() {
                    self.queue_subscription_update(sub.name.clone(), sub.source.clone());
                }
                if ui
                    .small_button(if expanded {
                        "收起节点"
                    } else {
                        "展开节点"
                    })
                    .clicked()
                {
                    self.expanded_sub = if expanded {
                        None
                    } else {
                        Some(sub.name.clone())
                    };
                }
                if ui.small_button("编辑").clicked() {
                    self.sub_edit_idx = Some(i);
                    self.sub_edit_name = sub.name.clone();
                    self.sub_edit_source = sub.source.clone();
                }
                // 破坏性操作（SB-01）：级联删除经对话框确认（含独占节点数 +
                // 本地文本不可重拉红字提示）
                if ui
                    .small_button(egui::RichText::new("删除").color(palette::DANGER))
                    .clicked()
                {
                    let cascade = crate::groups::exclusive_node_count(
                        &self.config,
                        &self.config.subscriptions[i].name,
                    );
                    self.confirm_state =
                        Some(crate::components::ConfirmAction::DeleteSubscription {
                            idx: i,
                            name: self.config.subscriptions[i].name.clone(),
                            cascade,
                            is_local_text: self.config.subscriptions[i]
                                .source
                                .starts_with("hydra-text://"),
                        });
                }
            });
            // 来源列只显示类型标签（本地导入/订阅·域名/文件·文件名），不外显原始长链接
            ui.small(subscription_source_label(&sub.source));

            // 展开归属节点：只读清单 + 单条「另存为手动」
            if expanded {
                if sub.nodes.is_empty() {
                    ui.small("  （该订阅暂无归属节点，请先「立即更新」）");
                }
                for addr in &sub.nodes {
                    let testing_this = self.node_testing_addr.as_deref() == Some(addr.as_str());
                    ui.indent(addr.as_str(), |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("[只读]")
                                    .size(palette::FONT_BADGE)
                                    .color(palette::ACCENT),
                            );
                            ui.label(addr);
                            // 测速中显示 spinner；结果进全局日志与调度器评分（与节点页一致）
                            if testing_this {
                                ui.add(egui::Spinner::new().size(14.0));
                                ui.label(
                                    egui::RichText::new("测速中…")
                                        .size(palette::FONT_SECONDARY)
                                        .color(palette::TEXT_WEAK),
                                );
                            }
                            // 紧凑操作行：分享 / 测速 / 另存为手动（原位）
                            if ui.small_button("🔗 分享").clicked() {
                                // 订阅节点不带密钥本体：build_share_link 按地址解析失败时
                                // 自动退化为仅地址信息（能带证书则带），与现有分享行为一致
                                self.open_share_dialog(addr.clone());
                            }
                            if ui.small_button("⚡ 测速").clicked() {
                                self.start_node_test(addr.clone());
                            }
                            if ui
                                .small_button("另存为手动")
                                .on_hover_text(
                                    "解除订阅认领，变为可编辑的手动节点（后续订阅更新不再覆盖/认领它）",
                                )
                                .clicked()
                                && self.config.save_subscription_node_as_manual(addr)
                            {
                                self.add_log(format!(
                                    "节点 {} 已另存为手动节点（不再随订阅更新）",
                                    addr
                                ));
                            }
                        });
                    });
                }
            }
        }

        // 订阅编辑对话框（名称重复校验与添加同一套规则）。
        // 对话框打开期间订阅可能被删除（同页删除按钮）→ 索引失效时静默关闭对话框，
        // 否则 subs_clone[idx] 越界 panic 崩溃整个 UI 线程
        if let Some(idx) = self.sub_edit_idx {
            if subs_clone.get(idx).is_none() {
                self.sub_edit_idx = None;
                self.add_log("编辑的订阅已被删除，对话框已关闭".to_string());
            }
        }
        if let Some(idx) = self.sub_edit_idx {
            let mut save_clicked = false;
            egui::Window::new(format!("编辑订阅「{}」", subs_clone[idx].name))
                .collapsible(false)
                .resizable(false)
                .default_width(480.0)
                .show(ui.ctx(), |ui| {
                    egui::Grid::new("sub_edit_grid")
                        .num_columns(2)
                        .spacing([palette::SPACING_SM, palette::SPACING_SM])
                        .show(ui, |ui| {
                            ui.label("名称:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.sub_edit_name)
                                    .desired_width(300.0),
                            );
                            ui.end_row();
                            ui.label("来源:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.sub_edit_source)
                                    .desired_width(300.0)
                                    .hint_text("https://… / 文件路径 / hydra-sub://…"),
                            );
                            ui.end_row();
                        });
                    if self.sub_edit_source.trim().is_empty() {
                        ui.colored_label(palette::DANGER, "✗ 来源不能为空");
                    }
                    let name = self.sub_edit_name.trim();
                    let name_conflict = !name.is_empty()
                        && self
                            .config
                            .subscriptions
                            .iter()
                            .enumerate()
                            .any(|(j, s)| j != idx && s.name == name);
                    if name_conflict {
                        ui.colored_label(
                            palette::DANGER,
                            "✗ 订阅名称已存在（名称是来源标记与更新对号的键）",
                        );
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .add(egui::Button::new(egui::RichText::new("💾 保存").strong()))
                            .clicked()
                        {
                            save_clicked = true;
                        }
                        if ui.button("取消").clicked() {
                            self.sub_edit_idx = None;
                        }
                    });
                });
            if save_clicked {
                let name = self.sub_edit_name.trim().to_string();
                let source = self.sub_edit_source.trim().to_string();
                if source.is_empty()
                    || name.is_empty()
                    || self
                        .config
                        .subscriptions
                        .iter()
                        .enumerate()
                        .any(|(j, s)| j != idx && s.name == name)
                {
                    self.add_log("订阅编辑保存失败：来源为空或名称重复/为空".to_string());
                } else {
                    self.config.subscriptions[idx].name = name.clone();
                    self.config.subscriptions[idx].source = source;
                    self.sub_edit_idx = None;
                    self.add_log(format!("订阅「{}」已保存", name));
                }
            }
        }

        // （导入/手动添加对话框已由 update() 集中渲染，本页不再重复调用）
    }

    /// 「＋ 新建 → 📡 添加订阅源」对话框（原平铺添加行收进对话框，交互更顺：
    /// 添加是低频动作，不必常驻占位；校验逻辑与原 add_subscription 完全一致）
    pub(crate) fn ui_sub_add_dialog(&mut self, ctx: &egui::Context) {
        let mut add_clicked = false;
        egui::Window::new("📡 添加订阅源")
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ctx, |ui| {
                egui::Grid::new("sub_add_grid")
                    .num_columns(2)
                    .spacing([palette::SPACING_SM, palette::SPACING_SM])
                    .show(ui, |ui| {
                        ui.label("名称:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_sub_name)
                                .desired_width(320.0)
                                .hint_text("可留空自动编号"),
                        );
                        ui.end_row();
                        ui.label("来源:");
                        ui.vertical(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_sub_source)
                                    .desired_width(320.0)
                                    .hint_text("https://… / 文件路径 / hydra-sub://…"),
                            );
                            if ui.small_button("浏览...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("订阅文件", &["txt", "sub"])
                                    .add_filter("全部文件", &["*"])
                                    .pick_file()
                                {
                                    self.new_sub_source = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("➕ 添加订阅").strong(),
                        ))
                        .clicked()
                    {
                        add_clicked = true;
                    }
                    if ui.button("取消").clicked() {
                        self.sub_add_open = false;
                        self.new_sub_name.clear();
                        self.new_sub_source.clear();
                    }
                });
                ui.small("支持 http(s) 订阅 URL、本地订阅文件路径与 hydra-sub:// 分享订阅");
            });
        if add_clicked && self.add_subscription() {
            // 添加成功才关闭对话框；校验失败保留窗口让用户修改
            self.sub_add_open = false;
        }
    }
}
