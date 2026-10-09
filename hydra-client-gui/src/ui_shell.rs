//! 应用骨架 UI：eframe::App 主循环（轮询回收 / 页面分发 / 对话框集中渲染）
//! + 系统托盘接线（命令轮询 / 关窗行为 / tooltip 同步）。

use crate::config;
use crate::nodes::Tab;
use crate::palette;
use crate::qr;
use crate::tray::TrayCommand;
use crate::HydraApp;
use eframe::egui;

impl eframe::App for HydraApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // 窗口关闭时停止代理并清除系统代理
        // 审查修复：改走 shutdown_and_wait_for_exit——带超时等待代理线程退出
        //（含 TUN 停机令牌 cancel），确保 RouteGuard 清理路由后再放行进程退出
        self.shutdown_and_wait_for_exit();
        // Exec-1：退出前强制落盘（兜底防抖窗口内尚未写盘的变更）
        self.maybe_save_config(true);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_start_receiver();
        // ── R-35：stop_proxy 后的非阻塞收敛 ──
        // 代理线程退出使 exit receiver 可读/断开时，在此清理 handle 与 receiver
        //（不在 UI 线程 join；JoinHandle drop = detach，线程自然结束）
        if !self.proxy_running && self.stop_flag.is_none() {
            if let Some(receiver) = &self.proxy_exit_receiver {
                match receiver.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;
                        self.add_log("代理线程已退出".to_string());
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
        }
        // ── T2：托盘命令轮询 + 关窗行为（隐藏到托盘 vs 真退出）──
        self.poll_tray_commands(ctx);
        self.handle_close_request(ctx);

        // 检查代理线程是否异常退出
        if self.proxy_running {
            if let Some(receiver) = &self.proxy_exit_receiver {
                match receiver.try_recv() {
                    Ok(_) => {
                        // 代理线程退出了（非正常退出，因为没有通过 stop_proxy）
                        self.proxy_running = false;
                        self.stop_flag = None;
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;

                        // 自动清除系统代理
                        Self::remove_system_proxy_static();
                        self.add_log("⚠️ 代理异常退出，已自动清除系统代理设置".to_string());
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // 代理还在运行
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // 通道断开，代理线程已退出
                        self.proxy_running = false;
                        self.stop_flag = None;
                        self.proxy_thread_handle = None;
                        self.proxy_exit_receiver = None;

                        // 自动清除系统代理
                        Self::remove_system_proxy_static();
                        self.add_log("⚠️ 代理线程异常断开，已自动清除系统代理设置".to_string());
                    }
                }
            }
        }

        // 定期健康检查（每30秒）
        if self.proxy_running {
            let should_check = match self.last_health_check {
                Some(last) => last.elapsed().as_secs() >= 30,
                None => true,
            };
            if should_check && self.health_check_receiver.is_none() {
                self.test_all_nodes();
            }
        }

        // 非阻塞地处理健康检查结果
        self.poll_health_check_results();
        // 非阻塞地处理单节点手动测试结果（A5）
        self.poll_node_test_results();
        // 非阻塞地处理订阅更新结果（Exec-C，串行驱动排队更新）
        self.poll_subscription_updates();
        // 非阻塞地处理二维码图片导入结果（R-15：解码在后台线程）
        self.poll_qr_import_result();

        // 连接页快照节流刷新（每 500ms 拉一次注册表；仅连接页激活时拉取，
        // 其余页面零开销。与 UI 重绘周期 500ms 对齐，见页尾 request_repaint_after）
        if self.current_tab == Tab::Connections {
            self.refresh_connections();
        }

        // 系统代理检测缓存刷新（仅 Windows；后台线程结果回投）
        #[cfg(windows)]
        self.poll_sys_proxy_check();

        // ── Team-Q v2：单节点分享对话框（二维码 + 完整链接 + 安全提示）──
        if self.share_dialog_open {
            let mut compact = self.share_compact;
            egui::Window::new(format!("分享节点 {}", self.share_node_addr))
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.add_space(palette::SPACING_XS);
                    ui.horizontal(|ui| {
                        ui.label("模式:");
                        if ui
                            .radio(!compact, "完整（含密钥/证书，对方即用）")
                            .clicked()
                            && compact
                        {
                            compact = false;
                        }
                        if ui
                            .radio(compact, "紧凑（仅证书指纹，需另发证书）")
                            .clicked()
                            && !compact
                        {
                            compact = true;
                        }
                    });

                    // 二维码显示（纹理缓存：URL 变化才重建）
                    let url = self
                        .share_link
                        .as_ref()
                        .map(|l| l.to_share_url())
                        .unwrap_or_default();
                    if url != self.share_url_cache || self.share_qr_texture.is_none() {
                        self.share_url_cache = url.clone();
                        self.share_qr_texture = qr::qr_color_image(&url).and_then(|img| {
                            ctx.load_texture("share_qr", img, egui::TextureOptions::NEAREST)
                                .into()
                        });
                    }
                    ui.separator();
                    match &self.share_qr_texture {
                        Some(tex) => {
                            ui.vertical_centered(|ui| {
                                ui.add(egui::Image::new((tex.id(), egui::vec2(240.0, 240.0))));
                            });
                        }
                        None => {
                            ui.colored_label(palette::DANGER, "✗ 二维码生成失败（链接过长？）");
                        }
                    }

                    ui.separator();
                    ui.label("分享链接（可复制）:");
                    egui::ScrollArea::vertical()
                        .max_height(90.0)
                        .show(ui, |ui| {
                            // 只读展示：clone 后丢弃编辑，避免用户改动影响二维码/复制内容
                            let mut url_display = self.share_url_cache.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut url_display)
                                    .desired_width(460.0)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                    ui.horizontal(|ui| {
                        if ui.button("复制链接").clicked() {
                            ui.ctx().copy_text(self.share_url_cache.clone());
                            self.add_log("分享链接已复制到剪贴板".to_string());
                        }
                    });

                    // 密钥掩码显示（明文永不出现在分享 UI）
                    let has_key = self
                        .share_link
                        .as_ref()
                        .map(|l| l.auth_key.is_some())
                        .unwrap_or(false);
                    let key_masked = if has_key {
                        config::mask_secret(self.config.auth_key.trim())
                    } else {
                        "（未携带）".to_string()
                    };
                    ui.horizontal(|ui| {
                        ui.label("认证密钥:");
                        ui.monospace(key_masked);
                    });
                    ui.small(format!(
                        "证书: {}",
                        if self
                            .share_link
                            .as_ref()
                            .map(|l| l.cert_der.is_some())
                            .unwrap_or(false)
                        {
                            "已包含 DER 本体"
                        } else if self
                            .share_link
                            .as_ref()
                            .map(|l| l.cert_fp.is_some())
                            .unwrap_or(false)
                        {
                            "仅含指纹（紧凑模式）"
                        } else {
                            "未包含（对方需自行导入）"
                        }
                    ));
                    ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）".to_string());

                    // 红字安全提示（危险语义色，收口 palette::DANGER）
                    ui.separator();
                    ui.colored_label(
                        palette::DANGER,
                        "⚠ 完整链接 = 持有节点（含密钥与证书），仅限可信渠道分享！",
                    );
                    ui.colored_label(
                        palette::DANGER,
                        "  请勿粘贴到群聊/公开网页/明文 http；普通渠道请用「紧凑」模式。",
                    );

                    ui.horizontal(|ui| {
                        if ui.button("关闭").clicked() {
                            self.share_dialog_open = false;
                        }
                    });
                });
            // 单选切换后重建链接（紧凑 = 去掉证书本体只留指纹）
            if compact != self.share_compact {
                self.share_compact = compact;
                self.share_link = self.build_share_link(&self.share_node_addr, compact);
                self.share_url_cache = String::new(); // 触发二维码重建
            }
        }

        // 分享链接对话框
        if self.show_share_link_dialog {
            egui::Window::new("分享链接")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label("分享链接内容:");
                    ui.text_edit_multiline(&mut self.share_link_text);

                    ui.horizontal(|ui| {
                        if ui.button("导入").clicked() {
                            self.import_share_links();
                        }
                        if ui.button("关闭").clicked() {
                            self.show_share_link_dialog = false;
                        }
                    });
                });
        }

        // ── T2：左侧导航栏（六区：状态总览/节点管理/订阅/分享/设置/日志）──
        egui::SidePanel::left("nav_panel")
            .exact_width(160.0)
            .show(ctx, |ui| {
                ui.add_space(palette::SPACING_SM);
                ui.heading("Hydra");
                ui.small("Multipath Proxy");
                ui.add_space(6.0);
                ui.separator();
                for tab in Tab::ALL {
                    let selected = self.current_tab == tab;
                    // UI 重设计第三批：图标 + 标题统一用 palette 正文字号
                    if ui
                        .add_sized(
                            [ui.available_width(), 26.0],
                            egui::SelectableLabel::new(
                                selected,
                                egui::RichText::new(tab.label()).size(palette::FONT_BODY),
                            ),
                        )
                        .clicked()
                    {
                        self.current_tab = tab;
                    }
                    ui.add_space(2.0);
                }
                // 底部常驻：代理运行状态指示
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(if self.proxy_running {
                        "🟢 代理运行中"
                    } else {
                        "⚪ 代理已停止"
                    });
                });
            });

        // ── T2：中央面板（按导航页签切换）──
        // 页面主体统一包垂直 ScrollArea（auto_shrink=false 占满宽度）：
        // 内容高过窗口时在页内滚动，而非溢出屏幕产生 egui「组件超出」告警
        egui::CentralPanel::default().show(ctx, |ui| {
            let tab = self.current_tab;
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| match tab {
                    Tab::Overview => self.ui_overview(ui),
                    Tab::Nodes => self.ui_nodes(ui),
                    Tab::Subscriptions => self.ui_subscriptions(ui),
                    Tab::Connections => self.ui_connections(ui),
                    Tab::Settings => self.ui_settings(ui),
                    Tab::Logs => self.ui_logs(ui),
                });
        });

        // ── Team-UI：节点编辑对话框 ──
        if self.node_edit_open {
            self.ui_node_edit_dialog(ctx);
        }

        // ── UI 重设计第二批：导入/手动添加/分享选择/添加订阅 对话框集中渲染 ──
        // （入口分布在订阅页「＋ 新建」下拉与节点页「🔗 分享节点」，跨页切换窗口不丢失）
        self.ui_nodes_dialogs(ctx);
        if self.sub_add_open {
            self.ui_sub_add_dialog(ctx);
        }

        // T2：托盘 tooltip 随代理状态同步；隐藏到托盘后仍需周期重绘
        // （轮询代理退出通道 / 托盘命令 / 实时速率刷新）
        self.sync_tray_tooltip();
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        // Exec-1：配置差分 + 防抖落盘（有变更时每秒至多写一次；启停/退出时强制写）
        self.maybe_save_config(false);
    }
}

// ═══════════════ T2（Team-G）：托盘接线 + UI 六区实现 ═══════════════
impl HydraApp {
    /// 托盘命令轮询：把托盘菜单/点击事件落到与 UI 按钮相同的内部方法上。
    pub(crate) fn poll_tray_commands(&mut self, ctx: &egui::Context) {
        let commands: Vec<TrayCommand> = match &self.tray {
            Some(t) => t.command_rx.try_iter().collect(),
            None => return,
        };
        for cmd in commands {
            match cmd {
                TrayCommand::ToggleWindow | TrayCommand::ShowWindow => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayCommand::StartProxy => self.start_proxy(),
                TrayCommand::StopProxy => self.stop_proxy(),
                TrayCommand::Quit => {
                    // 真退出：停代理并带超时等待线程退出（含 TUN 停机 + 路由清理，
                    // 见 shutdown_and_wait_for_exit）再关闭窗口；on_exit 兜底落盘
                    self.shutdown_and_wait_for_exit();
                    self.really_quit = true;
                    self.add_log("正在退出 Hydra...".to_string());
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// 关窗行为：默认隐藏到托盘（代理继续跑，隐藏 ≠ 退出）；
    /// 托盘「退出」或设置 close_to_tray=false 时放行真正关闭（on_exit 清理）。
    pub(crate) fn handle_close_request(&mut self, ctx: &egui::Context) {
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if !close_requested {
            return;
        }
        // 托盘不存在时隐藏=应用不可达（无任何唤回入口），必须放行真关闭
        if self.really_quit || !self.config.close_to_tray || self.tray.is_none() {
            return; // 放行关闭；on_exit 会停代理 + 清系统代理 + 强制落盘
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.add_log(
            "窗口已隐藏到系统托盘，代理继续运行（左键托盘恢复，右键菜单退出）".to_string(),
        );
    }

    /// 托盘 tooltip 与菜单禁用态和代理运行状态同步（变化才调用系统 API）
    pub(crate) fn sync_tray_tooltip(&mut self) {
        let tip = if self.proxy_running {
            "Hydra 代理运行中"
        } else if self.proxy_starting {
            "Hydra 代理启动中…"
        } else {
            "Hydra 代理已停止"
        };
        if self.last_tray_tooltip != tip {
            if let Some(t) = &self.tray {
                t.set_tooltip(tip);
            }
            self.last_tray_tooltip = tip.to_string();
        }
        // 菜单禁用态必须在去重块外无条件同步：last_tray_tooltip 启动即预置
        // 「已停止」文案，首帧会被 tooltip 去重跳过——若放块内，「停止代理」
        // 在停止态保持可点（set_running_state 自带 last_running 去重，零成本）
        if let Some(t) = &mut self.tray {
            t.set_running_state(self.proxy_running, self.proxy_starting);
        }
    }
}
