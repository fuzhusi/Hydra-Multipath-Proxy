//! 设置页：七分区折叠配置（凭据/核心/安全信任/TUN/系统/外观/关于）。

use crate::config;
use crate::palette;
use crate::HydraApp;
use eframe::egui;

impl HydraApp {
    /// 设置页（UI 重设计第三批：7 分区 CollapsingHeader 折叠，标题带图标）：
    /// ① 🔑 全局凭据（默认展开）② 🛰 代理核心（默认展开）③ 🛡 安全与信任（收起）
    /// ④ 🌐 TUN 透明代理（收起）⑤ 🖥 系统（收起）⑥ 🎨 外观与数据（收起）⑦ ℹ 关于与退出（收起）。
    /// 每个分区展开后首行为说明文字；全部配置项原样保留，功能零丢失。
    pub(crate) fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("设置")
                .size(palette::FONT_HEADING)
                .strong(),
        );
        ui.add_space(palette::SPACING_XS);

        // ◈ ① 全局凭据（UI 重设计第一批自「🛰 节点」页迁入，第三批改分区折叠；默认展开）
        // 过渡期这些字段仍为全局单值（GuiConfig），后端节点级凭据落地前
        // 对所有节点生效——此处诚实标注，不假装是节点级凭据。
        egui::CollapsingHeader::new(
            egui::RichText::new("🔑 全局凭据（当前对所有节点生效）")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(true)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：认证密钥与节点证书（全局回落）；逐节点独立证书在各节点的「编辑」对话框中设置",
            );
            ui.colored_label(
                    palette::warning(),
                    "⚠ 当前 hydra-client 按全局凭据连接：以下配置对所有节点生效；节点级凭据将在后端改造后逐节点生效",
                );
                // 认证密钥：默认掩码显示（如 a1b2****8f90），点击「编辑/显示」查看并编辑明文
                ui.horizontal(|ui| {
                    ui.label("认证密钥:");
                    if self.show_auth_key {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.config.auth_key)
                                .desired_width(200.0),
                        );
                        if ui.small_button("隐藏").clicked() {
                            self.show_auth_key = false;
                        }
                    } else {
                        let shown = if self.config.auth_key.is_empty() {
                            "（未设置）".to_string()
                        } else {
                            config::mask_secret(self.config.auth_key.trim())
                        };
                        ui.monospace(shown);
                        if ui.small_button("编辑/显示").clicked() {
                            self.show_auth_key = true;
                        }
                    }
                });
                // 密钥有效性实时校验（hex + 最短 16 字节）
                if self.show_auth_key && !self.config.auth_key.trim().is_empty() {
                    match hydra_client::auth_key_from_hex(self.config.auth_key.trim()) {
                        Ok(_) => {
                            ui.colored_label(palette::success(), "✓ 密钥格式有效")
                        }
                        Err(e) => ui.colored_label(palette::danger(), format!("✗ {}", e)),
                    };
                }

                // 节点证书：当前状态（路径/内嵌指纹）+ 浏览替换，实时校验存在性
                ui.horizontal(|ui| {
                    ui.label("节点证书:");
                    ui.small(Self::cert_status_text(&self.config));
                });
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.config.cert_path)
                            .desired_width(ui.available_width() - 80.0)
                            .hint_text("证书文件路径（清空则使用内嵌/分享导入的证书）"),
                    );
                    if ui.button("浏览替换...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("证书文件", &["der", "pem", "crt", "cer"])
                            .add_filter("全部文件", &["*"])
                            .pick_file()
                        {
                            self.config.cert_path = path.display().to_string();
                            self.add_log(format!("已选择节点证书: {}", path.display()));
                        }
                    }
                });
                if !self.config.cert_path.trim().is_empty()
                    && !std::path::Path::new(self.config.cert_path.trim()).exists()
                {
                    ui.colored_label(palette::danger(), "✗ 证书文件不存在，请检查路径");
                }

                // 传输为固定 TCP/TLS（TLS 1.3 + Noise-PSK）：Wave 3 起无其他模式
                ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）");
        });

        // ◈ ② 代理核心（默认展开：监听地址/探测间隔是常用配置）
        egui::CollapsingHeader::new(
            egui::RichText::new("🛰 代理核心")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(true)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：本地 SOCKS5 监听地址与 Offline 节点自动恢复探测间隔",
            );
            ui.horizontal(|ui| {
                ui.label("本地监听地址:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.config.proxy_listen_addr)
                        .desired_width(180.0)
                        .hint_text("127.0.0.1:1080"),
                );
            });
            // Offline 恢复探测间隔（对应 HYDRA_PROBE_INTERVAL_SECS）
            ui.horizontal(|ui| {
                ui.label("探测间隔(秒):");
                let mut secs = self.config.probe_interval_secs.unwrap_or(30);
                if ui
                    .add(egui::DragValue::new(&mut secs).clamp_range(1..=3600))
                    .changed()
                {
                    self.config.probe_interval_secs = Some(secs);
                }
                if self.config.probe_interval_secs.is_some() && ui.small_button("默认").clicked()
                {
                    self.config.probe_interval_secs = None;
                }
                ui.weak("（Offline 节点自动恢复探测，默认 30 秒）");
            });
            ui.small("认证密钥与节点证书在本页上方「全局凭据」区；新手引导可随时重看");
            if ui.button("显示新手引导").clicked() {
                for line in HydraApp::wizard_lines() {
                    self.add_log(line);
                }
            }
        });

        // ◈ ③ 安全与信任（默认收起：信任模式属高级项）
        egui::CollapsingHeader::new(
            egui::RichText::new("🛡 安全与信任")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：双信任模式——自签证书 pinning（默认） / 真证书 CA（可选叶证书硬 pin）",
            );
        // 拷贝为 String：后续要可变借用 self.config（pin 输入框），避免借用冲突
        let mode = self.config.trust_mode_effective().to_string();
        ui.horizontal(|ui| {
            ui.label("信任模式:");
            if ui
                .radio(mode == "pin", "自签 pinning（默认）")
                .clicked()
            {
                self.config.trust_mode = String::new(); // 空串 = 默认 pin（配置语义与 serde 默认一致）
                self.add_log("信任模式：自签 pinning（节点证书入本地信任根）".to_string());
            }
            if ui.radio(mode == "ca", "真证书 CA").clicked() {
                self.config.trust_mode = "ca".to_string();
                self.add_log(
                    "信任模式：真证书 CA（节点需 ACME 等真证书部署；自定义域名需另设 SNI，见 README）"
                        .to_string(),
                );
            }
        });
        // ca 模式：可选叶证书 SHA-256 硬 pin（64 hex，防 CA 误签发）
        if mode == "ca" {
            ui.horizontal(|ui| {
                ui.label("叶证书 SHA-256 硬 pin（可选）:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.config.ca_leaf_pin)
                        .desired_width(380.0)
                        .hint_text("64 位 hex，留空 = 仅信任公共 CA"),
                );
            });
            match config::validate_leaf_pin(&self.config.ca_leaf_pin) {
                Ok(()) if self.config.ca_leaf_pin.trim().is_empty() => {}
                Ok(()) => {
                    ui.colored_label(palette::success(), "✓ 格式有效（64 hex）");
                }
                Err(e) => {
                    ui.colored_label(palette::danger(), format!("✗ {e}"));
                }
            }
            ui.small("ca 模式不使用节点证书文件；节点侧用真证书（如 ACME）部署，SNI 须与证书 SAN 一致");
        } else {
            ui.small("pin 模式使用本页「全局凭据」区的节点证书（支持逐节点独立证书，见节点编辑）");
        }
        if self.proxy_running {
            ui.small("⚠ 代理正在运行：信任模式修改需停止并重新启动代理后生效");
        }
        });

        // ◈ ④ TUN 透明代理（默认收起：需管理员/root 的高级功能）
        egui::CollapsingHeader::new(
            egui::RichText::new("🌐 TUN 透明代理（需管理员/root；仅 TCP）")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：全局透明接管 TCP 流量，应用无需配置代理；首页亦有快捷开关",
            );
        if ui
            .checkbox(
                &mut self.config.tun_enabled,
                "TUN 透明代理（需管理员/root；仅 TCP）",
            )
            .changed()
        {
            self.add_log(if self.config.tun_enabled {
                "TUN 透明代理：已开启（下次启动代理生效；仅拦截 TCP，按端口列表）".to_string()
            } else {
                "TUN 透明代理：已关闭（下次启动代理生效）".to_string()
            });
            // 切换为开时立即触发一次后台检测（作废旧缓存，不阻塞 UI）
            #[cfg(windows)]
            if self.config.tun_enabled {
                self.sys_proxy_check_cache = None;
            }
        }
        let tun_on = self.config.tun_enabled;
        // ── 分流模式（智能分流 v1.1 §4.2）：TUN 开关下方的两个单选卡 ──
        // 全局接管 = 既有行为（默认，行为兼容）；规则分流 = 按规则文件决定 CN 直连/走节点。
        // horizontal_wrapped：窄窗口下自动换行——此前固定单行在 ~650px 窗口
        // 会把第二个单选裁剪出右缘（用户实测「看不见规则分流」的根因）
        ui.add_space(palette::SPACING_XS);
        ui.horizontal_wrapped(|ui| {
            ui.label("分流模式:");
            if ui
                .add_enabled(
                    tun_on,
                    egui::RadioButton::new(!self.config.tun_rule_mode, "全局接管（默认）"),
                )
                .clicked()
            {
                self.config.tun_rule_mode = false;
                self.maybe_save_config(true);
                self.add_log("分流模式：全局接管（默认；重启代理后生效）".to_string());
            }
            if ui
                .add_enabled(
                    tun_on,
                    egui::RadioButton::new(
                        self.config.tun_rule_mode,
                        "规则分流（CN 直连 · 其余走节点）",
                    ),
                )
                .clicked()
            {
                // 写入 cfg.tun_rule_mode 并立即持久化（force=true 跳过防抖）
                self.config.tun_rule_mode = true;
                self.maybe_save_config(true);
                self.add_log("分流模式：规则分流（CN 直连 · 其余经节点；重启代理后生效）".to_string());
            }
        });
        // 规则分流子区：规则文件路径 + 打开按钮 + DNS 联动提示 + 重启生效提示
        if tun_on && self.config.tun_rule_mode {
            // 规则文件路径：用户未自定义时显示默认路径（%APPDATA%\hydra\rules.txt）
            let (rule_path_display, rule_path) = Self::rule_file_path(&self.config);
            ui.horizontal(|ui| {
                ui.label("规则文件:");
                ui.monospace(rule_path_display);
            });
            ui.horizontal(|ui| {
                if ui.button("打开规则文件").clicked() {
                    // 文件不存在则先创建带注释的模板（UTF-8），再用系统默认程序打开
                    if !rule_path.exists() {
                        if let Some(dir) = rule_path.parent() {
                            let _ = std::fs::create_dir_all(dir);
                        }
                        match std::fs::write(&rule_path, Self::RULE_FILE_TEMPLATE) {
                            Ok(()) => self.add_log(format!("已创建规则模板: {}", rule_path.display())),
                            Err(e) => self.add_warn(format!("规则模板创建失败: {e}")),
                        }
                    }
                    Self::open_rule_file(&rule_path);
                }
                ui.small("（UTF-8，# 注释；语法见文件内模板）");
            });
            // DNS 直连解析联动提示（R2）：仅文案——逻辑由后端 HYDRA_TUN_DNS_DIRECT=1 联动
            crate::components::banner(
                ui,
                crate::components::BannerKind::Info,
                "ℹ 规则分流模式下 DNS 自动改为直连解析：国内域名由本地 DNS 解析出近端 CDN IP，GeoIP 才能判准并直连（否则经节点解析会拿到海外边缘 IP）",
            );
            ui.colored_label(
                palette::text_faint(),
                "重启代理后生效（规则文件修改亦需重启代理；未命中规则 → 走节点）",
            );
        }
        ui.add_enabled(
            tun_on,
            egui::TextEdit::singleline(&mut self.config.tun_addr)
                .desired_width(200.0)
                .hint_text("TUN 地址（默认 10.7.0.1/30）"),
        )
        .on_disabled_hover_text("先开启 TUN 透明代理");
        ui.add_enabled(
            tun_on,
            egui::TextEdit::singleline(&mut self.config.tun_ports)
                .desired_width(200.0)
                .hint_text("拦截端口列表（默认 80,443,8080,8443）"),
        )
        .on_disabled_hover_text("先开启 TUN 透明代理");
        ui.small("TUN 全流量接管，应用无需配置代理；仅 TCP（UDP 回 ICMP 不可达供应用回落）、无 DNS 劫持；\nIPv6 TCP 经动态 AnyIP 代理（v6 非 TCP 回 ICMPv6 不可达）；\n节点 IP 与系统 DNS 自动豁免防环路；退出/崩溃自动清理路由");
        // 与 CLI（hydra-client main.rs warn_system_proxy_loop）一致的环路告警：
        // Windows 系统代理 + TUN 全流量接管 → 经系统代理的流量二次进本代理。
        // 修复：检测移出渲染路径——此前每帧同步 spawn `reg query`（每秒几十个
        // 控制台窗口 + UI 线程反复阻塞）。现在 UI 只读缓存；缓存缺失/过期 10s
        // 时由后台线程检测并经 mpsc 回投（与 node_test_receiver 同范式）。
        #[cfg(windows)]
        if tun_on {
            // 缓存有效期 10s：过期后在 UI 线程仅发起后台检测（不等待结果）
            const SYS_PROXY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);
            let expired = match self.sys_proxy_check_cache {
                Some((at, _)) => at.elapsed() >= SYS_PROXY_CACHE_TTL,
                None => true,
            };
            if expired && self.sys_proxy_check_receiver.is_none() {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    // 后台线程同步执行 reg query（已加 CREATE_NO_WINDOW 不弹窗）
                    let _ = tx.send(hydra_client::windows_system_proxy_enabled());
                });
                self.sys_proxy_check_receiver = Some(rx);
            }
            // 缓存缺失时告警行先不显示（后台检测落地后的下一帧即显示）
            if let Some((_, sys_proxy_on)) = self.sys_proxy_check_cache {
                if sys_proxy_on {
                    ui.colored_label(
                        palette::warning(),
                        "⚠ 检测到 Windows 系统代理已开启：TUN 模式下经系统代理的流量会二次进入本代理形成环路，建议关闭系统代理",
                    );
                }
            }
        }
        });

        // ◈ ⑤ 系统（默认收起：托盘/关窗行为等系统级选项）
        egui::CollapsingHeader::new(
            egui::RichText::new("🖥 系统")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：开机自启（规划中）、关窗隐藏到托盘与托盘菜单行为",
            );
            ui.add_enabled(false, egui::Checkbox::new(&mut false, "开机自启（规划中）"))
                .on_disabled_hover_text("规划中：需随 TUN 服务模式一并实现");
            if ui
                .checkbox(
                    &mut self.config.close_to_tray,
                    "关闭窗口时隐藏到系统托盘（代理继续运行）",
                )
                .changed()
            {
                self.add_log(if self.config.close_to_tray {
                    "关窗行为：隐藏到系统托盘".to_string()
                } else {
                    "关窗行为：直接退出（停止代理并清理系统代理）".to_string()
                });
            }
            ui.small("托盘左键单击 = 显示/隐藏主窗；托盘右键菜单 = 显示主窗 / 启动 / 停止 / 退出");
        });

        // ◈ 📝 日志（批次 A3/A4：级别热调 + 自动保存开关；沿用既有设置行样式）
        egui::CollapsingHeader::new(
            egui::RichText::new("📝 日志")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：日志级别即时热调（无需重启）并持久化；内核事件见「📜 日志」页",
            );
            // A4：日志级别下拉（error/warn/info/debug/trace）——选中即热调
            // reload EnvFilter + 持久化；启动时按配置初始化（见 main.rs init_logging）。
            // P2-2：选中值经 config 归一化落盘（trim + 小写白名单）；RUST_LOG
            // 环境变量已设置 → 下拉禁用 + hover 提示，热调调用点同步跳过 reload。
            ui.horizontal(|ui| {
                ui.label("日志级别:");
                let current = self.config.log_level_effective();
                let rust_log = crate::log_bridge::rust_log_override();
                if rust_log {
                    // P2-2：RUST_LOG 环境变量优先，热调已跳过（下拉整体禁用 + 提示）
                    let (combo_rect,) = ui
                        .add_enabled_ui(false, |ui| {
                            egui::ComboBox::from_id_source("log_level_combo")
                                .selected_text(current.clone())
                                .show_ui(ui, |ui| {
                                    for level in ["error", "warn", "info", "debug", "trace"] {
                                        // 禁用态仅展示不响应点击（selectable_label must_use 抑制）
                                        let _ = ui.selectable_label(current == level, level);
                                    }
                                });
                            (ui.min_rect(),)
                        })
                        .inner;
                    // ComboBox 非 Widget 拿不到自身 Response：用其绘制矩形补一个
                    // hover 命中区（egui 0.27 Ui::interact）挂禁用提示
                    let resp = ui.interact(
                        combo_rect,
                        egui::Id::new("log_level_combo_rustlog_hint"),
                        egui::Sense::hover(),
                    );
                    resp.on_disabled_hover_text("RUST_LOG 环境变量优先，热调已跳过");
                    ui.small("（RUST_LOG 环境变量优先，级别热调已跳过）");
                } else {
                    egui::ComboBox::from_id_source("log_level_combo")
                        .selected_text(current.clone())
                        .show_ui(ui, |ui| {
                            for level in ["error", "warn", "info", "debug", "trace"] {
                                if ui
                                    .selectable_label(current == level, level)
                                    .clicked()
                                    && current != level
                                {
                                    match crate::log_bridge::set_level(level) {
                                        Ok(()) => {
                                            // P2-2：落盘值即归一值（下拉白名单本身就是小写规范形）
                                            self.config.log_level = level.to_string();
                                            self.maybe_save_config(true);
                                            self.add_log(format!(
                                                "日志级别已切换为 {level}（即时生效）"
                                            ));
                                        }
                                        Err(e) => {
                                            self.add_error(format!("日志级别切换失败: {e}"))
                                        }
                                    }
                                }
                            }
                        });
                }
                if current == "debug" || current == "trace" {
                    ui.colored_label(palette::warning(), "⚠ debug/trace 事件量大，排障后建议切回 info");
                }
            });
            // A3：「自动保存日志」开关（默认关 = 与基线行为一致）。
            // 开 = 追加写 %APPDATA%\hydra\logs\gui.log（每日滚动）；关 = 不写。
            ui.horizontal(|ui| {
                let mut on = self.config.log_to_file;
                if ui.checkbox(&mut on, "自动保存日志到文件（每日滚动）").changed() {
                    // 开关门控（无失败路径）；级别跟随全局 EnvFilter
                    //（P2-2：级别取归一化口径）
                    crate::log_bridge::set_file_logging(on, &self.config.log_level_effective());
                    {
                        self.config.log_to_file = on;
                            self.maybe_save_config(true);
                            let path = config::config_dir()
                                .map(|d| d.join("logs").join("gui.log"))
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "logs\\gui.log".to_string());
                            self.add_log(if on {
                                format!("自动保存日志：已开启（{}）", path)
                            } else {
                                "自动保存日志：已关闭".to_string()
                            });
                    }
                }
            });
            if self.config.log_to_file {
                ui.small(format!(
                    "日志文件: {}（日志页事件同步追加；每日滚动）",
                    config::config_dir()
                        .map(|d| d.join("logs").join("gui.log").display().to_string())
                        .unwrap_or_else(|| "(配置目录不可用)".to_string())
                ));
            }
        });

        // ◈ ⑥ 外观与数据（默认收起：主题与配置目录）
        egui::CollapsingHeader::new(
            egui::RichText::new("🎨 外观与数据")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：主题（侧栏底部 ◐ 可循环切换 深色/浅色/深海）与配置目录/配置文件位置",
            );
            ui.horizontal(|ui| {
                ui.label("主题:");
                ui.add_enabled(
                    false,
                    egui::Checkbox::new(&mut false, "深色（当前唯一主题）"),
                )
                .on_disabled_hover_text("主题选择预留，后续版本提供多主题");
            });
            ui.horizontal(|ui| {
                ui.label("配置目录:");
                ui.monospace(
                    config::config_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(配置目录不可用)".to_string()),
                );
                if ui.button("打开目录").clicked() {
                    if let Some(dir) = config::config_dir() {
                        #[cfg(windows)]
                        {
                            // CREATE_NO_WINDOW：打开目录不闪控制台窗口（点击时一次性调用）
                            let mut c = std::process::Command::new("explorer");
                            c.arg(&dir);
                            let _ = hydra_client::hide_console_window(&mut c).spawn();
                        }
                        #[cfg(not(windows))]
                        let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
                    }
                }
            });
            ui.small(format!(
                "配置文件: {}（自动保存）",
                config::config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(配置目录不可用)".to_string())
            ));
        });

        // ◈ ⑦ 关于与退出（默认收起；退出入口收进分区，托盘菜单同样可退出）
        egui::CollapsingHeader::new(
            egui::RichText::new("ℹ 关于与退出")
                .size(palette::FONT_TITLE)
                .strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.colored_label(
                palette::text_weak(),
                "说明：版本信息、项目文档与程序退出入口（运行日志见「📜 日志」页）",
            );
            ui.label(format!(
                "Hydra Multipath Proxy v{}",
                env!("CARGO_PKG_VERSION")
            ));
            ui.hyperlink_to(
                "项目文档（GitHub）",
                "https://github.com/hydra-multipath-proxy/hydra-multipath-proxy",
            );
            ui.small("检查更新：预留");

            ui.add_space(palette::SPACING_SM);

            // 退出入口（托盘菜单同样可退出）
            if ui
                .button(
                    egui::RichText::new("退出程序（停止代理并清理系统代理）")
                        .color(palette::danger()),
                )
                .clicked()
            {
                // 真退出：带超时等待代理线程退出（含 TUN 停机 + 路由清理）再关窗
                self.shutdown_and_wait_for_exit();
                self.really_quit = true;
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
        ui.add_space(palette::SPACING_XL);
    }

    // ── 智能分流（规则模式）辅助 ──────────────────────────────

    /// 规则文件模板：不存在时「打开规则文件」按钮以此初始化（R10：端口规则为例外形态）。
    /// 统一路由层：域名规则同时驱动 SOCKS/HTTP 路径（TUN 侧仅 IP 规则可判）
    const RULE_FILE_TEMPLATE: &str = "# Hydra 分流规则\n\
# 语法：IP-CIDR,1.2.3.0/24,DIRECT\n\
#       GEOIP,CN,DIRECT\n\
#       DST-PORT,8080,DIRECT\n\
#       DOMAIN-SUFFIX,example.com,DIRECT（域名后缀；本地代理模式下生效）\n\
#       DOMAIN,api.example.com,DIRECT（域名全等）\n\
#       DOMAIN-KEYWORD,google,PROXY（域名包含）\n\
# 匹配顺序：域名规则 → 端口 → CN 表 → 默认走节点\n\
# 默认策略：未命中 → 走节点\n";

    /// 规则文件路径解析：cfg.tun_rule_file 非空用之；空则用默认 %APPDATA%\hydra\rules.txt。
    /// 返回 (显示文本, 实际路径)；配置目录不可用时回退相对路径 rules.txt（仅显示降级）。
    fn rule_file_path(cfg: &config::GuiConfig) -> (String, std::path::PathBuf) {
        if !cfg.tun_rule_file.trim().is_empty() {
            let p = std::path::PathBuf::from(cfg.tun_rule_file.trim());
            (p.display().to_string(), p)
        } else if let Some(dir) = config::config_dir() {
            let p = dir.join("rules.txt");
            (p.display().to_string(), p)
        } else {
            // 极端场景（无 APPDATA/HOME）：显示默认形态，打开按钮按相对路径兜底
            ("rules.txt（配置目录不可用）".to_string(), "rules.txt".into())
        }
    }

    /// 用系统默认程序打开规则文件（Windows 不闪控制台；失败仅记日志不阻断）
    fn open_rule_file(path: &std::path::Path) {
        #[cfg(windows)]
        {
            let mut c = std::process::Command::new("explorer");
            c.arg(path);
            let _ = hydra_client::hide_console_window(&mut c).spawn();
        }
        #[cfg(not(windows))]
        {
            let _ = std::process::Command::new("xdg-open").arg(path).spawn();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 新增字段默认值：tun_rule_mode=false（全局接管，行为兼容）、tun_rule_file 为空串
    #[test]
    fn test_tun_rule_mode_defaults() {
        let cfg = config::GuiConfig::default();
        assert!(!cfg.tun_rule_mode);
        assert!(cfg.tun_rule_file.is_empty());
    }

    /// 持久化往返：规则模式与规则文件路径经 serde 存取后保持一致
    #[test]
    fn test_tun_rule_mode_serde_roundtrip() {
        let cfg = config::GuiConfig {
            tun_rule_mode: true,
            tun_rule_file: "D:\\rules\\my-rules.txt".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).expect("序列化");
        let back: config::GuiConfig = serde_json::from_str(&json).expect("反序列化");
        assert!(back.tun_rule_mode);
        assert_eq!(back.tun_rule_file, "D:\\rules\\my-rules.txt");
        // 缺失字段（旧配置）反序列化 → 默认值（向后兼容）
        let old: config::GuiConfig = serde_json::from_str("{}").expect("旧配置反序列化");
        assert!(!old.tun_rule_mode);
        assert!(old.tun_rule_file.is_empty());
    }

    /// 规则文件路径解析：空 tun_rule_file → 默认路径；非空 → 用户自定义路径
    #[test]
    fn test_rule_file_path_resolution() {
        let cfg = config::GuiConfig {
            tun_rule_mode: false,
            tun_rule_file: String::new(),
            ..Default::default()
        };
        let (display, path) = HydraApp::rule_file_path(&cfg);
        assert!(display.ends_with("rules.txt"));
        assert!(path.to_string_lossy().ends_with("rules.txt"));
        let cfg = config::GuiConfig {
            tun_rule_file: "C:\\temp\\custom.txt".to_string(),
            ..Default::default()
        };
        let (display, path) = HydraApp::rule_file_path(&cfg);
        assert_eq!(display, "C:\\temp\\custom.txt");
        assert_eq!(path, std::path::PathBuf::from("C:\\temp\\custom.txt"));
    }
}
