//! 节点编辑对话框：备注名/地址 + 全局安全与传输参数（实时校验）。

use crate::config;
use crate::config::GuiConfig;
use crate::palette;
use crate::HydraApp;
use eframe::egui;
use hydra_client::sha256_hex;
use std::net::SocketAddr;

impl HydraApp {
    // ═══════════════ Team-UI：节点编辑对话框 ═══════════════

    /// 打开节点编辑对话框（备注名/地址 + 全局安全与传输参数）
    pub(crate) fn open_node_edit(&mut self, addr: &str) {
        self.edit_orig_addr = addr.to_string();
        self.edit_name = self
            .config
            .node_names
            .get(addr)
            .cloned()
            .unwrap_or_default();
        self.edit_addr = addr.to_string();
        self.edit_auth_key = self.config.auth_key.clone();
        self.edit_show_auth = false;
        // 逐节点独立证书路径（多节点证书 HYDRA_NODE_CERTS 的 GUI 形态）；
        // 缺项 = 空串，回落全局证书（cert_path / 内嵌 DER / 环境变量）
        self.edit_cert_path = self
            .config
            .node_cert_paths
            .get(addr)
            .cloned()
            .unwrap_or_default();
        self.node_edit_open = true;
    }

    /// 编辑对话框中证书区域的当前状态描述：文件路径（存在性）或内嵌 DER 指纹短哈希
    pub(crate) fn cert_status_text(cfg: &GuiConfig) -> String {
        let path = cfg.cert_path.trim();
        if !path.is_empty() {
            return if std::path::Path::new(path).exists() {
                format!("✓ 证书文件: {}", path)
            } else {
                format!("✗ 证书文件不存在: {}", path)
            };
        }
        let b64 = cfg.cert_der_b64.trim();
        if !b64.is_empty() {
            use base64::Engine as _;
            return match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(der) => format!(
                    "✓ 内嵌证书 DER（sha256 前 16 位: {}）",
                    &sha256_hex(&der)[..16]
                ),
                Err(_) => "✗ 内嵌证书数据损坏（base64 解码失败）".to_string(),
            };
        }
        "未设置（将回落 HYDRA_NODE_CERT 环境变量）".to_string()
    }

    /// 保存节点编辑：先全量校验（任一失败不改配置），再写回 + 迁移地址 + 提示重启代理
    pub(crate) fn save_node_edit(&mut self) {
        // ── 校验阶段 ──
        let new_addr = self.edit_addr.trim().to_string();
        if new_addr.parse::<SocketAddr>().is_err() {
            self.add_log(format!(
                "节点编辑保存失败:「{}」不是有效的 地址:端口（示例 1.2.3.4:4433）",
                new_addr
            ));
            return;
        }
        let addr_changed = new_addr != self.edit_orig_addr;
        if addr_changed && self.config.node_addrs.contains(&new_addr) {
            self.add_log(format!("节点编辑保存失败: 地址 {} 已存在于列表", new_addr));
            return;
        }
        let key = self.edit_auth_key.trim().to_string();
        if !key.is_empty() {
            if let Err(e) = hydra_client::auth_key_from_hex(&key) {
                self.add_log(format!("节点编辑保存失败: 认证密钥无效 — {}", e));
                return;
            }
        }
        let cert_path = self.edit_cert_path.trim().to_string();
        if !cert_path.is_empty() && !std::path::Path::new(&cert_path).exists() {
            self.add_log(format!(
                "节点编辑保存失败: 证书文件不存在 {}（可清空路径改用内嵌证书）",
                cert_path
            ));
            return;
        }

        // ── 写回阶段（不会再失败）──
        let orig = self.edit_orig_addr.clone();
        if addr_changed {
            self.config.rename_node(&orig, &new_addr);
            // 运行时状态表同步换键
            if let Some(st) = self.node_status.remove(&orig) {
                self.node_status.insert(new_addr.clone(), st);
            }
        }
        self.config.set_node_name(&new_addr, self.edit_name.trim());
        self.config.auth_key = key;
        // 逐节点独立证书路径（空串 = 清除，回落全局证书）；rename_node 已随迁旧键，
        // 此处以编辑值覆盖新地址键（清除场景同步移除）
        self.config.set_node_cert_path(&new_addr, &cert_path);
        self.node_edit_open = false;
        self.add_log(format!("节点 {} 已保存", new_addr));
        // 全局参数（密钥/证书）只在代理启动时读取，运行中修改必须重启才生效
        if self.proxy_running {
            self.add_log(
                "⚠ 代理正在运行：本次修改（密钥/证书/模式/地址）需停止并重新启动代理后才生效"
                    .to_string(),
            );
        }
    }

    /// 节点编辑对话框 UI（egui::Window，实时校验提示）
    pub(crate) fn ui_node_edit_dialog(&mut self, ctx: &egui::Context) {
        let mut save_clicked = false;
        egui::Window::new(format!("编辑节点 {}", self.edit_orig_addr))
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label("节点信息（仅本节点）");
                egui::Grid::new("node_edit_grid")
                    .num_columns(2)
                    .spacing([palette::SPACING_SM, palette::SPACING_SM])
                    .show(ui, |ui| {
                        ui.label("备注名:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_name)
                                .desired_width(260.0)
                                .hint_text("可选，如「家里节点」"),
                        );
                        ui.end_row();
                        ui.label("地址:端口:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_addr)
                                .desired_width(260.0)
                                .hint_text("1.2.3.4:4433"),
                        );
                        ui.end_row();
                        // 来源只读（手动 / 订阅名；订阅节点不在本对话框编辑，见节点页）
                        ui.label("来源:");
                        ui.label(format!(
                            "[{}]（只读）",
                            self.config.node_source_label(&self.edit_orig_addr)
                        ));
                        ui.end_row();
                    });
                if !self.edit_addr.trim().is_empty()
                    && self.edit_addr.trim().parse::<SocketAddr>().is_err()
                {
                    ui.colored_label(
                        palette::danger(),
                        "✗ 地址格式应为 host:port（示例 1.2.3.4:4433 / [::1]:4433）",
                    );
                }

                ui.separator();
                ui.label("安全与传输（当前全局配置，所有节点共用）");

                // 认证密钥（默认掩码）
                ui.horizontal(|ui| {
                    ui.label("认证密钥:");
                    if self.edit_show_auth {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.edit_auth_key)
                                .desired_width(240.0),
                        );
                        if ui.small_button("隐藏").clicked() {
                            self.edit_show_auth = false;
                        }
                    } else {
                        let shown = if self.edit_auth_key.trim().is_empty() {
                            "（未设置）".to_string()
                        } else {
                            config::mask_secret(self.edit_auth_key.trim())
                        };
                        ui.monospace(shown);
                        if ui.small_button("编辑/显示").clicked() {
                            self.edit_show_auth = true;
                        }
                    }
                });
                if self.edit_show_auth && !self.edit_auth_key.trim().is_empty() {
                    match hydra_client::auth_key_from_hex(self.edit_auth_key.trim()) {
                        Ok(_) => ui.colored_label(palette::success(), "✓ 密钥格式有效"),
                        Err(e) => {
                            ui.colored_label(palette::danger(), format!("✗ {}", e))
                        }
                    };
                }

                // 证书：逐节点独立路径（仅本节点）；全局证书为回落
                ui.label("节点证书路径（仅本节点）:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.edit_cert_path)
                            .desired_width(320.0)
                            .hint_text("本节点独立证书（留空 = 用全局证书）"),
                    );
                    if ui.small_button("浏览...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("证书文件", &["der", "pem", "crt", "cer"])
                            .add_filter("全部文件", &["*"])
                            .pick_file()
                        {
                            self.edit_cert_path = path.display().to_string();
                        }
                    }
                });
                ui.small(format!(
                    "全局证书（回落）: {}",
                    Self::cert_status_text(&self.config)
                ));

                // 传输为固定 TCP/TLS（TLS 1.3 + Noise-PSK）：Wave 3 起无其他模式
                ui.label("传输模式: TCP/TLS（TLS 1.3 + Noise-PSK）");

                if self.proxy_running {
                    ui.separator();
                    ui.colored_label(palette::warning(), "⚠ 代理正在运行：保存后需停止并重新启动代理，修改才会生效");
                }

                // 方案 §4：诚实提示——认证密钥为全局单值；证书已支持逐节点独立路径（上）
                ui.separator();
                ui.small("当前认证密钥为全局单值（所有节点共用）；节点证书已支持逐节点独立路径，留空回落全局证书");

                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(egui::RichText::new("💾 保存").strong()))
                        .clicked()
                    {
                        save_clicked = true;
                    }
                    if ui.button("取消").clicked() {
                        self.node_edit_open = false;
                    }
                });
            });
        if save_clicked {
            self.save_node_edit();
        }
    }
}
