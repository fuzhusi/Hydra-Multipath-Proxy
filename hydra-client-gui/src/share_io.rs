//! 分享链接导入/导出、单节点分享对话框数据、二维码图片导入、
//! 手动添加表单提交（全部为 HydraApp 动作方法）。

use crate::config;
use crate::groups::{build_form_share_url, import_share_links_as_group};
use crate::nodes::NodeStatusInfo;
use crate::HydraApp;
use hydra_client::{
    generate_share_links, hex_encode_lower, parse_share_links, sha256_hex, ShareLink,
};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::net::SocketAddr;

impl HydraApp {
    pub(crate) fn export_share_links(&mut self) {
        // 将当前节点配置转换为NodeInfo列表
        let mut nodes = Vec::new();
        for node_addr in &self.config.node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                let node_info = NodeInfo {
                    address: addr,
                    bandwidth: 100.0,
                    latency: 10.0,
                    loss_rate: 0.01,
                    load: 0.5,
                    status: NodeStatus::Online,
                };
                nodes.push(node_info);
            }
        }

        // 生成分享链接
        let share_links = generate_share_links(&nodes);
        self.share_link_text = share_links;
        self.show_share_link_dialog = true;
        self.add_log("已生成分享链接".to_string());
    }

    pub(crate) fn import_share_links(&mut self) {
        let links = parse_share_links(&self.share_link_text);
        match links {
            Ok(links) => {
                let mut imported_count = 0;
                for link in links {
                    let addr_str = format!("{}:{}", link.address, link.port);
                    if !self.config.node_addrs.contains(&addr_str) {
                        self.config.node_addrs.push(addr_str);
                        imported_count += 1;
                    }
                }
                self.add_log(format!("导入了 {} 个节点", imported_count));
                self.show_share_link_dialog = false;
            }
            Err(e) => {
                self.add_log(format!("导入失败: {}", e));
            }
        }
    }

    // ═══════════════ Team-Q：分享体系 v2（二维码 + 密钥链接）═══════════════

    /// 为指定节点构造 v2 分享链接：带认证密钥 + 证书（完整）或证书指纹（紧凑）。
    /// 密钥/证书按当前配置解析，取不到的字段自动省略。
    /// TCP/TLS（TLS 1.3 + Noise-PSK）是唯一传输：不再附加 mode=obfs/ok 参数
    /// （legacy 链接的兼容解析由 hydra-client 的 share_link 层处理）。
    pub(crate) fn build_share_link(&self, addr_str: &str, compact: bool) -> Option<ShareLink> {
        let addr: SocketAddr = addr_str.trim().parse().ok()?;
        let node_info = NodeInfo {
            address: addr,
            bandwidth: 100.0,
            latency: 10.0,
            loss_rate: 0.01,
            load: 0.5,
            status: NodeStatus::Online,
        };
        let mut link = ShareLink::new(&node_info);

        // 认证密钥（完整分享核心字段；解析失败或非法长度则省略，链接退化为仅地址信息）
        if let Ok(key) = config::resolve_auth_key(&self.config) {
            if key.len() == 32 {
                // 32 字节已预检，Err 分支不可能；clone 兜底保守回退
                link = link.clone().with_auth_key_bytes(&key).unwrap_or(link);
            }
        }

        // 证书：完整模式带 DER 本体，紧凑模式只带 SHA-256 指纹
        let cert_der = std::fs::read(self.config.cert_path.trim()).ok();
        match cert_der {
            Some(der) if compact => {
                // 指纹非法（理论不可达——sha256_hex 恒 64hex）：退化为仅地址信息
                // （clone 保底回退，与上方 with_auth_key_bytes 同款写法）
                link = link
                    .clone()
                    .with_cert_fp(sha256_hex(&der))
                    .unwrap_or_else(|_| link.clone());
            }
            Some(der) => link = link.with_cert_der(&der),
            None => {}
        }
        Some(link)
    }

    /// 打开单节点分享对话框（完整/紧凑默认完整）
    pub(crate) fn open_share_dialog(&mut self, addr: String) {
        self.share_node_addr = addr;
        self.share_compact = false;
        self.share_link = self.build_share_link(&self.share_node_addr, false);
        self.share_url_cache = String::new(); // 强制重建二维码纹理
        self.share_dialog_open = true;
        if let Some(link) = &self.share_link {
            if link.is_full_share() {
                self.add_log(format!(
                    "已生成节点 {} 的完整分享（含密钥，注意仅限可信渠道）",
                    self.share_node_addr
                ));
            } else {
                self.add_log(format!(
                    "已生成节点 {} 的分享（缺少密钥或证书，对方可能需要手动补全）",
                    self.share_node_addr
                ));
            }
        }
    }

    /// 应用一条导入的 v2 分享链接：节点地址 + 密钥/证书/模式自动入配置。
    /// 返回 Err 时不改动任何配置（先全部校验再落库）。
    pub(crate) fn apply_imported_link(&mut self, link: &ShareLink) -> Result<(), String> {
        use base64::Engine as _;

        // 先校验后写：密钥/证书解码失败直接报错，不产生半套配置
        let auth_key_hex = match link.auth_key_bytes().map_err(|e| e.to_string())? {
            Some(bytes) => {
                let hex = hex_encode_lower(&bytes);
                // 校验 hex + 长度（与启动代理同一套规则）
                hydra_client::auth_key_from_hex(&hex)?;
                Some(hex)
            }
            None => None,
        };
        let cert_b64 = link
            .cert_der_bytes()
            .map_err(|e| e.to_string())?
            .map(|der| base64::engine::general_purpose::STANDARD.encode(&der));

        // ── 以下为落库（不会再失败）──
        if let Some(hex) = auth_key_hex {
            // 09-G-2：覆盖全局认证密钥前显式留痕——此前静默替换，旧密钥对应
            // 节点全部静默失联且不可回滚
            if self.config.auth_key.trim().is_empty() {
                self.add_log("已导入链接携带的认证密钥".to_string());
            } else if self.config.auth_key.trim() != hex {
                self.add_log(format!(
                    "⚠ 导入链接覆盖了原有认证密钥（旧 {} → 新 {}）；\
                     原密钥对应的节点将无法连接，如非预期请撤销导入",
                    config::mask_secret(self.config.auth_key.trim()),
                    config::mask_secret(&hex),
                ));
            }
            self.config.auth_key = hex;
        }
        if let Some(b64) = cert_b64 {
            self.config.cert_der_b64 = b64;
            // 已有证书文件时提示覆盖语义（cert_path 优先，导入值仅在路径为空时生效）
            if !self.config.cert_path.trim().is_empty() {
                self.add_log(
                    "提示：已存在证书文件路径，链接携带的证书仅在清空证书路径后生效".to_string(),
                );
            }
        }
        // 紧凑模式指纹：本地有证书文件时核对，不一致显式告警
        if let Some(fp) = &link.cert_fp {
            if let Ok(der) = std::fs::read(self.config.cert_path.trim()) {
                let local_fp = sha256_hex(&der);
                if &local_fp != fp {
                    self.add_log(format!(
                        "⚠ 证书指纹不一致！链接 cf={}，本地证书 sha256={}，请确认证书来源",
                        fp, local_fp
                    ));
                }
            }
        }
        // legacy 链接中的 mode/ok 参数由 hydra-client 兼容解析层处理；GUI 不再落库
        // hydra_mode/obfs_key（TCP/TLS 是唯一传输，配置字段已删除）。

        let addr_str = format!("{}:{}", link.address, link.port);
        if !self.config.node_addrs.contains(&addr_str) {
            self.config.node_addrs.push(addr_str.clone());
            self.node_status.insert(
                addr_str.clone(),
                NodeStatusInfo {
                    connected: false,
                    last_check: None,
                    latency_ms: None,
                },
            );
        }
        Ok(())
    }

    /// 记录一次导入结果（UI 绿/红提示 + 日志）
    pub(crate) fn set_import_status(&mut self, ok: bool, msg: String) {
        if ok {
            self.add_log(msg.clone());
        } else {
            self.add_log(format!("导入失败: {}", msg));
        }
        self.import_status = Some((ok, msg));
    }

    /// 「从分享链接导入」提交（保持粘贴版：多行粘贴 / 链接文件文本）：
    /// 1. 复用 `import_share_links_as_group` 创建命名分组（解析/认领/更新逻辑零改动）；
    /// 2. 任何校验或导入失败 → 红字提示 + 日志、不关窗；成功才关窗并清空表单。
    pub(crate) fn import_paste_submit(&mut self) {
        let name = self.import_group_name.clone();
        let text = self.import_paste_text.clone();
        match import_share_links_as_group(&mut self.config, &name, &text) {
            Ok(result) => {
                // 运行时节点状态同步（与 apply_subscription_update 同一套收口）
                for a in &result.added {
                    self.node_status.entry(a.clone()).or_insert(NodeStatusInfo {
                        connected: false,
                        last_check: None,
                        latency_ms: None,
                    });
                }
                for a in &result.removed {
                    self.node_status.remove(a);
                }
                // 凭据落全局配置（评审修复：粘贴导入此前丢弃链接中的 k=/cc=，
                // 启动代理报"未设置 HYDRA_AUTH_KEY"）。留痕语义与
                // apply_imported_link（二维码路径）一致
                if let Some(hex) = &result.auth_key_hex {
                    if self.config.auth_key.trim().is_empty() {
                        self.add_log("已导入链接携带的认证密钥".to_string());
                    } else if self.config.auth_key.trim() != hex {
                        self.add_log(
                            "⚠ 导入链接覆盖了原有认证密钥；原密钥对应的节点将无法连接，如非预期请撤销导入"
                                .to_string(),
                        );
                    }
                    self.config.auth_key = hex.clone();
                }
                if let Some(b64) = &result.cert_der_b64 {
                    self.config.cert_der_b64 = b64.clone();
                    if !self.config.cert_path.trim().is_empty() {
                        self.add_log(
                            "提示：已存在证书文件路径，链接携带的证书仅在清空证书路径后生效"
                                .to_string(),
                        );
                    }
                }
                let mut msg = format!(
                    "已导入分组「{}」：{} 个节点{}",
                    name.trim(),
                    result.node_count,
                    if result.auth_key_hex.is_some() {
                        "（密钥/证书已自动配置）"
                    } else {
                        ""
                    }
                );
                if result.bad_lines > 0 {
                    msg.push_str(&format!("（坏行 {} 条已跳过）", result.bad_lines));
                }
                self.set_import_status(true, msg);
                // 成功才关窗并清表单：条目已在订阅列表，节点已进该分组的组标签
                self.import_dialog_open = false;
                self.import_group_name.clear();
                self.import_paste_text.clear();
            }
            Err(e) => {
                // 失败不关窗：保留粘贴内容，便于就地修正后重试
                self.set_import_status(false, e);
            }
        }
    }

    /// 「从链接文件导入」：把文本文件内容读进粘贴框（导入仍走统一提交，便于先检查再导入）
    pub(crate) fn import_paste_load_file(&mut self) -> bool {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("链接/订阅文件", &["txt", "sub"])
            .add_filter("全部文件", &["*"])
            .pick_file()
        else {
            return false; // 用户取消
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                self.import_paste_text = text;
                self.add_log(format!(
                    "已从文件读入 {} 条待导入文本（检查后点「导入（创建分组）」）",
                    path.display()
                ));
                true
            }
            Err(e) => {
                self.set_import_status(false, format!("读取文件 {} 失败: {}", path.display(), e));
                false
            }
        }
    }

    /// 「✏️ 手动添加节点」提交（表单 = 结构化字段 + 创建命名分组）：
    /// 1. `build_form_share_url` 校验表单并构造 `hydra://` 链接
    ///    （地址非空 / 端口 1..=65535 / 证书文件存在性在此校验）；
    /// 2. 复用 `import_share_links_as_group` 创建命名分组（source =
    ///    `hydra-text://` + 构造链接，分组出现在订阅列表 + 节点页同名组标签）；
    /// 3. 证书路径写入 `node_cert_paths`（按节点独立证书，逐节点生效）；
    /// 4. 校验失败 → 红字提示 + 日志、不关窗；成功才关窗并清空表单。
    pub(crate) fn manual_add_submit(&mut self) {
        let name = self.manual_group_name.clone();
        let addr = self.manual_form_addr.clone();
        let port = self.manual_form_port.clone();
        let cert = self.manual_form_cert_path.clone();
        let url = match build_form_share_url(&addr, &port, "", &cert) {
            Ok(url) => url,
            Err(e) => {
                self.set_manual_status(false, e);
                return;
            }
        };
        match import_share_links_as_group(&mut self.config, &name, &url) {
            Ok(result) => {
                // 运行时节点状态同步（与分享导入同一套收口）
                for a in &result.added {
                    self.node_status.entry(a.clone()).or_insert(NodeStatusInfo {
                        connected: false,
                        last_check: None,
                        latency_ms: None,
                    });
                }
                for a in &result.removed {
                    self.node_status.remove(a);
                }
                // 证书路径按节点落库（manual_form_cert 留空 = 不写，回落全局证书）
                let node_addr = format!("{}:{}", addr.trim(), port.trim());
                self.config.set_node_cert_path(&node_addr, cert.trim());
                // 表单链接若携带密钥/证书（用户填了密钥或证书文件）同样落全局
                if let Some(hex) = &result.auth_key_hex {
                    if self.config.auth_key.trim() != hex {
                        self.config.auth_key = hex.clone();
                        self.add_log("已应用表单携带的认证密钥".to_string());
                    }
                }
                if let Some(b64) = &result.cert_der_b64 {
                    if self.config.cert_der_b64.trim().is_empty() {
                        self.config.cert_der_b64 = b64.clone();
                    }
                }
                let msg = format!(
                    "已创建分组「{}」：{} 个节点（地址 {}）",
                    name.trim(),
                    result.node_count,
                    node_addr
                );
                self.set_manual_status(true, msg);
                // 成功才关窗并清表单
                self.manual_add_open = false;
                self.manual_group_name.clear();
                self.manual_form_addr.clear();
                self.manual_form_port.clear();
                self.manual_form_cert_path.clear();
            }
            Err(e) => {
                // 失败不关窗：保留表单内容，便于就地修正后重试
                self.set_manual_status(false, e);
            }
        }
    }

    /// 记录手动添加结果（UI 绿/红提示 + 日志；与 set_import_status 同一收口风格）
    pub(crate) fn set_manual_status(&mut self, ok: bool, msg: String) {
        if ok {
            self.add_log(msg.clone());
        } else {
            self.add_log(format!("手动添加失败: {}", msg));
        }
        self.manual_add_status = Some((ok, msg));
    }

    /// 从二维码图片文件导入（R-15：rfd 选文件在 UI 线程，读文件+缩图+rqrr 解码
    /// 全部移入后台 std::thread，结果经 mpsc 回投，由 update 轮询非阻塞收集——
    /// 大图解码不再冻结界面；同一时刻仅允许一个导入任务进行）
    pub(crate) fn import_from_qr_image(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("图片文件", &["png", "jpg", "jpeg"])
            .add_filter("全部文件", &["*"])
            .pick_file()
        else {
            return; // 用户取消
        };
        if self.qr_import_receiver.is_some() {
            self.set_import_status(false, "已有二维码导入进行中，请稍候".to_string());
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.qr_import_receiver = Some(rx);
        std::thread::spawn(move || {
            // 后台线程：读文件 → 缩图 → rqrr 解码 → 解析分享链接（CPU 密集部分全部离 UI 线程）
            let result = std::fs::read(&path)
                .map_err(|e| format!("读取图片 {} 失败: {}", path.display(), e))
                .and_then(|bytes| crate::qr::decode_qr_from_bytes(&bytes))
                .and_then(|text| {
                    ShareLink::from_share_url(text.trim())
                        .map_err(|e| format!("二维码内容不是有效的 hydra 分享链接: {}", e))
                });
            let _ = tx.send(result);
        });
        self.set_import_status(
            true,
            "二维码解码中…（后台执行，完成后自动导入）".to_string(),
        );
    }

    /// 在 update 循环中非阻塞收集二维码导入结果并应用（R-15）
    pub(crate) fn poll_qr_import_result(&mut self) {
        let result = match &self.qr_import_receiver {
            Some(rx) => match rx.try_recv() {
                Ok(result) => Some(result),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // 后台线程异常退出：重置以允许再次发起导入
                    self.qr_import_receiver = None;
                    self.set_import_status(false, "二维码解码线程异常退出".to_string());
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
            },
            None => None,
        };
        if let Some(result) = result {
            self.qr_import_receiver = None;
            match result {
                Ok(link) => match self.apply_imported_link(&link) {
                    Ok(()) => self.set_import_status(
                        true,
                        format!(
                            "二维码导入成功：{}:{}（含密钥 {}）",
                            link.address,
                            link.port,
                            if link.auth_key.is_some() {
                                "是"
                            } else {
                                "否"
                            }
                        ),
                    ),
                    Err(e) => self.set_import_status(false, e),
                },
                Err(e) => self.set_import_status(false, e),
            }
        }
    }
}
