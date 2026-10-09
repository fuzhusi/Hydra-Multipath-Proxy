//! GUI 配置持久化（Exec-1）。
//!
//! 配置文件位置：
//! - Windows：`%APPDATA%\hydra\config.json`
//! - Linux/macOS：`~/.config/hydra/config.json`（`XDG_CONFIG_HOME` 优先）
//!
//! **权限提醒**：配置文件含认证密钥（hex）明文。
//! - Windows：`%APPDATA%` 位于用户 profile 目录（`%USERPROFILE%\AppData\Roaming`），
//!   默认 ACL 仅本机当前用户、Administrators 与 SYSTEM 可读，无需额外处理；
//! - Linux/macOS：本模块保存时以 `0600` 权限创建/写入文件；
//!   但 `~/.config` 父目录若由用户手工改宽过权限，请自行收紧。
//!   （README 面向用户的说明由项目总控统一补充。）
//!
//! **优先级规则：配置文件 > 环境变量**。环境变量（`HYDRA_AUTH_KEY` 等）保留向后兼容：
//! 仅当配置文件对应字段为空/缺失时，解析函数才回落读取环境变量——
//! 用户在 GUI 填一次密钥+证书路径后，双击 exe 即可直接使用。
//!
//! 实现说明：`HYDRA_PROBE_INTERVAL_SECS` 由
//! hydra-client 内部经 `*_from_env()` 读取（该 crate 归 WS-A/WS-B 所有，GUI 不越权改动），
//! 故本模块以「配置非空 → 覆盖写进程 env」实现同样的优先级，见 [`apply_env_overrides`]。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 配置目录名（各平台一致）
pub const APP_DIR_NAME: &str = "hydra";
/// 配置文件名
pub const CONFIG_FILE_NAME: &str = "config.json";

/// 与 hydra-client/src/speedtest.rs 中的 env 名保持一致
/// （GUI 不直接依赖 hydra-client 内部实现，此处为字面量同步，改名需两处同改）
pub const HYDRA_PROBE_INTERVAL_ENV: &str = "HYDRA_PROBE_INTERVAL_SECS";

/// 手动添加节点的来源标记文案（节点来源：手动 | 订阅名，见 [`SubscriptionConfig`]）
pub const NODE_SOURCE_MANUAL: &str = "手动";

/// 订阅项配置（Exec-C 订阅格式 v1）。
///
/// 订阅来源支持 http(s) URL 或本地文件路径（`hydra-sub://` 前缀可选），
/// 拉取与解析见 `subscription.rs` / `hydra-client::parse_subscription`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubscriptionConfig {
    /// 订阅名称（展示用，同时作为该订阅节点的来源标记）
    #[serde(default)]
    pub name: String,
    /// 订阅来源：http(s) URL 或本地文件路径（支持 `hydra-sub://` 前缀）
    #[serde(default)]
    pub source: String,
    /// 上次成功更新的 Unix 时间戳（秒）；None = 从未成功更新
    #[serde(default)]
    pub last_updated_secs: Option<u64>,
    /// 该订阅上次拉取成功归属到节点列表的地址（"host:port"）。
    /// 用于「更新订阅」时替换旧节点、删除订阅时连带清理，以及节点来源标记；
    /// 与手动添加/其他订阅冲突的地址不记入（保持原来源）。
    #[serde(default)]
    pub nodes: Vec<String>,
}

/// GUI 持久化配置。所有字段带 `serde(default)`：缺字段 / 旧版本文件 → 各字段默认值。
/// Default 手工实现（close_to_tray 默认 true，与 serde 默认一致）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiConfig {
    /// 代理本地监听地址（如 "127.0.0.1:1080"）
    #[serde(default)]
    pub proxy_listen_addr: String,
    /// 节点地址列表（"host:port"）
    #[serde(default)]
    pub node_addrs: Vec<String>,
    /// 节点预共享认证密钥（hex 编码，对应 HYDRA_AUTH_KEY）
    #[serde(default)]
    pub auth_key: String,
    /// 节点证书文件路径（对应 HYDRA_NODE_CERT，节点生成的 hydra-node-cert.der）
    #[serde(default)]
    pub cert_path: String,
    /// Team-Q v2：通过分享链接导入的节点证书 DER（base64 标准编码）。
    /// 与 cert_path 二选一：cert_path 优先，二者均空才回落环境变量。
    /// 导入完整分享（cc 字段）时直接入库，无需证书文件落盘。
    #[serde(default)]
    pub cert_der_b64: String,
    // TCP/TLS（TLS 1.3 + Noise-PSK）是唯一传输：Wave 3 已删除 hydra_mode/obfs_key 字段
    // （旧配置文件中的残留值按未知字段忽略，见下方测试）。
    /// Offline 恢复探测间隔（秒，对应 HYDRA_PROBE_INTERVAL_SECS）；None = 用库默认（30）
    #[serde(default)]
    pub probe_interval_secs: Option<u64>,
    /// 订阅列表（Exec-C v1；旧版本配置文件缺此字段 → 空列表）
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionConfig>,
    /// T2：关闭窗口时的行为——true（默认）= 隐藏到系统托盘（代理继续运行）；
    /// false = 直接退出（停止代理并清理系统代理）。
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    /// Team-UI：节点备注名（地址 "host:port" → 展示名）。缺项 = 无备注，显示地址本身。
    #[serde(default)]
    pub node_names: HashMap<String, String>,
    /// TUN 透明代理开关（已交付，需管理员/root；仅 TCP；true = 代理启动时叠加 TUN 模式）
    #[serde(default)]
    pub tun_enabled: bool,
    /// TUN 虚拟网卡地址（形如 "10.7.0.1/30"）；空串 = 用库默认 10.7.0.1/30
    #[serde(default)]
    pub tun_addr: String,
    /// TUN 拦截端口列表（逗号分隔）；空串 = 用库默认 80,443,8080,8443
    #[serde(default)]
    pub tun_ports: String,
    /// 信任模式："pin"（自签 pinning，默认；空串同 pin）| "ca"（真证书/公共 CA）
    #[serde(default)]
    pub trust_mode: String,
    /// ca 模式可选：叶证书 SHA-256 硬 pin（64 hex，防 CA 误签发；对应 HYDRA_CERT_SHA256）
    #[serde(default)]
    pub ca_leaf_pin: String,
    /// 多节点证书：节点地址 "host:port" → 该节点独立证书文件路径。
    /// 缺项节点回落全局 cert_path / cert_der_b64 / HYDRA_NODE_CERT（三级回落不变）。
    #[serde(default)]
    pub node_cert_paths: HashMap<String, String>,
}

/// serde 默认值：true（关窗默认隐藏到托盘）
fn default_true() -> bool {
    true
}

/// 手工 Default：close_to_tray = true（与 serde `default = "default_true"` 保持一致）
impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            proxy_listen_addr: String::new(),
            node_addrs: Vec::new(),
            auth_key: String::new(),
            cert_path: String::new(),
            cert_der_b64: String::new(),
            probe_interval_secs: None,
            subscriptions: Vec::new(),
            close_to_tray: true,
            node_names: HashMap::new(),
            tun_enabled: false,
            tun_addr: String::new(),
            tun_ports: String::new(),
            trust_mode: String::new(),
            ca_leaf_pin: String::new(),
            node_cert_paths: HashMap::new(),
        }
    }
}

impl GuiConfig {
    /// 节点来源标记（单一事实来源 = 各订阅的 `nodes` 列表，避免平行账本漂移）：
    /// 地址出现在某订阅的 nodes 中 → "订阅:<名>"；否则 → [`NODE_SOURCE_MANUAL`]。
    /// 多个订阅含同一地址时取先匹配者。
    pub fn node_source_label(&self, addr: &str) -> String {
        for sub in &self.subscriptions {
            if sub.nodes.iter().any(|n| n == addr) {
                return format!("订阅:{}", sub.name);
            }
        }
        NODE_SOURCE_MANUAL.to_string()
    }

    /// 所有订阅已认领的节点地址集合（更新订阅/删除订阅时用于"保留手动节点"判定）
    pub fn subscription_owned_addrs(&self) -> Vec<String> {
        self.subscriptions
            .iter()
            .flat_map(|s| s.nodes.iter().cloned())
            .collect()
    }

    /// Team-UI：节点展示名——有备注名返回备注名，否则返回地址本身。
    pub fn node_display_name(&self, addr: &str) -> String {
        match self.node_names.get(addr).map(|s| s.trim()) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => addr.to_string(),
        }
    }

    /// Team-UI：设置/清除节点备注名（trim 后为空 = 清除该条目，不存空串）。
    pub fn set_node_name(&mut self, addr: &str, name: &str) {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            self.node_names.remove(addr);
        } else {
            self.node_names
                .insert(addr.to_string(), trimmed.to_string());
        }
    }

    /// Team-UI：编辑对话框修改节点地址后的迁移——同步 node_addrs、订阅认领列表与备注名。
    /// 新地址已存在时不迁移（调用方应先拒绝），此处仅做幂等迁移。
    pub fn rename_node(&mut self, old: &str, new: &str) {
        if old == new {
            return;
        }
        for a in self.node_addrs.iter_mut() {
            if a == old {
                *a = new.to_string();
            }
        }
        for sub in self.subscriptions.iter_mut() {
            for n in sub.nodes.iter_mut() {
                if n == old {
                    *n = new.to_string();
                }
            }
        }
        if let Some(name) = self.node_names.remove(old) {
            self.node_names.entry(new.to_string()).or_insert(name);
        }
        // 节点独立证书路径随地址迁移（与备注名同语义：新地址已有条目则不覆盖）
        if let Some(p) = self.node_cert_paths.remove(old) {
            self.node_cert_paths.entry(new.to_string()).or_insert(p);
        }
    }

    /// 移除节点的残留状态收口（清备注名 + 独立证书路径）。
    /// 删除节点 / 订阅移除节点时必须调用：否则 node_cert_paths 残留会导致
    /// 同一地址日后复用为新节点时，旧证书被静默当作该节点的信任根。
    pub fn remove_node_state(&mut self, addr: &str) {
        self.node_names.remove(addr);
        self.node_cert_paths.remove(addr);
    }

    /// 生效信任模式："ca" → ca；其余（含空串/未知值）→ 默认 pin。
    pub fn trust_mode_effective(&self) -> &str {
        if self.trust_mode.trim() == "ca" {
            "ca"
        } else {
            "pin"
        }
    }

    /// 生效 TUN 地址：空串回落库默认 10.7.0.1/30
    pub fn tun_addr_or_default(&self) -> &str {
        let s = self.tun_addr.trim();
        if s.is_empty() {
            "10.7.0.1/30"
        } else {
            s
        }
    }

    /// 生效 TUN 端口列表：空串回落库默认 80,443,8080,8443
    pub fn tun_ports_or_default(&self) -> &str {
        let s = self.tun_ports.trim();
        if s.is_empty() {
            "80,443,8080,8443"
        } else {
            s
        }
    }

    /// 设置/清除节点独立证书路径（trim 后为空 = 清除该条目，不存空串）
    pub fn set_node_cert_path(&mut self, addr: &str, path: &str) {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            self.node_cert_paths.remove(addr);
        } else {
            self.node_cert_paths
                .insert(addr.to_string(), trimmed.to_string());
        }
    }
}

impl GuiConfig {
    /// Team-UI：订阅节点「另存为手动」——从唯一认领它的订阅 nodes 列表移除该地址。
    /// 移除后 `node_source_label` 即回落为「手动」；后续订阅更新按 manual_set 语义
    /// 保留该地址且不再认领（见 main.rs apply_subscription_update）。
    /// 返回是否发生了移除（地址不属于任何订阅时为 false）。
    pub fn save_subscription_node_as_manual(&mut self, addr: &str) -> bool {
        for sub in &mut self.subscriptions {
            if let Some(pos) = sub.nodes.iter().position(|n| n == addr) {
                sub.nodes.remove(pos);
                return true;
            }
        }
        false
    }
}

/// 返回配置目录；无法定位（如无 APPDATA/HOME）时返回 None（此时保存降级为仅内存态）。
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join(APP_DIR_NAME))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join(APP_DIR_NAME));
            }
        }
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join(APP_DIR_NAME))
    }
}

/// 返回配置文件完整路径
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(CONFIG_FILE_NAME))
}

/// 从指定路径加载配置。
/// - 文件不存在 → `Ok(None)`（首启场景，调用方进入向导）
/// - 文件存在但解析失败 → `Err`（调用方记日志并降级为默认值/环境变量，不覆盖写坏文件）
pub fn load_from_file(path: &Path) -> std::io::Result<Option<GuiConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let cfg: GuiConfig = serde_json::from_str(&text).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "配置文件解析失败（{}），已忽略并使用默认值: {}",
                path.display(),
                e
            ),
        )
    })?;
    Ok(Some(cfg))
}

/// 保存配置到指定路径（自动创建父目录；JSON pretty 格式）。
/// Unix 下以 0600 权限创建文件（含密钥，不放开组/其他用户读）。
pub fn save_to_file(path: &Path, cfg: &GuiConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("创建配置目录 {} 失败: {}", parent.display(), e))?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("配置序列化失败: {}", e))?;

    // 审查 R-29：原子写——此前直接 create+truncate 写 config.json，进程在写入
    // 中途崩溃/断电会留下半截 JSON，下次启动加载失败降级为默认配置，auth_key、
    // 全部节点、订阅一次性丢失。现先写同目录临时文件并 sync_all 落盘，再
    // rename 原子替换（同文件系统内 rename 原子；Windows 下 std::fs::rename
    // 以 MOVEFILE_REPLACE_EXISTING 语义覆盖旧文件）。
    // 临时文件名带进程号（09-P3-2）：固定名 `config.json.tmp` 在双实例并发保存
    // 时互相交错覆写，后到的 rename 会用坏文件替换好配置。pid 唯一化后各写各的
    // tmp，rename 原子性由文件系统保证。
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // 密钥明文：临时文件同样仅属主可读写
            .open(&tmp)
            .map_err(|e| format!("打开临时配置文件 {} 失败: {}", tmp.display(), e))?;
        f.write_all(json.as_bytes())
            .and_then(|_| f.flush())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("写入临时配置文件 {} 失败: {}", tmp.display(), e))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("打开临时配置文件 {} 失败: {}", tmp.display(), e))?;
        f.write_all(json.as_bytes())
            .and_then(|_| f.flush())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("写入临时配置文件 {} 失败: {}", tmp.display(), e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp); // 失败清理临时文件，不阻塞下次保存
        format!("替换配置文件 {} 失败: {}", path.display(), e)
    })
}

/// 掩码显示密钥：长度 > 8 → 保留前 4 后 4（如 `a1b2****8f90`）；
/// 长度 1..=8 → 全掩码；空串原样返回（UI 显示"未设置"）。
pub fn mask_secret(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}****{}", head, tail)
}

/// 认证密钥解析（配置文件 > 环境变量）：
/// 配置 `auth_key` 非空 → 按 hex 解码校验；否则回落 `HYDRA_AUTH_KEY` 环境变量。
pub fn resolve_auth_key(cfg: &GuiConfig) -> Result<Vec<u8>, String> {
    let from_config = cfg.auth_key.trim();
    if !from_config.is_empty() {
        return hydra_client::auth_key_from_hex(from_config);
    }
    hydra_client::auth_key_from_env()
}

/// 节点证书解析（证书文件路径 > 链接导入的内嵌 DER > 环境变量）：
/// `cert_path` 非空 → 读该文件；否则 `cert_der_b64` 非空 → base64 解码；
/// 二者均空才回落 `HYDRA_NODE_CERT` 环境变量。
pub fn resolve_node_certs(cfg: &GuiConfig) -> Result<Vec<Vec<u8>>, String> {
    let path = cfg.cert_path.trim();
    if !path.is_empty() {
        return std::fs::read(path)
            .map(|der| vec![der])
            .map_err(|e| format!("读取节点证书 {} 失败: {}", path, e));
    }
    let b64 = cfg.cert_der_b64.trim();
    if !b64.is_empty() {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("解码分享链接导入的节点证书失败: {}", e))?;
        return Ok(vec![der]);
    }
    hydra_client::node_certs_from_env()
}

/// 校验 ca 模式叶证书 SHA-256 硬 pin：空串 = 不 pin（合法）；非空须恰好 64 hex。
pub fn validate_leaf_pin(pin: &str) -> Result<(), String> {
    let s = pin.trim();
    if s.is_empty() {
        return Ok(());
    }
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "叶证书 SHA-256 非法：需要 64 位 hex 字符（当前 {} 字符）",
            s.chars().count()
        ));
    }
    Ok(())
}

/// 信任根构造（配置文件 > 环境变量语义与 resolve_node_certs 一致）：
/// - pin 模式（默认）：按「节点地址顺序收集证书」构造 TlsTrust::pinned；
/// - ca 模式：TlsTrust::public_ca（可选叶证书 SHA-256 硬 pin）。
///
/// `node_addrs` 顺序必须与传入 ProxyServer 的节点顺序一致（with_node_certs 按序对应）。
pub fn resolve_trust(
    cfg: &GuiConfig,
    node_addrs: &[String],
) -> Result<hydra_client::tcp_transport::TlsTrust, String> {
    if cfg.trust_mode_effective() == "ca" {
        validate_leaf_pin(&cfg.ca_leaf_pin)?;
        let pin = cfg.ca_leaf_pin.trim();
        let pin = if pin.is_empty() {
            None
        } else {
            Some(pin.to_string())
        };
        // ca 模式信任公共 CA，节点证书文件不入信任根
        return Ok(hydra_client::tcp_transport::TlsTrust::public_ca(pin));
    }
    let certs = resolve_node_certs_for_nodes(cfg, node_addrs)?;
    // 审查修复：pin 模式信任根为空（无节点 / 无任何证书）不再返回 Ok——
    // 空信任根会使 TLS 握手必然失败却无显式根因，test_all_nodes 删光节点后
    // 变成"静默空测"。此处提前报错，让 GUI 日志区透出原因。
    if certs.is_empty() {
        return Err(
            "pin 模式信任根为空：请先添加节点并配置节点证书（全局证书或逐节点证书）".to_string(),
        );
    }
    Ok(hydra_client::tcp_transport::TlsTrust::pinned(certs))
}

/// 多节点证书按序收集（对应 HYDRA_NODE_CERTS 的 GUI 形态）：
/// 每个节点先取 node_cert_paths[addr]（独立证书文件），缺项回落
/// 全局 resolve_node_certs（cert_path > cert_der_b64 > HYDRA_NODE_CERT）。
/// 返回向量顺序与 `node_addrs` 一一对应。
pub fn resolve_node_certs_for_nodes(
    cfg: &GuiConfig,
    node_addrs: &[String],
) -> Result<Vec<Vec<u8>>, String> {
    node_addrs
        .iter()
        .map(|addr| {
            let der = match cfg.node_cert_paths.get(addr).map(|s| s.trim()) {
                Some(p) if !p.is_empty() => std::fs::read(p)
                    .map_err(|e| format!("读取节点 {} 的证书 {} 失败: {}", addr, p, e)),
                _ => resolve_node_certs(cfg)
                    .and_then(|mut v| v.pop().ok_or_else(|| "节点证书解析结果为空".to_string())),
            }?;
            Ok(der)
        })
        .collect()
}

/// 将配置中的探测间隔覆盖写入进程环境变量（仅当配置值非空时覆盖，
/// 留空则保持 env 原值 = 向后兼容回落）。必须在任何工作线程 spawn 之前调用，
/// 避免与其他线程的 env 读取并发竞争。
pub fn apply_env_overrides(cfg: &GuiConfig) {
    if let Some(secs) = cfg.probe_interval_secs {
        std::env::set_var(HYDRA_PROBE_INTERVAL_ENV, secs.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip_full() {
        let cfg = GuiConfig {
            proxy_listen_addr: "127.0.0.1:1080".into(),
            node_addrs: vec!["127.0.0.1:4433".into(), "10.0.0.1:4433".into()],
            auth_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into(),
            cert_path: r"C:\certs\hydra-node-cert.der".into(),
            cert_der_b64: String::new(),
            probe_interval_secs: Some(15),
            subscriptions: Vec::new(),
            close_to_tray: true,
            node_names: Default::default(),
            tun_enabled: false,
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GuiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn test_missing_fields_default_values() {
        // 空对象 → 全默认
        let cfg: GuiConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg, GuiConfig::default());
        assert!(cfg.node_addrs.is_empty());
        assert_eq!(cfg.probe_interval_secs, None);

        // 部分字段：缺的补默认，不会反序列化报错（兼容旧版本文件）
        let cfg: GuiConfig = serde_json::from_str(r#"{"auth_key":"ff"}"#).unwrap();
        assert_eq!(cfg.auth_key, "ff");
        assert_eq!(cfg.proxy_listen_addr, "");
        assert!(cfg.node_addrs.is_empty());

        // 未知字段忽略（含旧版本遗留的 hydra_mode/obfs_key——字段已删除，按未知字段跳过）
        let cfg: GuiConfig =
            serde_json::from_str(r#"{"unknown_field": 1, "hydra_mode": "obfs"}"#).unwrap();
        assert_eq!(cfg, GuiConfig::default());
    }

    #[test]
    fn test_file_roundtrip_and_missing_file() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-gui-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join(CONFIG_FILE_NAME);

        // 文件不存在 → Ok(None)
        assert!(matches!(load_from_file(&path), Ok(None)));

        let cfg = GuiConfig {
            proxy_listen_addr: "127.0.0.1:1080".into(),
            node_addrs: vec!["127.0.0.1:4433".into()],
            auth_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into(),
            cert_path: "/tmp/node.der".into(),
            cert_der_b64: String::new(),
            probe_interval_secs: Some(30),
            subscriptions: Vec::new(),
            close_to_tray: true,
            node_names: Default::default(),
            tun_enabled: false,
            ..Default::default()
        };
        save_to_file(&path, &cfg).expect("保存应成功");
        let loaded = load_from_file(&path)
            .expect("加载应成功")
            .expect("应有配置");
        assert_eq!(loaded, cfg);

        // Unix 权限 0600（密钥明文保护）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // 坏 JSON → Err（不静默吞掉）
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_from_file(&path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 审查 R-29：保存为原子替换——两次覆盖保存后文件内容为最新且无 .tmp 残留
    #[test]
    fn test_save_atomic_no_tmp_leftover() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-gui-test-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join(CONFIG_FILE_NAME);
        let mut cfg = GuiConfig {
            auth_key: "11".repeat(32),
            ..GuiConfig::default()
        };
        save_to_file(&path, &cfg).expect("首次保存应成功");
        cfg.auth_key = "22".repeat(32);
        save_to_file(&path, &cfg).expect("覆盖保存（rename 替换）应成功");
        assert!(
            !path.with_extension("json.tmp").exists(),
            "临时文件应在 rename 后消失"
        );
        let loaded = load_from_file(&path)
            .expect("加载应成功")
            .expect("应有配置");
        assert_eq!(loaded.auth_key, "22".repeat(32), "覆盖后应为最新内容");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mask_secret() {
        // 长度 > 8：前 4 + **** + 后 4（任务书示例样式）
        assert_eq!(mask_secret("a1b2c3d4e5f68f90"), "a1b2****8f90");
        assert_eq!(mask_secret("a1b2c3d4e5f6a7b8"), "a1b2****a7b8");
        // 短密钥全掩码（不泄露长度外的信息）
        assert_eq!(mask_secret("12345678"), "********");
        assert_eq!(mask_secret("abc"), "***");
        assert_eq!(mask_secret("a"), "*");
        // 空串原样（UI 层显示"未设置"）
        assert_eq!(mask_secret(""), "");
        // 非 ASCII 按 char 计数，不切坏 UTF-8
        assert_eq!(mask_secret("密钥测试数据abcd"), "密钥测试****abcd");
    }

    #[test]
    fn test_resolve_auth_key_from_config() {
        // 配置优先：合法 hex 直接解码，不读环境变量
        // （密钥必须恰好 32 字节——snow NNpsk2 PSK 约束，客户端启动期 fail-fast）
        let cfg = GuiConfig {
            auth_key: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            ..Default::default()
        };
        let key = resolve_auth_key(&cfg).expect("配置内合法 hex 应解析成功");
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0x00);

        // 配置内非法 hex → Err（根因透出，不回落 env）
        let bad = GuiConfig {
            auth_key: "zz-not-hex".into(),
            ..Default::default()
        };
        assert!(resolve_auth_key(&bad).is_err());

        // 配置内 hex 长度非法（16 字节，旧文档曾允许）→ Err（审查 R-05）
        let short = GuiConfig {
            auth_key: "aabb".into(),
            ..Default::default()
        };
        assert!(resolve_auth_key(&short).is_err());
    }

    #[test]
    fn test_resolve_node_certs_from_config() {
        // 配置路径存在 → 读文件内容
        let dir = std::env::temp_dir().join(format!(
            "hydra-gui-cert-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("node.der");
        std::fs::write(&cert_path, [0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let cfg = GuiConfig {
            cert_path: cert_path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let certs = resolve_node_certs(&cfg).expect("应读取成功");
        assert_eq!(certs, vec![vec![0xDE, 0xAD, 0xBE, 0xEF]]);

        // 配置路径不存在 → Err 带根因
        let missing = GuiConfig {
            cert_path: dir.join("no-such.der").to_string_lossy().into_owned(),
            ..Default::default()
        };
        let err = resolve_node_certs(&missing).unwrap_err();
        assert!(err.contains("读取节点证书"), "错误信息应含根因: {}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_node_certs_embedded_der_fallback() {
        // Team-Q v2：cert_path 为空但 cert_der_b64 非空 → 解码内嵌 DER（链接导入场景，无需文件落盘）
        use base64::Engine as _;
        let cfg = GuiConfig {
            cert_der_b64: base64::engine::general_purpose::STANDARD
                .encode([0xDE, 0xAD, 0xBE, 0xEF]),
            ..Default::default()
        };
        let certs = resolve_node_certs(&cfg).expect("内嵌 DER 应解码成功");
        assert_eq!(certs, vec![vec![0xDE, 0xAD, 0xBE, 0xEF]]);

        // cert_path 优先于内嵌 DER
        let dir = std::env::temp_dir().join(format!("hydra-gui-der-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("node.der");
        std::fs::write(&cert_path, [0x01]).unwrap();
        let cfg = GuiConfig {
            cert_path: cert_path.to_string_lossy().into_owned(),
            cert_der_b64: "!!!bad!!!".into(),
            ..Default::default()
        };
        assert_eq!(resolve_node_certs(&cfg).unwrap(), vec![vec![0x01]]);

        // 坏 base64 且无路径 → Err 带根因
        let bad = GuiConfig {
            cert_der_b64: "!!!bad!!!".into(),
            ..Default::default()
        };
        let err = resolve_node_certs(&bad).unwrap_err();
        assert!(err.contains("解码"), "错误信息应含根因: {}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_legacy_obfs_fields_ignored() {
        // Wave 3：TCP/TLS 是唯一传输。旧配置文件残留的 hydra_mode/obfs_key
        // 按未知字段忽略（结构体未设 deny_unknown_fields），反序列化不报错。
        let old: GuiConfig = serde_json::from_str(
            r#"{"auth_key":"ff","hydra_mode":"obfs","obfs_key":"second-password"}"#,
        )
        .unwrap();
        assert_eq!(old.auth_key, "ff");
        assert_eq!(
            old,
            GuiConfig {
                auth_key: "ff".into(),
                ..Default::default()
            }
        );
    }

    // ===================== Exec-C：订阅字段持久化 =====================

    #[test]
    fn test_subscriptions_serde_roundtrip() {
        // 含订阅的完整往返
        let cfg = GuiConfig {
            subscriptions: vec![
                SubscriptionConfig {
                    name: "主订阅".into(),
                    source: "https://example.com/hydra-sub.txt".into(),
                    last_updated_secs: Some(1_700_000_000),
                    nodes: vec!["10.0.0.1:4433".into(), "10.0.0.2:4433".into()],
                },
                SubscriptionConfig {
                    name: "本地文件".into(),
                    source: "hydra-sub://D:\\subs\\a.txt".into(),
                    last_updated_secs: None,
                    nodes: Vec::new(),
                },
            ],
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GuiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn test_old_config_without_subscriptions_field() {
        // 旧版本配置文件（无 subscriptions 字段）→ 空列表，不报错（向后兼容）
        let old: GuiConfig = serde_json::from_str(r#"{"auth_key":"ff"}"#).unwrap();
        assert!(old.subscriptions.is_empty());

        // 订阅项缺字段 → 补默认（None / 空列表）
        let partial: GuiConfig =
            serde_json::from_str(r#"{"subscriptions":[{"name":"a","source":"s.txt"}]}"#).unwrap();
        assert_eq!(partial.subscriptions.len(), 1);
        assert_eq!(partial.subscriptions[0].name, "a");
        assert_eq!(partial.subscriptions[0].last_updated_secs, None);
        assert!(partial.subscriptions[0].nodes.is_empty());

        // 未知字段忽略
        let cfg: GuiConfig = serde_json::from_str(r#"{"subscriptions":[],"unknown":1}"#).unwrap();
        assert!(cfg.subscriptions.is_empty());
    }

    #[test]
    fn test_node_source_label_and_owned_addrs() {
        let cfg = GuiConfig {
            subscriptions: vec![
                SubscriptionConfig {
                    name: "主订阅".into(),
                    source: "https://example.com/s".into(),
                    last_updated_secs: None,
                    nodes: vec!["10.0.0.1:4433".into()],
                },
                SubscriptionConfig {
                    name: "备份订阅".into(),
                    source: "file:///x".into(),
                    last_updated_secs: None,
                    nodes: Vec::new(),
                },
            ],
            ..Default::default()
        };
        // 订阅节点 → 订阅名标记；其余 → 手动
        assert_eq!(cfg.node_source_label("10.0.0.1:4433"), "订阅:主订阅");
        assert_eq!(cfg.node_source_label("1.2.3.4:1"), NODE_SOURCE_MANUAL);
        // 空配置全部手动
        assert_eq!(
            GuiConfig::default().node_source_label("1.2.3.4:1"),
            NODE_SOURCE_MANUAL
        );

        let owned = cfg.subscription_owned_addrs();
        assert_eq!(owned, vec!["10.0.0.1:4433".to_string()]);
    }

    // ===================== UI 重设计 v2：TUN 预留字段 + 订阅节点另存为手动 =====================

    #[test]
    fn test_tun_enabled_reserved_default_false() {
        // 缺省 / 旧版本配置文件 → tun_enabled=false
        let cfg: GuiConfig = serde_json::from_str("{}").unwrap();
        assert!(!cfg.tun_enabled);
        let old: GuiConfig = serde_json::from_str(r#"{"auth_key":"ff"}"#).unwrap();
        assert!(!old.tun_enabled);

        // 显式 true 也能往返（TUN 开关现驱动代理线程叠加 TUN 模式）
        let cfg = GuiConfig {
            tun_enabled: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GuiConfig = serde_json::from_str(&json).unwrap();
        assert!(back.tun_enabled);
    }

    // ===================== TUN 地址/端口 + 信任模式 + 多节点证书 =====================

    #[test]
    fn test_tun_settings_serde_and_defaults() {
        // 新字段全量往返
        let cfg = GuiConfig {
            tun_enabled: true,
            tun_addr: "10.9.0.1/24".into(),
            tun_ports: "80,443".into(),
            ..Default::default()
        };
        let back: GuiConfig = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back, cfg);

        // 空串回落库默认（与 GUI 提示一致）
        assert_eq!(GuiConfig::default().tun_addr_or_default(), "10.7.0.1/30");
        assert_eq!(
            GuiConfig::default().tun_ports_or_default(),
            "80,443,8080,8443"
        );
        // 旧版本配置文件（缺字段）→ 空串，不报错
        let old: GuiConfig = serde_json::from_str(r#"{"auth_key":"ff"}"#).unwrap();
        assert_eq!(old.tun_addr_or_default(), "10.7.0.1/30");
    }

    #[test]
    fn test_trust_mode_and_leaf_pin() {
        // 空串/未知值 → 默认 pin；"ca" → ca
        assert_eq!(GuiConfig::default().trust_mode_effective(), "pin");
        let ca = GuiConfig {
            trust_mode: "ca".into(),
            ..Default::default()
        };
        assert_eq!(ca.trust_mode_effective(), "ca");
        let weird = GuiConfig {
            trust_mode: "bogus".into(),
            ..Default::default()
        };
        assert_eq!(weird.trust_mode_effective(), "pin");

        // 叶证书 pin 校验：空 = 不 pin（合法）；非空须 64 hex
        assert!(validate_leaf_pin("").is_ok());
        assert!(validate_leaf_pin("  ").is_ok());
        assert!(validate_leaf_pin(&"a".repeat(64)).is_ok());
        assert!(validate_leaf_pin(&"A1".repeat(32)).is_ok());
        assert!(validate_leaf_pin(&"a".repeat(63)).is_err());
        assert!(validate_leaf_pin(&"g".repeat(64)).is_err());

        // ca 模式 + 非法 pin → resolve_trust 报错（不静默忽略）
        let bad = GuiConfig {
            trust_mode: "ca".into(),
            ca_leaf_pin: "zz".into(),
            ..Default::default()
        };
        assert!(resolve_trust(&bad, &[]).is_err());

        // ca 模式 + 合法（空）pin → public_ca 成功
        assert!(resolve_trust(&ca, &[]).is_ok());
    }

    #[test]
    fn test_node_cert_paths_per_node_and_migration() {
        let dir = std::env::temp_dir().join(format!("hydra-gui-nodes-cert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.der");
        let b = dir.join("b.der");
        std::fs::write(&a, [0xAA]).unwrap();
        std::fs::write(&b, [0xBB]).unwrap();

        let cfg = GuiConfig {
            node_addrs: vec!["10.0.0.1:4433".into(), "10.0.0.2:4433".into()],
            node_cert_paths: [
                (
                    "10.0.0.1:4433".to_string(),
                    a.to_string_lossy().into_owned(),
                ),
                (
                    "10.0.0.2:4433".to_string(),
                    b.to_string_lossy().into_owned(),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        // 按节点顺序独立收集
        let certs = resolve_node_certs_for_nodes(&cfg, &cfg.node_addrs).unwrap();
        assert_eq!(certs, vec![vec![0xAA], vec![0xBB]]);

        // 缺项节点回落全局证书路径
        let mut cfg2 = GuiConfig {
            node_addrs: vec!["10.0.0.1:4433".into(), "10.0.0.2:4433".into()],
            ..Default::default()
        };
        cfg2.set_node_cert_path("10.0.0.1:4433", a.to_string_lossy().as_ref());
        assert!(cfg2.node_cert_paths.contains_key("10.0.0.1:4433"));
        // 全局 cert_path 由 resolve_node_certs 覆盖，此处给缺失路径验证回落错误来源
        cfg2.cert_path = dir.join("global.der").to_string_lossy().into_owned();
        let err = resolve_node_certs_for_nodes(&cfg2, &cfg2.node_addrs).unwrap_err();
        assert!(err.contains("global.der"), "缺项应回落全局: {}", err);

        // 空串 = 清除
        cfg2.set_node_cert_path("10.0.0.1:4433", "  ");
        assert!(!cfg2.node_cert_paths.contains_key("10.0.0.1:4433"));

        // 地址改名随迁（与备注名同语义）
        let mut cfg3 = GuiConfig {
            node_addrs: vec!["10.0.0.1:4433".into()],
            ..Default::default()
        };
        cfg3.set_node_cert_path("10.0.0.1:4433", "C:\\x.der");
        cfg3.rename_node("10.0.0.1:4433", "10.0.0.9:9999");
        assert_eq!(
            cfg3.node_cert_paths.get("10.0.0.9:9999").unwrap(),
            "C:\\x.der"
        );
        assert!(!cfg3.node_cert_paths.contains_key("10.0.0.1:4433"));

        // serde 往返
        let back: GuiConfig = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back, cfg);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_trust_pinned_collects_in_order() {
        // pin 模式（默认）：按节点顺序收集 → resolve_trust 成功（TlsTrust 内部持有证书）
        let dir = std::env::temp_dir().join(format!("hydra-gui-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("n.der");
        std::fs::write(&p, [0x01]).unwrap();
        let mut cfg = GuiConfig::default();
        cfg.set_node_cert_path("1.2.3.4:443", p.to_string_lossy().as_ref());
        assert!(resolve_trust(&cfg, &["1.2.3.4:443".to_string()]).is_ok());
        // pin 模式证书缺失 → 报错透出根因
        let _ = std::fs::remove_file(&p);
        assert!(resolve_trust(&cfg, &["1.2.3.4:443".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 审查修复：pin 模式空信任根必须 Err（不再 Ok(pinned([])) 静默空测）
    #[test]
    fn test_resolve_trust_pin_empty_root_is_err() {
        // 无任何证书来源（cert_path / cert_der_b64 / env 均空）+ 空节点列表 → Err
        let cfg = GuiConfig::default();
        let err = resolve_trust(&cfg, &[]).unwrap_err();
        assert!(err.contains("信任根为空"), "错误信息应含根因: {}", err);

        // 有节点地址但无证书可读 → 同样 Err（读文件失败路径）
        let err = resolve_trust(&cfg, &["1.2.3.4:443".to_string()]).unwrap_err();
        assert!(!err.is_empty());
    }

    /// 审查修复：remove_node_state 收口清理备注名与独立证书路径
    #[test]
    fn test_remove_node_state_clears_names_and_certs() {
        let mut cfg = GuiConfig::default();
        cfg.node_addrs.push("10.0.0.1:4433".into());
        cfg.set_node_name("10.0.0.1:4433", "旧节点");
        cfg.set_node_cert_path("10.0.0.1:4433", r"C:\certs\old.der");

        cfg.remove_node_state("10.0.0.1:4433");
        assert!(!cfg.node_names.contains_key("10.0.0.1:4433"));
        assert!(!cfg.node_cert_paths.contains_key("10.0.0.1:4433"));

        // 幂等：重复调用无副作用
        cfg.remove_node_state("10.0.0.1:4433");
        // 不存在的地址：无副作用
        cfg.remove_node_state("9.9.9.9:1");
        assert!(cfg.node_names.is_empty() && cfg.node_cert_paths.is_empty());
    }

    #[test]
    fn test_save_subscription_node_as_manual() {
        let mut cfg = GuiConfig {
            node_addrs: vec!["10.0.0.1:4433".into(), "10.0.0.2:4433".into()],
            subscriptions: vec![SubscriptionConfig {
                name: "主订阅".into(),
                source: "https://e/s".into(),
                last_updated_secs: None,
                nodes: vec!["10.0.0.1:4433".into()],
            }],
            ..Default::default()
        };

        // 订阅节点 → 移除认领，来源回落「手动」，地址保留在列表
        assert!(cfg.save_subscription_node_as_manual("10.0.0.1:4433"));
        assert!(cfg.subscriptions[0].nodes.is_empty());
        assert!(cfg.node_addrs.contains(&"10.0.0.1:4433".to_string()));
        assert_eq!(cfg.node_source_label("10.0.0.1:4433"), NODE_SOURCE_MANUAL);

        // 手动节点 / 不存在的地址 → false，无副作用
        assert!(!cfg.save_subscription_node_as_manual("10.0.0.2:4433"));
        assert!(!cfg.save_subscription_node_as_manual("9.9.9.9:1"));

        // 多订阅认领同一地址：只解除先匹配者
        cfg.subscriptions[0].nodes = vec!["10.0.0.3:4433".into()];
        cfg.subscriptions.push(SubscriptionConfig {
            name: "备份订阅".into(),
            source: "file:///x".into(),
            last_updated_secs: None,
            nodes: vec!["10.0.0.3:4433".into()],
        });
        assert!(cfg.save_subscription_node_as_manual("10.0.0.3:4433"));
        assert!(cfg.subscriptions[0].nodes.is_empty());
        assert_eq!(
            cfg.subscriptions[1].nodes,
            vec!["10.0.0.3:4433".to_string()]
        );
    }

    // ===================== Team-UI：节点备注名与地址编辑 =====================

    #[test]
    fn test_node_names_serde_roundtrip_and_default() {
        let mut cfg = GuiConfig::default();
        cfg.set_node_name("10.0.0.1:4433", "  家里节点 ");
        assert_eq!(cfg.node_names.get("10.0.0.1:4433").unwrap(), "家里节点");

        let json = serde_json::to_string(&cfg).unwrap();
        let back: GuiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);

        // 旧版本配置文件（无 node_names 字段）→ 空 map
        let old: GuiConfig = serde_json::from_str(r#"{"auth_key":"ff"}"#).unwrap();
        assert!(old.node_names.is_empty());
    }

    #[test]
    fn test_node_display_name() {
        let mut cfg = GuiConfig::default();
        assert_eq!(cfg.node_display_name("1.2.3.4:1"), "1.2.3.4:1");
        cfg.set_node_name("1.2.3.4:1", "A 节点");
        assert_eq!(cfg.node_display_name("1.2.3.4:1"), "A 节点");
        // 空串备注 = 清除，回落地址
        cfg.set_node_name("1.2.3.4:1", "   ");
        assert!(!cfg.node_names.contains_key("1.2.3.4:1"));
        assert_eq!(cfg.node_display_name("1.2.3.4:1"), "1.2.3.4:1");
    }

    #[test]
    fn test_rename_node_migrates_everywhere() {
        let mut cfg = GuiConfig {
            node_addrs: vec!["10.0.0.1:4433".into(), "10.0.0.2:4433".into()],
            subscriptions: vec![SubscriptionConfig {
                name: "主订阅".into(),
                source: "https://e/s".into(),
                last_updated_secs: None,
                nodes: vec!["10.0.0.1:4433".into()],
            }],
            ..Default::default()
        };
        cfg.set_node_name("10.0.0.1:4433", "旧名");

        cfg.rename_node("10.0.0.1:4433", "10.0.0.9:9999");
        // node_addrs 保序替换
        assert_eq!(
            cfg.node_addrs,
            vec!["10.0.0.9:9999".to_string(), "10.0.0.2:4433".to_string()]
        );
        // 订阅认领同步迁移（来源标记不丢）
        assert_eq!(
            cfg.subscriptions[0].nodes,
            vec!["10.0.0.9:9999".to_string()]
        );
        // 备注名随地址迁移
        assert!(!cfg.node_names.contains_key("10.0.0.1:4433"));
        assert_eq!(cfg.node_names.get("10.0.0.9:9999").unwrap(), "旧名");
        assert_eq!(cfg.node_source_label("10.0.0.9:9999"), "订阅:主订阅");

        // 相同地址幂等
        cfg.rename_node("10.0.0.9:9999", "10.0.0.9:9999");
        assert_eq!(cfg.node_addrs[0], "10.0.0.9:9999");
    }
}
