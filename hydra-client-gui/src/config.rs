//! GUI 配置持久化（Exec-1）。
//!
//! 配置文件位置：
//! - Windows：`%APPDATA%\hydra\config.json`
//! - Linux/macOS：`~/.config/hydra/config.json`（`XDG_CONFIG_HOME` 优先）
//!
//! **权限提醒**：配置文件含认证密钥（hex）与 obfs 密码明文。
//! - Windows：`%APPDATA%` 位于用户 profile 目录（`%USERPROFILE%\AppData\Roaming`），
//!   默认 ACL 仅本机当前用户、Administrators 与 SYSTEM 可读，无需额外处理；
//! - Linux/macOS：本模块保存时以 `0600` 权限创建/写入文件；
//!   但 `~/.config` 父目录若由用户手工改宽过权限，请自行收紧。
//! （README 面向用户的说明由项目总控统一补充。）
//!
//! **优先级规则：配置文件 > 环境变量**。环境变量（`HYDRA_AUTH_KEY` 等）保留向后兼容：
//! 仅当配置文件对应字段为空/缺失时，解析函数才回落读取环境变量——
//! 用户在 GUI 填一次密钥+证书路径后，双击 exe 即可直接使用。
//!
//! 实现说明：`HYDRA_MODE`/`HYDRA_OBFS_KEY`/`HYDRA_PROBE_INTERVAL_SECS` 由
//! hydra-client 内部经 `*_from_env()` 读取（该 crate 归 WS-A/WS-B 所有，GUI 不越权改动），
//! 故本模块以「配置非空 → 覆盖写进程 env」实现同样的优先级，见 [`apply_env_overrides`]。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 配置目录名（各平台一致）
pub const APP_DIR_NAME: &str = "hydra";
/// 配置文件名
pub const CONFIG_FILE_NAME: &str = "config.json";

/// 与 hydra-obfs/src/mode.rs、hydra-client/src/speedtest.rs 中的 env 名保持一致
/// （GUI 不直接依赖 hydra-obfs，此处为字面量同步，改名需两处同改）
pub const HYDRA_MODE_ENV: &str = "HYDRA_MODE";
pub const HYDRA_OBFS_KEY_ENV: &str = "HYDRA_OBFS_KEY";
pub const HYDRA_PROBE_INTERVAL_ENV: &str = "HYDRA_PROBE_INTERVAL_SECS";

/// GUI 持久化配置。所有字段带 `serde(default)`：缺字段 / 旧版本文件 → 各字段默认值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// 传输模式：""（默认，等价 masquerade）| "masquerade" | "obfs"（对应 HYDRA_MODE）
    #[serde(default)]
    pub hydra_mode: String,
    /// obfs 模式独立第二混淆密码（对应 HYDRA_OBFS_KEY；masquerade 模式忽略）
    #[serde(default)]
    pub obfs_key: String,
    /// Offline 恢复探测间隔（秒，对应 HYDRA_PROBE_INTERVAL_SECS）；None = 用库默认（30）
    #[serde(default)]
    pub probe_interval_secs: Option<u64>,
}

impl GuiConfig {
    /// 模式是否为 obfs（"" 与 "masquerade" 均视为伪装模式）
    pub fn is_obfs(&self) -> bool {
        self.hydra_mode.trim().eq_ignore_ascii_case("obfs")
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

    #[cfg(unix)]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // 密钥明文：仅文件属主可读写
            .open(path)
            .map_err(|e| format!("打开配置文件 {} 失败: {}", path.display(), e))?;
        f.write_all(json.as_bytes())
            .and_then(|_| f.flush())
            .map_err(|e| format!("写入配置文件 {} 失败: {}", path.display(), e))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, json)
            .map_err(|e| format!("写入配置文件 {} 失败: {}", path.display(), e))
    }
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

/// 节点证书解析（配置文件 > 环境变量）：
/// 配置 `cert_path` 非空 → 直接读该文件；否则回落 `HYDRA_NODE_CERT` 环境变量。
pub fn resolve_node_certs(cfg: &GuiConfig) -> Result<Vec<Vec<u8>>, String> {
    let path = cfg.cert_path.trim();
    if !path.is_empty() {
        return std::fs::read(path)
            .map(|der| vec![der])
            .map_err(|e| format!("读取节点证书 {} 失败: {}", path, e));
    }
    hydra_client::node_certs_from_env()
}

/// 将配置中的模式 / obfs 密码 / 探测间隔覆盖写入进程环境变量（仅当配置值非空时覆盖，
/// 留空则保持 env 原值 = 向后兼容回落）。必须在任何工作线程 spawn 之前调用，
/// 避免与其他线程的 env 读取并发竞争。
pub fn apply_env_overrides(cfg: &GuiConfig) {
    let mode = cfg.hydra_mode.trim();
    if !mode.is_empty() {
        std::env::set_var(HYDRA_MODE_ENV, mode);
    }
    let obfs_key = cfg.obfs_key.trim();
    if !obfs_key.is_empty() {
        std::env::set_var(HYDRA_OBFS_KEY_ENV, obfs_key);
    }
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
            hydra_mode: "obfs".into(),
            obfs_key: "second-password".into(),
            probe_interval_secs: Some(15),
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

        // 未知字段忽略
        let cfg: GuiConfig =
            serde_json::from_str(r#"{"unknown_field": 1, "hydra_mode": "obfs"}"#).unwrap();
        assert_eq!(cfg.hydra_mode, "obfs");
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
            hydra_mode: "masquerade".into(),
            obfs_key: String::new(),
            probe_interval_secs: Some(30),
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
        let cfg = GuiConfig {
            auth_key: "00112233445566778899aabbccddeeff".into(),
            ..Default::default()
        };
        let key = resolve_auth_key(&cfg).expect("配置内合法 hex 应解析成功");
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 0x00);

        // 配置内非法 hex → Err（根因透出，不回落 env）
        let bad = GuiConfig {
            auth_key: "zz-not-hex".into(),
            ..Default::default()
        };
        assert!(resolve_auth_key(&bad).is_err());

        // 配置内 hex 太短 → Err
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
    fn test_is_obfs() {
        assert!(!GuiConfig::default().is_obfs());
        assert!(GuiConfig {
            hydra_mode: "obfs".into(),
            ..Default::default()
        }
        .is_obfs());
        assert!(!GuiConfig {
            hydra_mode: "masquerade".into(),
            ..Default::default()
        }
        .is_obfs());
        assert!(!GuiConfig {
            hydra_mode: String::new(),
            ..Default::default()
        }
        .is_obfs());
    }
}
