//! 节点 toml 配置文件支持（施工方案遗留四大项之④）。
//!
//! 读取顺序（每字段独立回落）：**CLI 参数 > 环境变量 > 配置文件 > 默认值**。
//!
//! - 配置文件定位：`--config <path>`（CLI）> `HYDRA_NODE_CONFIG`（env，路径
//!   显式给出但文件缺失 = 显式报错退出）> 自动探测 `./node.toml` →
//!   `/etc/hydra/node.toml`（都不存在 = 无文件层，纯默认值）。
//! - 认证密钥优先级：`HYDRA_AUTH_KEY`（env）> `HYDRA_AUTH_KEY_FILE`（env）>
//!   配置文件 `auth_key_file` 字段。密钥文件化是为了修掉 env 泄漏面
//!   （shell history / `/proc/<pid>/environ`）；文件权限非 0600 时告警。
//! - 所有字段 `serde(default)`；未知字段 / 非法值显式报错（静默回落会让
//!   "以为开了健康检查"的用户得到黑洞）。
//!
//! 解析逻辑全部纯函数化（`resolve` 接收 `BTreeMap` 而非读真实 env），
//! 便于离线单测优先级与报错；`main.rs` 只做薄 I/O 壳。

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// 配置文件路径的环境变量名
pub const HYDRA_NODE_CONFIG_ENV: &str = "HYDRA_NODE_CONFIG";
/// 认证密钥文件环境变量
pub const HYDRA_AUTH_KEY_FILE_ENV: &str = "HYDRA_AUTH_KEY_FILE";
/// 日志级别环境变量（RUST_LOG 仍优先）
pub const HYDRA_LOG_LEVEL_ENV: &str = "HYDRA_LOG_LEVEL";

/// toml 配置文件结构（全部字段可选，未设置 = 回落 env/默认值）
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeFileConfig {
    pub listen_addr: Option<String>,
    pub auth_key_file: Option<String>,
    pub max_connections: Option<u32>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub cert_domains: Option<Vec<String>>,
    pub health_addr: Option<String>,
    pub log_level: Option<String>,
    /// 反代静态页回退开关（env `HYDRA_FALLBACK_PAGE`；默认 None = 关闭，
    /// 行为零变化；权衡见 fallback.rs 模块文档）
    pub fallback_page: Option<bool>,
}

/// 解析 toml 文本；未知字段 / 类型错误显式报错
pub fn parse_toml(text: &str) -> Result<NodeFileConfig, String> {
    toml::from_str(text).map_err(|e| format!("配置文件解析失败: {}", e))
}

/// CLI 能表达的覆盖项（密钥不进 CLI，避免进 /proc/<pid>/cmdline——审查确认并移除 --auth-key）
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub listen: Option<SocketAddr>,
}

/// 认证密钥来源（解析成 hex 字符串或文件路径，I/O 延后到 `load_auth_key`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthKeySource {
    /// 直接给定的 hex 字符串（CLI / HYDRA_AUTH_KEY）
    Inline(String),
    /// 密钥文件路径（HYDRA_AUTH_KEY_FILE / 配置文件 auth_key_file）
    File(PathBuf),
}

/// 解析完成的最终配置（main 直接据此构造 NodeOptions / 启动服务）
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub listen_addr: SocketAddr,
    pub max_connections: u32,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub cert_domains: Vec<String>,
    pub health_addr: Option<SocketAddr>,
    pub log_level: String,
    pub auth_key_source: AuthKeySource,
    /// 反代静态页回退开关（默认 false = 静默关流语义不变）
    pub fallback_page: bool,
}

/// 自动探测顺序：./node.toml → /etc/hydra/node.toml
pub fn probe_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("./node.toml"),
        PathBuf::from("/etc/hydra/node.toml"),
    ]
}

/// 决定配置文件层来源：显式路径（CLI > env）或自动探测；None = 无文件层
pub fn resolve_config_path(
    cli_config: Option<&Path>,
    env: &BTreeMap<String, String>,
) -> Option<PathBuf> {
    if let Some(p) = cli_config {
        return Some(p.to_path_buf());
    }
    if let Some(v) = env.get(HYDRA_NODE_CONFIG_ENV) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
        return None;
    }
    probe_paths().into_iter().find(|p| p.exists())
}

/// 读取并解析配置文件层（显式指定但读不到 = 显式报错）
pub fn load_file_layer(
    cli_config: Option<&Path>,
    env: &BTreeMap<String, String>,
) -> Result<Option<(PathBuf, NodeFileConfig)>, String> {
    match resolve_config_path(cli_config, env) {
        None => Ok(None),
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("读取配置文件 {} 失败: {}", path.display(), e))?;
            let cfg = parse_toml(&text).map_err(|e| format!("{}: {}", path.display(), e))?;
            Ok(Some((path, cfg)))
        }
    }
}

/// 可选地址字段解析：env > file > None（未配置）；空白值视为未设置该层；
/// 非法值带来源标签显式报错
fn parse_addr_opt(
    env_v: Option<&String>,
    file_v: Option<&String>,
    env_name: &str,
    field_name: &str,
) -> Result<Option<SocketAddr>, String> {
    let parse = |v: &str, what: &str| {
        v.trim().parse::<SocketAddr>().map_err(|e| {
            format!(
                "{} 非法（期望 ip:port 字面量，如 0.0.0.0:443，不做域名解析）: {}",
                what, e
            )
        })
    };
    if let Some(v) = env_v {
        if v.trim().is_empty() {
            return parse_addr_opt(None, file_v, env_name, field_name);
        }
        return parse(v, env_name).map(Some);
    }
    if let Some(v) = file_v {
        if v.trim().is_empty() {
            return Ok(None);
        }
        return parse(v, &format!("配置文件字段 {}", field_name)).map(Some);
    }
    Ok(None)
}

fn parse_u32_field(
    env_v: Option<&String>,
    file_v: Option<u32>,
    env_name: &str,
    default: u32,
) -> Result<u32, String> {
    if let Some(v) = env_v {
        // 空白 env 值 = 未设置（模块约定）：回落文件值/默认，而非解析失败启动退出
        if v.trim().is_empty() {
            return match file_v {
                Some(n) => Ok(n),
                None => Ok(default),
            };
        }
        return v
            .trim()
            .parse::<u32>()
            .map_err(|e| format!("{} 非法（期望正整数，如 1000）: {}", env_name, e));
    }
    match file_v {
        Some(n) => Ok(n),
        None => Ok(default),
    }
}

/// 分层解析全部字段。任一非法值 → Err（main 显式退出，绝不静默回落）。
pub fn resolve(
    cli: &CliOverrides,
    env: &BTreeMap<String, String>,
    file: Option<&NodeFileConfig>,
) -> Result<EffectiveConfig, String> {
    let d = crate::NodeOptions::default();
    let empty_file = NodeFileConfig::default();
    let f = file.unwrap_or(&empty_file);

    // listen：CLI 位置参数 > env > 文件 > 默认 0.0.0.0:8080
    let listen_addr = if let Some(a) = cli.listen {
        a
    } else {
        parse_addr_opt(
            env.get("HYDRA_LISTEN"),
            f.listen_addr.as_ref(),
            "HYDRA_LISTEN",
            "listen_addr",
        )?
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)))
    };

    let max_connections = parse_u32_field(
        env.get("HYDRA_MAX_CONNECTIONS"),
        f.max_connections,
        "HYDRA_MAX_CONNECTIONS",
        d.max_connections,
    )?
    .max(1);

    let cert_file = env
        .get("HYDRA_CERT_FILE")
        .map(|s| s.as_str())
        .or(f.cert_file.as_deref())
        .map_or_else(|| d.cert_file.clone(), PathBuf::from);
    let key_file = env
        .get("HYDRA_KEY_FILE")
        .map(|s| s.as_str())
        .or(f.key_file.as_deref())
        .map_or_else(|| d.key_file.clone(), PathBuf::from);

    // 域名：env 逗号分隔 > 文件数组；空值回落默认（与 from_env 行为一致）
    let domains_from_env = env.get("HYDRA_CERT_DOMAINS").map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let domains_from_file = f.cert_domains.as_ref().map(|v| {
        v.iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let cert_domains = match domains_from_env.or(domains_from_file) {
        Some(v) if !v.is_empty() => v,
        _ => d.cert_domains.clone(),
    };

    let health_addr = parse_addr_opt(
        env.get("HYDRA_HEALTH_ADDR"),
        f.health_addr.as_ref(),
        "HYDRA_HEALTH_ADDR",
        "health_addr",
    )?;

    let log_level = env
        .get(HYDRA_LOG_LEVEL_ENV)
        .map(|s| s.as_str())
        .or(f.log_level.as_deref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "info".to_string());

    // 反代静态页回退：env "1"=开 "0"=关 > 文件 bool 字段 > 默认关（保守升级）
    let fallback_page = match env.get("HYDRA_FALLBACK_PAGE").map(|s| s.trim()) {
        Some("1") => true,
        Some("0") => false,
        Some(v) if !v.is_empty() => {
            return Err(format!("HYDRA_FALLBACK_PAGE 非法（期望 0 或 1）: {v}"));
        }
        // 空白 env 值 = 未设置该层（模块约定）
        _ => f.fallback_page.unwrap_or(d.fallback_page),
    };

    // 认证密钥：HYDRA_AUTH_KEY > HYDRA_AUTH_KEY_FILE > 文件 auth_key_file
    // （CLI 不承接密钥——进 cmdline 全机可读；空白值视为未设置该层，防 systemd EnvironmentFile 空值踩坑）
    let non_blank = |s: &String| !s.trim().is_empty();
    let auth_key_source = if let Some(h) = env.get("HYDRA_AUTH_KEY").filter(|s| non_blank(s)) {
        AuthKeySource::Inline(h.trim().to_string())
    } else if let Some(p) = env.get(HYDRA_AUTH_KEY_FILE_ENV).filter(|s| non_blank(s)) {
        AuthKeySource::File(PathBuf::from(p.trim()))
    } else if let Some(p) = f.auth_key_file.as_ref().filter(|s| non_blank(s)) {
        AuthKeySource::File(PathBuf::from(p.trim()))
    } else {
        return Err(
            "未设置认证密钥。请设置 HYDRA_AUTH_KEY（hex），或 HYDRA_AUTH_KEY_FILE / \
             配置文件 auth_key_file 指向权限 600 的密钥文件。"
                .to_string(),
        );
    };

    Ok(EffectiveConfig {
        listen_addr,
        max_connections,
        cert_file,
        key_file,
        cert_domains,
        health_addr,
        log_level,
        auth_key_source,
        fallback_page,
    })
}

/// 读取认证密钥文件内容（unix 下校验权限非 0600 时告警，不拒绝——运维可用性优先）
fn read_auth_key_file(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("读取认证密钥文件 {} 失败: {}", path.display(), e))?;
    check_key_file_permissions(path);
    Ok(text.trim().to_string())
}

#[cfg(unix)]
fn check_key_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(m) = std::fs::metadata(path) {
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "警告：认证密钥文件 {} 权限为 {:o}，同机其他用户可读；建议 chmod 600",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn check_key_file_permissions(_path: &Path) {}

/// hex 解码 + 长度校验（必须恰好 32 字节：snow NNpsk2 PSK 约束，启动期 fail-fast，
/// 避免"按旧文档配 16..31 字节密钥 → 每条连接握手期静默失败"的排障陷阱——审查 R-05）
pub fn decode_auth_key(hex_str: &str) -> Result<Vec<u8>, String> {
    match hydra_protocol::hex_decode(hex_str) {
        Ok(key) if key.len() == 32 => Ok(key),
        Ok(_) => Err(
            "认证密钥长度非法：解码后必须恰好 32 字节（64 个 hex 字符；生成：openssl rand -hex 32）。"
                .to_string(),
        ),
        Err(e) => Err(format!("认证密钥不是合法的 hex：{}", e)),
    }
}

/// 按来源加载认证密钥（文件来源在此才做 I/O，保持 `resolve` 纯函数）
pub fn load_auth_key(source: &AuthKeySource) -> Result<Vec<u8>, String> {
    let hex_str = match source {
        AuthKeySource::Inline(h) => h.clone(),
        AuthKeySource::File(p) => read_auth_key_file(p)?,
    };
    decode_auth_key(&hex_str)
}

/// 初始化日志：RUST_LOG 优先，否则用配置的 log_level；非法级别显式报错
pub fn init_tracing(level: &str) -> Result<(), String> {
    use tracing_subscriber::EnvFilter;
    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => {
            EnvFilter::try_new(level).map_err(|e| format!("日志级别 {} 非法: {}", level, e))?
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 审查 N-08：空白 env 值 = 未设置，回落文件值/默认而非启动失败
    #[test]
    fn parse_u32_field_空白env回落文件与默认() {
        // 空白 env + 无文件值 → 默认
        assert_eq!(
            parse_u32_field(Some(&"  ".to_string()), None, "HYDRA_MAX_CONNECTIONS", 1000).unwrap(),
            1000
        );
        // 空白 env + 有文件值 → 文件值优先级保持（env 未设置语义）
        assert_eq!(
            parse_u32_field(
                Some(&"\t".to_string()),
                Some(500),
                "HYDRA_MAX_CONNECTIONS",
                1000
            )
            .unwrap(),
            500
        );
        // 非空白合法值照常解析
        assert_eq!(
            parse_u32_field(Some(&" 42 ".to_string()), Some(500), "X", 1000).unwrap(),
            42
        );
        // 非空白非法值仍显式报错（绝不静默吞错）
        assert!(parse_u32_field(Some(&"abc".to_string()), None, "X", 1000).is_err());
        // env 未设置：文件值 > 默认
        assert_eq!(parse_u32_field(None, Some(7), "X", 1000).unwrap(), 7);
        assert_eq!(parse_u32_field(None, None, "X", 1000).unwrap(), 1000);
    }

    /// 反代静态页开关：env > toml 字段 > 默认关；非法值显式报错
    #[test]
    fn fallback_page_分层解析与非法值() {
        fn env_of(v: Option<&str>) -> BTreeMap<String, String> {
            let mut m = BTreeMap::new();
            m.insert(
                "HYDRA_AUTH_KEY".to_string(),
                "a1".to_string(), // 密钥占位（resolve 只查来源，此处只需命中 Inline 分支）
            );
            if let Some(v) = v {
                m.insert("HYDRA_FALLBACK_PAGE".to_string(), v.to_string());
            }
            m
        }
        let cli = CliOverrides::default();
        let file = |fb: Option<bool>| NodeFileConfig {
            fallback_page: fb,
            ..NodeFileConfig::default()
        };

        // 默认关（保守升级）
        assert!(!resolve(&cli, &env_of(None), None).unwrap().fallback_page);
        // env "1" 开 / "0" 关；空白 = 未设置回落默认
        assert!(
            resolve(&cli, &env_of(Some("1")), None)
                .unwrap()
                .fallback_page
        );
        assert!(
            !resolve(&cli, &env_of(Some("0")), None)
                .unwrap()
                .fallback_page
        );
        assert!(
            !resolve(&cli, &env_of(Some("  ")), None)
                .unwrap()
                .fallback_page
        );
        // toml 字段：true 生效；env "0" 覆盖 toml true（env 优先）
        assert!(
            resolve(&cli, &env_of(None), Some(&file(Some(true))))
                .unwrap()
                .fallback_page
        );
        assert!(
            !resolve(&cli, &env_of(Some("0")), Some(&file(Some(true))))
                .unwrap()
                .fallback_page
        );
        // 非法值显式报错（绝不静默回落）
        assert!(resolve(&cli, &env_of(Some("true")), None).is_err());
        assert!(resolve(&cli, &env_of(Some("yes")), None).is_err());
    }
}
