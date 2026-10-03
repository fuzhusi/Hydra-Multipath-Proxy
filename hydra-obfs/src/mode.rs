//! 传输模式定义与 env 解析（C2 双模式）。

use serde::{Deserialize, Serialize};

/// 传输模式 env 变量：`HYDRA_MODE=masquerade|obfs`（未设置 = masquerade = V2 行为零改动）
pub const HYDRA_MODE_ENV: &str = "HYDRA_MODE";
/// obfs 独立第二密码 env 变量（防一处泄漏全暴露；不参与 QUIC/TLS 认证密钥派生）
pub const HYDRA_OBFS_KEY_ENV: &str = "HYDRA_OBFS_KEY";

/// 传输模式（C2）：两模式互斥不叠加，连接建立前由配置/分享链接确定。
///
/// - [`TransportMode::Masquerade`]（默认）：线缆形态 = 标准 h3 站点，走普通 quinn Endpoint，
///   与既有 V2 行为**完全一致零改动**。
/// - [`TransportMode::Obfs`]（逃生舱）：线缆形态 = 均匀随机字节，走 [`crate::ObfsUdpSocket`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// 伪装模式（默认）：标准 h3 站点形态
    Masquerade,
    /// 混淆模式（逃生舱，显式开启）：均匀随机字节形态
    Obfs,
}

impl TransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportMode::Masquerade => "masquerade",
            TransportMode::Obfs => "obfs",
        }
    }

    /// 解析模式字符串（大小写不敏感）。非法值显式报错——静默回落 masquerade 会让
    /// "以为开了 obfs"的用户得到静默黑洞，宁可启动失败。
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "masquerade" | "" => Ok(TransportMode::Masquerade),
            "obfs" => Ok(TransportMode::Obfs),
            other => Err(format!(
                "非法的传输模式 \"{other}\"（合法值：masquerade | obfs）"
            )),
        }
    }

    /// 从 env 读取模式；未设置 = masquerade；非法值 = Err（调用方启动失败）。
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(HYDRA_MODE_ENV) {
            Ok(v) => Self::parse(&v),
            Err(_) => Ok(TransportMode::Masquerade),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse_accepts_known_values() {
        assert_eq!(
            TransportMode::parse("masquerade"),
            Ok(TransportMode::Masquerade)
        );
        assert_eq!(TransportMode::parse(" obfs "), Ok(TransportMode::Obfs));
        assert_eq!(TransportMode::parse("OBFS"), Ok(TransportMode::Obfs));
        assert_eq!(TransportMode::parse(""), Ok(TransportMode::Masquerade));
    }

    #[test]
    fn mode_parse_rejects_unknown_values() {
        // 非法值必须显式报错，不允许静默回落（静默回落 = 用户以为的 obfs 变成黑洞）
        for bad in ["stealth", "obfs2", "0", "伪装"] {
            assert!(TransportMode::parse(bad).is_err(), "{bad} 应被拒绝");
        }
    }

    #[test]
    fn mode_serde_roundtrip_lowercase() {
        assert_eq!(
            serde_json::to_string(&TransportMode::Masquerade).unwrap(),
            "\"masquerade\""
        );
        assert_eq!(
            serde_json::to_string(&TransportMode::Obfs).unwrap(),
            "\"obfs\""
        );
        let m: TransportMode = serde_json::from_str("\"obfs\"").unwrap();
        assert_eq!(m, TransportMode::Obfs);
    }
}
