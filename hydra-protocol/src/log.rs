//! 日志脱敏工具：目标地址不出现在明文日志中（客户端与节点共用）。
//!
//! 背景：双视角评估确认"客户端日志明文记录访问的每个 URL/域名"是当前
//! 保密性最大短板——本机日志、远端节点日志、任何收集这些日志的系统都会
//! 成为浏览历史的泄点。此处统一提供脱敏函数。

use ring::digest::{digest, SHA256};

/// 目标地址脱敏：SHA-256 前 8 个 hex 字符（短哈希，可关联同一目标但不泄露明文）+ 保留端口。
///
/// 例：`www.baidu.com:443` → `a1b2c3d4:443`
/// 完整明文仅在 `RUST_LOG=debug` 级别的调试日志中按需出现，info 级别一律脱敏。
pub fn mask_target(target: &str) -> String {
    let h = digest(&SHA256, target.as_bytes());
    let mut hex = String::with_capacity(8);
    for b in &h.as_ref()[..4] {
        hex.push_str(&format!("{:02x}", b));
    }
    match target.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            format!("{}:{}", hex, port)
        }
        _ => hex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_target_with_port() {
        let m = mask_target("www.baidu.com:443");
        assert_eq!(m.len(), 8 + 4);
        assert!(m.ends_with(":443"));
        assert!(!m.contains("baidu"));
        // 同一目标哈希稳定（可关联诊断），不同目标不同
        assert_eq!(m, mask_target("www.baidu.com:443"));
        assert_ne!(m, mask_target("www.google.com:443"));
    }

    #[test]
    fn test_mask_target_no_port() {
        let m = mask_target("example.com");
        assert_eq!(m.len(), 8);
    }
}
