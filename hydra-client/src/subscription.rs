//! Hydra 订阅格式 v1 解析层（Exec-C）。
//!
//! ## 订阅格式（v1）
//!
//! 一个订阅 = 一段多行文本，每行一个 `hydra://` 分享链接（格式见 [`crate::share_link`]，
//! 含可选 `mode` 参数；**不携带认证密钥/混淆密钥本体**——密钥经 `HYDRA_AUTH_KEY` /
//! `HYDRA_OBFS_KEY` 带外约定，故订阅泄露不直接泄露密钥）。同时兼容：
//!
//! - 每行单独 base64 编码的分享链接；
//! - 整体 base64 编码（把整个多行订阅 base64 后传输，适配仅能传单行文本的渠道）；
//! - `#` 开头的注释行与空行，跳过。
//!
//! 本格式是**自家格式**：不兼容机场的 base64 节点订阅——那些是其他协议
//! （ss/vmess/trojan…）的节点，解析了 Hydra 客户端也无法使用。服务对象是
//! "自建多节点"场景：用户把若干 `hydra://` 分享链接汇成一个文件/URL 分发。
//!
//! ## 订阅来源（拉取见 GUI 侧 `hydra-client-gui/src/subscription.rs`）
//!
//! - 本地文件路径；
//! - http(s) URL（明文 http 允许但 GUI 会日志提示中间人篡改风险）；
//! - `hydra-sub://` 前缀 + 上述来源（如 `hydra-sub://https://example.com/sub`），
//!   仅作来源类型标记，剥除前缀后按剩余部分处理。
//!
//! ## 解析语义
//!
//! 错误的行**跳过不致命**：返回成功列表 + 错误行列表（含行号与原因），
//! 只要有一个链接解析成功订阅即可用。

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::share_link::ShareLink;

/// 订阅解析结果：成功链接 + 错误行（坏行跳过不致命）。
#[derive(Debug, Clone, Default)]
pub struct SubscriptionParse {
    /// 解析成功的分享链接（按出现顺序，重复行不去重——去重由调用方按地址合并）
    pub links: Vec<ShareLink>,
    /// 错误行描述（"第 N 行: 原因"），空 = 全部成功
    pub errors: Vec<String>,
}

impl SubscriptionParse {
    /// 是否至少解析出一个可用节点
    pub fn is_ok(&self) -> bool {
        !self.links.is_empty()
    }
}

/// 解析订阅文本（v1）。
///
/// 流程：
/// 1. 空文本 → 空结果（不算错误）；
/// 2. 文本中不含 `hydra://` 时，尝试**整体 base64 解码**（剔除全部空白字符后），
///    解出且含 `hydra://` 则用解码文本继续，否则按原文逐行处理（各行逐一报错）；
/// 3. 逐行解析：`hydra://` 开头按分享链接解析；否则尝试按单行 base64 解析；
///    注释/空行跳过；无法识别的行记入 [`SubscriptionParse::errors`]。
pub fn parse_subscription(text: &str) -> SubscriptionParse {
    let mut result = SubscriptionParse::default();

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return result;
    }

    // 整体 base64 兼容：原文没有 hydra:// 时先试整体解码
    let working: String = if trimmed.contains("hydra://") {
        trimmed.to_string()
    } else {
        let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        match BASE64
            .decode(compact.as_bytes())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(decoded) if decoded.contains("hydra://") => decoded,
            _ => trimmed.to_string(), // 解不出有效内容：按原文处理，逐行报错
        }
    };

    for (i, line) in working.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parsed = if line.starts_with("hydra://") {
            ShareLink::from_share_url(line)
        } else {
            ShareLink::from_base64(line)
        };

        match parsed {
            Ok(link) => result.links.push(link),
            Err(e) => result.errors.push(format!(
                "第 {} 行: {}（内容: {}）",
                i + 1,
                e,
                truncate(line, 40)
            )),
        }
    }

    result
}

/// 截断过长内容用于错误信息展示（按字符截断，不切坏 UTF-8）
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars).collect();
        format!("{}…", head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_obfs::TransportMode;
    use hydra_protocol::NodeStatus;

    const LINK_A: &str =
        "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online";
    const LINK_B: &str =
        "hydra://192.168.1.100:9000?bandwidth=80&latency=15&loss_rate=0.02&load=0.3&status=online";
    const LINK_OBFS: &str = "hydra://10.0.0.1:443?bandwidth=50&latency=20&loss_rate=0.05&load=0.1&status=degraded&mode=obfs";

    #[test]
    fn test_parse_multiline_plain() {
        let text = format!("# 注释行\n{}\n\n{}\n{}\n", LINK_A, LINK_B, LINK_OBFS);
        let parsed = parse_subscription(&text);
        assert_eq!(parsed.links.len(), 3);
        assert!(parsed.errors.is_empty());
        assert_eq!(parsed.links[0].address, "127.0.0.1");
        assert_eq!(parsed.links[0].port, 8080);
        assert_eq!(parsed.links[1].address, "192.168.1.100");
        assert_eq!(parsed.links[2].mode, TransportMode::Obfs);
    }

    #[test]
    fn test_parse_whole_base64() {
        // 整体 base64：多行订阅编码成一段 base64
        let text = format!("{}\n{}\n", LINK_A, LINK_OBFS);
        let encoded = BASE64.encode(text.as_bytes());
        let parsed = parse_subscription(&encoded);
        assert_eq!(parsed.links.len(), 2);
        assert!(parsed.errors.is_empty());
        assert_eq!(parsed.links[0].address, "127.0.0.1");
        assert_eq!(parsed.links[1].address, "10.0.0.1");
        assert_eq!(parsed.links[1].port, 443);
    }

    #[test]
    fn test_parse_per_line_base64_mixed() {
        // 每行单独 base64 + 明文行混排
        let line_a = BASE64.encode(LINK_A.as_bytes());
        let text = format!("{}\n{}\n", line_a, LINK_B);
        let parsed = parse_subscription(&text);
        assert_eq!(parsed.links.len(), 2);
        assert!(parsed.errors.is_empty());
        assert_eq!(parsed.links[0].address, "127.0.0.1");
        assert_eq!(parsed.links[1].address, "192.168.1.100");
    }

    #[test]
    fn test_bad_lines_skipped_and_reported() {
        // 坏行跳过不致命：好行照常解析，坏行带行号进 errors
        let text = format!("{}\nnot-a-link\nhydra://bad\n{}\n", LINK_A, LINK_B);
        let parsed = parse_subscription(&text);
        assert_eq!(parsed.links.len(), 2);
        assert_eq!(parsed.errors.len(), 2);
        assert!(parsed.errors[0].starts_with("第 2 行"));
        assert!(parsed.errors[1].starts_with("第 3 行"));
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_empty_and_comment_only() {
        // 空文本 / 纯注释 / 纯空白 → 空结果、零错误
        for text in ["", "   \n\t\n", "# 只有注释\n# 第二行注释\n"] {
            let parsed = parse_subscription(text);
            assert!(parsed.links.is_empty(), "text: {:?}", text);
            assert!(parsed.errors.is_empty(), "text: {:?}", text);
            assert!(!parsed.is_ok());
        }
    }

    #[test]
    fn test_invalid_base64_falls_back_to_per_line_errors() {
        // 非 base64、非 hydra:// 的文本：整体解码失败 → 逐行报错，不 panic
        let parsed = parse_subscription("hello world\nsecond line\n");
        assert!(parsed.links.is_empty());
        assert_eq!(parsed.errors.len(), 2);
    }

    #[test]
    fn test_all_error_lines_is_not_ok() {
        let parsed = parse_subscription("garbage\n");
        assert!(!parsed.is_ok());
        assert_eq!(parsed.errors.len(), 1);
    }

    #[test]
    fn test_whole_base64_of_base64_lines_not_confused() {
        // 整体 base64 内容本身是"每行 base64"的多行文本：仍然逐行解出
        let inner = format!("{}\n{}\n", BASE64.encode(LINK_A.as_bytes()), LINK_B);
        let encoded = BASE64.encode(inner.as_bytes());
        let parsed = parse_subscription(&encoded);
        assert_eq!(parsed.links.len(), 2);
        assert!(parsed.errors.is_empty());
    }

    #[test]
    fn test_status_and_params_roundtrip_through_subscription() {
        let text = format!("{}\n", LINK_OBFS);
        let parsed = parse_subscription(&text);
        assert_eq!(parsed.links.len(), 1);
        let link = &parsed.links[0];
        assert!(matches!(link.status, NodeStatus::Degraded));
        assert_eq!(link.bandwidth, 50.0);
        assert_eq!(link.latency, 20.0);
        // 订阅内容不含密钥本体（hydra:// 链接本就不带 key）
        assert!(!text.contains("key="));
    }
}
