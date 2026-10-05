//! 订阅拉取（Exec-C）——GUI 侧。
//!
//! 解析层在 `hydra-client/src/subscription.rs`（纯解析、无 IO）；本模块只负责
//! **取得订阅原文**：http(s) URL（ureq 阻塞拉取，GUI 在后台线程调用，与既有
//! 节点测试线程模式一致）或本地文件路径（`std::fs`）。支持 `hydra-sub://`
//! 来源前缀（见下）。
//!
//! ## 为什么拉取在 GUI 侧而不是 hydra-client
//!
//! `ureq` 按 Exec-C 约定只加入 GUI 的 Cargo.toml；`hydra-client` 的依赖树
//! 不引入 HTTP 客户端，解析层保持可独立单测。
//!
//! ## `hydra-sub://` 来源标记
//!
//! `hydra-sub://` + 来源（URL 或文件路径），如：
//! - `hydra-sub://https://example.com/hydra-sub.txt`
//! - `hydra-sub:///home/user/sub.txt`、`hydra-sub://D:\subs\sub.txt`
//!
//! 前缀仅是"这是一个订阅来源"的类型标记（v1 不做 scheme 解析），剥除后按
//! 剩余部分处理。直接写 URL / 文件路径同样有效。
//!
//! ## 安全说明
//!
//! - 订阅内容只含 `hydra://` 分享链接，**不含认证密钥/混淆密钥本体**；
//! - 明文 `http://` 允许使用（自建内网场景常见），但返回值带 `plaintext_http`
//!   标记，调用方必须日志提示中间人篡改风险（订阅可被注入任意节点地址）。

use std::time::Duration;

use hydra_client::{parse_subscription, ShareLink};

/// 订阅来源默认拉取超时（任务约定 10s）
pub const SUBSCRIPTION_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// 剥除 `hydra-sub://` 来源前缀并去除首尾空白（无前缀原样返回）
pub fn normalize_subscription_source(input: &str) -> String {
    let s = input.trim();
    // "hydra-sub://x" → "x"；"hydra-sub:///path" → "/path"；"hydra-sub://D:\s" → "D:\s"
    s.strip_prefix("hydra-sub://")
        .unwrap_or(s)
        .trim()
        .to_string()
}

/// 订阅拉取结果：原文 + 是否明文 http（供调用方日志提示）
#[derive(Debug)]
pub struct FetchedSubscription {
    pub text: String,
    /// true = 来源是明文 http://，存在中间人篡改风险（内容可被注入任意节点地址）
    pub plaintext_http: bool,
}

/// 拉取订阅内容（阻塞）。
///
/// - `http(s)://` 开头 → ureq 阻塞 GET，总超时 `timeout`；
/// - 其他 → 按本地文件路径读取；
/// - `hydra-sub://` 前缀先剥除（[`normalize_subscription_source`]）。
///
/// 失败根因以 `Err(String)` 透出（对齐 A5 风格：不静默吞错）。
pub fn fetch_subscription(source: &str, timeout: Duration) -> Result<FetchedSubscription, String> {
    let src = normalize_subscription_source(source);
    if src.is_empty() {
        return Err("订阅来源为空".to_string());
    }

    // 「从分享链接导入」创建的命名分组：source = hydra-text:// + 粘贴原文（内嵌文本，
    // 非外部来源指针）。更新 = 直接把原文交给解析层重解析，与「立即更新」同一入口。
    // 与 hydra-sub://（指向 URL/文件的指针）约定并行，互不影响。
    if let Some(text) = src.strip_prefix("hydra-text://") {
        return Ok(FetchedSubscription {
            text: text.to_string(),
            plaintext_http: false,
        });
    }

    if src.starts_with("http://") || src.starts_with("https://") {
        let plaintext_http = src.starts_with("http://");
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        let resp = agent
            .get(&src)
            .call()
            .map_err(|e| format!("订阅拉取失败 ({}): {}", src, e))?;
        let text = resp
            .into_string()
            .map_err(|e| format!("订阅内容读取失败 ({}): {}", src, e))?;
        Ok(FetchedSubscription {
            text,
            plaintext_http,
        })
    } else {
        let text = std::fs::read_to_string(&src)
            .map_err(|e| format!("读取订阅文件 {} 失败: {}", src, e))?;
        Ok(FetchedSubscription {
            text,
            plaintext_http: false,
        })
    }
}

/// 一次订阅「拉取 + 解析」的完整结果（后台线程 → UI 线程经 mpsc 传递）
pub struct SubscriptionOutcome {
    /// 订阅名称（发起更新时已知，用于结果回投对号）
    pub name: String,
    /// 解析成功的分享链接（坏行已跳过）
    pub links: Vec<ShareLink>,
    /// 错误行描述（不致命，UI 日志展示）
    pub errors: Vec<String>,
    /// 来源为明文 http（UI 须日志提示篡改风险）
    pub plaintext_http: bool,
}

/// 拉取并解析一个订阅（阻塞；调用方用 `std::thread::spawn` 包裹在后台线程执行，
/// 与既有节点测试线程模式一致）。失败根因以 `Err` 透出。
pub fn fetch_and_parse_subscription(
    name: String,
    source: String,
    timeout: Duration,
) -> Result<SubscriptionOutcome, String> {
    let fetched = fetch_subscription(&source, timeout)?;
    let parsed = parse_subscription(&fetched.text);
    Ok(SubscriptionOutcome {
        name,
        links: parsed.links,
        errors: parsed.errors,
        plaintext_http: fetched.plaintext_http,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_and_parse_local_file() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-sub-parse-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sub.txt");
        let body =
            "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&status=online\n坏行\n";
        std::fs::write(&path, body).unwrap();

        let outcome = fetch_and_parse_subscription(
            "测试订阅".to_string(),
            path.to_string_lossy().into_owned(),
            SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .unwrap();
        assert_eq!(outcome.name, "测试订阅");
        assert_eq!(outcome.links.len(), 1);
        assert_eq!(outcome.links[0].address, "127.0.0.1");
        assert_eq!(outcome.errors.len(), 1);
        assert!(!outcome.plaintext_http);

        // 拉取失败（文件不存在）→ Err 根因
        assert!(fetch_and_parse_subscription(
            "x".to_string(),
            dir.join("no-such.sub").to_string_lossy().into_owned(),
            SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_local_text_source_is_parsed_directly() {
        // 分享导入分组（hydra-text:// 前缀 = 内嵌原文）：更新时直接重解析原文，
        // 不走 http/文件路径；多行原文逐行解析，坏行计入 errors
        let pasted = "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&status=online\n坏行\n";
        let outcome = fetch_and_parse_subscription(
            "分享导入1".to_string(),
            format!("hydra-text://{}", pasted),
            SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .unwrap();
        assert_eq!(outcome.name, "分享导入1");
        assert_eq!(outcome.links.len(), 1);
        assert_eq!(outcome.links[0].address, "127.0.0.1");
        assert_eq!(outcome.errors.len(), 1);
        assert!(!outcome.plaintext_http);
    }

    #[test]
    fn test_normalize_strips_prefix_and_whitespace() {
        assert_eq!(
            normalize_subscription_source("  hydra-sub://https://example.com/sub  "),
            "https://example.com/sub"
        );
        // 三斜杠：剥除 "//" 后保留 "/path"
        assert_eq!(
            normalize_subscription_source("hydra-sub:///etc/hydra.sub"),
            "/etc/hydra.sub"
        );
        // Windows 路径
        assert_eq!(
            normalize_subscription_source("hydra-sub://D:\\subs\\a.txt"),
            "D:\\subs\\a.txt"
        );
        // 无前缀原样（去空白）
        assert_eq!(
            normalize_subscription_source(" https://example.com/s "),
            "https://example.com/s"
        );
        assert_eq!(
            normalize_subscription_source("C:\\subs\\a.txt"),
            "C:\\subs\\a.txt"
        );
    }

    #[test]
    fn test_fetch_local_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-sub-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sub.txt");
        let body = "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&status=online\n";
        std::fs::write(&path, body).unwrap();

        // 普通路径与 hydra-sub:// 前缀路径都能读到同一文件
        let fetched =
            fetch_subscription(path.to_str().unwrap(), SUBSCRIPTION_FETCH_TIMEOUT).unwrap();
        assert_eq!(fetched.text, body);
        assert!(!fetched.plaintext_http);

        let fetched = fetch_subscription(
            &format!("hydra-sub://{}", path.display()),
            SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .unwrap();
        assert_eq!(fetched.text, body);

        // 不存在的文件 → Err 带根因
        let missing = dir.join("no-such.sub");
        let err =
            fetch_subscription(missing.to_str().unwrap(), SUBSCRIPTION_FETCH_TIMEOUT).unwrap_err();
        assert!(err.contains("读取订阅文件"), "err: {}", err);

        // 空来源 → Err
        assert!(fetch_subscription("   ", SUBSCRIPTION_FETCH_TIMEOUT).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
