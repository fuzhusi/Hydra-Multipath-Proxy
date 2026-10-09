//! 反代静态页回退（抗主动探测增强，Trojan 经典手法）。
//!
//! 背景：节点 443 端口有真 TLS，但「非代理流量」（版本字节错误 / Noise-PSK
//! 握手失败 / 地址帧失步）此前一律**零字节静默关流**。主动探测者的弱指纹：
//! 「443 有真 TLS，但每次连接都被无数据关闭」——真实网站从不会这样。
//!
//! 本模块内置一份自包含静态 HTML（内联 CSS、无外部资源引用、文案不出现
//! 本项目任何字样），认证失败路径改为回复一个正常的 HTTP/1.1 200 页面后
//! 再关闭连接——与标准反向代理「任何非代理流量都得到同一落地页」的行为
//! 一致。
//!
//! # ⚠ 权衡（两种防探测策略各有指纹，无免费午餐）
//!
//! - **静默关流**：不泄露任何应用层数据，但「有 TLS 却永不出字节」本身就是
//!   可被主动探测统计的强信号。
//! - **回退静态页**：对单个探测者「看起来像真网站」，但**每次都返回同一份
//!   固定页面**也可被批量探测统计（字节级一致、无真实站点的路由多样性/
//!   动态内容），且给探测者一个确定性的比对样本。
//!
//! 选择建议：**真证书部署建议开启**（TLS 层已与真实站点难以区分，回退页
//! 补齐应用层相似度，收益大于固定页面指纹的代价）；自签证书 + 无域名的
//! 隐蔽部署可保持默认关闭（静默关流），避免为「伪装网站」引入新一致性
//! 指纹。该权衡同样写入 README 部署指南。
//!
//! 回退响应仍受认证阶段既有保护约束（版本字节/握手读超时
//! `AUTH_TIMEOUT`、TLS 握手超时、连接额度 Semaphore、idle 看门狗注入），
//! 不为探测者提供额外的资源驻留面。

use std::io;
// 基线修复：签名 `W: AsyncWrite + Unpin` 需要 trait 在模块作用域（此前缺失
// 导致 `cargo test --doc` 编译失败；单元测试路径因 cfg(test) 布局侥幸编译）
use tokio::io::AsyncWrite;

/// 内置默认静态页：自包含单文件（内联 CSS，无外部资源引用），伪装成普通
/// 的个人主页/博客落地页。文案中文，不出现本项目任何字样。
pub const FALLBACK_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>山间小筑 · 记录生活与阅读</title>
<style>
:root { --ink:#3a3f45; --paper:#faf8f4; --accent:#7a8b6f; --line:#e6e1d8; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:"Noto Serif SC","Songti SC",Georgia,serif; background:var(--paper);
       color:var(--ink); line-height:1.8; }
header { padding:64px 24px 40px; text-align:center; border-bottom:1px solid var(--line); }
header h1 { font-size:2rem; font-weight:600; letter-spacing:.12em; }
header p { margin-top:10px; color:#8a8578; font-size:.95rem; }
nav { display:flex; justify-content:center; gap:28px; padding:18px 0;
      border-bottom:1px solid var(--line); font-size:.95rem; }
nav a { color:var(--ink); text-decoration:none; }
nav a:hover { color:var(--accent); }
main { max-width:680px; margin:0 auto; padding:48px 24px; }
article { margin-bottom:44px; }
article h2 { font-size:1.25rem; font-weight:600; margin-bottom:6px; }
article time { color:#a49e8f; font-size:.85rem; }
article p { margin-top:10px; }
article a { color:var(--accent); text-decoration:none; }
article a:hover { text-decoration:underline; }
footer { text-align:center; padding:32px 24px 48px; color:#a49e8f;
         font-size:.85rem; border-top:1px solid var(--line); }
</style>
</head>
<body>
<header>
  <h1>山间小筑</h1>
  <p>读书、行走，偶尔写点碎碎念</p>
</header>
<nav>
  <a href="/">首页</a>
  <a href="/archives">归档</a>
  <a href="/about">关于</a>
</nav>
<main>
  <article>
    <h2>雨季读《瓦尔登湖》</h2>
    <time>2026-09-14</time>
    <p>连着下了半个月的雨，正好把搁置许久的书读完。梭罗写湖面的冰裂声，
    像有人在深夜里轻轻敲门。合上书，窗外雨声未停，倒觉得安静了许多。</p>
    <a href="/posts/walden">继续阅读 →</a>
  </article>
  <article>
    <h2>周末去了趟郊外的茶山</h2>
    <time>2026-08-30</time>
    <p>三个小时山路，云雾一直没散。茶农说今年的秋茶要推迟一周。
    回程在山脚吃了碗素面，热汤下肚，什么疲惫都没了。</p>
    <a href="/posts/tea-hill">继续阅读 →</a>
  </article>
  <article>
    <h2>把博客从框架迁回了手写 HTML</h2>
    <time>2026-08-02</time>
    <p>折腾了一圈构建工具，最后发现需要的只是几个静态页面。
    砍掉依赖之后，加载快了，心也静了。</p>
    <a href="/posts/back-to-static">继续阅读 →</a>
  </article>
</main>
<footer>© 2026 山间小筑 · 由一杯热茶驱动</footer>
</body>
</html>
"#;

/// 当前 UTC 时间的 RFC 7231 IMF-fixdate（`Tue, 15 Nov 1994 08:12:31 GMT`）。
/// std 无 httpdate 格式化；手写 civil-from-days（Howard Hinnant 算法）避免引
/// chrono。09-P3-10：真实 HTTP 服务 SHOULD 携带 Date——缺它本身就是可被动
/// 统计的指纹。
fn http_date_now() -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil-from-days：z 为自 1970-03-01 起的天数偏移技巧
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    let weekday = ((days % 7) + 4) % 7; // 1970-01-01 是周四
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday as usize],
        d,
        MONTHS[(mth - 1) as usize],
        y,
        h,
        m,
        s
    )
}

/// 写出完整的 HTTP/1.1 200 静态页响应（状态行 + 头 + body 后正常关闭由
/// 调用方负责）。泛型 `W` 使 TLS 流（含 split 后的写半）均可直接使用。
///
/// 头部固定：`Date`（RFC 7231，09-P3-10 补齐——真实 HTTP 服务 SHOULD 有，缺失
/// 即可被动统计的指纹）、`Content-Type: text/html; charset=utf-8`、
/// `Content-Length`（与 body 字节数严格一致）、`Connection: close`——探测者
/// 无论发什么（哪怕不足以构成 HTTP 请求），都得到同一响应，这是标准反代行为。
pub async fn http_serve_fallback<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Date: {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        http_date_now(),
        FALLBACK_HTML.len(),
        FALLBACK_HTML
    );
    // 写错误（对端已断开等）对节点侧无害：探测连接收尾即可
    w.write_all(response.as_bytes()).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 响应格式：状态行 200、头齐全、Content-Length 与 body 实际字节数一致、
    /// body 完整等于 FALLBACK_HTML。
    #[tokio::test]
    async fn 回退响应格式正确() {
        let mut buf = Vec::new();
        http_serve_fallback(&mut buf).await.unwrap();
        let text = String::from_utf8(buf.clone()).unwrap();

        // 状态行
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n"),
            "状态行必须是 200 OK"
        );

        // 头部齐全且顺序稳定
        assert!(text.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        let len_line = text
            .lines()
            .find(|l| l.starts_with("Content-Length:"))
            .expect("必须有 Content-Length 头");
        let declared: usize = len_line
            .strip_prefix("Content-Length: ")
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // 头与 body 以空行分隔；body 完整且长度与声明一致
        let (head, body) = text.split_once("\r\n\r\n").expect("必须有头/体空行分隔");
        assert_eq!(body, FALLBACK_HTML, "body 必须完整等于内置页面");
        assert_eq!(declared, FALLBACK_HTML.len(), "Content-Length 与 body 一致");
        assert_eq!(declared, body.len());
        // 头部不应含任何 body 内容（空行即终止）
        assert!(!head.contains("<!DOCTYPE"));
        // 页面自包含：无外部资源引用
        assert!(!FALLBACK_HTML.contains("http://"));
        assert!(!FALLBACK_HTML.contains("https://"));
        assert!(!FALLBACK_HTML.contains("src="));
        assert!(!FALLBACK_HTML.contains("href=\"http"));
    }

    /// 任何非代理输入（含不足以构成 HTTP 请求的垃圾字节）都得到同一响应——
    /// 回退逻辑只看开关，不解析请求。
    #[tokio::test]
    async fn 回退不依赖输入内容() {
        for probe in [&b""[..], &b"\x01\x02"[..], &b"GET / HTTP/1.1\r\n"[..]] {
            let mut buf = Vec::new();
            http_serve_fallback(&mut buf).await.unwrap();
            assert!(
                buf.starts_with(b"HTTP/1.1 200 OK\r\n"),
                "输入 {:?} 也应得到整页",
                probe
            );
        }
    }
}
