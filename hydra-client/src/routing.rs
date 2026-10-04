//! 国内直连分流（域名后缀版 v1，不做 GeoIP）。
//!
//! ## 定位与默认值
//! 默认 **关闭**（`HYDRA_SPLIT` 未设置 = 全部流量走加密节点）——本项目是隐私优先
//! 的多路径代理，"所有目标域名仅在加密通道内出现"是核心承诺，分流是用户显式
//! 换取国内访问速度的可选项，不应悄悄生效。
//!
//! ## 隐私取舍（开启 `HYDRA_SPLIT=cn` 后必须知晓）
//! 命中 CN 域名表的目标将**不再经过加密通道**，而是客户端本机明文 TCP 直连：
//! - 本地网络/ISP 可明文观察到你访问了这些国内域名（系统 DNS 查询 + TLS SNI）；
//! - 直连路径使用操作系统解析器解析域名（与走节点时"域名永不明文离开本机"相反）；
//! - 作为交换：国内目标延迟显著降低，不占用 VPS 流量。
//!
//! ## 匹配规则
//! - 输入为 SOCKS5 域名（atyp 0x03）与 HTTP Host 的**域名形态**；
//! - **IP 字面量目标一律不参与匹配**——本版无 GeoIP，IPv4/IPv6 目标始终走节点
//!   （如实注释：这是能力边界，不是疏忽）；
//! - 域名后缀匹配要求完整标签边界：`evil-baidu.com` 不会误命中 `baidu.com`；
//! - `localhost` 等本机回显名恒直连（本地开发/测试便利）；
//! - `.cn` 顶级域通配（覆盖 gov.cn / edu.cn 等全部二级）。
//!
//! ## 用户扩展
//! `HYDRA_DIRECT_DOMAIN_FILE` 指向一行一域名的文本文件（`#` 注释、`*.example.com`
//! 通配写法均容忍），与内置表合并；env 仅在首次分流判定时读取一次（非热点路径）。

use std::collections::HashSet;
use std::sync::atomic::{AtomicI8, Ordering};
use std::sync::OnceLock;
use tracing::warn;

/// 内置 CN 域名后缀表（小写、不带前导点；命中 = 目标域等于该条目或以其为完整后缀）。
/// 覆盖国内主流站点主域与常见独立 CDN/账号域（属于其主域的子域由后缀匹配天然覆盖）。
const BUILTIN_CN_SUFFIXES: &[&str] = &[
    // ── 搜索/门户 ──
    "baidu.com",
    "bdstatic.com",
    "bdimg.com",
    "baidubce.com",
    "bcebos.com",
    "baidupcs.com",
    "so.com",
    "360.com",
    "qihoo.com",
    "qhres.com",
    "360safe.com",
    "sohu.com",
    "itc.cn",
    "sogou.com",
    "sina.com",
    "weibo.com",
    "weibocdn.com",
    // ── 社交/IM ──
    "qq.com",
    "tencent.com",
    "gtimg.com",
    "qcloud.com",
    "myqcloud.com",
    "tencentcloudapi.com",
    "weixin.com",
    "wechat.com",
    "zhihu.com",
    "zhimg.com",
    "douban.com",
    "xiaohongshu.com",
    "xhscdn.com",
    "toutiao.com",
    // ── 字节系 ──
    "bytedance.com",
    "douyin.com",
    "douyinpic.com",
    "douyinstatic.com",
    "douyinvod.com",
    "zjcdn.com",
    "ixigua.com",
    "pstatp.com",
    "snssdk.com",
    "feishu.cn", // .cn 通配已覆盖，保留以显式表达
    // ── 电商/支付 ──
    "taobao.com",
    "tmall.com",
    "tbcdn.cn", // 同上，显式保留
    "1688.com",
    "alibaba.com",
    "aliyun.com",
    "aliyuncs.com",
    "alicdn.com",
    "alipay.com",
    "alipayobjects.com",
    "aliyundrive.com",
    "jd.com",
    "360buyimg.com",
    "jdcloud.com",
    "jingxi.com",
    "pinduoduo.com",
    "yangkeduo.com",
    "pddpic.com",
    "vip.com",
    "vipshop.com",
    "dangdang.com",
    "cainiao.com",
    // ── 视频/音频 ──
    "bilibili.com",
    "hdslb.com",
    "bilivideo.com",
    "biliapi.net",
    "biliapi.com",
    "b23.tv",
    "iqiyi.com",
    "iqiyipic.com",
    "qy.net",
    "youku.com",
    "ykimg.com",
    "mgtv.com",
    "kuaishou.com",
    "gifshow.com",
    "yximgs.com",
    "huya.com",
    "douyu.com",
    // ── 生活服务 ──
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "dpfile.com",
    "ele.me",
    "58.com",
    "ganji.com",
    "anjuke.com",
    "lianjia.com",
    "ke.com",
    "ctrip.com",
    "qunar.com",
    "12306.cn", // .cn 通配已覆盖，保留以显式表达
    "zhipin.com",
    // ── 硬件/云厂商 ──
    "xiaomi.com",
    "mi.com",
    "miui.com",
    "xiaomiyoupin.com",
    "huawei.com",
    "huaweicloud.com",
    "vmall.com",
    "hicloud.com",
    "hihonor.com",
    // ── 内容/社区/工具 ──
    "163.com",
    "126.com",
    "netease.com",
    "netease.im",
    "yodao.com",
    "csdn.net",
    "gitee.com",
    "oschina.net",
    "segmentfault.com",
    "juejin.cn", // .cn 通配已覆盖，保留以显式表达
    "xueqiu.com",
    "eastmoney.com",
    "10jqka.com.cn",
    "smzdm.com",
    "xunlei.com",
    "acfun.cn", // .cn 通配已覆盖，保留以显式表达
];

/// 本机回显名：恒直连（便于本地开发/测试，如连本机回显服务）。
const LOOPBACK_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
];

/// 分流开关缓存：-1 = 未初始化（首次读取 env），0 = 关闭，1 = 开启。
/// 每连接一次的判定不是热点路径（热点是逐块转发），但 env 读取也只发生一次。
static SPLIT_STATE: AtomicI8 = AtomicI8::new(-1);

static ALL_SUFFIXES: OnceLock<HashSet<String>> = OnceLock::new();

/// `HYDRA_SPLIT` 解析（纯函数，便于单测）：仅 `cn`（大小写/空白容忍）开启分流；
/// 未设置或其他任何值 = 关闭（隐私优先定位不变）。
fn split_flag_from_env(val: Option<&str>) -> bool {
    matches!(val, Some(v) if v.trim().eq_ignore_ascii_case("cn"))
}

/// 当前是否开启国内直连分流（`HYDRA_SPLIT=cn`）。结果缓存，勿在逐块转发等
/// 热点路径反复调用（本模块对外接口已内部缓存）。
pub fn split_enabled() -> bool {
    match SPLIT_STATE.load(Ordering::Relaxed) {
        0 => false,
        1 => true,
        _ => {
            let enabled = split_flag_from_env(std::env::var("HYDRA_SPLIT").ok().as_deref());
            SPLIT_STATE.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
            enabled
        }
    }
}

/// 仅供测试：进程内强制覆盖分流开关，规避集成测试中进程级 env 的并行竞态。
/// env 解析逻辑由 [`split_flag_from_env`] 单测覆盖。
#[doc(hidden)]
pub fn set_split_enabled_for_test(on: bool) {
    SPLIT_STATE.store(if on { 1 } else { 0 }, Ordering::Relaxed);
}

/// 域名形态目标是否直连（内置 CN 表 ∪ 用户扩展表，含 `.cn` 通配与回环名）。
/// 输入应为**域名**；IP 字面量请走 [`is_direct_target`]（其会直接拒绝）。
pub fn is_direct(domain: &str) -> bool {
    let d = normalize_domain(domain);
    if d.is_empty() {
        return false;
    }
    // 本机回显名恒直连（本地测试便利）
    if LOOPBACK_NAMES.contains(&d.as_str()) || d.ends_with(".localhost") {
        return true;
    }
    // .cn 顶级域通配（含 gov.cn / edu.cn / com.cn 等全部二级）
    if d == "cn" || d.ends_with(".cn") {
        return true;
    }
    suffix_match(all_suffixes(), &d)
}

/// `host:port` 形态目标的分流判定入口（proxy.rs 接线用）。
///
/// 仅域名形态参与匹配；IPv4/IPv6 字面量（含 `[::1]` 括号形态）一律返回 `false`——
/// 本版无 GeoIP，按 IP 分流如实不支持，IP 目标始终走加密节点。
pub fn is_direct_target(target: &str) -> bool {
    if !split_enabled() {
        return false;
    }
    match host_part(target) {
        Some(host) => is_direct(host),
        None => false,
    }
}

/// 从 `host:port` 目标提取主机名；IP 字面量返回 None（不做分流）。
fn host_part(target: &str) -> Option<&str> {
    let host = match target.rsplit_once(':') {
        Some((h, _)) if !h.is_empty() => h,
        _ => target,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host)
    }
}

/// 归一化：去首尾空白、小写、去结尾点、容忍 `*.example.com` 通配写法。
fn normalize_domain(d: &str) -> String {
    let mut s = d.trim().to_ascii_lowercase();
    while s.ends_with('.') {
        s.pop();
    }
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    s
}

/// 完整标签边界的后缀匹配：自右向左逐级检查。
/// `www.baidu.com` → 检查 `www.baidu.com` / `baidu.com` / `com`；
/// `evil-baidu.com` 的各级后缀均不在表中 → 不误命中。
fn suffix_match(table: &HashSet<String>, domain: &str) -> bool {
    let mut rest = domain;
    loop {
        if table.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, tail)) => rest = tail,
            None => return false,
        }
    }
}

/// 合并后的分流后缀表（内置 ∪ 用户扩展），进程内仅构建一次。
fn all_suffixes() -> &'static HashSet<String> {
    ALL_SUFFIXES.get_or_init(|| {
        let mut set: HashSet<String> = BUILTIN_CN_SUFFIXES.iter().map(|s| s.to_string()).collect();
        match std::env::var("HYDRA_DIRECT_DOMAIN_FILE") {
            Ok(path) => match load_domain_file(&path) {
                Ok(extra) => {
                    info_loaded(path, extra.len());
                    set.extend(extra);
                }
                Err(e) => {
                    warn!(
                        "HYDRA_DIRECT_DOMAIN_FILE={} 读取失败（{}），仅使用内置 CN 域名表",
                        path, e
                    );
                }
            },
            Err(_) => {}
        }
        set
    })
}

fn info_loaded(path: String, count: usize) {
    // 单独小函数避免在 get_or_init 闭包里嵌套宏展开过深
    tracing::info!(
        "已加载用户直连域名表 {}（{} 条），与内置 CN 表合并",
        path,
        count
    );
}

/// 读取用户扩展域名文件：一行一域名；`#` 注释与空行忽略。
pub(crate) fn load_domain_file(path: &str) -> std::io::Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(normalize_domain)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 后缀匹配：命中 ──

    #[test]
    fn direct_hits() {
        for d in [
            "baidu.com",
            "www.baidu.com",
            "tieba.baidu.com",
            "a.b.www.qq.com",
            "mail.163.com",
            "bilibili.com",
            "live.bilibili.com",
            "v.qq.com",
            "douyin.com",
            "localhost",
            "LOCALHOST",  // 大小写不敏感
            "baidu.com.", // 结尾点容忍
            "foo.gov.cn", // .cn 通配
            "anything.cn",
            "BaiDu.Com", // 大小写归一
        ] {
            assert!(is_direct(d), "{d} 应命中直连表");
        }
    }

    // ── 后缀匹配：不命中（含误匹配防护）──

    #[test]
    fn direct_misses_and_no_false_positive() {
        for d in [
            "google.com",
            "github.com",
            "cloudflare.com",
            "evil-baidu.com", // 后缀必须完整标签边界，不得子串误命中
            "notbaidu.com",
            "baidu.com.evil.com", // baidu.com 不是它的完整后缀
            "xuyao-baidu.com",
            "qq.com.evil.org",
            "com",      // 裸 TLD 不命中
            "",         // 空
            "   ",      // 空白
            "intranet", // 无点单标签（非回环名）不命中
        ] {
            assert!(!is_direct(d), "{d} 不应命中直连表");
        }
    }

    // ── 开关状态 + IP 字面量不参与分流（无 GeoIP）──
    // 注意：分流开关是进程级全局状态，所有依赖其取值的断言必须合并在单个测试内，
    // 避免并行单测互相干扰。

    #[test]
    fn split_state_and_ip_literals() {
        // 未开分流时一律 false
        set_split_enabled_for_test(false);
        assert!(!split_enabled());
        assert!(!is_direct_target("baidu.com:443"));
        assert!(!is_direct_target("localhost:9999"));
        // IP 字面量即使开了分流也不直连（本版无 GeoIP）
        set_split_enabled_for_test(true);
        assert!(split_enabled());
        for t in [
            "127.0.0.1:8080", // 既有测试用 "127.0.0.1" 域名形态——必须保持走节点
            "8.8.8.8:53",
            "[::1]:443",
            "[2001:db8::1]:80",
        ] {
            assert!(!is_direct_target(t), "{t} 为 IP 字面量，不应直连");
        }
        // 域名形态在开启后命中
        assert!(is_direct_target("www.taobao.com:443"));
        assert!(is_direct_target("localhost:9999"));
        set_split_enabled_for_test(false);
    }

    // ── env 解析 ──

    #[test]
    fn split_flag_parsing() {
        assert!(!split_flag_from_env(None), "未设置 = 关闭（隐私优先）");
        assert!(!split_flag_from_env(Some("")));
        assert!(!split_flag_from_env(Some("off")));
        assert!(!split_flag_from_env(Some("direct")));
        assert!(split_flag_from_env(Some("cn")));
        assert!(split_flag_from_env(Some("CN")));
        assert!(split_flag_from_env(Some("cn ")));
        assert!(split_flag_from_env(Some(" cn ")));
    }

    // ── 用户扩展文件 ──

    #[test]
    fn load_domain_file_parses() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "hydra-routing-test-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(
            &path,
            "# 注释行\nmy-company.example.com\n\n*.corp.example.cn\nUPPER.Example.COM.\n",
        )
        .unwrap();
        let set = load_domain_file(path.to_str().unwrap()).unwrap();
        assert!(set.contains("my-company.example.com"));
        assert!(set.contains("corp.example.cn"), "*. 前缀应被剥去");
        assert!(set.contains("upper.example.com"));
        assert_eq!(set.len(), 3, "注释与空行应被忽略");
        let _ = std::fs::remove_file(&path);
    }
}
