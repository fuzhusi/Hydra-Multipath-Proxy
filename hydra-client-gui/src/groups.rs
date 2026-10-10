//! 命名分组纯逻辑：分享链接导入建组、手动表单建组、订阅节点合并替换、
//! 来源标记分类。UI 与单测共用，见 Cargo 同目录 subscription.rs（拉取层）。

use crate::config::{GuiConfig, SubscriptionConfig};
use hydra_client::{parse_subscription, ShareLink, TransportChoice, TransportMode};
use hydra_protocol::{NodeInfo, NodeStatus};
use std::collections::HashSet;
use std::net::SocketAddr;

// ── 「从分享链接导入」→ 创建命名分组（复刻 Clash Profile 语义）──

/// 本地文本来源前缀：分享导入创建的分组把**粘贴的原始文本**（可多行）存进
/// `SubscriptionConfig::source`，对该分组点「立即更新」= 重新解析这段文本并按
/// 认领合并（见 `subscription::fetch_subscription` 的 `hydra-text://` 分支）。
/// 与 `hydra-sub://`（来源指针）约定并行不冲突：一个指向外部来源，一个内嵌原文。
pub(crate) const LOCAL_TEXT_SOURCE_PREFIX: &str = "hydra-text://";

/// 分享导入分组的默认名称（分享导入1、分享导入2…按现有订阅名递增避重）
pub(crate) fn next_import_group_name(subs: &[SubscriptionConfig]) -> String {
    let mut n = 1;
    loop {
        let candidate = format!("分享导入{}", n);
        if !subs.iter().any(|s| s.name == candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// 手动添加分组的默认名称（手动节点1、手动节点2…按现有订阅名递增避重）
pub(crate) fn next_manual_group_name(subs: &[SubscriptionConfig]) -> String {
    let mut n = 1;
    loop {
        let candidate = format!("手动节点{}", n);
        if !subs.iter().any(|s| s.name == candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// 订阅节点「合并替换」纯逻辑（UI 无关；`apply_subscription_update` 与分享导入共用）：
/// - 手动节点与其它订阅的节点全部保留；
/// - 本订阅旧节点被新列表替换（仅移除"仅本订阅认领"的地址，返回给调用方清状态）；
/// - 与手动/其它订阅冲突的地址不重复添加，归属保持原状（单一事实来源 =
///   各订阅 nodes 列表，见 [`GuiConfig::node_source_label`]）。
///
/// 返回 (新增地址, 被移除地址)；本订阅 nodes 认领列表与 last_updated 在此一并落库。
pub(crate) fn apply_subscription_node_update(
    cfg: &mut GuiConfig,
    name: &str,
    links: &[ShareLink],
) -> (Vec<String>, Vec<String>) {
    let Some(idx) = cfg.subscriptions.iter().position(|s| s.name == name) else {
        return (Vec::new(), Vec::new());
    };

    // 新地址列表（去重保序）
    let mut new_addrs: Vec<String> = Vec::new();
    for link in links {
        let addr = format!("{}:{}", link.address, link.port);
        if !new_addrs.contains(&addr) {
            new_addrs.push(addr);
        }
    }

    let old_sub_nodes = cfg.subscriptions[idx].nodes.clone();
    let owned_before: HashSet<String> = cfg.subscription_owned_addrs().into_iter().collect();
    let manual_set: HashSet<String> = cfg
        .node_addrs
        .iter()
        .filter(|a| !owned_before.contains(*a))
        .cloned()
        .collect();
    let others_set: HashSet<String> = cfg
        .subscriptions
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != idx)
        .flat_map(|(_, s)| s.nodes.iter().cloned())
        .collect();
    let new_set: HashSet<String> = new_addrs.iter().cloned().collect();

    // 1) 移除：仅本订阅认领、且新列表不再包含的旧节点
    let to_remove: Vec<String> = old_sub_nodes
        .iter()
        .filter(|a| !new_set.contains(*a) && !manual_set.contains(*a) && !others_set.contains(*a))
        .cloned()
        .collect();
    cfg.node_addrs.retain(|a| !to_remove.contains(a));
    for a in &to_remove {
        // 审查修复：订阅更新移除旧节点时清残留状态（remove_node_state 收口）
        cfg.remove_node_state(a);
    }

    // 2) 追加：新地址中尚未在列表、且不被其他订阅认领的
    let mut added = Vec::new();
    for a in &new_addrs {
        if cfg.node_addrs.contains(a) || others_set.contains(a) {
            continue;
        }
        cfg.node_addrs.push(a.clone());
        added.push(a.clone());
    }

    // 3) 本订阅新认领列表：最终在列表中、非手动、非其他订阅的地址
    let claimed: Vec<String> = new_addrs
        .iter()
        .filter(|a| {
            cfg.node_addrs.contains(*a) && !manual_set.contains(*a) && !others_set.contains(*a)
        })
        .cloned()
        .collect();
    cfg.subscriptions[idx].nodes = claimed;
    cfg.subscriptions[idx].last_updated_secs = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    (added, to_remove)
}

/// 一次「创建分组导入」的结果（节点状态同步所需的最小信息）
#[derive(Debug)]
pub(crate) struct GroupImportResult {
    /// 新加入节点列表的地址（调用方补 node_status 初始记录）
    pub(crate) added: Vec<String>,
    /// 被移出节点列表的地址（调用方清理 node_status；config 内部状态已由纯函数清理）
    pub(crate) removed: Vec<String>,
    /// 最终归属该分组的节点数
    pub(crate) node_count: usize,
    /// 解析失败的坏行数（不致命，日志展示）
    pub(crate) bad_lines: usize,
}

/// 从粘贴文本创建**命名分组**（纯逻辑，UI 与单测共用）：
/// 1. 名称必填且不得与现有订阅重名（与 add_subscription 同规则）；
/// 2. 用 `parse_subscription` 逐行解析（坏行跳过并计数；整体 base64 兼容）；
/// 3. 全部链接解析失败 → 报错，不创建分组；
/// 4. 创建 `SubscriptionConfig`，source 存 `hydra-text://` + 粘贴原文（更新语义）；
/// 5. 节点按认领合并进该分组；合并后分组认领 0 个节点 → 撤销创建并报错。
pub(crate) fn import_share_links_as_group(
    cfg: &mut GuiConfig,
    name: &str,
    text: &str,
) -> Result<GroupImportResult, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("请先填写分组名称".to_string());
    }
    if cfg.subscriptions.iter().any(|s| s.name == name) {
        return Err(format!("分组名称「{}」已存在，请换一个名称", name));
    }
    let text = text.trim();
    if text.is_empty() {
        return Err("请先粘贴 hydra:// 分享链接".to_string());
    }
    // 逐行解析（坏行跳过不致命；整体 base64 订阅文本也兼容）
    let parsed = parse_subscription(text);
    if parsed.links.is_empty() {
        let detail = if parsed.errors.is_empty() {
            "未在文本中找到 hydra:// 分享链接".to_string()
        } else {
            format!(
                "全部链接解析失败（{} 条坏行），未创建分组",
                parsed.errors.len()
            )
        };
        return Err(detail);
    }

    // 先建分组条目（source = 粘贴原文 + hydra-text:// 前缀，供「立即更新」重解析）
    cfg.subscriptions.push(SubscriptionConfig {
        name: name.to_string(),
        source: format!("{}{}", LOCAL_TEXT_SOURCE_PREFIX, text),
        last_updated_secs: None,
        nodes: Vec::new(),
    });

    // 按认领合并节点（复用订阅更新的同一套纯逻辑）
    let (added, removed) = apply_subscription_node_update(cfg, name, &parsed.links);

    // 空分组清理：合并后该分组未认领任何节点（如地址全被手动/其他订阅认领）→ 撤销
    let node_count = cfg
        .subscriptions
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.nodes.len())
        .unwrap_or(0);
    if node_count == 0 {
        cfg.subscriptions.retain(|s| s.name != name);
        return Err(format!(
            "分组「{}」未认领到任何节点（地址可能已被手动/其他订阅持有），未创建",
            name
        ));
    }

    Ok(GroupImportResult {
        added,
        removed,
        node_count,
        bad_lines: parsed.errors.len(),
    })
}

/// 「从分享链接导入」表单字段 → 构造 `hydra://` 分享链接文本（纯逻辑，UI 与单测共用）。
/// 全部校验通过才返回链接文本；任何失败返回给用户的错误消息（调用方红字提示、不关窗）：
/// - 地址：非空；IP 或域名均可（`SocketAddr` 解析失败按域名处理，链接 host 直接存域名）；
/// - 端口：1..=65535 的数字；
/// - 密钥：留空 = 不带密钥字段（导入端回落全局密钥）；填了按 hex 校验（32 字节）；
/// - 证书：留空 = 不带证书（cc= 字段缺席，对方需自备）；填了必须存在且可读。
pub(crate) fn build_form_share_url(
    address: &str,
    port: &str,
    auth_key_hex: &str,
    cert_path: &str,
) -> Result<String, String> {
    let address = address.trim();
    if address.is_empty() {
        return Err("服务器地址不能为空".to_string());
    }
    let port_text = port.trim();
    let port: u16 = port_text
        .parse()
        .map_err(|_| format!("端口非法：「{}」（需要 1..=65535 的数字）", port_text))?;
    if port == 0 {
        return Err(format!(
            "端口非法：「{}」（需要 1..=65535 的数字）",
            port_text
        ));
    }

    // 认证密钥：填了则覆盖全局（与 build_share_link 的 with_auth_key_bytes 一致）
    let key_bytes = if auth_key_hex.trim().is_empty() {
        None
    } else {
        Some(
            hydra_client::auth_key_from_hex(auth_key_hex.trim())
                .map_err(|e| format!("认证密钥非法: {}", e))?,
        )
    };

    // 证书文件：填了则必须可读（DER 本体进链接 cc= 字段）
    let cert_der = if cert_path.trim().is_empty() {
        None
    } else {
        Some(std::fs::read(cert_path.trim()).map_err(|e| {
            format!(
                "读取证书 {} 失败: {}（留空 = 不带证书，对方需自备）",
                cert_path.trim(),
                e
            )
        })?)
    };

    // NodeInfo 需要 SocketAddr：IP:port 直接解析；域名时用 0.0.0.0 占位，
    // 再把 ShareLink.address 覆盖为域名字符串（链接本就支持域名 host）
    let (node_addr, link_address) = match format!("{}:{}", address, port).parse::<SocketAddr>() {
        Ok(a) => (a, address.to_string()),
        Err(_) => (
            format!("0.0.0.0:{}", port)
                .parse()
                .expect("0.0.0.0:port 必然可解析"),
            address.to_string(),
        ),
    };
    let node_info = NodeInfo {
        address: node_addr,
        bandwidth: 100.0,
        latency: 10.0,
        loss_rate: 0.01,
        load: 0.5,
        status: NodeStatus::Online,
    };
    let mut link = ShareLink::new_with_mode(&node_info, TransportMode::Masquerade)
        .with_transport(TransportChoice::Tcp);
    link.address = link_address;
    if let Some(key) = &key_bytes {
        // 09-P3-6：非法长度显式报错（builder 不再 panic）
        link = link.with_auth_key_bytes(key).map_err(|e| e.to_string())?;
    }
    if let Some(der) = &cert_der {
        link = link.with_cert_der(der);
    }
    Ok(link.to_share_url())
}

/// 订阅列表「来源」列的展示标签（纯逻辑，UI 与单测共用）。
/// 不再外显原始 `hydra-text://…` 长链接：
/// - `hydra-text://` 前缀 →「本地导入」（分享表单构造的链接，原文内嵌不外显）；
/// - `hydra-sub://` 前缀 → 剥除后按剩余部分判定（仅作来源类型标记）；
/// - http/https →「订阅 · 域名」（只显示域名，不泄露完整路径）；
/// - 其余按本地文件路径处理 →「文件 · 文件名」。
pub(crate) fn subscription_source_label(source: &str) -> String {
    let source = source.trim();
    if source.starts_with(LOCAL_TEXT_SOURCE_PREFIX) {
        return "本地导入".to_string();
    }
    let inner = source.strip_prefix("hydra-sub://").unwrap_or(source);
    if let Some(rest) = inner
        .strip_prefix("https://")
        .or_else(|| inner.strip_prefix("http://"))
    {
        // 手工取 host：截到第一个 '/'（不引 url crate，GUI 侧零新依赖）
        let host = rest.split(['/']).next().unwrap_or("");
        if host.is_empty() {
            return "订阅".to_string();
        }
        return format!("订阅 · {}", host);
    }
    // 路径分隔符归一：Windows 风格路径（C:\a\b.txt）在 Linux 上 '\' 不是分隔符，
    // 直接 Path 解析取不到文件名——先统一 '\' → '/' 再取（跨平台显示一致）
    let normalized = inner.replace('\\', "/");
    match std::path::Path::new(&normalized).file_name() {
        Some(name) => format!("文件 · {}", name.to_string_lossy()),
        None => "文件".to_string(),
    }
}

/// 返回订阅独占节点数（级联删除确认文案用）：删该订阅会连带移除的节点数。
/// 纯函数：只读配置、不修改状态（SB-01 确认对话框数据源）。
#[allow(clippy::too_many_lines)]
pub(crate) fn exclusive_node_count(cfg: &GuiConfig, sub_name: &str) -> usize {
    let Some(sub) = cfg.subscriptions.iter().find(|s| s.name == sub_name) else {
        return 0;
    };
    let others_owned: std::collections::HashSet<String> = cfg
        .subscriptions
        .iter()
        .filter(|s| s.name != sub_name)
        .flat_map(|s| s.nodes.iter().cloned())
        .collect();
    sub.nodes
        .iter()
        .filter(|a| !others_owned.contains(*a))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::tests::group_fixture;
    use crate::nodes::{filter_nodes_by_group, GROUP_MANUAL};
    use crate::subscription;

    // ── 「从分享链接导入」→ 创建命名分组 ──

    /// 构造一条合法的 v1 分享链接（与 subscription 层测试同一格式）
    fn share_link_line(addr: &str, port: u16) -> String {
        format!(
            "hydra://{}:{}?bandwidth=100&latency=10&loss_rate=0.01&status=online",
            addr, port
        )
    }

    #[test]
    fn next_import_group_name_skips_existing_subscription_names() {
        // 空列表 → 分享导入1
        assert_eq!(next_import_group_name(&[]), "分享导入1");
        // 已有 分享导入1 → 分享导入2；连号占用逐个后移
        let mut subs = vec![SubscriptionConfig {
            name: "分享导入1".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        }];
        assert_eq!(next_import_group_name(&subs), "分享导入2");
        subs.push(SubscriptionConfig {
            name: "分享导入2".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        assert_eq!(next_import_group_name(&subs), "分享导入3");
        // 与普通订阅名不冲突（只对「分享导入N」序列避重）
        subs.push(SubscriptionConfig {
            name: "分享导入3".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        assert_eq!(next_import_group_name(&subs), "分享导入4");
    }

    #[test]
    fn import_as_group_creates_named_group_and_filters() {
        let mut cfg = GuiConfig::default();
        let text = format!(
            "{}\n坏行\n{}\n",
            share_link_line("10.1.0.1", 1001),
            share_link_line("10.1.0.2", 1002)
        );
        let result = import_share_links_as_group(&mut cfg, "分享导入1", &text).unwrap();
        // 分组条目出现在订阅列表；source 存粘贴原文（hydra-text:// 前缀，更新语义）
        assert_eq!(cfg.subscriptions.len(), 1);
        assert_eq!(cfg.subscriptions[0].name, "分享导入1");
        assert!(cfg.subscriptions[0]
            .source
            .starts_with(LOCAL_TEXT_SOURCE_PREFIX));
        assert!(cfg.subscriptions[0]
            .source
            .contains(&share_link_line("10.1.0.1", 1001)));
        // 2 个节点认领进该分组，1 条坏行
        assert_eq!(result.node_count, 2);
        assert_eq!(result.bad_lines, 1);
        assert_eq!(cfg.subscriptions[0].nodes.len(), 2);
        assert_eq!(result.added.len(), 2);
        // 节点已进入节点列表，且组视图可按该分组过滤
        assert_eq!(cfg.node_addrs.len(), 2);
        let filtered = filter_nodes_by_group(
            &cfg,
            &cfg.node_addrs.clone(),
            &Some("分享导入1".to_string()),
        );
        assert_eq!(filtered.len(), 2);
        // 「手动」组为空（节点全归分组）
        assert!(filter_nodes_by_group(
            &cfg,
            &cfg.node_addrs.clone(),
            &Some(GROUP_MANUAL.to_string())
        )
        .is_empty());
    }

    #[test]
    fn import_as_group_rejects_duplicate_and_invalid() {
        let mut cfg = GuiConfig::default();
        cfg.subscriptions.push(SubscriptionConfig {
            name: "已有分组".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        // 名称重复 → 报错，不新建
        let err =
            import_share_links_as_group(&mut cfg, "已有分组", &share_link_line("10.2.0.1", 2001))
                .unwrap_err();
        assert!(err.contains("已存在"), "err: {}", err);
        assert_eq!(cfg.subscriptions.len(), 1);
        // 空名称 → 报错
        assert!(import_share_links_as_group(&mut cfg, "  ", "x").is_err());
        // 全部链接解析失败 → 报错，不创建分组
        let err =
            import_share_links_as_group(&mut cfg, "新分组", "不是链接\n也不是链接").unwrap_err();
        assert!(err.contains("未创建分组"), "err: {}", err);
        assert!(cfg.subscriptions.len() == 1 && cfg.node_addrs.is_empty());
        // 空文本 → 报错
        assert!(import_share_links_as_group(&mut cfg, "新分组", "   ").is_err());
    }

    #[test]
    fn import_as_group_rolls_back_when_no_node_claimed() {
        // 目标地址已被其他订阅认领 → 新分组认领 0 节点 → 撤销创建（空分组清理）
        let mut cfg = group_fixture();
        let owned = "10.0.0.2:2"; // 已被「订阅A」认领
        let err =
            import_share_links_as_group(&mut cfg, "分享导入X", &share_link_line("10.0.0.2", 2))
                .unwrap_err();
        assert!(err.contains("未认领到任何节点"), "err: {}", err);
        // 未留下空分组，节点列表无变化
        assert!(!cfg.subscriptions.iter().any(|s| s.name == "分享导入X"));
        assert_eq!(cfg.node_addrs.len(), 4);
        let _ = owned;
    }

    #[test]
    fn local_text_source_reparse_produces_same_links() {
        // 「更新」语义：source（hydra-text:// + 原文）重解析 = 原导入同样的节点集合
        let text = format!(
            "{}\n{}\n",
            share_link_line("10.3.0.1", 3001),
            share_link_line("10.3.0.2", 3002)
        );
        let mut cfg = GuiConfig::default();
        import_share_links_as_group(&mut cfg, "分享导入1", &text).unwrap();
        let source = cfg.subscriptions[0].source.clone();
        let reparsed = subscription::fetch_and_parse_subscription(
            "分享导入1".to_string(),
            source,
            subscription::SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .unwrap();
        let mut addrs: Vec<String> = reparsed
            .links
            .iter()
            .map(|l| format!("{}:{}", l.address, l.port))
            .collect();
        addrs.sort();
        assert_eq!(
            addrs,
            vec!["10.3.0.1:3001".to_string(), "10.3.0.2:3002".to_string()]
        );
    }

    // ── 表单化导入 v2：build_form_share_url / subscription_source_label ──

    #[test]
    fn form_share_url_builds_parseable_link_from_addr_and_port() {
        // 地址 + 端口 → 构造成功，且能被分享链接解析层还原（零新后端验证）
        let url = build_form_share_url("43.133.91.218", "443", "", "").unwrap();
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.address, "43.133.91.218");
        assert_eq!(parsed.port, 443);
        // 默认 TCP 传输 + Masquerade 模式；不带密钥/证书
        assert!(parsed.transport_is_tcp());
        assert_eq!(parsed.mode, TransportMode::Masquerade);
        assert!(parsed.auth_key.is_none());
        assert!(parsed.cert_der.is_none());
    }

    #[test]
    fn form_share_url_accepts_domain_address() {
        // 域名地址：SocketAddr 解析不行 → 域名:port 形式照常进链接
        let url = build_form_share_url("  node.example.com ", "8443", "", "").unwrap();
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.address, "node.example.com");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn form_share_url_rejects_invalid_port_and_empty_address() {
        // 端口非法：非数字 / 0 / 越界
        assert!(build_form_share_url("1.2.3.4", "abc", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "0", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "70000", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "", "", "").is_err());
        // 地址为空（含纯空白）→ 拒绝
        assert!(build_form_share_url("", "443", "", "").is_err());
        assert!(build_form_share_url("   ", "443", "", "").is_err());
    }

    #[test]
    fn form_share_url_embeds_auth_key_when_given() {
        // 填了密钥 → 写入链接（覆盖全局）；非法 hex → 拒绝
        let hex = "ab".repeat(32);
        let url = build_form_share_url("10.0.0.9", "443", &hex, "").unwrap();
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.auth_key_bytes().unwrap().unwrap(), {
            let mut v = Vec::new();
            for i in 0..32 {
                v.push(u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
            }
            v
        });
        assert!(build_form_share_url("10.0.0.9", "443", "不是hex", "").is_err());
    }

    #[test]
    fn form_share_url_requires_readable_cert_file() {
        // 证书路径不存在 → 拒绝
        assert!(build_form_share_url("10.0.0.9", "443", "", "Z:/不存在的证书.der").is_err());
        // 证书文件存在 → DER 进链接 cc 字段（指纹随之写入）
        let dir = std::env::temp_dir().join(format!("hydra_form_cert_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("node.der");
        let der: Vec<u8> = (0..=255u8).cycle().take(512).collect();
        std::fs::write(&cert_path, &der).unwrap();
        let url =
            build_form_share_url("10.0.0.9", "443", "", &cert_path.display().to_string()).unwrap();
        let parsed = ShareLink::from_share_url(&url).unwrap();
        assert_eq!(parsed.cert_der_bytes().unwrap().unwrap(), der);
        assert!(parsed.cert_fp.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn form_share_url_feeds_group_import_end_to_end() {
        // 端到端：表单 → 构造链接 → import_share_links_as_group 创建分组（复用全部分组逻辑）
        let url = build_form_share_url("10.4.0.7", "9443", "", "").unwrap();
        let mut cfg = GuiConfig::default();
        let result = import_share_links_as_group(&mut cfg, "分享导入1", &url).unwrap();
        assert_eq!(result.node_count, 1);
        assert_eq!(cfg.node_addrs, vec!["10.4.0.7:9443".to_string()]);
        assert!(cfg.subscriptions[0]
            .source
            .starts_with(LOCAL_TEXT_SOURCE_PREFIX));
        // 「更新」语义：hydra-text:// 存的是构造出的链接文本，重解析照常工作
        let reparsed = subscription::fetch_and_parse_subscription(
            "分享导入1".to_string(),
            cfg.subscriptions[0].source.clone(),
            subscription::SUBSCRIPTION_FETCH_TIMEOUT,
        )
        .unwrap();
        assert_eq!(reparsed.links.len(), 1);
        assert_eq!(reparsed.links[0].port, 9443);
    }

    // ── 手动添加节点（表单 + 创建命名分组）──

    #[test]
    fn next_manual_group_name_skips_existing_subscription_names() {
        // 空列表 → 手动节点1
        assert_eq!(next_manual_group_name(&[]), "手动节点1");
        // 已有 手动节点1/2 → 顺延；与「分享导入N」序列互不干扰
        let mut subs = vec![
            SubscriptionConfig {
                name: "手动节点1".to_string(),
                source: String::new(),
                last_updated_secs: None,
                nodes: Vec::new(),
            },
            SubscriptionConfig {
                name: "分享导入1".to_string(),
                source: String::new(),
                last_updated_secs: None,
                nodes: Vec::new(),
            },
        ];
        assert_eq!(next_manual_group_name(&subs), "手动节点2");
        subs.push(SubscriptionConfig {
            name: "手动节点2".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        assert_eq!(next_manual_group_name(&subs), "手动节点3");
    }

    #[test]
    fn manual_form_creates_named_group_and_filters() {
        // 端到端：表单字段 → build_form_share_url 构造链接 → 创建命名分组「手动节点1」
        // → 节点进列表 → 组视图可按该分组过滤（组能力对表单创建的分组通用）
        let url = build_form_share_url("10.5.0.9", "443", "", "").unwrap();
        let mut cfg = GuiConfig::default();
        let result = import_share_links_as_group(&mut cfg, "手动节点1", &url).unwrap();
        assert_eq!(result.node_count, 1);
        // 分组条目出现在订阅列表，source = hydra-text:// + 构造链接
        assert_eq!(cfg.subscriptions.len(), 1);
        assert_eq!(cfg.subscriptions[0].name, "手动节点1");
        assert!(cfg.subscriptions[0]
            .source
            .starts_with(LOCAL_TEXT_SOURCE_PREFIX));
        assert_eq!(cfg.node_addrs, vec!["10.5.0.9:443".to_string()]);
        // 组过滤：该分组能看到节点；「手动」组为空
        let filtered = filter_nodes_by_group(
            &cfg,
            &cfg.node_addrs.clone(),
            &Some("手动节点1".to_string()),
        );
        assert_eq!(filtered, vec!["10.5.0.9:443".to_string()]);
        assert!(filter_nodes_by_group(
            &cfg,
            &cfg.node_addrs.clone(),
            &Some(GROUP_MANUAL.to_string())
        )
        .is_empty());
        // 证书路径按节点独立落库（manual_add_submit 的收口行为）
        cfg.set_node_cert_path("10.5.0.9:443", r"C:\certs\n1.der");
        assert_eq!(
            cfg.node_cert_paths.get("10.5.0.9:443").map(String::as_str),
            Some(r"C:\certs\n1.der")
        );
    }

    #[test]
    fn manual_form_rejects_bad_input_and_duplicate_name() {
        // 端口 0 / 越界 / 非数字、空地址 → build_form_share_url 拒绝（红字不建组的前置校验）
        assert!(build_form_share_url("", "443", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "0", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "70000", "", "").is_err());
        assert!(build_form_share_url("1.2.3.4", "abc", "", "").is_err());
        // 证书路径不存在 → 拒绝
        assert!(build_form_share_url("1.2.3.4", "443", "", "Z:/无此文件.der").is_err());
        // 名称与现有订阅重名 → import_share_links_as_group 拒绝且不新建
        let mut cfg = GuiConfig::default();
        cfg.subscriptions.push(SubscriptionConfig {
            name: "手动节点1".to_string(),
            source: String::new(),
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        let url = build_form_share_url("10.5.0.10", "443", "", "").unwrap();
        let err = import_share_links_as_group(&mut cfg, "手动节点1", &url).unwrap_err();
        assert!(err.contains("已存在"), "err: {}", err);
        assert!(cfg.node_addrs.is_empty());
        // 换避重名「手动节点2」后成功
        assert!(import_share_links_as_group(&mut cfg, "手动节点2", &url).is_ok());
        assert_eq!(cfg.node_addrs, vec!["10.5.0.10:443".to_string()]);
    }

    #[test]
    fn subscription_source_label_classifies_sources() {
        // 本地导入：hydra-text:// 前缀（原文再长也不外显）
        assert_eq!(
            subscription_source_label(&format!(
                "{}{}",
                LOCAL_TEXT_SOURCE_PREFIX,
                share_link_line("10.0.0.1", 1)
            )),
            "本地导入"
        );
        // 订阅：http/https 只显示域名
        assert_eq!(
            subscription_source_label("https://sub.example.com/path/sub?token=abc"),
            "订阅 · sub.example.com"
        );
        assert_eq!(
            subscription_source_label("http://1.2.3.4:8080/sub"),
            "订阅 · 1.2.3.4:8080"
        );
        // hydra-sub:// 前缀：剥除后按剩余部分判定
        assert_eq!(
            subscription_source_label("hydra-sub://https://sub.example.com/sub"),
            "订阅 · sub.example.com"
        );
        // 文件：显示文件名
        assert_eq!(
            subscription_source_label(r"C:\Users\me\nodes.txt"),
            "文件 · nodes.txt"
        );
        assert_eq!(subscription_source_label("nodes.txt"), "文件 · nodes.txt");
    }
}
