//! 节点领域纯逻辑：导航页签、节点状态信息、组视图过滤、择优调度参考。

use crate::config::GuiConfig;
use std::collections::HashMap;

/// 在线节点延迟中位数（纯函数，总览统计卡与单测共用）：
/// 仅统计「测过且在线」的节点；无在线节点返回 None。
pub(crate) fn median_online_latency(status: &HashMap<String, NodeStatusInfo>) -> Option<u64> {
    let mut lats: Vec<u64> = status
        .values()
        .filter(|s| s.connected)
        .filter_map(|s| s.latency_ms)
        .collect();
    if lats.is_empty() {
        return None;
    }
    lats.sort_unstable();
    Some(lats[lats.len() / 2])
}

/// 当前节点候选（纯函数，总览统计卡与单测共用）：
/// 在线节点中延迟最低者（与调度器「最低延迟优先」语义一致，作参考展示）。
/// 返回 (地址, 延迟ms)；地址为 owned String——UI 在借用 cfg 前取快照，避免渲染闭包借用冲突。
pub(crate) fn best_online_node(cfg: &GuiConfig, status: &HashMap<String, NodeStatusInfo>) -> Option<(String, u64)> {
    cfg.node_addrs
        .iter()
        .filter_map(|a| {
            status
                .get(a)
                .filter(|s| s.connected)
                .and_then(|s| s.latency_ms.map(|ms| (a.clone(), ms)))
        })
        .min_by_key(|(_, ms)| *ms)
}

/// UI 重设计 v2：左侧导航六页（状态总览 / 节点 / 订阅 / 连接 / 日志 / 设置）。
/// 分享入口并入节点页（单节点分享在节点行内，批量导出在节点页工具区）；
/// 订阅独立成页：只管订阅源生命周期，节点归属在节点页以来源标记区分。
/// 连接页：实时展示经代理的活跃连接（目标/流量/时长）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tab {
    Overview,
    Nodes,
    Subscriptions,
    Connections,
    Logs,
    Settings,
}

impl Tab {
    pub(crate) const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Nodes,
        Tab::Subscriptions,
        Tab::Connections,
        Tab::Logs,
        Tab::Settings,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Tab::Overview => "🏠 首页",
            Tab::Nodes => "🛰 节点",
            Tab::Subscriptions => "📡 订阅",
            Tab::Connections => "🔗 连接",
            Tab::Logs => "📜 日志",
            Tab::Settings => "⚙ 设置",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NodeStatusInfo {
    pub(crate) connected: bool,
    pub(crate) last_check: Option<std::time::Instant>,
    pub(crate) latency_ms: Option<u64>,
}

// ── UI 重设计第二批：节点页组视图（复刻 Clash Meta 代理组 tabs）──
/// 组标签的保留键：手动组（未被任何订阅认领的节点）。
pub(crate) const GROUP_MANUAL: &str = "manual";

/// 节点所属组的组键（与 GuiConfig 认领机制一致，单一事实来源 = 各订阅 nodes 列表）：
/// 被某订阅认领 → Some(订阅名)；否则 → None（手动）。多订阅含同一地址取先匹配者。
pub(crate) fn node_group_of(cfg: &GuiConfig, addr: &str) -> Option<String> {
    cfg.subscriptions
        .iter()
        .find(|s| s.nodes.iter().any(|n| n == addr))
        .map(|s| s.name.clone())
}

/// 按组过滤节点列表（组视图纯函数，供 UI 与单测共用）：
/// group=None → 全部；Some(GROUP_MANUAL) → 未被任何订阅认领的手动节点；
/// Some(订阅名) → 该订阅认领且仍在节点列表中的地址。
pub(crate) fn filter_nodes_by_group(
    cfg: &GuiConfig,
    node_addrs: &[String],
    group: &Option<String>,
) -> Vec<String> {
    match group.as_deref() {
        None => node_addrs.to_vec(),
        Some(GROUP_MANUAL) => node_addrs
            .iter()
            .filter(|a| node_group_of(cfg, a).is_none())
            .cloned()
            .collect(),
        Some(name) => node_addrs
            .iter()
            .filter(|a| node_group_of(cfg, a).as_deref() == Some(name))
            .cloned()
            .collect(),
    }
}

/// 组成员的在线/离线摘要（测过且连通=在线；测过但失败=离线；未测不计入）。
pub(crate) fn group_summary(
    status: &HashMap<String, NodeStatusInfo>,
    addrs: &[String],
) -> (usize, usize) {
    let mut online = 0;
    let mut offline = 0;
    for a in addrs {
        match status.get(a) {
            Some(s) if s.last_check.is_some() => {
                if s.connected {
                    online += 1;
                } else {
                    offline += 1;
                }
            }
            _ => {}
        }
    }
    (online, offline)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::SubscriptionConfig;

    // ── UI 重设计第二批：节点页组视图（组过滤纯函数）──

    /// 组过滤测试夹具：手动 1 节点 + 订阅A 认领 2 节点 + 订阅B 认领 1 节点
    pub(crate) fn group_fixture() -> GuiConfig {
        let mut cfg = GuiConfig {
            node_addrs: vec![
                "10.0.0.1:1".to_string(),  // 手动
                "10.0.0.2:2".to_string(),  // 订阅A
                "10.0.0.3:3".to_string(),  // 订阅A
                "10.0.0.4:4".to_string(),  // 订阅B
            ],
            ..GuiConfig::default()
        };
        cfg.subscriptions.push(SubscriptionConfig {
            name: "订阅A".to_string(),
            source: "https://a.example".to_string(),
            last_updated_secs: None,
            nodes: vec!["10.0.0.2:2".to_string(), "10.0.0.3:3".to_string()],
        });
        cfg.subscriptions.push(SubscriptionConfig {
            name: "订阅B".to_string(),
            source: "https://b.example".to_string(),
            last_updated_secs: None,
            nodes: vec!["10.0.0.4:4".to_string()],
        });
        cfg
    }

    #[test]
    fn node_group_of_claims_follow_subscription_nodes() {
        let cfg = group_fixture();
        // 被订阅认领 → Some(订阅名)；未被认领 → None（手动）
        assert_eq!(node_group_of(&cfg, "10.0.0.1:1"), None);
        assert_eq!(node_group_of(&cfg, "10.0.0.2:2"), Some("订阅A".to_string()));
        assert_eq!(node_group_of(&cfg, "10.0.0.4:4"), Some("订阅B".to_string()));
        // 不在节点列表但被订阅认领：组归属仍按订阅 nodes 判定（过滤时被列表约束）
        assert_eq!(node_group_of(&cfg, "9.9.9.9:9"), None);
    }

    #[test]
    fn filter_nodes_by_group_none_all_manual_and_sub() {
        let cfg = group_fixture();
        let addrs = cfg.node_addrs.clone();
        // None = 全部
        assert_eq!(filter_nodes_by_group(&cfg, &addrs, &None), addrs);
        // Some("manual") = 未被任何订阅认领的手动节点
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some(GROUP_MANUAL.to_string())),
            vec!["10.0.0.1:1".to_string()]
        );
        // Some(订阅名) = 该订阅认领的地址
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some("订阅A".to_string())),
            vec!["10.0.0.2:2".to_string(), "10.0.0.3:3".to_string()]
        );
        // 不存在的组名 = 空列表（UI 侧已回落「全部」，此处仅保证纯函数确定性）
        assert!(filter_nodes_by_group(&cfg, &addrs, &Some("不存在".to_string())).is_empty());
    }

    #[test]
    fn filter_nodes_by_group_empty_config_and_no_subs() {
        // 无订阅配置：全部 = 手动 = 节点列表
        let cfg = GuiConfig {
            node_addrs: vec!["1.2.3.4:4433".to_string()],
            ..GuiConfig::default()
        };
        let addrs = cfg.node_addrs.clone();
        assert_eq!(filter_nodes_by_group(&cfg, &addrs, &None), addrs);
        assert_eq!(
            filter_nodes_by_group(&cfg, &addrs, &Some(GROUP_MANUAL.to_string())),
            addrs
        );
        assert!(
            filter_nodes_by_group(&cfg, &addrs, &Some("订阅A".to_string())).is_empty()
        );
        // 空列表
        assert!(filter_nodes_by_group(&cfg, &[], &None).is_empty());
    }

    #[test]
    fn group_summary_counts_online_offline_only_when_checked() {
        let mut status = HashMap::new();
        let mk = |connected: bool| NodeStatusInfo {
            connected,
            last_check: Some(std::time::Instant::now()),
            latency_ms: None,
        };
        status.insert("a".to_string(), mk(true));
        status.insert("b".to_string(), mk(false));
        // 未测（last_check=None）不计入摘要
        status.insert(
            "c".to_string(),
            NodeStatusInfo {
                connected: false,
                last_check: None,
                latency_ms: None,
            },
        );
        // 无记录的 d 同样不计入
        let addrs: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert_eq!(group_summary(&status, &addrs), (1, 1));
        assert_eq!(group_summary(&status, &[]), (0, 0));
    }

    #[test]
    fn median_online_latency_ignores_offline_and_unchecked() {
        let mk = |connected: bool, ms: Option<u64>| NodeStatusInfo {
            connected,
            last_check: Some(std::time::Instant::now()),
            latency_ms: ms,
        };
        let mut status = HashMap::new();
        assert_eq!(median_online_latency(&status), None);
        // 离线/未测不计入
        status.insert("a".to_string(), mk(false, None));
        status.insert(
            "b".to_string(),
            NodeStatusInfo {
                connected: false,
                last_check: None,
                latency_ms: Some(10),
            },
        );
        assert_eq!(median_online_latency(&status), None);
        status.insert("c".to_string(), mk(true, Some(300)));
        status.insert("d".to_string(), mk(true, Some(100)));
        status.insert("e".to_string(), mk(true, Some(500)));
        // 在线延迟 {100,300,500} → 中位 300
        assert_eq!(median_online_latency(&status), Some(300));
    }

    #[test]
    fn best_online_node_picks_lowest_latency() {
        let mk = |connected: bool, ms: Option<u64>| NodeStatusInfo {
            connected,
            last_check: Some(std::time::Instant::now()),
            latency_ms: ms,
        };
        let cfg = GuiConfig {
            node_addrs: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..GuiConfig::default()
        };
        let mut status = HashMap::new();
        // 无在线 → None
        assert_eq!(best_online_node(&cfg, &status), None);
        status.insert("a".to_string(), mk(true, Some(210)));
        status.insert("b".to_string(), mk(false, Some(1)));
        status.insert("c".to_string(), mk(true, Some(80)));
        // 在线中延迟最低者胜出（离线的 1ms 不参与）
        assert_eq!(best_online_node(&cfg, &status), Some(("c".to_string(), 80)));
    }
}
