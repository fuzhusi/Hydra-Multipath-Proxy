//! 订阅管理动作：添加/删除订阅、串行后台更新队列、合并替换落库。

use crate::config::SubscriptionConfig;
use crate::groups::apply_subscription_node_update;
use crate::nodes::NodeStatusInfo;
use crate::subscription;
use crate::HydraApp;
use hydra_client::ShareLink;
use std::collections::HashSet;

impl HydraApp {
    // ═══════════════ Exec-C：订阅（hydra-sub v1）═══════════════
    //
    // 数据流：UI 线程 queue_subscription_update → 后台线程 fetch_and_parse_subscription
    // （ureq 阻塞拉取/文件读取 + parse_subscription）→ mpsc → UI 线程
    // poll_subscription_updates → apply_subscription_update 合并替换。
    // 单条后台通道 + 待更新队列：多订阅串行拉取，UI 零阻塞。

    /// 添加订阅（名称可留空自动编号；名称重复拒绝——名称是来源标记与更新对号的键）
    pub(crate) fn add_subscription(&mut self) -> bool {
        let source = self.new_sub_source.trim().to_string();
        if source.is_empty() {
            self.add_log(
                "订阅来源不能为空（http(s) URL、文件路径或 hydra-sub:// 前缀）".to_string(),
            );
            return false;
        }
        let name = if self.new_sub_name.trim().is_empty() {
            format!("订阅{}", self.config.subscriptions.len() + 1)
        } else {
            self.new_sub_name.trim().to_string()
        };
        if self.config.subscriptions.iter().any(|s| s.name == name) {
            self.add_log(format!("订阅名称「{}」已存在，请换一个名称", name));
            return false;
        }
        self.config.subscriptions.push(SubscriptionConfig {
            name: name.clone(),
            source,
            last_updated_secs: None,
            nodes: Vec::new(),
        });
        self.add_log(format!("已添加订阅「{}」，点「更新」拉取节点", name));
        self.new_sub_name.clear();
        self.new_sub_source.clear();
        true
    }

    /// 删除订阅：连带清理仅该订阅认领的节点（手动/其他订阅认领的保留）
    pub(crate) fn delete_subscription(&mut self, idx: usize) {
        if idx >= self.config.subscriptions.len() {
            return;
        }
        let sub = self.config.subscriptions.remove(idx);
        let others_owned: HashSet<String> =
            self.config.subscription_owned_addrs().into_iter().collect();
        let removed: Vec<String> = sub
            .nodes
            .iter()
            .filter(|a| !others_owned.contains(*a))
            .cloned()
            .collect();
        self.config.node_addrs.retain(|a| !removed.contains(a));
        for a in &removed {
            self.node_status.remove(a);
            // 审查修复：连带清备注名与独立证书路径（remove_node_state 收口）
            self.config.remove_node_state(a);
        }
        self.add_log(format!(
            "删除订阅「{}」，连带移除其节点 {} 个",
            sub.name,
            removed.len()
        ));
    }

    /// 排队更新一个订阅（后台串行）
    pub(crate) fn queue_subscription_update(&mut self, name: String, source: String) {
        self.pending_sub_updates.push_back((name, source));
        self.start_next_subscription_update();
    }

    /// 更新全部订阅
    pub(crate) fn update_all_subscriptions(&mut self) {
        if self.config.subscriptions.is_empty() {
            self.add_log("没有订阅可更新，请先在「订阅」区添加".to_string());
            return;
        }
        for s in &self.config.subscriptions {
            self.pending_sub_updates
                .push_back((s.name.clone(), s.source.clone()));
        }
        self.start_next_subscription_update();
    }

    /// 启动队列中的下一个订阅更新（已有更新在跑则返回；已删除的订阅跳过）
    pub(crate) fn start_next_subscription_update(&mut self) {
        if self.sub_update_receiver.is_some() {
            return;
        }
        loop {
            let Some((name, source)) = self.pending_sub_updates.pop_front() else {
                return;
            };
            if !self.config.subscriptions.iter().any(|s| s.name == name) {
                self.add_log(format!("订阅「{}」已删除，跳过更新", name));
                continue;
            }
            let (tx, rx) = std::sync::mpsc::channel();
            self.add_log(format!("开始更新订阅「{}」...", name));
            std::thread::spawn(move || {
                let result = crate::subscription::fetch_and_parse_subscription(
                    name.clone(),
                    source.clone(),
                    subscription::SUBSCRIPTION_FETCH_TIMEOUT,
                );
                let _ = tx.send(result);
            });
            self.sub_update_receiver = Some(rx);
            return;
        }
    }

    /// 在 update 循环中非阻塞地收取订阅更新结果并启动下一个排队更新
    pub(crate) fn poll_subscription_updates(&mut self) {
        let mut finished = None;
        if let Some(rx) = &self.sub_update_receiver {
            match rx.try_recv() {
                Ok(result) => finished = Some(result),
                // 线程 panic 等导致 sender 被弃：重置，允许再次发起
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.sub_update_receiver = None;
                    self.add_log("订阅更新线程异常退出，已重置".to_string());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(result) = finished {
            self.sub_update_receiver = None;
            match result {
                Ok(outcome) => {
                    // 安全约定：明文 http 允许但必须提示（订阅可被中间人注入任意节点地址）
                    if outcome.plaintext_http {
                        self.add_log(format!(
                            "⚠ 订阅「{}」使用明文 HTTP 拉取，内容可能被篡改，建议改用 https",
                            outcome.name
                        ));
                    }
                    self.apply_subscription_update(&outcome.name, outcome.links, outcome.errors);
                }
                Err(e) => self.add_log(format!("订阅更新失败: {}", e)),
            }
        }
        self.start_next_subscription_update();
    }

    /// 订阅更新成功后的节点合并替换：
    /// - 手动节点与其它订阅的节点全部保留；
    /// - 本订阅旧节点被新列表替换（仅移除"仅本订阅认领"的地址）；
    /// - 与手动/其它订阅冲突的地址不重复添加，归属保持原状（单一事实来源 =
    ///   各订阅 nodes 列表，见 GuiConfig::node_source_label）。
    pub(crate) fn apply_subscription_update(
        &mut self,
        name: &str,
        links: Vec<ShareLink>,
        errors: Vec<String>,
    ) {
        if !self.config.subscriptions.iter().any(|s| s.name == name) {
            self.add_log(format!("订阅「{}」已在更新期间被删除，丢弃更新结果", name));
            return;
        }

        // 合并替换的纯逻辑（与分享导入分组共用，见 apply_subscription_node_update）
        let (added, to_remove) = apply_subscription_node_update(&mut self.config, name, &links);
        let new_addrs_len = self
            .config
            .subscriptions
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.nodes.len())
            .unwrap_or(0);

        // 运行时节点状态同步（纯函数只动 config，不持 node_status）
        for a in &added {
            self.node_status.entry(a.clone()).or_insert(NodeStatusInfo {
                connected: false,
                last_check: None,
                latency_ms: None,
            });
        }
        for a in &to_remove {
            self.node_status.remove(a);
        }

        self.add_log(format!(
            "订阅「{}」更新成功：{} 个节点（坏行 {} 条跳过，新增 {}、移除 {}）",
            name,
            new_addrs_len,
            errors.len(),
            added.len(),
            to_remove.len()
        ));
        for e in errors.iter().take(3) {
            self.add_log(format!("  订阅坏行: {}", e));
        }
        if errors.len() > 3 {
            self.add_log(format!("  ...另有 {} 条坏行省略", errors.len() - 3));
        }
    }
}
