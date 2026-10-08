//! 节点测速 / 健康检查动作：单节点测速、全量测速、组测速、
//! 结果轮询回收、Windows 系统代理状态后台检测。

use crate::nodes::NodeStatusInfo;
use crate::probe::{probe_runtime, probe_target};
use crate::config;
use crate::HydraApp;
use std::net::SocketAddr;

    /// Test connectivity to a single node（A5：失败根因以 Err 透出，不再吞掉）
    /// 信任根由调用方按「配置文件 > 环境变量」构造后传入（config.rs resolve_trust，
    /// 支持 pin/ca 双信任模式与逐节点证书）
    /// 0-7 修复"测速假绿"：不再只做 TCP connect（测不出密钥错误），而是完整走
    /// `connect_target`（TCP+TLS+Noise-PSK 认证 + 节点应答）。探测目标默认
    /// `1.1.1.1:443`（问题 3：原 `192.0.0.1:9` 撞静默丢包防火墙导致健康节点被
    /// 误判"测速超时"；现可用 `HYDRA_PROBE_TARGET` env 覆盖，见 PROBE_TARGET_*），
    /// 错误分类：
    /// - 节点回"目标不可达"（TargetUnreachable / 应答 0x01）→ **认证已通过，节点健康 ✓**，
    ///   返回耗时 ms（测速语义不变）；
    /// - Noise 握手失败 → 认证/密钥错误 ✗；
    /// - TCP 连接失败/超时 → 节点不可达 ✗。
impl HydraApp {

    pub(crate) async fn test_node_connection(
        addr_str: &str,
        trust: hydra_client::tcp_transport::TlsTrust,
        auth_key: Vec<u8>,
    ) -> std::result::Result<u64, String> {
        use hydra_client::tcp_transport::connect_target;
        use hydra_protocol::HydraError;

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("地址解析失败: {}", e))?;

        let start = std::time::Instant::now();
        // 总时限 10s：目标探测在节点侧快速失败（1.1.1.1:443 节点侧建连 ~1ms 级），
        // 正常远小于该值；覆盖 TCP/TLS 5s+握手
        let probe = tokio::time::timeout(
            std::time::Duration::from_millis(10_000),
            connect_target(addr, hydra_client::DEFAULT_SNI, &trust, &auth_key, &probe_target()),
        )
        .await;
        match probe {
            // 目标探测成功（1.1.1.1:443 可直连时可能发生）——握手已通过，同样算节点健康
            Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
            Ok(Err(e)) => match &e {
                // 节点存活且完成了 Noise 认证，只是目标连不上（含 SSRF 拒绝/DNS 失败）
                // → 节点健康，测速语义 = 返回耗时 ms
                HydraError::TargetUnreachable(_) => Ok(start.elapsed().as_millis() as u64),
                _ => {
                    let msg = e.to_string();
                    if msg.contains("Noise 握手失败") || msg.contains("认证失败") {
                        Err(format!("认证/密钥错误（Noise 握手失败）: {}", msg))
                    } else if msg.contains("TCP connect") {
                        Err(format!("节点不可达: {}", msg))
                    } else {
                        Err(msg)
                    }
                }
            },
            Err(_) => Err(format!("节点测速超时（10s）: {}", addr)),
        }
    }

    /// 发起单节点手动测试：后台线程 + 通道，结果在 update 循环中非阻塞收集
    pub(crate) fn start_node_test(&mut self, addr: String) {
        if self.node_test_receiver.is_some() {
            self.add_log("已有节点测试正在进行，请稍候".to_string());
            return;
        }
        // 信任根按「配置文件 > 环境变量」构造（支持 ca 模式与逐节点证书）；失败根因直接进日志
        let trust = match config::resolve_trust(&self.config, std::slice::from_ref(&addr)) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("节点 {} 测试失败: {}", addr, e));
                return;
            }
        };
        // 0-7：完整握手测速需要认证密钥（PSK）——解析失败直接报错（假密钥测不出健康）
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("节点 {} 测试失败（认证密钥未就绪）: {}", addr, e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        self.add_log(format!("开始测试节点 {}...", addr));
        // 卡片 spinner 依据：记录正在测速的节点地址，结果落地后在 poll 中清除
        self.node_testing_addr = Some(addr.clone());
        std::thread::spawn(move || {
            // 审查 R-34：复用进程级探测 runtime（不再每次冷启动一个多线程 runtime）
            let result =
                probe_runtime().block_on(HydraApp::test_node_connection(&addr, trust, auth_key));
            let _ = tx.send((addr, result));
        });
        self.node_test_receiver = Some(rx);
    }

    /// 在 update 循环中非阻塞地收取后台系统代理检测结果并写入缓存
    /// （UI 线程零阻塞：只 try_recv，检测本身在后台线程执行）
    #[cfg(windows)]
    pub(crate) fn poll_sys_proxy_check(&mut self) {
        if let Some(rx) = &self.sys_proxy_check_receiver {
            match rx.try_recv() {
                Ok(enabled) => {
                    // 结果落地：写缓存并清空在途标记，允许 TTL 过期后再次刷新
                    self.sys_proxy_check_cache = Some((std::time::Instant::now(), enabled));
                    self.sys_proxy_check_receiver = None;
                }
                // 后台线程异常退出（panic 等）：清空在途标记，下帧可重试
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.sys_proxy_check_receiver = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    /// 在 update 循环中非阻塞地收取单节点测试结果
    pub(crate) fn poll_node_test_results(&mut self) {
        let mut finished = None;
        if let Some(rx) = &self.node_test_receiver {
            match rx.try_recv() {
                Ok(result) => finished = Some(result),
                // 线程 panic 等原因导致 sender 被弃：清空 receiver，允许再次发起测试
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.node_test_receiver = None;
                    self.node_testing_addr = None;
                    self.add_log("节点测试线程异常退出，已重置".to_string());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((addr, result)) = finished {
            self.node_test_receiver = None;
            // 单测结束：清除卡片 spinner 标记
            if self.node_testing_addr.as_deref() == Some(addr.as_str()) {
                self.node_testing_addr = None;
            }
            let now = std::time::Instant::now();
            match result {
                Ok(latency) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            connected: true,
                            last_check: Some(now),
                            latency_ms: Some(latency),
                        },
                    );
                    self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                }
                Err(reason) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            connected: false,
                            last_check: Some(now),
                            latency_ms: None,
                        },
                    );
                    self.add_log(format!("节点 {} 测试失败: {}", addr, reason));
                }
            }
            // UI 重设计第二批：组级测速——上一个单测完成后自动取队列中的下一个成员
            // （复用 start_node_test 的互斥通道，逐个串行，不与「全部测速」并发通道冲突）
            if let Some(next) = self.pending_node_tests.pop_front() {
                self.start_node_test(next);
            }
        }
    }

    /// Test all nodes and update status (non-blocking)
    pub(crate) fn test_all_nodes(&mut self) {
        // 审查修复：节点列表为空直接记日志返回，不做静默空测
        //（配合 resolve_trust pin 模式空信任根报错，双保险）
        if self.config.node_addrs.is_empty() {
            self.add_log("没有节点可测试（节点列表为空），已跳过".to_string());
            return;
        }
        let node_addrs = self.config.node_addrs.clone();
        // 信任根按「配置文件 > 环境变量」构造（支持 ca 模式与逐节点证书）；失败根因直接进日志
        let trust = match config::resolve_trust(&self.config, &node_addrs) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("全部节点测试失败: {}", e));
                return;
            }
        };
        // 0-7：完整握手测速需要认证密钥（PSK）
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("全部节点测试失败（认证密钥未就绪）: {}", e));
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();

        // 在后台线程中测试所有节点（审查 R-34：复用进程级探测 runtime，
        // 不再每 30s 冷启动/销毁一个多线程 runtime——num_cpus 个 worker 线程、
        // epoll 实例与线程创建毛刺全部消除）
        std::thread::spawn(move || {
            probe_runtime().block_on(async {
                // 并发测试所有节点
                let mut handles = Vec::new();
                for addr in &node_addrs {
                    let addr = addr.clone();
                    let trust = trust.clone();
                    let auth_key = auth_key.clone();
                    let tx = tx.clone();
                    handles.push(tokio::spawn(async move {
                        let result = Self::test_node_connection(&addr, trust, auth_key).await;
                        let _ = tx.send((addr, result));
                    }));
                }
                // 等待所有测试完成
                for handle in handles {
                    let _ = handle.await;
                }
            });
        });

        // 存储 receiver 以便在 update 循环中非阻塞地收集结果
        self.health_check_receiver = Some(rx);
        self.last_health_check = Some(std::time::Instant::now());
    }

    /// UI 重设计第二批：组级测速——对本组成员逐个发起单节点测试。
    /// 复用 start_node_test 的互斥逻辑：已有单测进行中时直接提示并放弃本次排队；
    /// 后续成员进入 pending_node_tests 队列，poll_node_test_results 串行接续。
    pub(crate) fn start_group_test(&mut self, addrs: Vec<String>) {
        if addrs.is_empty() {
            self.add_log("本组没有节点可测试".to_string());
            return;
        }
        if self.node_test_receiver.is_some() {
            self.add_log("已有节点测试正在进行，请稍候".to_string());
            return;
        }
        let mut it = addrs.into_iter();
        let first = it.next().expect("非空队列必有首元素");
        self.pending_node_tests.extend(it);
        self.start_node_test(first);
    }

    /// 在 update 循环中非阻塞地处理健康检查结果
    pub(crate) fn poll_health_check_results(&mut self) {
        // 先收集所有结果到临时列表，避免借用冲突
        let mut results = Vec::new();
        let mut should_clear = false;

        if let Some(rx) = &self.health_check_receiver {
            // 非阻塞地接收所有可用结果。
            // 必须区分 Empty 与 Disconnected：Empty = 结果尚未产生，保留 receiver 下帧再收；
            // Disconnected = 发送端已关闭且队列排空，本批即最终结果，才允许清除 receiver。
            // （此前首次 poll 时 Empty 也置 should_clear，导致 3s 后才到达的结果全部丢失）
            loop {
                match rx.try_recv() {
                    Ok((addr, result)) => results.push((addr, result)),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        should_clear = true;
                        break;
                    }
                }
            }
        }

        // 处理收集到的结果
        for (addr, result) in results {
            let now = std::time::Instant::now();
            match result {
                Ok(latency) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            connected: true,
                            last_check: Some(now),
                            latency_ms: Some(latency),
                        },
                    );
                    self.add_log(format!("节点 {} 连接成功 ({}ms)", addr, latency));
                }
                Err(reason) => {
                    self.node_status.insert(
                        addr.clone(),
                        NodeStatusInfo {
                            connected: false,
                            last_check: Some(now),
                            latency_ms: None,
                        },
                    );
                    // A5：把失败根因（含证书错误）完整显示
                    self.add_log(format!("节点 {} 测试失败: {}", addr, reason));
                }
            }
        }

        // 清除 receiver
        if should_clear {
            self.health_check_receiver = None;
        }
    }
}
