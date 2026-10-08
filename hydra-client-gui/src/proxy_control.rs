//! 代理生命周期：代理线程主体（run_proxy_until_stopped）、启动/停止、
//! 系统代理开关（经 windows_proxy，仅 Windows）、停机收敛。

use crate::config;
use crate::HydraApp;
use crate::probe::probe_runtime;
use hydra_client::{ProxyServer, TrafficMonitor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// 代理线程异步主体（抽出为自由函数以便单测时序回归）。
///
/// 【问题 2 根因与修复】此前版本在此处先 `let _ = watcher.await;` 再进 select 跑
/// `proxy.start()`——watcher 的完成条件是 bound_addr 就绪，而 bound_addr 只有
/// start() 里的 bind 才会置位，于是 watcher 在等 start、start 却排在 watcher
/// 之后从未开始执行：两者互相等待，每次启动必然干等 60s 超时
///（用户日志 16:56:34 启动 → 16:57:39 "60s 内未就绪"即此）。
/// 修复：就绪 watcher 保持 tokio 后台任务并发运行（发出就绪/超时信号即返回，
/// 克隆的 ready_tx 丢弃无副作用），不再阻塞等待；start() 立即进入 select 执行
/// 认证检查 → register_nodes → bind → 置 bound_addr（正常数毫秒完成）。
/// stop 信号通过 stop_flag 轮询分支优雅停机（含 TUN 任务取消与路由清理）。
pub(crate) async fn run_proxy_until_stopped(
    proxy: Arc<ProxyServer>,
    tx: std::sync::mpsc::Sender<std::result::Result<SocketAddr, std::io::Error>>,
    stop_flag: Arc<AtomicBool>,
    tun_task: Option<(hydra_client::ShutdownToken, tokio::task::JoinHandle<()>)>,
) {
    // 就绪信号以真实 bound_addr 置位为准——后台并发 watcher，绝不阻塞 start()
    let p2 = proxy.clone();
    let ready_tx = tx.clone();
    tokio::spawn(async move {
        for _ in 0..600 {
            if let Some(bound) = p2.bound_addr() {
                let _ = ready_tx.send(Ok(bound));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = ready_tx.send(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "代理监听 60s 内未就绪（地址被占用或节点预热超时）",
        )));
    });
    tokio::select! {
        result = proxy.start() => {
            match result {
                Ok(()) => {
                    println!("[Proxy Thread] Proxy server exited normally");
                }
                Err(e) => {
                    eprintln!("[Proxy Thread] Proxy server error: {}", e);
                    // release 版无控制台：失败必须回传 UI 可见
                    let _ = tx.send(Err(std::io::Error::other(format!("代理异常退出: {e}"))));
                }
            }
        }
        _ = async {
            while !stop_flag.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => {
            println!("[Proxy Thread] Received stop signal");
            // TUN 任务优雅停机：取消令牌 → 栈任务退出 → RouteGuard Drop 清理路由；
            // 最多等 5s（与 CLI 停机超时一致），超时则随 runtime 关闭强收
            if let Some((token, task)) = tun_task {
                token.cancel();
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
            }
        }
    }
}

impl HydraApp {

    pub(crate) fn start_proxy(&mut self) {
        if self.proxy_running {
            self.add_log("代理已经在运行".to_string());
            return;
        }
        if self.proxy_starting {
            self.add_log("代理正在启动中（节点预热可能需要数十秒），请稍候".to_string());
            return;
        }
        // 审查 P3-6：上一实例正在退出（TUN 收尾/端口释放可达数秒）时禁止立即
        // 重启——否则新实例 bind SOCKS 端口失败，用户看到莫名的「启动失败」。
        // proxy_exit_receiver 在退出完全收敛后才清空，是「正在退出」的权威信号。
        if self.proxy_exit_receiver.is_some() {
            self.add_log("上一代理实例正在退出（端口/TUN 清理中），请等几秒后再启动".to_string());
            return;
        }

        // Exec-1：探测间隔 env 覆盖已移至 HydraApp::new（审查 R-24：多线程进程
        // 运行期调用 std::env::set_var 与后台线程的 env 读取构成数据竞争 UB；
        // new 阶段确认尚无工作线程，仅此一次安全）。

        let proxy_addr: SocketAddr = match self.config.proxy_listen_addr.trim().parse() {
            Ok(addr) => addr,
            Err(e) => {
                self.add_log(format!("地址解析错误: {}", e));
                return;
            }
        };

        // ── 认证密钥：先读配置文件，缺项再回落环境变量（config.rs）──
        // 在 GUI 线程解析完成后再移交代理线程；失败根因直接进日志。
        let auth_key = match config::resolve_auth_key(&self.config) {
            Ok(k) => k,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };

        // 先测试所有节点连接（审查 R-37，Wave 3 修复）：test_all_nodes 的结果是异步
        // 回来的（经健康检查通道在后续帧落地），此刻统计 node_status 必然是上一轮的
        // 过期值（首启恒为 0，"没有可用节点"与"代理已就绪"并存的自相矛盾日志）。
        // 改为中性提示；真实结果由 poll_health_check_results 落地后自然刷新 UI。
        self.add_log("正在测试节点连接...".to_string());
        self.test_all_nodes();
        self.add_log("节点连通性检测已在后台启动，结果稍后自动更新".to_string());

        // 解析节点地址。
        // P1-14 修复：首启时健康检查尚未返回、node_status 全是初始"未连接"值，
        // 据此过滤节点会导致首次启动必然"没有可用节点"而取消。
        // 现不再按可能过期的健康状态拦截，仅过滤非法地址；不可达节点
        // 由代理自身的故障切换与调度器 Offline 标记处理。
        let mut nodes = Vec::new();
        let mut valid_node_addrs = Vec::new();
        let node_addrs = self.config.node_addrs.clone();
        for node_addr in &node_addrs {
            if let Ok(addr) = node_addr.parse::<SocketAddr>() {
                let state = match self.node_status.get(node_addr.as_str()) {
                    Some(st) if st.connected => "已验证",
                    Some(st) if st.last_check.is_some() => "上次检测不可达，仍尝试",
                    _ => "未验证",
                };
                nodes.push(addr);
                valid_node_addrs.push(node_addr.clone());
                self.add_log(format!("添加节点: {} ({})", addr, state));
            } else {
                self.add_log(format!("跳过无效节点地址: {}", node_addr));
            }
        }

        if nodes.is_empty() {
            self.add_log("错误: 没有有效的节点地址，代理启动取消".to_string());
            return;
        }

        // ── 信任根：pin（默认，逐节点证书按序收集）/ ca（真证书 + 可选叶 pin）──
        // 节点顺序与 with_nodes 传入顺序一致（with_node_certs 按序对应）
        let trust = match config::resolve_trust(&self.config, &valid_node_addrs) {
            Ok(t) => t,
            Err(e) => {
                self.add_log(format!("代理启动失败: {}", e));
                return;
            }
        };
        let trust_for_proxy = trust.clone();

        // ── TUN 透明代理（已交付，需管理员/root）：GUI 与代理同进程，TUN 需在 ProxyServer::start
        // 之外叠加（run_tun 独立任务，共享同一调度器/凭据）。配置在此解析，
        // 权限不足等错误经就绪通道透传到日志区。
        let tun_enabled = self.config.tun_enabled;
        let tun_cfg = if tun_enabled {
            match hydra_client::tun_config_from_settings(
                Some(self.config.tun_addr_or_default()),
                Some(self.config.tun_ports_or_default()),
                &nodes,
            ) {
                Ok(c) => {
                    // 与 CLI（main.rs warn_system_proxy_loop）一致的环路告警：
                    // TUN 全流量接管 + 系统代理 → 经系统代理的流量二次进本代理
                    #[cfg(windows)]
                    if hydra_client::windows_system_proxy_enabled() {
                        self.add_log(
                            "⚠ 检测到 Windows 系统代理已开启：TUN 模式下经系统代理的流量会\
                             二次进入本代理形成环路，建议关闭系统代理后使用 TUN 模式"
                                .to_string(),
                        );
                    }
                    self.add_log(format!(
                        "TUN 透明代理开启：地址 {} 端口 {:?}（需管理员/root；仅 TCP；\n                         Windows 还需 wintun.dll）",
                        self.config.tun_addr_or_default(),
                        c.listen_ports
                    ));
                    Some(c)
                }
                Err(e) => {
                    self.add_log(format!("代理启动失败: {}", e));
                    return;
                }
            }
        } else {
            None
        };

        // 创建流量统计器
        let traffic_monitor = Arc::new(TrafficMonitor::new());
        self.traffic_monitor = Some(traffic_monitor.clone());

        // 连接页：清空上一轮会话的连接条目与本地速率差分缓存（注册表为进程级
        // 单例，重启代理后旧条目对用户而言是噪音）
        hydra_client::connections::connections_registry().clear();
        self.conn_snapshot.clear();
        self.conn_prev.clear();
        self.conn_rates.clear();
        self.conn_last_refresh = None;

        // R-16：启动后台流量采样线程（每 500ms 采一次 TrafficStats 写入缓存槽，
        // UI 帧只读缓存，不再 block_in_place/block_on 阻塞渲染）。复用进程级探测
        // runtime（R-34 范式），采样线程可在任意线程 block_on。
        // 旧采样线程若在（重复启动场景），先置位其停止标记。
        if let Some(old) = self.traffic_sampler_stop.take() {
            old.store(true, Ordering::Relaxed);
        }
        {
            let cache = self.traffic_stats_cache.clone();
            let monitor = traffic_monitor.clone();
            // UI 重设计第三批：采样线程同步向历史序列追加（每 500ms 一个点）
            let history = self.traffic_history.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            std::thread::spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    let stats = probe_runtime().block_on(monitor.get_stats());
                    // 审查 P3-5：get_stats 可能阻塞至数百毫秒——若此间 stop 被
                    // 置位（快速重启场景），本次采样的陈旧累计值不得写入新
                    // 会话的缓存/曲线（会被差分误计为当日流量并注入陈旧点）
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(mut slot) = cache.lock() {
                        *slot = Some(stats.clone());
                    }
                    if let Ok(mut hist) = history.lock() {
                        hist.push_sample(&stats);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            });
            self.traffic_sampler_stop = Some(stop);
        }
        // 新会话清空上一轮的过期统计快照，避免启动瞬间显示旧速率
        if let Ok(mut slot) = self.traffic_stats_cache.lock() {
            *slot = None;
        }
        // 曲线序列同步清空（当日累计保留，见 SpeedHistory::reset_samples）
        if let Ok(mut hist) = self.traffic_history.lock() {
            hist.reset_samples();
        }

        // 使用独立线程运行代理
        let (tx, rx) =
            std::sync::mpsc::channel::<std::result::Result<std::net::SocketAddr, std::io::Error>>();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let proxy_addr_clone = proxy_addr;
        let nodes_clone = nodes.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();
        let traffic_monitor_clone = traffic_monitor.clone();
        // 审查修复：TUN 停机令牌提升到 GUI 线程创建并存入 HydraApp 字段——
        // 真退出路径（托盘退出/关窗退出/on_exit）可直接 cancel，保证
        // RouteGuard 的路由清理在任何停机时序下都有机会执行
        let tun_shutdown_token = if tun_cfg.is_some() {
            Some(hydra_client::new_tun_shutdown_token())
        } else {
            None
        };
        self.tun_shutdown = tun_shutdown_token.clone();
        let mut tun_token_for_thread = tun_shutdown_token.clone();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                // 认证密钥/信任根已由 GUI 线程按「配置文件 > 环境变量」解析完毕（见上）
                let proxy = std::sync::Arc::new(
                    ProxyServer::new(proxy_addr_clone)
                        .with_nodes(nodes_clone)
                        .with_traffic_monitor(traffic_monitor_clone)
                        .with_auth_key(auth_key)
                        .with_trust(trust_for_proxy),
                );
                println!("[Proxy Thread] Starting proxy server...");
                // ── TUN 叠加（已交付）：与 SOCKS 监听并存。register_nodes 需在
                // start 之前让调度器已有节点（tun_channel_opener 依赖节点优先级表）
                // tun_task = (停机令牌, TUN 栈任务句柄)；None = 未开启或启动失败
                let tun_task: Option<(
                    hydra_client::ShutdownToken,
                    tokio::task::JoinHandle<()>,
                )> = if let Some(tcfg) = tun_cfg {
                    // GUI 依赖 hydra-client 默认 features（含 tun）；配置构造失败已在
                    // GUI 线程拦截，此处失败（设备创建/路由）经通道透传日志区
                    {
                        proxy.register_nodes().await;
                        match proxy.tun_channel_opener() {
                            Ok(opener) => {
                                // UDP 接管（09 交付）：工厂在 TUN 开启时构建
                                let udp_factory = if tcfg.udp_relay {
                                    match proxy.tun_udp_channel_factory() {
                                        Ok(f) => Some(f),
                                        Err(e) => {
                                            // 此处已进入代理线程（不可触 UI 状态）；
                                            // run_stack 对 None 工厂会再输出日志
                                            tracing::warn!("UDP 接管未启用: {e}");
                                            None
                                        }
                                    }
                                } else {
                                    None
                                };
                                // 令牌本体已在 GUI 线程创建并存入 HydraApp（真退出
                                // 路径可达），此处取传入的令牌 clone 给 TUN 栈任务。
                                // tx 用独立克隆（任务内发送失败根因，不占用主通道所有权）
                                let tun_tx = tx.clone();
                                let tun_token = tun_token_for_thread
                                    .take()
                                    .expect("TUN 已启用时停机令牌必须存在");
                                let shutdown2 = tun_token.clone();
                                let task = tokio::spawn(async move {
                                    if let Err(e) = hydra_client::tun::run_tun(
                                        tcfg,
                                        opener,
                                        udp_factory,
                                        shutdown2,
                                    )
                                    .await
                                    {
                                        // 权限不足（非管理员/root）/ 缺 wintun.dll 等根因
                                        // 经就绪通道透传到 GUI 日志区，不静默
                                        let _ = tun_tx.send(Err(std::io::Error::other(format!(
                                            "TUN 模式启动失败: {e}（设备创建需管理员/root；\
                                             Windows 还需 wintun.dll）"
                                        ))));
                                    }
                                });
                                Some((tun_token, task))
                            }
                            Err(e) => {
                                let _ = tx.send(Err(std::io::Error::other(format!(
                                    "TUN 模式启动失败: {e}"
                                ))));
                                None
                            }
                        }
                    }
                } else {
                    None
                };
                run_proxy_until_stopped(proxy, tx, stop_flag_clone, tun_task).await;
            });
            println!("[Proxy Thread] Thread exiting...");
            // 代理线程退出时发送通知
            let _ = exit_tx.send(());
        });

        self.stop_flag = Some(stop_flag);
        self.proxy_thread_handle = Some(handle);
        self.proxy_exit_receiver = Some(exit_rx);
        // 非阻塞启动：就绪信号经 proxy_start_receiver 在 update 轮询中处理。
        // 阻塞式 recv 会冻结 UI（节点预热/弱网下可达数十秒）
        self.proxy_start_receiver = Some(rx);
        self.proxy_starting = true;
        self.add_log("代理启动中…（节点预热可能需要数十秒，视网络质量而定）".to_string());
        // 启动阶段性日志（问题 1/2 附加）：让用户知道当前卡在哪一步，
        // 就绪后 poll_start_receiver 会接续输出「✓ 代理已就绪」
        self.add_log(format!("正在绑定 {}…", proxy_addr));
    }

    /// update 轮询：消费代理就绪信号（非阻塞，替代原先冻结 UI 的阻塞 recv）
    pub(crate) fn poll_start_receiver(&mut self) -> Option<()> {
        // 07-P2-5：必须区分 Empty 与 Disconnected——Empty = 结果尚未产生，保留
        // receiver 下帧再收；Disconnected = 代理线程在就绪信号发出前已退出
        //（如 Runtime::new().unwrap() panic），若吞掉则 proxy_starting 恒为 true，
        // 「启动代理」按钮从此永久命中早退分支，无法再次启动。
        // 审查修复：每轮一次性排空通道——此前只消费一条就丢弃 receiver，
        // 同帧内随后到达的消息（典型：TUN 启动失败根因紧跟就绪/失败信号）
        // 会被静默丢弃，故障定位线索丢失。
        let mut messages: Vec<std::result::Result<std::net::SocketAddr, std::io::Error>> =
            Vec::new();
        let mut disconnected = false;
        if let Some(rx) = &self.proxy_start_receiver {
            loop {
                match rx.try_recv() {
                    Ok(sig) => messages.push(sig),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        if messages.is_empty() {
            if disconnected {
                // 代理线程异常退出：清 receiver、复位启动态，恢复可再次启动。
                // 09-G-1：同时清 stop_flag / handle / exit_receiver——此前只清
                // 前两者，残留的 stop_flag 使 update 收敛分支
                //（!proxy_running && stop_flag.is_none()）永不接管，残留的
                // exit_receiver 使 start_proxy 永久命中"上一实例正在退出"。
                self.proxy_start_receiver = None;
                self.proxy_starting = false;
                self.stop_flag = None;
                self.proxy_thread_handle = None;
                self.proxy_exit_receiver = None;
                if self.proxy_running {
                    // 运行中代理线程死亡：exit_receiver 分支已清系统代理，此处补日志
                    self.add_log("代理线程异常退出（已移除系统代理，可重新启动）".to_string());
                } else {
                    self.add_log("代理启动线程异常退出（未发出就绪信号即终止）".to_string());
                }
                return Some(());
            }
            return None;
        }
        // 09-P1-6（TUN 竞态修复）：按序处理**全部**消息，且运行态保持 receiver
        // 存活（TUN 任务失败可在就绪信号之后数秒才发出）。已置运行态后到达的
        // Err（典型：SOCKS 就绪信号先于 TUN 失败信号经同一通道到达）触发降级
        // 处理——回退设置系统代理。此前该 Err 只进一行日志：UI 显示“TUN 已全
        // 局接管”而 TUN 已死、系统代理又被跳过，流量明文直连且无系统代理兜底。
        let mut degraded: Vec<std::io::Error> = Vec::new();
        let mut failure = None;
        for sig in messages {
            match sig {
                Ok(addr) if !self.proxy_running => {
                    self.proxy_running = true;
                    self.proxy_starting = false;
                    self.proxy_bound_addr = Some(addr);
                    self.add_log(format!("✓ 代理已就绪，监听地址: {addr}"));
                    self.maybe_save_config(true);
                    // 审查修复：TUN 模式已全局接管流量，就绪后不再叠加系统代理
                    //（否则制造"系统代理 + TUN"二次进本代理的被警示终态）
                    if self.config.tun_enabled {
                        self.add_log("TUN 模式运行中：已全局接管流量，跳过系统代理设置".to_string());
                    } else {
                        let proxy_url = format!("socks5://{addr}");
                        self.set_system_proxy(&proxy_url);
                        self.add_log("已设置系统全局代理".to_string());
                    }
                }
                Ok(addr) => {
                    self.add_log(format!("（附加就绪信号）代理监听地址: {addr}"));
                }
                Err(e) if !self.proxy_running => {
                    // 启动失败（就绪信号之前的失败）：停掉代理线程，交收敛分支清理
                    failure = Some(e);
                    break;
                }
                Err(e) => {
                    degraded.push(e);
                }
            }
        }
        if let Some(e) = failure {
            self.add_log(format!("代理启动失败: {e}"));
            if let Some(flag) = &self.stop_flag {
                flag.store(true, Ordering::Relaxed);
            }
            // 07-P3-10 零成本顺修：置位 stop_flag 后立即清空，让 update 的
            // 收敛分支（!proxy_running && stop_flag.is_none()）正常接管
            // JoinHandle / exit_receiver 清理
            self.stop_flag = None;
            // 失败态 receiver 使命完成（后续可能有附加消息，但失败已定）
            self.proxy_start_receiver = None;
            self.proxy_starting = false;
            return Some(());
        }
        if !degraded.is_empty() && self.proxy_running {
            for e in &degraded {
                self.add_log(format!("⚠ TUN 模式启动失败: {e}"));
            }
            self.add_log(
                "⚠ TUN 全局接管未生效：已自动回退为系统代理模式（若回退失败请手动开启系统代理）"
                    .to_string(),
            );
            if let Some(addr) = self.proxy_bound_addr {
                let proxy_url = format!("socks5://{addr}");
                self.set_system_proxy(&proxy_url);
            }
        }
        Some(())
    }

    pub(crate) fn set_system_proxy(&mut self, proxy_url: &str) {
        // 审查 R-24：不再向本进程写 http_proxy 等 6 个 env var——GUI 自身进程不
        // 通过 env 读代理（env 只对子进程有意义，GUI 不 spawn 走代理的子进程）；
        // 运行期 set_var 与代理/健康检查/订阅线程的 env 读取构成数据竞争（UB）。
        // 系统代理设置由下方各平台原生路径（注册表/gsettings/kwriteconfig）完成。

        // 解析代理地址和端口（审查 R-38，Wave 3 修复）：不再按 ':' 盲切——
        // IPv6 监听（GUI 支持 `[::1]:4433`）时 `socks5://[::1]:1080` 会被切碎成
        // 错误端口段，gsettings/kwriteconfig 写入损坏的桌面代理配置。
        // 按 RFC 3986 authority 解析：先剥 scheme，再区分方括号 IPv6 与 host:port。
        let after_scheme = proxy_url.split("://").nth(1).unwrap_or(proxy_url);
        // Windows 注册表分支直接用 host:port 原串（含 IPv6 方括号形态，WinINet 惯例）；
        // Linux/macOS 分支自行动构造代理串，不用该绑定
        #[cfg(windows)]
        let addr_port = after_scheme;
        let (proxy_host, proxy_port) = if let Some(rest) = after_scheme.strip_prefix('[') {
            // IPv6 字面量：`[::1]:1080`
            match rest.split_once("]:") {
                Some((host, port)) => (host, port),
                None => (rest.trim_end_matches(']'), "1080"),
            }
        } else {
            // host:port（rsplit 从右侧取最后一个 ':'，兼容无端口 host）
            match after_scheme.rsplit_once(':') {
                Some((host, port)) => (host, port),
                None => (after_scheme, "1080"),
            }
        };

        // A1：Windows 注册表真实实现（HKCU Internet Settings + WinINet 刷新）
        #[cfg(windows)]
        {
            match crate::windows_proxy::enable(addr_port) {
                Ok(()) => {}
                Err(e) => self.add_log(format!("设置 Windows 系统代理失败: {}", e)),
            }
        }

        // Linux 桌面代理（gsettings / KDE），Windows 下不执行
        #[cfg(unix)]
        {
            // 设置 GNOME 桌面代理（参考 v2rayN 实现）
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "manual"])
                .output();

            // 设置所有协议的代理（http, https, ftp, socks）
            for protocol in &["http", "https", "ftp", "socks"] {
                let _ = std::process::Command::new("gsettings")
                    .args([
                        "set",
                        &format!("org.gnome.system.proxy.{}", protocol),
                        "host",
                        proxy_host,
                    ])
                    .output();
                let _ = std::process::Command::new("gsettings")
                    .args([
                        "set",
                        &format!("org.gnome.system.proxy.{}", protocol),
                        "port",
                        proxy_port,
                    ])
                    .output();
            }

            // 设置忽略的主机（本地地址不走代理）
            let _ = std::process::Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
                ])
                .output();

            // 检测并设置 KDE 代理（如果在 KDE 环境下）
            if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
                if desktop.contains("KDE") || desktop.contains("plasma") {
                    let kwriteconfig =
                        if std::env::var("KDE_SESSION_VERSION").unwrap_or_default() == "6" {
                            "kwriteconfig6"
                        } else {
                            "kwriteconfig5"
                        };
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "ProxyType",
                            "1",
                        ])
                        .output();
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "socksProxy",
                            &format!("socks://{}:{}", proxy_host, proxy_port),
                        ])
                        .output();
                    // 通知 KDE 重新加载配置
                    let _ = std::process::Command::new("dbus-send")
                        .args([
                            "--type=signal",
                            "/KIO/Scheduler",
                            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                            "string:",
                        ])
                        .output();
                }
            }
        }

        let _ = (proxy_host, proxy_port);
    }

    pub(crate) fn remove_system_proxy_static() {
        // 审查 R-24：对应 set_system_proxy，移除本进程 6 个 proxy env var 的运行期
        // 写入（remove_var 同样是多线程进程的 UB 面；GUI 不依赖这些变量）

        // A1：Windows 恢复旧值（stop/panic/Drop 三条清理路径都经此静态函数）
        #[cfg(windows)]
        crate::windows_proxy::disable();

        // Linux 桌面代理清理，Windows 下不执行
        #[cfg(unix)]
        {
            // 清除 GNOME 桌面代理
            let _ = std::process::Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", "none"])
                .output();

            // 清除 KDE 代理
            if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
                if desktop.contains("KDE") || desktop.contains("plasma") {
                    let kwriteconfig =
                        if std::env::var("KDE_SESSION_VERSION").unwrap_or_default() == "6" {
                            "kwriteconfig6"
                        } else {
                            "kwriteconfig5"
                        };
                    let _ = std::process::Command::new(kwriteconfig)
                        .args([
                            "--file",
                            "kioslaverc",
                            "--group",
                            "Proxy Settings",
                            "--key",
                            "ProxyType",
                            "0",
                        ])
                        .output();
                    let _ = std::process::Command::new("dbus-send")
                        .args([
                            "--type=signal",
                            "/KIO/Scheduler",
                            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                            "string:",
                        ])
                        .output();
                }
            }
        }
    }

    pub(crate) fn remove_system_proxy(&self) {
        Self::remove_system_proxy_static();
    }

    pub(crate) fn stop_proxy(&mut self) {
        if let Some(stop_flag) = &self.stop_flag {
            stop_flag.store(true, Ordering::Relaxed);
        }

        // 审查 R-35：不在 UI 线程 join 代理线程——停止信号靠线程内 100ms 轮询，
        // join 至少阻塞 UI 100ms；若 start() 正处于长 await 链（节点预热数十秒）
        // UI 将冻结同样久，托盘/按钮/窗口全部无响应。退出确认交给 update 里已有的
        // proxy_exit_receiver 轮询分支（收到退出通知后再清理 handle）。
        // 此处只置 stop_flag、立即返回，UI 状态先置"停止中"。
        self.proxy_running = false;
        self.proxy_starting = false;
        self.proxy_start_receiver = None;
        self.stop_flag = None;
        // R-16：停止流量采样线程（线程内 ≤500ms 自行退出，不 join）
        if let Some(stop) = self.traffic_sampler_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Ok(mut slot) = self.traffic_stats_cache.lock() {
            *slot = None;
        }
        // 曲线序列同步清空（当日累计保留）
        if let Ok(mut hist) = self.traffic_history.lock() {
            hist.reset_samples();
        }
        // handle/exit receiver 保留给 update 的退出通知分支收敛，避免泄漏：
        // 线程退出后 exit_rx 断开 → 该分支清理两者。

        // 移除系统全局代理
        self.remove_system_proxy();
        self.add_log("代理停止中，已移除系统代理".to_string());
        // 关键动作立即落盘
        self.maybe_save_config(true);
    }

    /// 真退出专用：停止代理并同步等待代理线程退出（含 TUN 停机），上限 5s。
    ///
    /// 审查修复背景：此前三条真退出路径（托盘退出 / 关窗退出 / on_exit）只调用
    /// stop_proxy 即放行进程关闭，TUN 的停机令牌锁在代理线程内部，RouteGuard
    /// 可能来不及 Drop 清理路由 → 退出后路由残留导致断网。
    /// 现退出时序：置 stop_flag → 直接 cancel TUN 令牌（令牌已提升为 HydraApp
    /// 字段）→ UI 线程带超时轮询 proxy_exit_receiver（std::thread::sleep，
    /// 5s 内可接受）；超时也保证 cancel 已发出，路由清理由线程随后完成。
    /// 注：GUI 退出等待逻辑依赖真实窗口事件循环，无法自动化单测，以人工验证为准。
    pub(crate) fn shutdown_and_wait_for_exit(&mut self) {
        let running = self.proxy_running
            || self.stop_flag.is_some()
            || self.proxy_exit_receiver.is_some();
        if !running {
            return; // 代理未在运行，无需等待
        }
        self.stop_proxy();
        // 确保 TUN 停机令牌已发出（代理线程内也会 cancel，这里双保险且不依赖时序）
        if let Some(token) = &self.tun_shutdown {
            token.cancel();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut exited = false;
        while std::time::Instant::now() < deadline {
            match &self.proxy_exit_receiver {
                Some(rx) => match rx.try_recv() {
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        exited = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                },
                None => {
                    exited = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if exited {
            self.proxy_thread_handle = None;
            self.proxy_exit_receiver = None;
            self.add_log("代理线程已退出（TUN 路由清理完成）".to_string());
        } else {
            self.add_log(
                "⚠ 等待代理/TUN 停机超时（5s）：停机信号与 TUN 令牌已发出，\
                 路由清理将由代理线程退出时的 RouteGuard 完成"
                    .to_string(),
            );
        }
        self.tun_shutdown = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 问题 2：bound_addr 时序回归（run_proxy_until_stopped）──

    /// 构造一个不依赖真实节点证书的代理实例：带 auth key + 显式 trust（空 pin 列表
    /// 即可通过 start() 的前置检查），监听地址由调用方给定。bind 在任何连接发生前
    /// 完成，因此无需真实节点。
    fn test_proxy(addr: SocketAddr) -> Arc<ProxyServer> {
        Arc::new(
            ProxyServer::new(addr)
                .with_auth_key(vec![0x42u8; 32])
                .with_trust(hydra_client::tcp_transport::TlsTrust::pinned(Vec::new())),
        )
    }

    /// 抓一个当前空闲的 TCP 端口（临时监听后立即释放）
    fn free_port() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("绑定临时端口失败")
            .local_addr()
            .expect("读取临时端口失败")
    }

    /// 根因回归：修复前 watcher 在 proxy.start() 之前被 await（互相等待），
    /// bound_addr 永远等不到、必然 60s 超时；修复后 start() 立即执行 bind，
    /// 就绪信号应在 3s 内到达。
    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_binds_within_3s() {
        let addr = free_port();
        let proxy = test_proxy(addr);
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let task =
            tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
        // 阻塞 recv 移入 spawn_blocking，避免冻结异步测试执行器
        let signal = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                rx.recv_timeout(std::time::Duration::from_secs(3))
            }),
        )
        .await
        .expect("bound_addr 未在 3s 内就绪（问题 2 回归）")
        .expect("阻塞接收任务失败")
        .expect("recv 失败");
        match signal {
            Ok(bound) => assert_eq!(bound, addr),
            Err(e) => panic!("启动失败信号: {e}"),
        }
        // 收尾：置 stop 让 select 的停机分支结束，任务正常退出
        stop.store(true, Ordering::Relaxed);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    /// 场景回归：「启动 → 立即 stop → 再启动」同一端口两轮都应在 3s 内就绪
    #[tokio::test(flavor = "multi_thread")]
    async fn start_stop_restart_binds_within_3s_each_round() {
        let addr = free_port();
        for round in 1..=2 {
            let proxy = test_proxy(addr);
            let (tx, rx) = std::sync::mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let task =
                tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
            let signal = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    rx.recv_timeout(std::time::Duration::from_secs(3))
                }),
            )
            .await
            .unwrap_or_else(|_| panic!("第 {round} 轮 bound_addr 未在 3s 内就绪"))
            .expect("阻塞接收任务失败")
            .expect("recv 失败");
            match signal {
                Ok(bound) => assert_eq!(bound, addr),
                Err(e) => panic!("第 {round} 轮启动失败信号: {e}"),
            }
            // 立即 stop：停机分支退出 select，端口释放后下一轮可复用
            stop.store(true, Ordering::Relaxed);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
            // 给内核一点时间释放监听套接字
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// 场景回归：「并发测速负载 + 启动」——启动路径不得被后台负载拖过 3s
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_load_does_not_delay_bind() {
        let addr = free_port();
        // 模拟并发测速负载：持续 2s 的小睡眠任务（真实测速为网络 IO，同样是
        // 独立任务不占用启动路径；此前根因是启动路径自我串行死锁）
        let load = tokio::spawn(async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        let proxy = test_proxy(addr);
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let task =
            tokio::spawn(run_proxy_until_stopped(proxy, tx, stop.clone(), None));
        let started = std::time::Instant::now();
        let signal = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                rx.recv_timeout(std::time::Duration::from_secs(3))
            }),
        )
        .await
        .expect("并发负载下 bound_addr 未在 3s 内就绪")
        .expect("阻塞接收任务失败")
        .expect("recv 失败");
        assert!(
            matches!(signal, Ok(bound) if bound == addr),
            "信号异常: {signal:?}"
        );
        // 额外断言实际耗时远小于 3s（一般毫秒级）
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        let _ = load.await;
    }
}
