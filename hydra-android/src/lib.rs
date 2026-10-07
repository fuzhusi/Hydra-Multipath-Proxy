//! Hydra Android 绑定层（uniffi → Kotlin）。
//!
//! 设计约束（docs/design/移动端Android方案-v2.md v2.1）：
//! - **显式参数化**：节点/PSK/证书全部由 Kotlin 传入（R8：PSK 存
//!   EncryptedSharedPreferences，Kotlin 侧解密后以 hex/bytes 交付），本层
//!   零 env 读取、零文件路径依赖。
//! - **R4 防环回**：[`SocketProtect`] 回调接口——引擎每个新出站 socket 在
//!   **建连前**回调 Kotlin 层调 `VpnService.protect(fd)`（09-P1-7 起**全链路
//!   接线**：经 `hydra_core::socket_protect` 钩子在 `TcpSocket` 阶段调用），
//!   回调返回 `false`（protect 失败）时该连接立即中止——放行会被本应用 TUN
//!   捕获回环。iOS 等无 VPN 环回问题的平台传 None。
//! - 引擎生命周期独立 tokio runtime：`start()` 立即返回（绑定监听在后台完成，
//!   经 [`HydraEngine::bound_addr`] 查询），`stop()` 关停全部任务。
//!
//! Kotlin 冒烟单测（android/app）：经绑定构造 → start → 查询监听地址 → stop。

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use hydra_core::{proxy::ProxyServer, tcp_transport::TlsTrust, traffic::TrafficMonitor};

// ── uniffi 导出类型 ─────────────────────────────────────────────────────────

/// 节点描述（addr 形如 "1.2.3.4:443"；IPv6 用 "[::1]:443" 字面量形式）
#[derive(uniffi::Record, Debug, Clone)]
pub struct NodeSpec {
    pub addr: String,
}

/// TLS 信任模式（v2.1 信任双路线）
#[derive(uniffi::Enum, Debug, Clone)]
pub enum TrustMode {
    /// 自签证书 pin：Kotlin 从 EncryptedSharedPreferences/Assets 读 der 传入
    Pinned { cert_der: Vec<Vec<u8>> },
    /// 真证书部署：公共 CA 根 + 域名校验（sni 必填）
    PublicCa,
}

/// 引擎统计快照（进程内 SOCKS 与未来 TUN 通道同一计数面）
#[derive(uniffi::Record, Debug, Clone)]
pub struct EngineStats {
    pub sent: u64,
    pub received: u64,
    pub upload_speed: f64,
    pub download_speed: f64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub uptime_secs: u64,
}

/// R4 防环回：出站 socket 保护回调（Kotlin 实现 → `VpnService.protect(fd)`）。
/// fd 为引擎新建出站 socket 的文件描述符；在任何 connect 之前调用。
/// **返回 protect 是否成功**：false 时引擎中止该连接（放行 = 流量进自身
/// TUN 回环，宁失败不放行）。Kotlin 实现示例：
/// `override fun protect(fd: Long): Boolean = vpnService.protect(fd.toInt())`
#[uniffi::export(callback_interface)]
pub trait SocketProtect: Send + Sync {
    fn protect(&self, fd: i64) -> bool;
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum HydraEngineError {
    #[error("配置非法: {msg}")]
    InvalidConfig { msg: String },
    #[error("引擎启动失败: {msg}")]
    Start { msg: String },
    #[error("引擎未运行")]
    NotRunning,
}

/// 引擎运行句柄：独立 tokio runtime + ProxyServer 任务
struct EngineHandle {
    runtime: tokio::runtime::Runtime,
    monitor: Arc<TrafficMonitor>,
    bound: Arc<OnceLock<String>>,
    accept_task: tokio::task::JoinHandle<()>,
}

/// Hydra 引擎（进程内 SOCKS5 代理，M1 手机浏览器手动配代理即用此路径；
/// M2 全局 VPN 由 Kotlin VpnService 把 TUN 流量导向本引擎监听端口）。
#[derive(uniffi::Object)]
pub struct HydraEngine {
    state: Mutex<Option<EngineHandle>>,
    nodes: Vec<String>,
    auth_key: Vec<u8>,
    trust: TlsTrust,
    sni: String,
    listen_port: u16,
}

#[uniffi::export]
impl HydraEngine {
    /// 构造引擎（不做网络操作）。
    /// - `auth_key_hex`：64 个 hex 字符（32 字节 PSK，snow NNpsk2 约束）
    /// - `sni`：None = 默认 hydra.node
    /// - `listen_port`：进程内 SOCKS5 监听端口（0 = 系统随机分配）
    #[uniffi::constructor]
    pub fn new(
        nodes: Vec<NodeSpec>,
        auth_key_hex: String,
        trust: TrustMode,
        sni: Option<String>,
        listen_port: u16,
    ) -> Result<Arc<Self>, HydraEngineError> {
        if nodes.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: "至少需要一个节点".to_string(),
            });
        }
        // 09-A-1：节点地址逐条解析校验——此前 `filter_map(parse().ok())` 把
        // 解析失败（典型：域名节点）静默过滤，引擎以 0 节点"成功启动"且无
        // 任何可用出口。域名节点解析需要系统 resolver（且其 socket 同样要过
        // protect），M2 tun_core 一并支持；当前显式报错给出明确原因。
        let mut parsed_nodes = Vec::with_capacity(nodes.len());
        let mut invalid = Vec::new();
        for n in &nodes {
            match n.addr.parse::<std::net::SocketAddr>() {
                Ok(a) => parsed_nodes.push(a),
                Err(_) => invalid.push(n.addr.clone()),
            }
        }
        if parsed_nodes.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: format!(
                    "节点地址全部无法解析为 IP:端口（域名节点暂不支持，M2 接入）：{:?}",
                    invalid
                ),
            });
        }
        if !invalid.is_empty() {
            return Err(HydraEngineError::InvalidConfig {
                msg: format!("节点地址无法解析为 IP:端口: {:?}", invalid),
            });
        }
        let auth_key = hydra_core::auth_key_from_hex(&auth_key_hex).map_err(|msg| {
            HydraEngineError::InvalidConfig { msg }
        })?;
        let trust = match trust {
            TrustMode::Pinned { cert_der } => {
                if cert_der.is_empty() {
                    return Err(HydraEngineError::InvalidConfig {
                        msg: "pin 模式必须提供至少一张节点证书（der）".to_string(),
                    });
                }
                TlsTrust::pinned(cert_der)
            }
            TrustMode::PublicCa => {
                // 真证书模式：sni 即校验域名（缺省 hydra.node 为自签约定值，
                // 真证书部署应显式传入）
                TlsTrust::public_ca(None)
            }
        };
        Ok(Arc::new(Self {
            state: Mutex::new(None),
            nodes: parsed_nodes.into_iter().map(|a| a.to_string()).collect(),
            auth_key,
            trust,
            sni: sni.unwrap_or_else(|| hydra_core::DEFAULT_SNI.to_string()),
            listen_port,
        }))
    }

    /// 启动引擎（绑定进程内 SOCKS5 监听并常驻；重复调用报 Start 错误）。
    /// `protect`：R4 出站 socket 保护回调，可传 None（仅调试/直连节点场景）。
    pub fn start(self: Arc<Self>, protect: Option<Box<dyn SocketProtect>>) -> Result<(), HydraEngineError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.is_some() {
            return Err(HydraEngineError::Start {
                msg: "引擎已在运行".to_string(),
            });
        }
        // R4 防环回全链路接线（09-P1-7）：把 Kotlin 回调安装为 hydra-core 的
        // 进程级出站 socket 保护钩子——引擎每个新出站连接（节点/直连）在
        // TcpSocket 阶段（connect 前）回调 protect(fd)，失败即中止该连接。
        // 进程级单次安装：重复 start 传新回调时以首次为准（返回 false 不报错）。
        if let Some(cb) = protect {
            let hook: hydra_core::socket_protect::ProtectHook = Box::new(move |fd| cb.protect(fd));
            let _ = hydra_core::socket_protect::set_socket_protect_hook(hook);
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| HydraEngineError::Start { msg: e.to_string() })?;

        let mut server = ProxyServer::new(
            std::net::SocketAddr::from(([127, 0, 0, 1], self.listen_port)),
        )
        .with_nodes(
            self.nodes
                .iter()
                .filter_map(|a| a.parse().ok())
                .collect(),
        )
        .with_auth_key(self.auth_key.clone())
        .with_trust(self.trust.clone())
        .with_sni(self.sni.clone());

        let monitor = Arc::new(TrafficMonitor::new());
        server = server.with_traffic_monitor(monitor.clone());

        // OnceLock 的 Clone 是「另起一个空实例」语义，必须套 Arc 才是共享同一槽
        let bound: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let bound_slot = bound.clone();
        let server = Arc::new(server);
        // start() 校验凭据 + 绑定监听后进入 accept 循环；绑定失败即时上抛
        let prep = server.clone();
        let accept_task = runtime.spawn(async move {
            // 先跑 start() 到绑定完成再放行：bound_addr 就绪即可视为已启动
            if let Err(e) = prep.start().await {
                tracing::error!("HydraEngine accept 循环退出: {e}");
            }
        });
        // 等待监听绑定（最多 5s；ProxyServer::start 绑定后即写 bound_addr）
        let srv_for_wait = server.clone();
        let wait = async move {
            for _ in 0..100 {
                if let Some(addr) = srv_for_wait.bound_addr() {
                    let _ = bound_slot.set(addr.to_string());
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(HydraEngineError::Start {
                msg: "5s 内未完成监听绑定".to_string(),
            })
        };
        runtime.block_on(wait)?;

        *state = Some(EngineHandle {
            runtime,
            monitor,
            bound,
            accept_task,
        });
        Ok(())
    }

    /// 停止引擎并回收 runtime（幂等：未运行时为 no-op）
    pub fn stop(&self) {
        if let Some(h) = self.state.lock().unwrap_or_else(|p| p.into_inner()).take() {
            h.accept_task.abort();
            h.runtime.shutdown_timeout(Duration::from_secs(3));
        }
    }

    /// 进程内 SOCKS5 监听地址（形如 "127.0.0.1:1080"；未绑定完成时 None）
    pub fn bound_addr(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|h| h.bound.get().cloned())
    }

    /// 流量统计（引擎未运行时报 NotRunning）
    pub fn stats(&self) -> Result<EngineStats, HydraEngineError> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let h = state.as_ref().ok_or(HydraEngineError::NotRunning)?;
        let s = h.runtime.block_on(h.monitor.get_stats());
        Ok(EngineStats {
            sent: s.bytes_sent,
            received: s.bytes_received,
            upload_speed: s.upload_speed,
            download_speed: s.download_speed,
            active_connections: s.active_connections,
            total_connections: s.total_connections,
            uptime_secs: s.uptime_secs,
        })
    }
}

// uniffi scaffolding（proc-macro 导出风格的收尾宏）
uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "ab";

    fn engine(port: u16) -> Arc<HydraEngine> {
        HydraEngine::new(
            vec![NodeSpec { addr: "127.0.0.1:44300".to_string() }],
            HEX.repeat(32),
            TrustMode::Pinned {
                // 占位 der（启动只校验非空，握手期才会真正解析）
                cert_der: vec![vec![0x30u8, 0x00]],
            },
            None,
            port,
        )
        .unwrap()
    }

    #[test]
    fn engine_start_stop_smoke() {
        let e = engine(0);
        // start(self: Arc<Self>) 消费句柄——测试里先克隆一份供断言复用
        let e2 = e.clone();
        let e3 = e.clone();
        e2.start(None).expect("启动应成功（绑定 127.0.0.1 随机端口）");
        let bound = e.bound_addr().expect("启动后应有监听地址");
        assert!(bound.starts_with("127.0.0.1:"), "bound={bound}");
        // 重复启动必须报错
        assert!(e3.start(None).is_err());
        let s = e.stats().expect("运行中 stats 可查");
        assert_eq!(s.total_connections, 0);
        e.stop();
        assert!(e.bound_addr().is_none(), "stop 后监听地址清空");
        assert!(e.stats().is_err(), "stop 后 stats 报 NotRunning");
        // 幂等 stop
        e.stop();
    }

    #[test]
    fn engine_rejects_bad_config() {
        assert!(HydraEngine::new(vec![], "00".repeat(32),
            TrustMode::Pinned { cert_der: vec![vec![0x30]] }, None, 0).is_err());
        assert!(HydraEngine::new(
            vec![NodeSpec { addr: "127.0.0.1:443".to_string() }],
            "00".repeat(31), // 31 字节：NNpsk2 约束必须 32
            TrustMode::Pinned { cert_der: vec![vec![0x30]] }, None, 0).is_err());
        assert!(HydraEngine::new(
            vec![NodeSpec { addr: "127.0.0.1:443".to_string() }],
            "00".repeat(32),
            TrustMode::Pinned { cert_der: vec![] }, None, 0).is_err());
    }
}
