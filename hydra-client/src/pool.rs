use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use hydra_protocol::handshake::{self, AuthMode};
use hydra_protocol::{HydraError, Result};

/// 池中单条连接的包装
struct PooledConnection {
    connection: Connection,
    /// 最后一次使用此连接的时间
    last_used: Instant,
    /// 此连接已被用于打开流的次数
    use_count: u64,
    /// 首条流协商出的节点认证版本：Some(true)=v3、Some(false)=v2；
    /// None=未协商（Auto 模式下首条流优先试 v3，失败回落 v2 并记忆）
    negotiated_v3: Option<bool>,
}

impl PooledConnection {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            last_used: Instant::now(),
            use_count: 0,
            negotiated_v3: None,
        }
    }

    /// 检查连接是否仍然可用（未关闭）
    fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// v3 通道绑定材料：节点证书 SHA-256 指纹（peer_identity → rustls 0.21
    /// Vec<Certificate>）+ QUIC/TLS exporter（quinn 0.10 export_keying_material）。
    fn binding_material(&self) -> Result<([u8; 32], [u8; 32])> {
        let cert_fp = match self.connection.peer_identity() {
            Some(any) => {
                let certs = any
                    .downcast::<Vec<rustls::Certificate>>()
                    .map_err(|_| HydraError::ProtocolError("peer_identity 类型异常".into()))?;
                certs
                    .first()
                    .map(|c| handshake::cert_fingerprint(&c.0))
                    .ok_or_else(|| {
                        HydraError::ProtocolError("节点未提供证书（无法通道绑定）".into())
                    })?
            }
            None => {
                return Err(HydraError::ProtocolError(
                    "连接未完成 TLS 握手（无 peer 证书）".into(),
                ))
            }
        };
        let mut exporter = [0u8; handshake::EXPORTER_LEN];
        self.connection
            .export_keying_material(&mut exporter, handshake::EXPORTER_LABEL, b"")
            .map_err(|e| {
                HydraError::ProtocolError(format!("export_keying_material 失败: {e:?}"))
            })?;
        Ok((cert_fp, exporter))
    }

    /// v3 路径：open_bi + Noise_NNpsk2 握手（0x03 版本字节由 client_side 写入）
    async fn open_bi_v3(&mut self, auth_key: &[u8]) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| HydraError::ProtocolError(format!("Failed to open stream: {}", e)))?;
        let (cert_fp, exporter) = self.binding_material()?;
        match tokio::time::timeout(
            handshake::HANDSHAKE_TIMEOUT,
            handshake::client_side(&mut send, &mut recv, auth_key, &cert_fp, &exporter),
        )
        .await
        {
            Ok(Ok(_)) => Ok((send, recv)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(HydraError::ProtocolError("v3 握手超时".into())),
        }
    }

    /// v2 路径：open_bi + 一次性 HMAC token（行为与 V2 逐字节一致）
    async fn open_bi_v2(&mut self, auth_key: &[u8]) -> Result<(SendStream, RecvStream)> {
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| HydraError::ProtocolError(format!("Failed to open stream: {}", e)))?;
        let token = hydra_protocol::AuthToken::generate(auth_key, hydra_protocol::CLIENT_ID);
        send.write_all(&token)
            .await
            .map_err(HydraError::QuinnWriteError)?;
        Ok((send, recv))
    }

    /// 获取一条已完成认证的双向流。
    /// Auto：优先 v3，v3 被拒（旧节点）自动回落 v2 并在本连接上记忆，后续流直达。
    async fn open_bi(&mut self, auth_key: &[u8], auth_mode: AuthMode) -> Result<(SendStream, RecvStream)> {
        let prefer_v3 = match self.negotiated_v3 {
            Some(v) => v,
            None => auth_mode.accepts_v3(),
        };
        let result = if prefer_v3 {
            match self.open_bi_v3(auth_key).await {
                Ok(r) => {
                    self.negotiated_v3 = Some(true);
                    Ok(r)
                }
                Err(e) if auth_mode == AuthMode::V3 => Err(e),
                // confirm 不匹配 = 握手被拒/被篡改（中间人或密钥不一致）——
                // 这是 v3 安全属性生效的表现，绝不可静默回落 v2（可利用的降级攻击面）
                Err(e) if e.to_string().contains("确认值不匹配") => {
                    error!("v3 handshake confirm mismatch (possible MITM/tampering) — refusing v2 downgrade: {e}");
                    Err(e)
                }
                Err(_) => {
                    // v3 被拒（v2-only 节点首字节 0x03 不合 legacy token → 静默关流）
                    warn!("v3 handshake rejected/failed; falling back to v2 token auth");
                    let r = self.open_bi_v2(auth_key).await;
                    if r.is_ok() && auth_mode == AuthMode::Auto {
                        self.negotiated_v3 = Some(false);
                    }
                    r
                }
            }
        } else {
            self.open_bi_v2(auth_key).await
        };
        if result.is_ok() {
            self.last_used = Instant::now();
            self.use_count += 1;
        }
        result
    }
}

/// 连接池配置
#[derive(Clone)]
pub struct PoolConfig {
    /// 每个远端地址最多保留的空闲连接数
    pub max_idle_per_node: usize,
    /// 空闲连接的存活时间，超过后在下次清理时移除
    pub idle_timeout: Duration,
    /// 连接池清理间隔
    pub cleanup_interval: Duration,
    /// 新连接的握手超时
    pub connect_timeout: Duration,
    /// 节点预共享密钥（每条流认证：v2 HMAC token 或 v3 Noise 握手）
    pub auth_key: Vec<u8>,
    /// 认证版本（HYDRA_AUTH_MODE=auto|v2|v3；默认 auto：优先 v3、旧节点回落 v2）
    pub auth_mode: AuthMode,
    /// SNI 伪装域名
    pub sni: String,
    /// 客户端 QUIC/TLS 配置（含节点证书信任根）
    pub client_config: quinn::ClientConfig,
}

/// QUIC 连接池
pub struct ConnectionPool {
    /// 共享的 QUIC Endpoint，所有出站连接都通过它建立
    endpoint: Endpoint,
    /// 按远端地址分组的连接池
    pools: Arc<RwLock<HashMap<SocketAddr, Vec<PooledConnection>>>>,
    config: PoolConfig,
}

impl ConnectionPool {
    /// 创建新的连接池
    pub fn new(endpoint: Endpoint, config: PoolConfig) -> Self {
        let pool = Self {
            endpoint,
            pools: Arc::new(RwLock::new(HashMap::new())),
            config,
        };
        pool.spawn_cleanup_task();
        pool
    }

    /// 从池中获取一条到指定地址的双向流。
    /// 锁只保护取/还连接本身，网络 I/O（open_bi + token 写入）在锁外执行，
    /// 避免慢连接把其它节点的取流请求全部串行化。
    pub async fn get_stream(&self, addr: SocketAddr) -> Result<(SendStream, RecvStream)> {
        // 从池中取出一条候选连接（LIFO，优先复用最近活跃的）
        let mut candidate = {
            let mut pools = self.pools.write().await;
            pools.get_mut(&addr).and_then(|conns| conns.pop())
        };

        while let Some(mut pc) = candidate {
            if pc.is_alive() {
                match pc.open_bi(&self.config.auth_key, self.config.auth_mode).await {
                    Ok(streams) => {
                        // 连接仍在使用中，放回池中
                        let mut pools = self.pools.write().await;
                        let conns = pools.entry(addr).or_default();
                        if conns.len() < self.config.max_idle_per_node {
                            conns.push(pc);
                        }
                        return Ok(streams);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to open stream on pooled connection to {}: {}",
                            addr, e
                        );
                        // 连接可能已损坏，丢弃并尝试下一条
                    }
                }
            }
            // 连接已死或无法打开流，取下一条候选
            candidate = {
                let mut pools = self.pools.write().await;
                pools.get_mut(&addr).and_then(|conns| conns.pop())
            };
        }

        // 没有可用连接，建立新连接
        info!("Pool miss: establishing new QUIC connection to {}", addr);
        let connection = self.connect(addr).await?;

        let mut pc = PooledConnection::new(connection);
        let streams = pc
            .open_bi(&self.config.auth_key, self.config.auth_mode)
            .await?;

        // 将连接放入池中
        {
            let mut pools = self.pools.write().await;
            let conns = pools.entry(addr).or_default();
            if conns.len() < self.config.max_idle_per_node {
                conns.push(pc);
            }
            // 超过上限则丢弃（drop 会自动关闭连接）
        }

        Ok(streams)
    }

    /// 从池中获取一条到指定地址的双向流，带重试
    pub async fn get_stream_with_retry(
        &self,
        addr: SocketAddr,
        max_retries: u32,
    ) -> Result<(SendStream, RecvStream)> {
        let mut last_error = None;

        for attempt in 0..max_retries {
            match self.get_stream(addr).await {
                Ok(streams) => return Ok(streams),
                Err(e) => {
                    warn!(
                        "Attempt {}/{} failed for {}: {}",
                        attempt + 1,
                        max_retries,
                        addr,
                        e
                    );
                    last_error = Some(e);
                    // 短暂等待后重试
                    if attempt < max_retries - 1 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| HydraError::ConnectionError("All retries failed".to_string())))
    }

    /// 移除指定地址的所有连接（当检测到连接问题时调用）
    pub async fn remove_all(&self, addr: &SocketAddr) {
        let mut pools = self.pools.write().await;
        if let Some(conns) = pools.remove(addr) {
            info!("Removed {} connections to {} from pool", conns.len(), addr);
        }
    }

    /// 建立新的 QUIC 连接（使用证书 pinning 配置与伪装 SNI）
    async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let connecting = self.endpoint.connect_with(
            self.config.client_config.clone(),
            addr,
            &self.config.sni,
        )?;
        match tokio::time::timeout(self.config.connect_timeout, connecting).await {
            Ok(Ok(conn)) => {
                info!("New QUIC connection established to {}", addr);
                Ok(conn)
            }
            Ok(Err(e)) => {
                error!("QUIC connection to {} failed: {}", addr, e);
                Err(e.into())
            }
            Err(_) => {
                error!("QUIC connection to {} timed out", addr);
                Err(HydraError::ConnectionError(format!(
                    "Connection to {} timed out",
                    addr
                )))
            }
        }
    }

    /// 主动向池中预热连接（可在启动时调用）。
    ///
    /// B4：预热数量可经 env `HYDRA_WARM_UP` 覆盖（默认 2，clamp 0..=8，在本函数内收敛，
    /// 调用点 proxy.rs 不感知）；多条连接之间加入 0-500ms 随机抖动，避免启动瞬间出现
    /// 固定规模的并发握手突发（被动流量指纹特征）。
    pub async fn warm_up(&self, addr: SocketAddr, count: usize) {
        let count = resolve_warm_up_count(std::env::var("HYDRA_WARM_UP").ok().as_deref(), count);
        for i in 0..count {
            // 相邻预热连接之间的随机间隔（第一条之前不等待）
            if i > 0 {
                tokio::time::sleep(warm_up_jitter()).await;
            }
            match self.connect(addr).await {
                Ok(conn) => {
                    let pc = PooledConnection::new(conn);
                    let mut pools = self.pools.write().await;
                    pools.entry(addr).or_default().push(pc);
                    info!("Warmed up connection to {}", addr);
                }
                Err(e) => {
                    warn!("Failed to warm up connection to {}: {}", addr, e);
                    break;
                }
            }
        }
    }

    /// 启动后台清理任务
    fn spawn_cleanup_task(&self) {
        let pools = self.pools.clone();
        let interval = self.config.cleanup_interval;
        let idle_timeout = self.config.idle_timeout;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                Self::cleanup(&pools, idle_timeout).await;
            }
        });
    }

    /// 清理失效和空闲超时的连接
    async fn cleanup(
        pools: &RwLock<HashMap<SocketAddr, Vec<PooledConnection>>>,
        idle_timeout: Duration,
    ) {
        let mut pools = pools.write().await;
        let now = Instant::now();
        let mut total_removed = 0;

        for conns in pools.values_mut() {
            conns.retain(|pc| {
                let alive = pc.is_alive();
                let fresh = now.duration_since(pc.last_used) < idle_timeout;
                if !alive || !fresh {
                    total_removed += 1;
                    false
                } else {
                    true
                }
            });
        }

        // 移除空的地址条目
        pools.retain(|_, conns| !conns.is_empty());

        if total_removed > 0 {
            info!(
                "Connection pool cleanup: removed {} stale connections",
                total_removed
            );
        }
    }

    /// 获取当前池中所有地址的连接数统计
    pub async fn stats(&self) -> HashMap<SocketAddr, usize> {
        let pools = self.pools.read().await;
        pools
            .iter()
            .map(|(addr, conns)| (*addr, conns.len()))
            .collect()
    }
}

// ===================== B4 预热可配 + 启动抖动 =====================

/// 预热连接数上限（env HYDRA_WARM_UP 与调用方请求值均 clamp 到此范围）
pub const MAX_WARM_UP_CONNECTIONS: usize = 8;

/// 解析预热连接数（纯函数；env 以参数注入，避免进程全局 env 污染单测）。
///
/// env `HYDRA_WARM_UP`：预热连接数，clamp 0..=8，未设置时默认 2。
/// - 未设置/空白 → 回退调用方请求值（proxy.rs 现传 2，与默认一致，调用点不动）
/// - 非数字 → 告警 + 回退调用方请求值（同样 clamp）
/// - 负数 → 0；超出上限 → 8（均告警）
fn resolve_warm_up_count(env_raw: Option<&str>, requested: usize) -> usize {
    let trimmed = env_raw.map(str::trim).filter(|s| !s.is_empty());
    let parsed = trimmed.and_then(|s| s.parse::<i64>().ok());
    match parsed {
        Some(v) => {
            let clamped = v.clamp(0, MAX_WARM_UP_CONNECTIONS as i64) as usize;
            if clamped as i64 != v {
                warn!("HYDRA_WARM_UP={v} 超出 0..={MAX_WARM_UP_CONNECTIONS}，取 {clamped}");
            }
            clamped
        }
        None => {
            let fallback = requested.min(MAX_WARM_UP_CONNECTIONS);
            if let Some(raw) = trimmed {
                warn!("HYDRA_WARM_UP={raw:?} 非法，回退请求值 {fallback}");
            }
            fallback
        }
    }
}

/// 0..=500ms 随机预热间隔：打散启动瞬间的连接握手突发（去被动流量指纹特征）。
/// 与 transport.rs 的 keepalive 抖动同款 ring 写法；fill 失败概率可忽略，退化为 0 延迟。
fn warm_up_jitter() -> Duration {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 2];
    let _ = rng.fill(&mut buf);
    Duration::from_millis((u16::from_be_bytes(buf) % 501) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b4_warm_up_defaults_to_requested_value() {
        // 未设置 → 回退请求值（proxy.rs 传 2 即默认 2）
        assert_eq!(resolve_warm_up_count(None, 2), 2);
        // 空白视为未设置
        assert_eq!(resolve_warm_up_count(Some("   "), 3), 3);
        // 非数字 → 回退请求值（同样 clamp）
        assert_eq!(resolve_warm_up_count(Some("junk"), 2), 2);
        assert_eq!(
            resolve_warm_up_count(Some("-x"), 100),
            MAX_WARM_UP_CONNECTIONS
        );
    }

    #[test]
    fn b4_warm_up_env_overrides_requested() {
        assert_eq!(resolve_warm_up_count(Some("5"), 2), 5);
        assert_eq!(resolve_warm_up_count(Some("0"), 2), 0);
        assert_eq!(resolve_warm_up_count(Some("3"), 100), 3);
    }

    #[test]
    fn b4_warm_up_clamped_to_0_8() {
        assert_eq!(resolve_warm_up_count(Some("-7"), 2), 0);
        assert_eq!(
            resolve_warm_up_count(Some("999"), 2),
            MAX_WARM_UP_CONNECTIONS
        );
        assert_eq!(resolve_warm_up_count(Some("8"), 2), 8);
        // 调用方传入的请求值同样被 clamp（防御未来调用点变化）
        assert_eq!(resolve_warm_up_count(None, 100), MAX_WARM_UP_CONNECTIONS);
    }

    #[test]
    fn b4_jitter_within_0_500ms_and_varied() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let d = warm_up_jitter();
            assert!(d <= Duration::from_millis(500));
            seen.insert(d.as_millis());
        }
        assert!(seen.len() > 1, "0-500ms 抖动不应退化为固定值");
    }
}
