use quinn::{Connection, Endpoint, SendStream, RecvStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use hydra_protocol::{Result, HydraError};

/// 池中单条连接的包装
struct PooledConnection {
    connection: Connection,
    /// 最后一次使用此连接的时间
    last_used: Instant,
    /// 此连接已被用于打开流的次数
    use_count: u64,
}

impl PooledConnection {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            last_used: Instant::now(),
            use_count: 0,
        }
    }

    /// 检查连接是否仍然可用（未关闭）
    fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// 获取一条双向流，同时更新使用记录
    async fn open_bi(&mut self) -> Result<(SendStream, RecvStream)> {
        let streams = self.connection.open_bi().await
            .map_err(|e| HydraError::ProtocolError(format!("Failed to open stream: {}", e)))?;
        self.last_used = Instant::now();
        self.use_count += 1;
        Ok(streams)
    }
}

/// 连接池配置
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// 每个远端地址最多保留的空闲连接数
    pub max_idle_per_node: usize,
    /// 空闲连接的存活时间，超过后在下次清理时移除
    pub idle_timeout: Duration,
    /// 连接池清理间隔
    pub cleanup_interval: Duration,
    /// 新连接的握手超时
    pub connect_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_node: 4,
            idle_timeout: Duration::from_secs(300),  // 5 分钟
            cleanup_interval: Duration::from_secs(60), // 每分钟清理一次
            connect_timeout: Duration::from_secs(10),
        }
    }
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

    /// 从池中获取一条到指定地址的双向流
    pub async fn get_stream(
        &self,
        addr: SocketAddr,
    ) -> Result<(SendStream, RecvStream)> {
        // 尝试从池中获取现有连接
        {
            let mut pools = self.pools.write().await;
            if let Some(conns) = pools.get_mut(&addr) {
                // 从尾部取（LIFO），优先复用最近活跃的连接
                while let Some(mut pc) = conns.pop() {
                    if pc.is_alive() {
                        match pc.open_bi().await {
                            Ok(streams) => {
                                // 将连接放回池中（它还在使用中）
                                conns.push(pc);
                                return Ok(streams);
                            }
                            Err(e) => {
                                warn!("Failed to open stream on pooled connection to {}: {}", addr, e);
                                // 连接可能已损坏，丢弃它
                            }
                        }
                    }
                    // 连接已死或无法打开流，丢弃
                }
            }
        }

        // 没有可用连接，建立新连接
        info!("Pool miss: establishing new QUIC connection to {}", addr);
        let connection = self.connect(addr).await?;

        let mut pc = PooledConnection::new(connection);
        let streams = pc.open_bi().await?;

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
                    warn!("Attempt {}/{} failed for {}: {}", attempt + 1, max_retries, addr, e);
                    last_error = Some(e);
                    // 短暂等待后重试
                    if attempt < max_retries - 1 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| HydraError::ConnectionError("All retries failed".to_string())))
    }

    /// 移除指定地址的所有连接（当检测到连接问题时调用）
    pub async fn remove_all(&self, addr: &SocketAddr) {
        let mut pools = self.pools.write().await;
        if let Some(conns) = pools.remove(addr) {
            info!("Removed {} connections to {} from pool", conns.len(), addr);
        }
    }

    /// 建立新的 QUIC 连接
    async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let connecting = self.endpoint.connect(addr, "localhost")?;
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
                Err(HydraError::ConnectionError(
                    format!("Connection to {} timed out", addr),
                ))
            }
        }
    }

    /// 主动向池中预热连接（可在启动时调用）
    pub async fn warm_up(&self, addr: SocketAddr, count: usize) {
        for _ in 0..count {
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
    async fn cleanup(pools: &RwLock<HashMap<SocketAddr, Vec<PooledConnection>>>, idle_timeout: Duration) {
        let mut pools = pools.write().await;
        let now = Instant::now();
        let mut total_removed = 0;

        for (_addr, conns) in pools.iter_mut() {
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
            info!("Connection pool cleanup: removed {} stale connections", total_removed);
        }
    }

    /// 获取当前池中所有地址的连接数统计
    pub async fn stats(&self) -> HashMap<SocketAddr, usize> {
        let pools = self.pools.read().await;
        pools.iter().map(|(addr, conns)| (*addr, conns.len())).collect()
    }
}
