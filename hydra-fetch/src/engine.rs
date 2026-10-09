//! 隧道工厂与 worker 层：评分加权选节点、故障记账、单块取回（含隧道复用）。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hydra_core::scheduler::Scheduler;
use hydra_core::tcp_transport::{self, TcpNodeStream};
use hydra_protocol::HydraError;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::http::{self, BodyKind, BodyReader};
use crate::state::FetchState;

/// 单块最大尝试次数（同一轮内；轮间由编排层重新选节点）
pub const MAX_ATTEMPTS: usize = 3;
/// 分块下载最大重试轮数（每轮在最新节点状态下重新选节点）
pub const MAX_ROUNDS: usize = 3;

/// 隧道工厂：`Scheduler`（评分/记账）+ 凭据。Clone 语义 = 共享同一调度器
/// 评分面（多 worker 的失败记账互相可见）。
pub struct TunnelFactory {
    scheduler: Arc<Scheduler>,
    sni: String,
    trust: tcp_transport::TlsTrust,
    auth_key: Vec<u8>,
}

impl Clone for TunnelFactory {
    fn clone(&self) -> Self {
        Self {
            scheduler: Arc::clone(&self.scheduler),
            sni: self.sni.clone(),
            trust: self.trust.clone(),
            auth_key: self.auth_key.clone(),
        }
    }
}

impl TunnelFactory {
    pub fn new(
        scheduler: Arc<Scheduler>,
        sni: String,
        trust: tcp_transport::TlsTrust,
        auth_key: Vec<u8>,
    ) -> Self {
        Self {
            scheduler,
            sni,
            trust,
            auth_key,
        }
    }

    /// 评分加权随机选节点（排名权重：最优 N、次优 N-1……分散且偏向最优；
    /// 本用途非密码学随机，避免引入 rand 依赖）
    fn pick_weighted(&self, nodes: &[hydra_protocol::NodeInfo]) -> Option<SocketAddr> {
        if nodes.is_empty() {
            return None;
        }
        let total: u64 = (1..=nodes.len() as u64).sum();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(1);
        let mut pick = (nanos ^ (std::process::id() as u64).rotate_left(17)) % total;
        for (i, n) in nodes.iter().enumerate() {
            let w = (nodes.len() - i) as u64;
            if pick < w {
                return Some(n.address);
            }
            pick -= w;
        }
        nodes.first().map(|n| n.address)
    }

    /// 打开隧道（评分加权选节点 + 握手 + 目标帧 + 2B 应答）。
    /// 失败记账对齐 open_target 语义：`TargetUnreachable` = 目标侧问题，换节点
    /// 大概率同样失败，直接报错不污染评分；`ProtocolError` = 本地编码问题同不
    /// 标记；其余传输错误标记节点 Offline 后继续下一候选（候选耗尽报最后错误）。
    pub async fn open(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<(SocketAddr, TcpNodeStream), String> {
        let candidates = self.scheduler.get_nodes_by_priority().await;
        let mut last_err = HydraError::ConnectionError("无可用节点".to_string());
        for _ in 0..candidates.len().max(1) {
            let Some(node) = self.pick_weighted(&candidates) else {
                break;
            };
            let stream =
                match tcp_transport::connect_channel(node, &self.sni, &self.trust, &self.auth_key)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("节点 {node} 握手失败，标记 Offline 并换节点: {e}");
                        self.scheduler.mark_node_offline(&node).await;
                        last_err = e;
                        continue;
                    }
                };
            let stream = match tcp_transport::request_target(
                stream,
                &format!("{target_host}:{target_port}"),
            )
            .await
            {
                Ok(s) => s,
                Err(HydraError::TargetUnreachable(m)) => {
                    return Err(format!("目标不可达（节点 {node} 健康，不标记故障）: {m}"));
                }
                Err(HydraError::ProtocolError(m)) => {
                    return Err(format!("本地协议错误: {m}"));
                }
                Err(e) => {
                    tracing::warn!("节点 {node} 目标帧失败，标记 Offline 并换节点: {e}");
                    self.scheduler.mark_node_offline(&node).await;
                    last_err = e;
                    continue;
                }
            };
            return Ok((node, stream));
        }
        Err(format!("隧道建立失败: {last_err}"))
    }
}

/// 单块取回错误分类
pub enum ChunkError {
    /// 内容变更（If-Range 不匹配 / Range 被忽略 / 416）——终止并行，重下
    ContentChanged,
    /// 可重试（传输故障/5xx/超时）；隧道已丢弃
    Retryable(String),
    /// 致命（如 403 拒绝）——终止整个下载
    Fatal(String),
}

/// worker 持有的隧道（节点 + 目标站 TLS 流）；None = 需要新建
pub type WorkerTunnel = Option<(SocketAddr, tokio_rustls::client::TlsStream<TcpNodeStream>)>;

/// 块取回上下文（目标站定位与校验器；与 worker 持久状态分离便于复用）
pub struct ChunkCtx<'a> {
    pub factory: &'a TunnelFactory,
    pub tls: &'a crate::target_tls::TargetTlsConnector,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub if_range: Option<&'a str>,
}

/// 取回一个块并写入文件当前位置（调用方负责先 seek 到块起点）。
/// 成功后**保留隧道**供下一块复用（keep-alive：Content-Length/chunked 界定
/// 完整 body 后连接干净）；失败一律丢弃隧道（状态可能已脏）。
pub async fn fetch_chunk(
    ctx: &ChunkCtx<'_>,
    tunnel: &mut WorkerTunnel,
    file: &mut tokio::fs::File,
    job_start: u64,
    job_end_excl: u64,
) -> Result<(), ChunkError> {
    let expect = job_end_excl - job_start;
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        // 1. 隧道（复用或新建）
        if tunnel.is_none() {
            let (node, stream) = ctx
                .factory
                .open(ctx.host, ctx.port)
                .await
                .map_err(ChunkError::Retryable)?;
            let tls_stream = ctx
                .tls
                .connect(ctx.host, stream)
                .await
                .map_err(|e| ChunkError::Retryable(format!("目标站 TLS 握手失败: {e}")))?;
            *tunnel = Some((node, tls_stream));
        }
        let (_, stream) = tunnel.as_mut().expect("上方已建隧道");

        // 2. 请求
        let req = http::build_request(
            "GET",
            ctx.host,
            ctx.path,
            Some((job_start, Some(job_end_excl - 1))),
            ctx.if_range,
        );
        if let Err(e) = stream.write_all(&req).await {
            *tunnel = None;
            if attempts >= MAX_ATTEMPTS {
                return Err(ChunkError::Retryable(format!("请求写入失败: {e}")));
            }
            continue;
        }

        // 3. 响应头
        let (head, prefix) = match http::read_response_head(stream).await {
            Ok(x) => x,
            Err(e) => {
                *tunnel = None;
                if attempts >= MAX_ATTEMPTS {
                    return Err(ChunkError::Retryable(format!("响应头读取失败: {e}")));
                }
                continue;
            }
        };

        // 4. 状态分派
        match head.status {
            206 => {}
            200 => {
                // Range 被忽略（If-Range 不匹配/服务器不支持）：按字节读只会拼脏
                return Err(ChunkError::ContentChanged);
            }
            416 => return Err(ChunkError::ContentChanged),
            408 | 429 | 500..=599 => {
                *tunnel = None;
                if attempts >= MAX_ATTEMPTS {
                    return Err(ChunkError::Retryable(format!("HTTP {}", head.status)));
                }
                continue;
            }
            code => return Err(ChunkError::Fatal(format!("HTTP {code}"))),
        }

        // 5. body：流式写文件（256KB 缓冲；16MB 块不整读进内存）。
        //    每次尝试先 seek 回块起点——中途失败重试时文件位置必须复位。
        //    响应头读取带出的 body 前缀经 BodyReader 统一交付（不重复写入）
        let expect_len = match head.body_kind {
            BodyKind::Length(n) => n,
            _ => {
                // chunked/EOF 帧式无法界定块边界且连接不可复用——该块换新隧道
                // 重试；若服务器恒定如此，轮次耗尽后整体失败（罕见：Range 206
                // 几乎恒带 Content-Length）
                *tunnel = None;
                if attempts >= MAX_ATTEMPTS {
                    return Err(ChunkError::Retryable(
                        "206 响应无 Content-Length（chunked/EOF），无法定界块".to_string(),
                    ));
                }
                continue;
            }
        };
        if expect_len != expect {
            return Err(ChunkError::ContentChanged);
        }
        file.seek(std::io::SeekFrom::Start(job_start))
            .await
            .map_err(|e| ChunkError::Retryable(format!("文件 seek 失败: {e}")))?;
        let mut reader = BodyReader::new(stream, &head, prefix);
        let mut written = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            if written >= expect_len {
                break;
            }
            let want = buf.len().min((expect_len - written) as usize);
            let n = match reader.read(&mut buf[..want]).await {
                Ok(n) => n,
                Err(e) => {
                    *tunnel = None;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(ChunkError::Retryable(format!("body 读取失败: {e}")));
                    }
                    break; // 换新隧道重试本块（从头重下该块）
                }
            };
            if n == 0 {
                *tunnel = None;
                if attempts >= MAX_ATTEMPTS {
                    return Err(ChunkError::Retryable("body 提前结束".to_string()));
                }
                break;
            }
            if let Err(e) = file.write_all(&buf[..n]).await {
                return Err(ChunkError::Retryable(format!("文件写入失败: {e}")));
            }
            written += n as u64;
        }
        if written == expect_len {
            return Ok(());
        }
        if attempts >= MAX_ATTEMPTS {
            return Err(ChunkError::Retryable(format!(
                "块读取不完整（{written}/{expect_len}）"
            )));
        }
        // 未满 attempts：continue 重试（从头重下该块）
    }
}

/// 标记块完成（位图 + 字节计数），随后调用方负责保存状态文件
pub fn mark_done(state: &mut FetchState, fetched: &AtomicU64, index: usize, len: u64) {
    if let Some(d) = state.done.get_mut(index) {
        *d = true;
    }
    fetched.fetch_add(len, Ordering::Relaxed);
}
