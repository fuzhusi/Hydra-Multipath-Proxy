//! 下载编排：探测 → 分块计划 → 多轮 worker 池 → 拼装/续传/校验/就位。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use hydra_core::scheduler::Scheduler;
use hydra_protocol::{NodeInfo, NodeStatus};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::engine::{
    fetch_chunk, mark_done, ChunkError, TunnelFactory, WorkerTunnel, MAX_ATTEMPTS, MAX_ROUNDS,
};
use crate::http::{self, BodyReader};
use crate::probe::{self, ProbeResult};
use crate::state::FetchState;
use crate::target_tls::TargetTlsConnector;

#[derive(Debug, Clone)]
pub struct FetchConfig {
    pub nodes: Vec<std::net::SocketAddr>,
    pub sni: String,
    pub trust: hydra_core::tcp_transport::TlsTrust,
    pub auth_key: Vec<u8>,
    /// 并发 worker 数（0 = 自动 min(16, 节点数×4)）
    pub workers: usize,
    pub chunk_size: u64,
    pub url: String,
    pub output: PathBuf,
    pub expect_sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct ChunkJob {
    index: usize,
    start: u64,
    end_excl: u64,
}

/// 单轮共享状态（每轮重建——jobs 为该轮失败块队列）
struct Shared {
    factory: TunnelFactory,
    tls: TargetTlsConnector,
    jobs: Vec<ChunkJob>,
    cursor: AtomicUsize,
    file_path: PathBuf,
    state: std::sync::Mutex<FetchState>,
    state_path: PathBuf,
    fetched: Arc<AtomicU64>,
    if_range: Option<String>,
    host: String,
    port: u16,
    path: String,
    /// 内容变更终止（If-Range 不匹配等）：停止一切重试，要求整文件重下
    content_changed: std::sync::atomic::AtomicBool,
    /// 致命错误（如 403）：同样终止一切重试，但保留状态文件且错误文案独立
    fatal: std::sync::Mutex<Option<String>>,
}

impl Shared {
    fn complete(&self, job: &ChunkJob) {
        mark_done(
            &mut self.state.lock().unwrap(),
            &self.fetched,
            job.index,
            job.end_excl - job.start,
        );
    }

    fn content_changed(&self) -> bool {
        self.content_changed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn flag_content_changed(&self) {
        self.content_changed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn flag_fatal(&self, msg: String) {
        *self.fatal.lock().unwrap() = Some(msg);
        self.content_changed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn fatal_msg(&self) -> Option<String> {
        self.fatal.lock().unwrap().clone()
    }
}

/// worker：消费本轮块队列；每块 ≤MAX_ATTEMPTS 次尝试（每次新建/复用隧道）；
/// ContentChanged 置全局终止标志；轮内失败块经 fail_tx 交回编排层进下一轮。
async fn worker(id: usize, shared: Arc<Shared>, fail_tx: mpsc::UnboundedSender<ChunkJob>) {
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .open(&shared.file_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[worker-{id}] 输出文件打开失败: {e}");
            shared.flag_content_changed(); // 触发整体终止（其余 worker 检旗退出）
            return;
        }
    };
    let mut tunnel: WorkerTunnel = None;
    loop {
        if shared.content_changed() {
            return;
        }
        let idx = shared.cursor.fetch_add(1, Ordering::Relaxed);
        if idx >= shared.jobs.len() {
            return; // 本轮队列消费完毕
        }
        let job = shared.jobs[idx].clone();
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            let ctx = crate::engine::ChunkCtx {
                factory: &shared.factory,
                tls: &shared.tls,
                host: &shared.host,
                port: shared.port,
                path: &shared.path,
                if_range: shared.if_range.as_deref(),
            };
            match fetch_chunk(&ctx, &mut tunnel, &mut file, job.start, job.end_excl).await {
                Ok(()) => {
                    shared.complete(&job);
                    // 状态持久化（失败仅告警——位图丢失只影响续传，不影响本次下载）
                    let snapshot = {
                        let s = shared.state.lock().unwrap();
                        s.clone()
                    };
                    if let Err(e) = snapshot.save(&shared.state_path).await {
                        eprintln!("[worker-{id}] 状态保存失败（不影响下载）: {e}");
                    }
                    break;
                }
                Err(ChunkError::ContentChanged) => {
                    eprintln!("[worker-{id}] 块 {} 内容变更（If-Range 不匹配/Range 被忽略）——终止并行重下", job.index);
                    shared.flag_content_changed();
                    let _ = fail_tx.send(job.clone());
                    return;
                }
                Err(ChunkError::Fatal(e)) => {
                    eprintln!("[worker-{id}] 块 {} 致命错误: {e}", job.index);
                    shared.flag_fatal(e);
                    let _ = fail_tx.send(job.clone());
                    return;
                }
                Err(ChunkError::Retryable(e)) => {
                    eprintln!(
                        "[worker-{id}] 块 {} 第 {attempts}/{MAX_ATTEMPTS} 次尝试失败: {e}",
                        job.index
                    );
                    if attempts >= MAX_ATTEMPTS {
                        let _ = fail_tx.send(job.clone());
                        break;
                    }
                }
            }
        }
    }
}

/// 主入口：返回 Ok = 下载完成（文件已就位于 output）
pub async fn run(cfg: FetchConfig) -> Result<(), String> {
    if cfg.nodes.is_empty() {
        return Err("未配置节点（HYDRA_NODES 环境变量或位置参数）".to_string());
    }
    // 1. 调度器 + 恢复探测器（测速评分照常工作）+ 工厂 + 目标 TLS
    let scheduler = Arc::new(Scheduler::new());
    for (idx, addr) in cfg.nodes.iter().enumerate() {
        scheduler
            .add_node(NodeInfo {
                address: *addr,
                bandwidth: (100.0 - idx as f64 * 10.0).max(10.0),
                latency: 10.0,
                loss_rate: 0.01,
                load: 0.5,
                status: NodeStatus::Online,
            })
            .await;
    }
    let traffic = Arc::new(hydra_core::traffic::TrafficMonitor::new());
    hydra_core::speedtest::spawn_recovery_probe(
        scheduler.clone(),
        cfg.trust.clone(),
        cfg.sni.clone(),
        Arc::new(cfg.auth_key.clone()),
        traffic,
    );
    let factory = TunnelFactory::new(
        scheduler.clone(),
        cfg.sni.clone(),
        cfg.trust.clone(),
        cfg.auth_key.clone(),
    );
    let tls = TargetTlsConnector::new()?;

    // 2. 探测
    println!("探测目标: {}", cfg.url);
    let pr: ProbeResult = probe::probe(&tls, &factory, &cfg.url).await?;
    let total = pr
        .total_len
        .ok_or_else(|| "目标未提供 Content-Length（动态内容），无法分块下载".to_string())?;
    let parallel = pr.accept_ranges && total > 0;
    println!(
        "目标总长 {:.2}MB | 分块并行: {} | 校验器: {}",
        total as f64 / 1048576.0,
        if parallel {
            "是"
        } else {
            "否（单流回落）"
        },
        if pr.etag.is_some() {
            "ETag"
        } else if pr.last_modified.is_some() {
            "Last-Modified（弱）"
        } else {
            "无"
        },
    );

    let part_path = cfg.output.with_extension("part");
    let state_path = FetchState::path_for(&cfg.output);
    let if_range = pr.etag.clone().or_else(|| pr.last_modified.clone());

    if !parallel {
        // 单流回落：清掉过期状态文件；就位尾段（校验/rename）与并行路径共用
        let _ = tokio::fs::remove_file(&state_path).await;
        single_stream(&factory, &tls, &pr, &part_path).await?;
    } else {
        parallel_download(
            cfg.clone(),
            factory,
            tls,
            pr,
            total,
            &part_path,
            &state_path,
            if_range,
        )
        .await?;
    }

    // ── 统一就位尾段：SHA-256 校验 → rename → 删状态文件 ──
    if let Some(expect) = &cfg.expect_sha256 {
        print!("校验 SHA-256…");
        let actual = crate::sha256::file_sha256_hex(part_path.as_path())
            .await
            .map_err(|e| format!("SHA-256 计算失败: {e}"))?;
        if !actual.eq_ignore_ascii_case(expect) {
            return Err(format!(
                "SHA-256 不匹配：期望 {expect}，实际 {actual}（文件已保留于 {}）",
                part_path.display()
            ));
        }
        println!("通过");
    }
    tokio::fs::rename(part_path, &cfg.output)
        .await
        .map_err(|e| format!("文件就位失败: {e}"))?;
    let _ = tokio::fs::remove_file(state_path).await;
    println!("✓ 下载完成: {}", cfg.output.display());
    Ok(())
}

/// 并行分块下载（多轮 worker 池；就位尾段由 run() 统一执行）
#[allow(clippy::too_many_arguments)]
async fn parallel_download(
    cfg: FetchConfig,
    factory: TunnelFactory,
    tls: TargetTlsConnector,
    pr: ProbeResult,
    total: u64,
    part_path: &PathBuf,
    state_path: &PathBuf,
    if_range: Option<String>,
) -> Result<(), String> {
    // 3. 状态恢复（评审 P0：URL/总长/块大小任一漂移即失效重下）
    let chunk_size = cfg.chunk_size.max(1);
    let mut st = match FetchState::load(&state_path.clone()).await {
        Ok(Some(s)) if s.resumable(&cfg.url, total, chunk_size).is_some() => {
            // 服务器当前校验器与状态文件一致才可续传（ETag 优先，Last-Modified 兜底）
            let validator_match = match (&s.etag, &pr.etag) {
                (Some(a), Some(b)) => a == b,
                _ => match (&s.last_modified, &pr.last_modified) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                },
            };
            if validator_match {
                println!(
                    "断点续传：已完成 {}/{} 块（剩余 {:.2}MB）",
                    s.done.iter().filter(|d| **d).count(),
                    s.done.len(),
                    s.remaining_bytes() as f64 / 1048576.0
                );
                s
            } else {
                println!("状态文件校验器与服务器不一致——重新下载");
                FetchState::new(
                    &cfg.url,
                    total,
                    chunk_size,
                    pr.etag.clone(),
                    pr.last_modified.clone(),
                )
            }
        }
        _ => FetchState::new(
            &cfg.url,
            total,
            chunk_size,
            pr.etag.clone(),
            pr.last_modified.clone(),
        ),
    };

    // 4. 预分配 .part（总长固定；分块按偏移写入）
    {
        let f = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&part_path)
            .await
            .map_err(|e| format!("输出文件打开失败: {e}"))?;
        f.set_len(total)
            .await
            .map_err(|e| format!("文件预分配失败: {e}"))?;
    }

    // 5. 多轮 worker 池（≤3 轮；轮间节点故障记账已刷新）
    let mut jobs: Vec<ChunkJob> = st
        .done
        .iter()
        .enumerate()
        .filter(|(_, d)| !**d)
        .map(|(i, _)| ChunkJob {
            index: i,
            start: i as u64 * chunk_size,
            end_excl: ((i as u64 + 1) * chunk_size).min(total),
        })
        .collect();
    let fetched = Arc::new(AtomicU64::new(0));
    let total_to_fetch: u64 = jobs.iter().map(|j| j.end_excl - j.start).sum();
    // 0 = 自动 min(16, 节点数×4)（与 --help 承诺一致）；显式值 clamp 1..=16
    let workers = if cfg.workers == 0 {
        cfg.nodes.len().saturating_mul(4).clamp(1, 16)
    } else {
        cfg.workers.clamp(1, 16)
    }
    .min(jobs.len().max(1));

    // 进度报告（1s 粒度；下载结束即退出）
    let progress_fetched = Arc::clone(&fetched);
    let reporter = tokio::spawn(async move {
        let mut last_bytes = 0u64;
        let mut last_t = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let now = progress_fetched.load(Ordering::Relaxed);
            let speed =
                now.saturating_sub(last_bytes) as f64 / last_t.elapsed().as_secs_f64().max(0.001);
            last_bytes = now;
            last_t = std::time::Instant::now();
            eprint!(
                "\r进度 {:.1}%  {:.2}MB/s    ",
                now as f64 / total_to_fetch.max(1) as f64 * 100.0,
                speed / 1048576.0
            );
        }
    });

    let mut round = 0usize;
    loop {
        round += 1;
        if jobs.is_empty() {
            break;
        }
        if round > 3 {
            break;
        }
        if round > 1 {
            println!("第 {round} 轮重试：{} 个块", jobs.len());
        }
        let shared = Arc::new(Shared {
            factory: factory.clone(),
            tls: tls.clone(),
            jobs: jobs.clone(),
            cursor: AtomicUsize::new(0),
            file_path: part_path.clone(),
            state: std::sync::Mutex::new(st.clone()),
            state_path: state_path.clone(),
            fetched: Arc::clone(&fetched),
            if_range: if_range.clone(),
            host: pr.host.clone(),
            port: pr.port,
            path: pr.path.clone(),
            content_changed: std::sync::atomic::AtomicBool::new(false),
            fatal: std::sync::Mutex::new(None),
        });
        let (fail_tx, mut fail_rx) = mpsc::unbounded_channel::<ChunkJob>();
        let mut handles = Vec::new();
        for id in 0..workers {
            handles.push(tokio::spawn(worker(
                id,
                Arc::clone(&shared),
                fail_tx.clone(),
            )));
        }
        drop(fail_tx); // 全部 worker 结束后 recv 返回 None
        while fail_rx.recv().await.is_some() {}
        for h in handles {
            let _ = h.await;
        }
        st = shared.state.lock().unwrap().clone();
        if let Some(msg) = shared.fatal_msg() {
            reporter.abort();
            // 致命错误：保留状态文件（配置修复后续传）
            return Err(msg);
        }
        if shared.content_changed() {
            reporter.abort();
            let _ = tokio::fs::remove_file(state_path).await;
            return Err("目标内容在下载过程中变更（校验器不匹配）——已终止，请重新下载".to_string());
        }
        jobs = {
            st.done
                .iter()
                .enumerate()
                .filter(|(_, d)| !**d)
                .map(|(i, _)| ChunkJob {
                    index: i,
                    start: i as u64 * chunk_size,
                    end_excl: ((i as u64 + 1) * chunk_size).min(total),
                })
                .collect()
        };
    }
    reporter.abort();
    eprint!("\r");

    if !jobs.is_empty() {
        return Err(format!(
            "{} 个块在 {MAX_ROUNDS} 轮重试后仍失败——已保留断点状态，稍后重跑同一命令可续传",
            jobs.len()
        ));
    }

    // 6. 就位尾段（校验/rename/删状态）由 run() 统一执行
    Ok(())
}

/// 单流回落：全量 GET（BodyReader 兼容三种帧式），不支持断点续传
async fn single_stream(
    factory: &TunnelFactory,
    tls: &TargetTlsConnector,
    pr: &ProbeResult,
    part_path: &PathBuf,
) -> Result<(), String> {
    let (_node, tunnel) = factory.open(&pr.host, pr.port).await?;
    let mut tls_stream = tls.connect(&pr.host, tunnel).await?;
    let req = http::build_request("GET", &pr.host, &pr.path, None, None);
    tokio::io::AsyncWriteExt::write_all(&mut tls_stream, &req)
        .await
        .map_err(|e| format!("请求写入失败: {e}"))?;
    let (head, prefix) = http::read_response_head(&mut tls_stream)
        .await
        .map_err(|e| format!("响应读取失败: {e}"))?;
    if head.status != 200 && head.status != 206 {
        return Err(format!("单流下载失败（HTTP {}）", head.status));
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)
        .await
        .map_err(|e| format!("输出文件打开失败: {e}"))?;
    let mut reader = BodyReader::new(&mut tls_stream, &head, prefix);
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("读取失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("写入失败: {e}"))?;
        total += n as u64;
        eprint!("\r单流下载中… {:.2}MB", total as f64 / 1048576.0);
    }
    eprintln!();
    if let Some(expect_len) = pr.total_len {
        if total != expect_len {
            return Err(format!(
                "长度不匹配：期望 {expect_len}，实际 {total}（Content-Length 与实际 body 不符）"
            ));
        }
    }
    println!("✓ 单流下载完成: {total} 字节");
    Ok(())
}
