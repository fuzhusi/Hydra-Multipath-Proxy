//! UDP-over-proxy 节点侧中继：在已认证的单条 TCP/TLS 流上多路复用 UDP 会话。
//!
//! 入口由 [`crate::tcp_server`] 分流：地址帧目标以 [`UDP_RELAY_PREFIX`]
//! （`@udp-relay/`）开头 → 回 2B OK 后进入 [`serve`]（`@hydra-p2p/` 信令
//! 分流同款模式；普通 TCP 目标路径零改动）。
//!
//! # 会话模型
//! - 客户端对每个 UDP 会话使用唯一 session_id，首包数据隐式建立会话；
//! - 每个 session_id 绑定一个 `connect` 到目标地址的 UDP socket（首包决定
//!   目标）；同一 session 后续换目标 = 回收旧 socket、按新目标重建绑定；
//! - 收到 UDP 回包 → 以同 session_id 写下行数据帧（与上行帧对称，
//!   帧格式见 [`hydra_protocol::udp_frame`]）；
//! - 会话空闲 [`UDP_SESSION_IDLE_SECS`] 秒由回收任务移除并下行 close 帧；
//!   客户端也可发 close 帧主动关闭。
//!
//! # 资源与安全
//! - 连接级空闲看门狗 [`UDP_CONN_IDLE_SECS`]（09-P1-1）：整条连接无任何上行帧
//!   达此时长即主动关闭——防半开/静默连接永久占用连接额度（TCP/信令路径同款
//!   防护见 tcp_server pump 与 signal 读超时，UDP 路径此前三无）；
//! - 每连接会话上限 [`UDP_MAX_SESSIONS`]：满时新会话的数据报丢弃并计数，
//!   同时下行 close 帧让客户端解除映射（09-P3-6）；
//! - 数据报超限（帧编码期拒绝）丢弃并计数；
//! - 目标地址过 SSRF 过滤：字面 IP 直接复查，域名节点侧 DNS 解析（5s 超时）
//!   后复查。判定逻辑单源复用 `handler::classify_blocked_ip`（09-P2-5 起两侧
//!   收敛为同一实现，防镜像分叉）；默认拒绝私有目标，
//!   `HYDRA_ALLOW_PRIVATE_TARGETS=1` 放开，语义与 TCP 路径一致；
//! - 连接内 DNS 结果缓存（TTL 60s，≤128 条）+ 解析速率预算（1s 窗口 ≤10 次，
//!   超限丢帧）：换目标/新会话不再逐帧 getaddrinfo，防单连接打满 tokio
//!   blocking 池拖垮全节点 DNS（09-P2-3）；
//! - DNS AAAA 查询本地过滤（v4-only 节点降噪）：无 IPv6 出口路由的节点对
//!   目标端口 53 的 AAAA 查询直接合成 NODATA 应答（不建会话、不出上游），
//!   客户端回落 A 记录，从源头消除字面 v6 目标的 ENETUNREACH 错误日志。
//!   判定与开关见 [`crate::dns_aaaa`]（`HYDRA_DNS_FILTER_AAAA` 可覆盖）。
//!
//! # 任务结构
//! ```text
//! serve（上行读循环：TLS 帧 → 会话表 → 数据报；select 会话死亡通知）
//!   ├─ 每会话任务（select: 上行队列 / socket 回包 → 下行帧；异常退出经
//!   │   dead 通道上报 → 主循环删表项 + 下行 close，防僵尸会话 09-P2-2）
//!   └─ 回收任务（周期扫描 last_active，超时移除 + 下行 close）
//! ```
//! 上行读循环退出（EOF/坏帧/空闲超时）即整表 drop：各会话任务的发送队列被
//! 关闭而退出，回收任务被显式 abort——连接结束不留悬挂任务。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dns_aaaa;
use crate::handler::classify_blocked_ip;
use hydra_protocol::mask_target;
use hydra_protocol::udp_frame::{
    encode_udp_close, encode_udp_data, read_udp_frame, write_udp_frame, UdpFrame, MAX_DATAGRAM_LEN,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// UDP 中继模式的保留目标前缀（与 `@hydra-p2p/` 信令分流同款保留前缀）
pub const UDP_RELAY_PREFIX: &str = "@udp-relay/";

/// 每条连接的 UDP 会话上限（防单连接耗尽 fd/内存）。
/// 256（TUN 接线后上调）：桌面 TUN 的全流量 UDP（DNS/QUIC/P2P）单连接会话
/// 数远超原 64（P2P 场景取值）；实际内存远小于最坏预算（DNS 报文 ≪ 64KB 队列
/// 上限），且客户端 LRU（4096）+ 节点空闲回收双面限流。
pub const UDP_MAX_SESSIONS: usize = 256;

/// 会话空闲回收阈值（双向均无活动达此时长即移除会话并下行 close）
pub const UDP_SESSION_IDLE_SECS: u64 = 60;

/// 连接级空闲看门狗（09-P1-1）：整条连接无任何**上行帧**达此时长即主动关闭。
/// 与 TCP 转发路径的 pump idle（300s）对齐；会话回收（60s）先行，本阈值兜底
/// 回收"会话表已空但客户端不发帧不关流"的半开/静默连接。取 max(idle, 本值)。
const UDP_CONN_IDLE_SECS: u64 = 300;

/// 目标 DNS 解析超时（与 TCP 路径 resolve 的 5s 层次一致）
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// 单会话上行数据报队列深度： UDP 本就允许丢包，队列满直接丢弃（不计入
/// overlimit_drops——那是协议层超限/会话满的专属计数）
const SESSION_QUEUE_DEPTH: usize = 16;

// ── 会话表 ──────────────────────────────────────────────────────────────

/// 单个 UDP 会话的句柄：上行队列 + 共享的最后活跃时间戳（毫秒）+ 当前绑定目标。
pub(crate) struct SessionHandle {
    /// 上行数据报队列（发满即丢，UDP 语义允许）
    tx: mpsc::Sender<Vec<u8>>,
    /// 最后活跃毫秒时间戳（上行发数据/下行收回包均刷新）
    last_active_ms: Arc<AtomicU64>,
    /// 当前绑定的目标地址（同 session 换目标时用于判定需重建绑定）
    target: String,
}

impl SessionHandle {
    pub(crate) fn new(
        tx: mpsc::Sender<Vec<u8>>,
        last_active_ms: Arc<AtomicU64>,
        target: String,
    ) -> Self {
        Self {
            tx,
            last_active_ms,
            target,
        }
    }

    pub(crate) fn touch(&self) {
        self.last_active_ms.store(now_ms(), Ordering::Relaxed);
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// 克隆句柄（仅克隆队列发送端；用于不在持锁状态下调 touch/投递）
    pub(crate) fn clone_handle(&self) -> SessionHandle {
        SessionHandle {
            tx: self.tx.clone(),
            last_active_ms: self.last_active_ms.clone(),
            target: self.target.clone(),
        }
    }
}

/// session_id → 会话句柄 的连接内会话表（上行读循环独占写；回收任务经
/// Mutex 短暂锁定移除超时项）。状态机单测见文件底部 tests。
pub(crate) struct UdpSessionTable {
    sessions: HashMap<u16, SessionHandle>,
    /// 协议层丢弃计数：会话满/数据报超限等被丢弃的上行数据报数
    pub overlimit_drops: u64,
}

impl UdpSessionTable {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            overlimit_drops: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.sessions.len() >= UDP_MAX_SESSIONS
    }

    /// 插入新会话。满表 → None（调用方丢弃数据报并计数）。
    pub(crate) fn insert(&mut self, sid: u16, handle: SessionHandle) -> Option<()> {
        if self.is_full() {
            return None;
        }
        self.sessions.insert(sid, handle);
        Some(())
    }

    pub(crate) fn get(&self, sid: u16) -> Option<&SessionHandle> {
        self.sessions.get(&sid)
    }

    pub(crate) fn remove(&mut self, sid: u16) -> Option<SessionHandle> {
        self.sessions.remove(&sid)
    }

    /// 摘除所有空闲超过 `idle` 的会话，返回其 session_id（调用方负责下行
    /// close 通知客户端）。队列发送端随句柄 drop 而关闭 → 会话任务自退出。
    pub(crate) fn reap_expired(&mut self, idle: Duration) -> Vec<u16> {
        let now = now_ms();
        let idle_ms = idle.as_millis() as u64;
        let expired: Vec<u16> = self
            .sessions
            .iter()
            .filter(|(_, h)| {
                now.saturating_sub(h.last_active_ms.load(Ordering::Relaxed)) >= idle_ms
            })
            .map(|(&sid, _)| sid)
            .collect();
        for sid in &expired {
            self.sessions.remove(sid);
        }
        expired
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── SSRF 过滤（单源复用 handler::classify_blocked_ip，09-P2-5）──────────

/// `HYDRA_ALLOW_PRIVATE_TARGETS=1` 放开私有目标（进程内首次调用时固化，
/// 与 handler.rs 同款 OnceLock 语义，防运行期改动安全边界）。
fn private_targets_allowed() -> bool {
    static ALLOW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ALLOW.get_or_init(|| {
        matches!(
            std::env::var("HYDRA_ALLOW_PRIVATE_TARGETS"),
            Ok(v) if v == "1"
        )
    })
}

/// 连接内 DNS 解析缓存（09-P2-3）：目标串 → (地址, 解析时刻)。
/// 换目标/新会话的每帧解析被 TTL 内的缓存吸收，不再逐帧 getaddrinfo——
/// 此前同 session 交替两目标即可每帧一次解析，单连接线速小帧可打满
/// tokio blocking 池（512 线程），拖垮全节点 DNS。缓存条目在解析时已过
/// SSRF 过滤，命中即跳过复查。
struct DnsCache {
    entries: HashMap<String, (SocketAddr, std::time::Instant)>,
}

impl DnsCache {
    const TTL: Duration = Duration::from_secs(60);
    const MAX_ENTRIES: usize = 128;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, target: &str) -> Option<SocketAddr> {
        let now = std::time::Instant::now();
        self.entries
            .retain(|_, (_, t)| now.duration_since(*t) < Self::TTL);
        self.entries.get(target).map(|(a, _)| *a)
    }

    fn put(&mut self, target: &str, addr: SocketAddr) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            // 上限兜底（真实客户端换目标数有限；打满即攻击流量，整体清空
            // 由解析速率预算限流，不会放大解析压力）
            self.entries.clear();
        }
        self.entries
            .insert(target.to_string(), (addr, std::time::Instant::now()));
    }
}

/// 每连接真实解析速率预算（09-P2-3）：滑动 1s 窗口内最多
/// [`ResolveBudget::MAX_PER_SEC`] 次真实 DNS 解析，超限直接丢弃该帧
/// （UDP 语义允许丢包）——缓存未命中的高频换目标不再无限消耗 blocking 池。
struct ResolveBudget {
    window_start: std::time::Instant,
    used: u32,
}

impl ResolveBudget {
    const MAX_PER_SEC: u32 = 10;

    fn new() -> Self {
        Self {
            window_start: std::time::Instant::now(),
            used: 0,
        }
    }

    fn try_take(&mut self) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= Self::MAX_PER_SEC {
            false
        } else {
            self.used += 1;
            true
        }
    }
}

/// 解析目标地址（字面 IP 优先，否则节点侧 DNS，5s 超时）并过 SSRF 过滤。
/// 命中黑名单/解析失败/超时 → None（调用方丢弃数据报并按需回收会话）。
async fn resolve_udp_target(target: &str) -> Option<SocketAddr> {
    let addr: SocketAddr = if let Ok(a) = target.parse() {
        a
    } else {
        match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(target.to_string())).await {
            Err(_) => {
                warn!("UDP 目标 DNS 解析超时: {}", mask_target(target));
                crate::metrics::metrics()
                    .target_fail
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            Ok(r) => match r {
                Ok(addrs) => {
                    // 收集后优先取 IPv4，否则首个地址（与 handler::resolve_and_connect 同语义）
                    let v: Vec<SocketAddr> = addrs.collect();
                    match v
                        .iter()
                        .find(|a| a.is_ipv4())
                        .or_else(|| v.first())
                        .copied()
                    {
                        Some(a) => a,
                        None => {
                            warn!("UDP 目标 DNS 无可用地址: {}", mask_target(target));
                            return None;
                        }
                    }
                }
                Err(e) => {
                    warn!("UDP 目标 DNS 解析失败: {} ({e})", mask_target(target));
                    crate::metrics::metrics()
                        .target_fail
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }
            },
        }
    };
    if !private_targets_allowed() {
        if let Some(reason) = classify_blocked_ip(addr.ip()) {
            warn!(
                "UDP 目标被 SSRF 过滤拒绝（{}）: {}",
                reason,
                mask_target(&addr.to_string())
            );
            crate::metrics::metrics()
                .target_fail
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
    }
    crate::metrics::metrics()
        .target_ok
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(addr)
}

// ── 中继服务 ────────────────────────────────────────────────────────────

/// UDP 中继服务入口（tcp_server 分流后调用；默认 60s 空闲回收）。
pub(crate) async fn serve<R, W>(rd: R, wr: W, max_age: Option<Duration>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_with_idle_and_filter(
        rd,
        wr,
        Duration::from_secs(UDP_SESSION_IDLE_SECS),
        None,
        max_age,
    )
    .await;
}

/// 完整形态：`aaaa_filter = None` 按节点配置自动判定（每连接读取一次，
/// 不逐帧查 env/OnceLock）；`Some(bool)` 显式强制（测试注入用）。
/// `max_age` = 连接最长寿命（V3.3 Tier1；None = 关闭）——UDP 中继是长寿命
/// 主力路径，寿命到期整连接关闭（客户端侧 UDP 通道自带重连，会话丢失由
/// 节点侧会话回收语义兜底）。
/// Send + 'static：会话/回收任务经 tokio::spawn 持有共享的 writer/表。
async fn serve_with_idle_and_filter<R, W>(
    mut rd: R,
    wr: W,
    idle: Duration,
    aaaa_filter: Option<bool>,
    max_age: Option<Duration>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let aaaa_filter = aaaa_filter.unwrap_or_else(dns_aaaa::aaaa_filter_enabled);
    let started = std::time::Instant::now();
    let age_deadline = max_age.and_then(|d| started.checked_add(d));
    let table = Arc::new(Mutex::new(UdpSessionTable::new()));
    crate::metrics::metrics()
        .udp_relay_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // 下行写端：多个会话任务 + 回收任务并发写，tokio::Mutex 串行化（帧级原子）
    let writer: Arc<tokio::sync::Mutex<W>> = Arc::new(tokio::sync::Mutex::new(wr));

    // 连接级空闲看门狗（09-P1-1）：max(idle, UDP_CONN_IDLE_SECS)。测试注入的
    // 短 idle 只影响会话回收，不影响连接级阈值（测试不必等 300s）。
    let conn_idle = idle.max(Duration::from_secs(UDP_CONN_IDLE_SECS));

    // 回收任务：周期扫描空闲会话，移除并下行 close 帧（间隔 = idle/4，下限 100ms）
    let reaper = {
        let table = table.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            let tick = (idle / 4).max(Duration::from_millis(100));
            loop {
                tokio::time::sleep(tick).await;
                let expired = table.lock().unwrap().reap_expired(idle);
                for sid in expired {
                    debug!("UDP 会话 {sid} 空闲回收，下行 close");
                    let mut w = writer.lock().await;
                    if write_udp_frame(&mut *w, &encode_udp_close(sid))
                        .await
                        .is_err()
                    {
                        return; // 客户端连接已死：回收任务随之结束
                    }
                }
            }
        })
    };

    // 会话异常死亡通知通道（09-P2-2 僵尸会话修复）：session_task 因 socket/
    // 下行写错误退出时上报 sid，主循环删表项并下行 close——否则表项残留且
    // 每帧上行 touch 使回收任务永不判定过期，会话永久黑洞。
    let (dead_tx, mut dead_rx) = mpsc::unbounded_channel::<u16>();
    // serve 自持一份发送端：避免"全部会话任务已退出"时 recv() 返回 None 被
    // 误判为连接结束（空会话表是常态）。
    let _dead_tx_keepalive = dead_tx.clone();

    // 连接内解析缓存与速率预算（09-P2-3）
    let mut dns_cache = DnsCache::new();
    let mut resolve_budget = ResolveBudget::new();
    // DNS AAAA 本地应答计数（连接关闭时汇入可观测性日志）
    let mut aaaa_local_replies = 0usize;

    // ── 上行读循环：TLS 流帧 → 会话表 → 数据报 ──
    // 帧读取独立任务（企业评审并发 B-1 修复）：read_udp_frame 是两次
    // read_exact、裸流无内部缓冲——**取消不安全**（被 select 其他分支取消
    // 会丢已消费的半帧字节，下一轮从帧中间解析 = 整条连接流失步断连）。
    // 移入专属任务（永不取消，随 rd EOF / 主循环退出后通道关闭自然结束），
    // 主循环经 mpsc 消费——mpsc::recv 取消安全，dead 分支触发不再丢字节。
    let (frame_tx, mut frame_rx) = mpsc::channel::<hydra_protocol::Result<UdpFrame>>(8);
    tokio::spawn(async move {
        loop {
            match read_udp_frame(&mut rd).await {
                Ok(f) => {
                    if frame_tx.send(Ok(f)).await.is_err() {
                        break; // 主循环已退出（连接关闭），任务随之结束
                    }
                }
                Err(e) => {
                    let _ = frame_tx.send(Err(e)).await; // 送达后任务退出
                    break;
                }
            }
        }
    });
    loop {
        // budget = min(连接空闲看门狗, 寿命剩余)：寿命到期即便活跃也唤醒
        let timeout_dur = age_deadline
            .map(|dl| conn_idle.min(dl.saturating_duration_since(std::time::Instant::now())))
            .unwrap_or(conn_idle);
        tokio::select! {
            // 会话任务异常死亡：删表项 + 下行 close（客户端解除映射后可重建）
            dead = dead_rx.recv() => {
                match dead {
                    Some(sid) => {
                        let removed = table.lock().unwrap().remove(sid).is_some();
                        if removed {
                            debug!("UDP 会话 {sid} 任务异常退出，回收并下行 close");
                            let mut w = writer.lock().await;
                            let _ = write_udp_frame(&mut *w, &encode_udp_close(sid)).await;
                        }
                    }
                    // 仅在 _dead_tx_keepalive 也被丢弃后到达（连接收尾路径），退出
                    None => break,
                }
            }
            frame = tokio::time::timeout(timeout_dur, frame_rx.recv()) => {
                // 帧来源 = 帧读取任务的 mpsc（recv 取消安全）；None = 任务已
                // 退出（EOF/协议错误/主循环退出后通道关闭）
                match frame {
                    // 连接级空闲超时：会话表可能为空（回收先行），客户端静默不关流
                    // ——主动关闭，释放 permit/fd/reaper（09-P1-1）。
                    // 寿命到期（V3.3 Tier1）：整连接关闭（区别于空闲的日志语义）
                    Err(_) => {
                        let aged = age_deadline
                            .map(|dl| std::time::Instant::now() >= dl)
                            .unwrap_or(false);
                        if aged {
                            info!("UDP 中继连接达到最长寿命，主动关闭（客户端通道将自动重连）");
                        } else {
                            info!(
                                "UDP 中继连接空闲超时（{}s 无上行帧），主动关闭",
                                conn_idle.as_secs()
                            );
                        }
                        break;
                    }
                    Ok(None) => {
                        debug!("UDP 帧读取任务已退出（客户端关闭或协议错误），连接结束");
                        break;
                    }
                    Ok(Some(Err(e))) => {
                        debug!("UDP 中继上行读结束: {e}");
                        break;
                    }
                    Ok(Some(Ok(f))) => match f {
                        UdpFrame::Close { session_id } => {
                            if table.lock().unwrap().remove(session_id).is_some() {
                                debug!("UDP 会话 {session_id} 客户端请求关闭");
                            }
                            // 未知 session 的 close 视为 no-op（幂等）
                        }
                        UdpFrame::Data {
                            session_id,
                            target,
                            datagram,
                        } => {
                            if uplink_data(
                                &table,
                                &writer,
                                session_id,
                                &target,
                                datagram,
                                &mut dns_cache,
                                &mut resolve_budget,
                                &dead_tx,
                                aaaa_filter,
                            )
                            .await
                            {
                                aaaa_local_replies += 1;
                            }
                        }
                    },
                }
            }
        }
    }

    // 连接结束：整表 drop → 各会话任务发送队列关闭而退出；回收任务显式 abort。
    // overlimit_drops 连接级汇总日志（09-P3：协议层丢弃计数此前完全不可观测）
    {
        let drops = table.lock().unwrap().overlimit_drops;
        if aaaa_local_replies > 0 {
            info!("UDP 中继连接关闭：DNS AAAA 查询本地 NODATA 应答 {aaaa_local_replies} 次（v4-only 降噪）");
        }
        if drops > 0 {
            info!("UDP 中继连接关闭：累计协议层丢弃 {drops} 个数据报（会话满/解析超限/速率预算）");
        }
    }
    reaper.abort();
    drop(table);
    info!("UDP 中继连接关闭");
}

/// 处理一帧上行数据：建会话 / 更新绑定 / 投递数据报。
/// 返回 `true` = 该数据报已本地合成应答（DNS AAAA 过滤，未投递上游）。
#[allow(clippy::too_many_arguments)]
async fn uplink_data<W>(
    table: &Arc<Mutex<UdpSessionTable>>,
    writer: &Arc<tokio::sync::Mutex<W>>,
    session_id: u16,
    target: &str,
    datagram: Vec<u8>,
    dns_cache: &mut DnsCache,
    resolve_budget: &mut ResolveBudget,
    dead_tx: &mpsc::UnboundedSender<u16>,
    aaaa_filter: bool,
) -> bool
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    // DNS AAAA 本地过滤（v4-only 节点降噪）：无 IPv6 出口的节点对 AAAA
    // 查询直接合成 NODATA 应答——不建会话、不出上游流量。客户端 OS 收到
    // 「无 AAAA」后回落 A，从源头消除 TUN/VPN 模式字面 v6 目标的
    // ENETUNREACH 错误日志（此前单节点单日 1.5 万条）。解析不中即放行。
    // 注意：拦截在会话表操作之前 return——AAAA-only 流量永不建节点会话；
    // 客户端侧映射在 send_to 写帧前已登记（hydra-core udp_relay），下行
    // NODATA 帧可被正确接收；客户端 LRU 淘汰对此类 sid 发的 close 在节点
    // 侧是幂等 no-op。
    if aaaa_filter && dns_aaaa::target_port(target) == Some(53) {
        if let Some(q_end) = dns_aaaa::aaaa_query_question_end(&datagram) {
            let reply = dns_aaaa::synthesize_nodata(&datagram, q_end);
            // 编码失败理论不可达（上限已在编码期约束）：按丢弃处理（客户端
            // DNS 重发自愈），不落入会话路径——保持「不出上游」语义
            match encode_udp_data(session_id, target, &reply) {
                Ok(frame) => {
                    let mut w = writer.lock().await;
                    if write_udp_frame(&mut *w, &frame).await.is_ok() {
                        debug!(
                            "DNS AAAA 查询本地 NODATA 应答（无 v6 出口）: {}",
                            mask_target(target)
                        );
                        return true;
                    }
                    // 下行写失败 = 客户端连接已死：直接丢弃（主循环下次读即退出）
                    return false;
                }
                Err(_) => return false,
            }
        }
    }

    // 09-P2-3（原审查 P2-1）：先查表——已存在会话且目标未变时**跳过 DNS 解析**
    // 直接投递（此前每帧 resolve：域名目标每包一次 DNS 查询放大上游、5s 解析
    // 超时会停摆该连接全部会话的上行）。
    let existing_target = {
        let t = table.lock().unwrap();
        t.get(session_id).map(|h| h.target().to_string())
    };
    if existing_target.as_deref() != Some(target) {
        // 缓存命中（TTL 内、解析时已过 SSRF）：跳过解析直接建连
        let addr = match dns_cache.get(target) {
            Some(a) => a,
            None => {
                // 解析速率预算（09-P2-3）：1s 窗口内真实解析超限直接丢帧，
                // 防单连接打满 tokio blocking 池（不回收会话——突发换目标
                // 不应抹掉既有绑定）
                if !resolve_budget.try_take() {
                    table.lock().unwrap().overlimit_drops += 1;
                    debug!(
                        "UDP 目标解析速率超限（1s ≤10 次），丢弃: {}",
                        mask_target(target)
                    );
                    return false;
                }
                // 目标解析 + SSRF 过滤失败：丢弃该数据报；已存在的会话一并回收
                // （目标失效的会话没有继续存在的意义）
                let Some(addr) = resolve_udp_target(target).await else {
                    let mut t = table.lock().unwrap();
                    t.overlimit_drops += 1;
                    if t.remove(session_id).is_some() {
                        debug!("UDP 会话 {session_id} 因目标失效而回收");
                    }
                    return false;
                };
                dns_cache.put(target, addr);
                addr
            }
        };

        // 新会话，或同 session 换目标：回收旧绑定（句柄 drop → 会话任务退出），
        // 按新目标重建 socket。锁内只做「摘旧 + 判满」，bind().await 在锁外
        // （MutexGuard 非 Send，不能跨 await）
        let full = {
            let mut t = table.lock().unwrap();
            t.remove(session_id);
            if t.is_full() {
                t.overlimit_drops += 1;
                true
            } else {
                false
            }
        };
        if full {
            // 09-P3-6：会话满对新建会话下行 close，让客户端解除映射
            // （此前静默丢弃，客户端对第 65 个目标起完全无感知）
            let mut w = writer.lock().await;
            let _ = write_udp_frame(&mut *w, &encode_udp_close(session_id)).await;
            debug!(
                "UDP 会话数达上限 {UDP_MAX_SESSIONS}，丢弃 {} 的数据报并下行 close",
                mask_target(target)
            );
            return false;
        }
        // 锁外建 socket + 派生会话任务（await 期间不持有表锁）
        match bind_session_socket(addr).await {
            Ok(socket) => {
                let (tx, rx) = mpsc::channel(SESSION_QUEUE_DEPTH);
                let last_active = Arc::new(AtomicU64::new(now_ms()));
                let handle = SessionHandle::new(tx, last_active.clone(), target.to_string());
                // 锁外 await 完成后重新上锁回填；二次查满（锁释放窗口可能有
                // 并发新建）
                let mut t = table.lock().unwrap();
                if t.is_full() {
                    t.overlimit_drops += 1;
                    return false; // socket 由 Ok(socket) 分支的 drop 关闭
                }
                if t.insert(session_id, handle).is_none() {
                    return false; // 理论不可达（is_full 已查）；保守不投递
                }
                tokio::spawn(session_task(
                    session_id,
                    socket,
                    target.to_string(),
                    rx,
                    last_active,
                    writer.clone(),
                    dead_tx.clone(),
                ));
                debug!("UDP 会话 {session_id} 建立 → {}", mask_target(target));
            }
            Err(e) => {
                table.lock().unwrap().overlimit_drops += 1;
                debug!("UDP socket 绑定失败（{}）: {e}", mask_target(target));
                return false;
            }
        }
    }

    // 投递数据报（会话可能刚建立也可能已存在）；队列满/会话已死 → 丢弃。
    // 克隆句柄后立即释放表锁，touch/try_send 不占用锁。
    let handle = table
        .lock()
        .unwrap()
        .get(session_id)
        .map(|h| h.clone_handle());
    match handle {
        Some(h) => {
            h.touch();
            if let Err(e) = h.tx.try_send(datagram) {
                if matches!(e, tokio::sync::mpsc::error::TrySendError::Closed(_)) {
                    // 队列发送端已关闭 = 会话任务已死（socket/下行写错误退出）。
                    // 09-P2-2：删表项 + 下行 close，防「每帧 touch 使回收任务
                    // 永不判定过期」的僵尸会话黑洞。
                    let removed = table.lock().unwrap().remove(session_id).is_some();
                    if removed {
                        debug!(
                            "UDP 会话 {session_id} 上行队列已关闭（任务已死），回收并下行 close"
                        );
                        let mut w = writer.lock().await;
                        let _ = write_udp_frame(&mut *w, &encode_udp_close(session_id)).await;
                    }
                } else {
                    // 队列满 = 对端 socket 短时过载：UDP 语义直接丢包
                    debug!("UDP 会话 {session_id} 上行队列满，丢弃数据报");
                }
            }
        }
        None => {
            table.lock().unwrap().overlimit_drops += 1;
        }
    }
    false
}

/// 按目标地址族绑定本地 UDP socket 并 connect 到目标（收发免地址参数，
/// 且内核只收来自该目标的回包——会话绑定语义）。
async fn bind_session_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let local = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// 单会话任务：select 上行队列（数据报 → socket）与 UDP 回包（→ 下行帧）。
/// 上行队列关闭（表移除/连接结束）或 socket 出错即退出；任何**异常**退出
/// （socket 收发错误/下行写错误）经 `dead_tx` 上报 sid——主循环据此删表项
/// 并下行 close（09-P2-2 僵尸会话修复；表移除/连接结束的正常退出无需上报，
/// 表项已不在）。
async fn session_task<W>(
    session_id: u16,
    socket: UdpSocket,
    target: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
    last_active: Arc<AtomicU64>,
    writer: Arc<tokio::sync::Mutex<W>>,
    dead_tx: mpsc::UnboundedSender<u16>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Metrics v2：活跃会话 gauge（任务生命周期 = 会话生命周期）
    let _session_guard = crate::metrics::UdpSessionGuard::enter();
    let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
    loop {
        // 不用 biased：持续高速上行不应饥饿下行回包（审查批次 P3）
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(datagram) => {
                    match socket.send(&datagram).await {
                        Ok(_) => {
                            crate::metrics::metrics()
                                .udp_datagrams_fwd
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {
                            debug!("UDP 会话 {session_id} socket 发送失败，会话结束");
                            crate::metrics::metrics()
                                .udp_datagrams_drop
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let _ = dead_tx.send(session_id);
                            break;
                        }
                    }
                }
                None => break, // 表移除/连接结束：会话任务自退出
            },
            n = socket.recv(&mut buf) => match n {
                Ok(n) => {
                    last_active.store(now_ms(), Ordering::Relaxed);
                    // 下行帧与上行对称：session_id + 目标地址帧 + 数据报
                    let frame = match encode_udp_data(session_id, &target, &buf[..n]) {
                        Ok(f) => f,
                        Err(_) => continue, // 理论不可达（上限已在编码期约束）
                    };
                    let mut w = writer.lock().await;
                    if write_udp_frame(&mut *w, &frame).await.is_err() {
                        debug!("UDP 会话 {session_id} 下行写失败，会话结束");
                        let _ = dead_tx.send(session_id);
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 会话 {session_id} socket 接收错误: {e}");
                    let _ = dead_tx.send(session_id);
                    break;
                }
            },
        }
    }
}

/// 上行投递的窄接口预留位已并入 [`SessionHandle::clone_handle`]（会话表
/// 单测直接用真实句柄 + mpsc 接收端，不依赖真实 socket）。
#[cfg(test)]
mod tests {
    use super::*;
    use hydra_protocol::udp_frame::UdpFrame;
    use tokio::io::duplex;

    fn handle_with_age(age_ms: u64) -> (SessionHandle, mpsc::Receiver<Vec<u8>>, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::channel(4);
        let last = Arc::new(AtomicU64::new(now_ms().saturating_sub(age_ms)));
        (
            SessionHandle::new(tx, last.clone(), "127.0.0.1:5353".to_string()),
            rx,
            last,
        )
    }

    // ── 表状态机 ──

    #[test]
    fn 表_插入_上限_移除() {
        let mut t = UdpSessionTable::new();
        assert!(t.is_empty());
        for sid in 0..UDP_MAX_SESSIONS as u16 {
            let (h, _rx, _) = handle_with_age(0);
            assert!(t.insert(sid, h).is_some(), "sid {sid} 应可插入");
        }
        assert_eq!(t.len(), UDP_MAX_SESSIONS);
        assert!(t.is_full());
        let (h, _rx, _) = handle_with_age(0);
        assert!(t.insert(999, h).is_none(), "满表插入应被拒绝");
        assert_eq!(t.remove(0).map(|_| ()), Some(()));
        assert!(!t.is_full());
    }

    #[test]
    fn 表_空闲回收_只摘超时项() {
        let mut t = UdpSessionTable::new();
        let (_h_fresh, _rx_fresh, _) = handle_with_age(0);
        let (h_old, mut rx_old, _) = handle_with_age(120_000);
        t.insert(1, _h_fresh).unwrap();
        t.insert(2, h_old).unwrap();
        let expired = t.reap_expired(Duration::from_secs(60));
        assert_eq!(expired, vec![2]);
        assert!(t.get(1).is_some(), "活跃会话不应被回收");
        assert!(t.get(2).is_none());
        // 被回收会话的句柄已 drop → 发送端关闭：接收端读到 None（会话任务据此退出）
        drop(t);
        assert!(rx_old.blocking_recv().is_none());
    }

    #[test]
    fn 表_touch_重置空闲计时() {
        let mut t = UdpSessionTable::new();
        let (h, _rx, last) = handle_with_age(120_000);
        t.insert(5, h).unwrap();
        // 回包活跃刷新时间戳（session_task 下行路径同样调 touch）
        last.store(now_ms(), Ordering::Relaxed);
        assert!(t.reap_expired(Duration::from_secs(60)).is_empty());
    }

    // ── SSRF 单源判定（复用 handler::classify_blocked_ip）──

    #[test]
    fn ssrf_判定_与tcp路径同源对齐() {
        use std::net::IpAddr;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(classify_blocked_ip(p("127.0.0.1")), Some("loopback"));
        assert_eq!(classify_blocked_ip(p("10.1.2.3")), Some("RFC1918 private"));
        assert_eq!(
            classify_blocked_ip(p("192.168.1.1")),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip(p("169.254.169.254")),
            Some("link-local")
        );
        assert_eq!(
            classify_blocked_ip(p("::ffff:127.0.0.1")),
            Some("loopback"),
            "IPv4 映射形态须按 v4 规则复查"
        );
        assert_eq!(
            classify_blocked_ip(p("64:ff9b::a00:1")),
            Some("RFC1918 private"),
            "NAT64 内嵌 v4 须复查"
        );
        assert_eq!(classify_blocked_ip(p("fd00::1")), Some("IPv6 ULA private"));
        assert_eq!(
            classify_blocked_ip(p("224.0.0.1")),
            Some("multicast 224.0.0.0/4")
        );
        // 09-P2-5 收敛单源后 UDP 路径同样拦 v6 组播/2001:db8 与 TEST-NET
        assert_eq!(
            classify_blocked_ip(p("ff02::fb")),
            Some("IPv6 multicast ff00::/8")
        );
        assert_eq!(
            classify_blocked_ip(p("2001:db8::1")),
            Some("documentation 2001:db8::/32")
        );
        assert_eq!(
            classify_blocked_ip(p("192.0.2.1")),
            Some("documentation TEST-NET-1 192.0.2.0/24")
        );
        assert_eq!(classify_blocked_ip(p("8.8.8.8")), None);
        assert_eq!(classify_blocked_ip(p("2606:4700::1111")), None);
    }

    // ── 全链路回环（无 TLS：serve 直挂 duplex 流，验证帧封装/分发/回收）──

    /// 起 127.0.0.1 UDP 回显 socket，返回其 "ip:port"
    async fn spawn_udp_echo() -> String {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn relay_回环_数据帧双向与会话分发() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        let echo = spawn_udp_echo().await;
        let (mut cli, srv) = duplex(65536);
        // DuplexStream 不可 Clone：split 出节点侧读写两半交给 serve
        let (srv_rd, srv_wr) = tokio::io::split(srv);
        tokio::spawn(serve_with_idle_and_filter(
            srv_rd,
            srv_wr,
            Duration::from_secs(60),
            None,
            None, // max_age
        ));

        // 两个会话各自隐式建立并回环（数据报按 session_id 分发不串线）
        for sid in [1u16, 2] {
            let payload = format!("ping-{sid}").into_bytes();
            write_udp_frame(&mut cli, &encode_udp_data(sid, &echo, &payload).unwrap())
                .await
                .unwrap();
            match read_udp_frame(&mut cli).await.unwrap() {
                UdpFrame::Data {
                    session_id,
                    datagram,
                    ..
                } => {
                    assert_eq!(session_id, sid);
                    assert_eq!(datagram, payload);
                }
                other => panic!("期望数据帧，实际 {other:?}"),
            }
        }

        // close 帧：节点侧回收（后续同 session 数据重新建会话，依然回环）
        write_udp_frame(&mut cli, &encode_udp_close(1))
            .await
            .unwrap();
        write_udp_frame(&mut cli, &encode_udp_data(1, &echo, b"re-usable").unwrap())
            .await
            .unwrap();
        match read_udp_frame(&mut cli).await.unwrap() {
            UdpFrame::Data { datagram, .. } => assert_eq!(datagram, b"re-usable"),
            other => panic!("期望数据帧，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_同session换目标_更新绑定() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        let echo = spawn_udp_echo().await;
        let (mut cli, srv) = duplex(65536);
        // DuplexStream 不可 Clone：split 出节点侧读写两半交给 serve
        let (srv_rd, srv_wr) = tokio::io::split(srv);
        tokio::spawn(serve_with_idle_and_filter(
            srv_rd,
            srv_wr,
            Duration::from_secs(60),
            None,
            None, // max_age
        ));
        // 同一 session 先打 A 后打 B：两次都应回环成功（绑定已更新）
        write_udp_frame(&mut cli, &encode_udp_data(7, &echo, b"first").unwrap())
            .await
            .unwrap();
        write_udp_frame(&mut cli, &encode_udp_data(7, &echo, b"second").unwrap())
            .await
            .unwrap();
        let d1 = match read_udp_frame(&mut cli).await.unwrap() {
            UdpFrame::Data { datagram, .. } => datagram,
            other => panic!("{other:?}"),
        };
        let d2 = match read_udp_frame(&mut cli).await.unwrap() {
            UdpFrame::Data { datagram, .. } => datagram,
            other => panic!("{other:?}"),
        };
        assert_eq!(d1, b"first");
        assert_eq!(d2, b"second");
    }

    #[tokio::test]
    async fn relay_空闲回收_短超时实测下行close() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        let echo = spawn_udp_echo().await;
        let (mut cli, srv) = duplex(65536);
        // DuplexStream 不可 Clone：split 出节点侧读写两半交给 serve
        let (srv_rd, srv_wr) = tokio::io::split(srv);
        tokio::spawn(serve_with_idle_and_filter(
            srv_rd,
            srv_wr,
            Duration::from_millis(300),
            None,
            None, // max_age
        ));
        write_udp_frame(&mut cli, &encode_udp_data(3, &echo, b"go").unwrap())
            .await
            .unwrap();
        assert!(matches!(
            read_udp_frame(&mut cli).await.unwrap(),
            UdpFrame::Data { .. }
        ));
        // 双向静默超过 300ms：回收任务应下行 close 帧
        let start = std::time::Instant::now();
        let frame = tokio::time::timeout(Duration::from_secs(5), read_udp_frame(&mut cli))
            .await
            .expect("应在空闲后收到下行 close")
            .unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "close 不应早于空闲阈值"
        );
        assert_eq!(frame, UdpFrame::Close { session_id: 3 });
    }

    #[tokio::test]
    async fn relay_ssrf拒绝_数据报被丢弃且不建会话() {
        // 默认拒绝私有目标（OnceLock 进程内固化：本二进制内已有测试设 1，
        // 故该用例改用公网黑名单段的字面地址验证拒绝路径，不依赖 env 状态）
        let (mut cli, srv) = duplex(4096);
        // DuplexStream 不可 Clone：split 出节点侧读写两半交给 serve
        let (srv_rd, srv_wr) = tokio::io::split(srv);
        tokio::spawn(serve_with_idle_and_filter(
            srv_rd,
            srv_wr,
            Duration::from_secs(60),
            None,
            None, // max_age
        ));
        // 240.0.0.0/4 保留段：恒被拒绝（无论 env 放宽与否）
        write_udp_frame(
            &mut cli,
            &encode_udp_data(9, "240.0.0.1:5353", b"x").unwrap(),
        )
        .await
        .unwrap();
        // 空闲阈值内不应有任何下行帧（数据报被丢弃、会话未建立）
        let r = tokio::time::timeout(Duration::from_millis(400), read_udp_frame(&mut cli)).await;
        assert!(r.is_err(), "SSRF 拒绝目标不应产生下行帧");
    }

    #[tokio::test]
    async fn relay_dns_aaaa查询_本地nodata应答且不建会话() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        // 显式注入 Some(true)：自动判定依赖节点 v6 路由探测（OnceLock 进程级
        // 缓存，开发机/CI 多有 v6 → 判定为关），测试必须绕开环境
        let echo = spawn_udp_echo().await;
        let (mut cli, srv) = duplex(65536);
        let (srv_rd, srv_wr) = tokio::io::split(srv);
        tokio::spawn(serve_with_idle_and_filter(
            srv_rd,
            srv_wr,
            Duration::from_secs(60),
            Some(true),
            None, // max_age
        ));

        // 构造真实 AAAA 查询（ID 0xABCD + qname + qtype=AAAA/qclass=IN）
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&28u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());

        write_udp_frame(&mut cli, &encode_udp_data(11, "8.8.8.8:53", &q).unwrap())
            .await
            .unwrap();

        // 下行应是同 sid 的 NODATA 应答：ID 原样 / QR=1 / RA=1 / RD 保留 /
        // AN=NS=AR=0 / 问题节逐字节回显
        match read_udp_frame(&mut cli).await.unwrap() {
            UdpFrame::Data {
                session_id,
                target,
                datagram,
            } => {
                assert_eq!(session_id, 11);
                assert_eq!(target, "8.8.8.8:53");
                assert_eq!(datagram.len(), q.len(), "应答仅含首部+问题节");
                assert_eq!(&datagram[..2], &q[..2], "事务 ID 原样");
                assert_eq!(datagram[2] & 0x80, 0x80, "QR=1");
                assert_eq!(datagram[2] & 0x01, 0x01, "RD 保留");
                assert_eq!(datagram[3], 0x80, "RA=1、RCODE=0");
                assert_eq!(&datagram[6..12], &[0; 6], "AN/NS/AR=0");
                assert_eq!(&datagram[12..], &q[12..], "问题节回显");
            }
            other => panic!("期望 NODATA 数据帧，实际 {other:?}"),
        }

        // 不出上游：此后无任何转发路径产生的下行帧
        let r = tokio::time::timeout(Duration::from_millis(400), read_udp_frame(&mut cli)).await;
        assert!(r.is_err(), "AAAA 查询不应产生上游转发");

        // 过滤开启时非 DNS 流量不受影响：普通 UDP 仍正常转发回环
        write_udp_frame(&mut cli, &encode_udp_data(12, &echo, b"plain").unwrap())
            .await
            .unwrap();
        match read_udp_frame(&mut cli).await.unwrap() {
            UdpFrame::Data { datagram, .. } => assert_eq!(datagram, b"plain"),
            other => panic!("期望回环数据帧，实际 {other:?}"),
        }
    }

    // ── 全链路 E2E（真 TLS + Noise-PSK + 客户端 open_udp_channel）──────────
    // hydra-client 是本 crate 的 dev-dependency（与信令集成测试同款依赖形态）

    #[tokio::test]
    async fn e2e_客户端udp通道到回显socket全链路() {
        std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
        use hydra_client::tcp_transport::TlsTrust;

        // 节点：随机端口 + 自签证书持久化到独立临时目录
        let dir = std::env::temp_dir().join(format!(
            "hydra-udp-relay-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let auth_key = vec![7u8; 32];
        let opts = crate::server::NodeOptions {
            max_connections: 16,
            cert_file: dir.join("cert.der"),
            key_file: dir.join("key.der"),
            ..crate::server::NodeOptions::default()
        };
        let server =
            crate::server::HydraServer::new("127.0.0.1:0".parse().unwrap(), auth_key.clone(), opts)
                .await
                .expect("节点启动");
        let node_addr = server.tcp_listen_addr.expect("TCP 监听地址");
        let cert = server.cert_der().to_vec();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 本地 UDP 回显 socket
        let echo_addr = spawn_udp_echo().await;

        // 客户端：pin 节点证书建 UDP 通道
        let trust = TlsTrust::pinned(vec![cert]);
        let mut ch =
            hydra_client::udp_relay::open_udp_channel(node_addr, "hydra.node", &trust, &auth_key)
                .await
                .expect("UDP 通道建立");

        // 数据报 → 节点中继 → UDP 回显 → 下行帧 → 客户端按 session 分发
        let payload = b"hello-udp-relay";
        ch.send_to(&echo_addr, payload).await.expect("send_to");
        let (target, data) = tokio::time::timeout(Duration::from_secs(5), ch.recv_from())
            .await
            .expect("超时未收到回包")
            .expect("recv_from");
        assert_eq!(target, echo_addr, "下行目标地址帧应与回显 socket 一致");
        assert_eq!(data, payload);
        assert_eq!(ch.active_sessions(), 1);

        // 第二个目标：新会话不串线
        let echo2 = spawn_udp_echo().await;
        ch.send_to(&echo2, b"second-session").await.unwrap();
        let (target, data) = tokio::time::timeout(Duration::from_secs(5), ch.recv_from())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(target, echo2);
        assert_eq!(data, b"second-session");
        assert_eq!(ch.active_sessions(), 2);

        // 主动 close 后映射解除
        assert!(ch.close_target(&echo2).await.unwrap());
        assert_eq!(ch.active_sessions(), 1);
    }
}
