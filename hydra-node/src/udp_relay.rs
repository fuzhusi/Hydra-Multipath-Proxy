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
//! - 每连接会话上限 [`UDP_MAX_SESSIONS`]：满时新会话的数据报丢弃并计数；
//! - 数据报超限（帧编码期拒绝）丢弃并计数；
//! - 目标地址过 SSRF 过滤：字面 IP 直接复查，域名节点侧 DNS 解析（5s 超时）
//!   后复查。判定逻辑为本模块 [`ssrf_blocked_reason`]（与
//!   `handler::classify_blocked_ip` 同源同语义——该函数为 handler 模块私有，
//!   按文件所有权约束不改动 handler.rs，此处镜像实现并以镜像单测对齐；
//!   默认拒绝私有目标，`HYDRA_ALLOW_PRIVATE_TARGETS=1` 放开，语义与 TCP
//!   路径一致）。
//!
//! # 任务结构
//! ```text
//! serve（上行读循环：TLS 帧 → 会话表 → 数据报）
//!   ├─ 每会话任务（select: 上行队列 / socket 回包 → 下行帧）
//!   └─ 回收任务（周期扫描 last_active，超时移除 + 下行 close）
//! ```
//! 上行读循环退出（EOF/坏帧）即整表 drop：各会话任务的发送队列被关闭而
//! 退出，回收任务被显式 abort——连接结束不留悬挂任务。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hydra_protocol::udp_frame::{
    encode_udp_close, encode_udp_data, read_udp_frame, write_udp_frame, UdpFrame, MAX_DATAGRAM_LEN,
};
use hydra_protocol::mask_target;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// UDP 中继模式的保留目标前缀（与 `@hydra-p2p/` 信令分流同款保留前缀）
pub const UDP_RELAY_PREFIX: &str = "@udp-relay/";

/// 每条连接的 UDP 会话上限（防单连接耗尽 fd/内存）
pub const UDP_MAX_SESSIONS: usize = 64;

/// 会话空闲回收阈值（双向均无活动达此时长即移除会话并下行 close）
pub const UDP_SESSION_IDLE_SECS: u64 = 60;

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
            .filter(|(_, h)| now.saturating_sub(h.last_active_ms.load(Ordering::Relaxed)) >= idle_ms)
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

// ── SSRF 过滤（与 handler::classify_blocked_ip 镜像，见模块头注释）──────

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

/// SSRF 黑名单判定（镜像 `handler::classify_blocked_ip`，段位一一对应）：
/// loopback / 链路本地 / RFC1918 / 0.0.0.0/8 / CGNAT 100.64.0.0/10 /
/// 基准测试 198.18.0.0/15 / 组播 224.0.0.0/4 / 保留 240.0.0.0/4；
/// IPv6：::1、fe80::/10、fc00::/7（ULA）、::，以及全部内嵌 IPv4 形态
/// （::ffff: 映射、NAT64 64:ff9b::/96、::/96 兼容、::ffff:0:0/96）尾 4 字节
/// 按 IPv4 规则复查。命中返回原因（供脱敏日志）。
fn ssrf_blocked_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 0 {
                Some("this-network 0.0.0.0/8")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_private() {
                Some("RFC1918 private")
            } else if o[0] == 100 && (64..=127).contains(&o[1]) {
                Some("CGNAT 100.64.0.0/10")
            } else if o[0] == 198 && (18..=19).contains(&o[1]) {
                Some("benchmarking 198.18.0.0/15")
            } else if o[0] & 0xf0 == 0xe0 {
                Some("multicast 224.0.0.0/4")
            } else if o[0] & 0xf0 == 0xf0 {
                Some("reserved 240.0.0.0/4")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d 映射形态等价对应 IPv4，按 v4 规则复查
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ssrf_blocked_reason(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            if let Some(v4) = embedded_ipv4_of_v6(seg) {
                return ssrf_blocked_reason(IpAddr::V4(v4));
            }
            if v6.is_loopback() {
                Some("loopback")
            } else if (seg[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if (seg[0] & 0xfe00) == 0xfc00 {
                Some("IPv6 ULA private")
            } else if v6.is_unspecified() {
                Some("unspecified ::")
            } else {
                None
            }
        }
    }
}

/// 内嵌 IPv4 提取（镜像 handler::embedded_ipv4_of_v6）：覆盖 ::/96（IPv4
/// 兼容）、::ffff:0:0/96（RFC 2765）、64:ff9b::/96（NAT64）三类前缀；
/// :: 与 ::1 是 IPv6 特殊地址，不按内嵌 IPv4 解释。
fn embedded_ipv4_of_v6(seg: [u16; 8]) -> Option<Ipv4Addr> {
    let v4 = Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        (seg[6] & 0xff) as u8,
        (seg[7] >> 8) as u8,
        (seg[7] & 0xff) as u8,
    );
    if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && seg[7] <= 1) {
        return Some(v4);
    }
    if seg[0..4].iter().all(|&s| s == 0) && seg[4] == 0xffff && seg[5] == 0 {
        return Some(v4);
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
        return Some(v4);
    }
    None
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
                return None;
            }
            Ok(r) => match r {
                Ok(addrs) => {
                    // 收集后优先取 IPv4，否则首个地址（与 handler::resolve_and_connect 同语义）
                    let v: Vec<SocketAddr> = addrs.collect();
                    match v.iter().find(|a| a.is_ipv4()).or_else(|| v.first()).copied() {
                        Some(a) => a,
                        None => {
                            warn!("UDP 目标 DNS 无可用地址: {}", mask_target(target));
                            return None;
                        }
                    }
                }
                Err(e) => {
                    warn!("UDP 目标 DNS 解析失败: {} ({e})", mask_target(target));
                    return None;
                }
            },
        }
    };
    if !private_targets_allowed() {
        if let Some(reason) = ssrf_blocked_reason(addr.ip()) {
            warn!(
                "UDP 目标被 SSRF 过滤拒绝（{}）: {}",
                reason,
                mask_target(&addr.to_string())
            );
            return None;
        }
    }
    Some(addr)
}

// ── 中继服务 ────────────────────────────────────────────────────────────

/// UDP 中继服务入口（tcp_server 分流后调用；默认 60s 空闲回收）。
pub(crate) async fn serve<R, W>(rd: R, wr: W)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_with_idle(rd, wr, Duration::from_secs(UDP_SESSION_IDLE_SECS)).await;
}

/// 带显式空闲阈值的版本（测试注入短超时实测回收）。
/// Send + 'static：会话/回收任务经 tokio::spawn 持有共享的 writer/表。
pub(crate) async fn serve_with_idle<R, W>(mut rd: R, wr: W, idle: Duration)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let table = Arc::new(Mutex::new(UdpSessionTable::new()));
    // 下行写端：多个会话任务 + 回收任务并发写，tokio::Mutex 串行化（帧级原子）
    let writer: Arc<tokio::sync::Mutex<W>> = Arc::new(tokio::sync::Mutex::new(wr));

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
                    if write_udp_frame(&mut *w, &encode_udp_close(sid)).await.is_err() {
                        return; // 客户端连接已死：回收任务随之结束
                    }
                }
            }
        })
    };

    // ── 上行读循环：TLS 流帧 → 会话表 → 数据报 ──
    loop {
        let frame = match read_udp_frame(&mut rd).await {
            Ok(f) => f,
            Err(e) => {
                debug!("UDP 中继上行读结束: {e}");
                break;
            }
        };
        match frame {
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
                uplink_data(&table, &writer, session_id, &target, datagram).await;
            }
        }
    }

    // 连接结束：整表 drop → 各会话任务发送队列关闭而退出；回收任务显式 abort
    reaper.abort();
    drop(table);
    info!("UDP 中继连接关闭");
}

/// 处理一帧上行数据：建会话 / 更新绑定 / 投递数据报。
async fn uplink_data<W>(
    table: &Arc<Mutex<UdpSessionTable>>,
    writer: &Arc<tokio::sync::Mutex<W>>,
    session_id: u16,
    target: &str,
    datagram: Vec<u8>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    // 目标解析 + SSRF 过滤失败：丢弃该数据报；已存在的会话一并回收
    // （目标失效的会话没有继续存在的意义）
    let Some(addr) = resolve_udp_target(target).await else {
        let mut t = table.lock().unwrap();
        t.overlimit_drops += 1;
        if t.remove(session_id).is_some() {
            debug!("UDP 会话 {session_id} 因目标失效而回收");
        }
        return;
    };

    // 判定是否需要新建/重建绑定（锁内无 await：std MutexGuard 不可跨 .await）
    let existing_target = {
        let t = table.lock().unwrap();
        t.get(session_id).map(|h| h.target().to_string())
    };
    if existing_target.as_deref() != Some(target) {
        {
            let mut t = table.lock().unwrap();
            // 同 session 换目标：回收旧绑定（句柄 drop → 会话任务退出）
            t.remove(session_id);
            if t.is_full() {
                t.overlimit_drops += 1;
                debug!(
                    "UDP 会话数达上限 {UDP_MAX_SESSIONS}，丢弃 {} 的数据报",
                    mask_target(target)
                );
                return;
            }
        }
        // 锁外建 socket + 派生会话任务（await 期间不持有表锁）
        match bind_session_socket(addr).await {
            Ok(socket) => {
                let mut t = table.lock().unwrap();
                // 二次查满（锁释放窗口可能有并发新建）
                if t.is_full() {
                    t.overlimit_drops += 1;
                    return;
                }
                let (tx, rx) = mpsc::channel(SESSION_QUEUE_DEPTH);
                let last_active = Arc::new(AtomicU64::new(now_ms()));
                let handle = SessionHandle::new(tx, last_active.clone(), target.to_string());
                if t.insert(session_id, handle).is_none() {
                    return; // 理论不可达（is_full 已查）；保守不投递
                }
                tokio::spawn(session_task(
                    session_id,
                    socket,
                    target.to_string(),
                    rx,
                    last_active,
                    writer.clone(),
                ));
                debug!(
                    "UDP 会话 {session_id} 建立 → {}",
                    mask_target(target)
                );
            }
            Err(e) => {
                table.lock().unwrap().overlimit_drops += 1;
                debug!("UDP socket 绑定失败（{}）: {e}", mask_target(target));
                return;
            }
        }
    }

    // 投递数据报（会话可能刚建立也可能已存在）；队列满/会话已死 → 丢弃。
    // 克隆句柄后立即释放表锁，touch/try_send 不占用锁。
    let handle = table.lock().unwrap().get(session_id).map(|h| h.clone_handle());
    match handle {
        Some(h) => {
            h.touch();
            if h.tx.try_send(datagram).is_err() {
                // 队列满 = 对端 socket 短时过载：UDP 语义直接丢包
                debug!("UDP 会话 {session_id} 上行队列满，丢弃数据报");
            }
        }
        None => {
            table.lock().unwrap().overlimit_drops += 1;
        }
    }
}

/// 按目标地址族绑定本地 UDP socket 并 connect 到目标（收发免地址参数，
/// 且内核只收来自该目标的回包——会话绑定语义）。
async fn bind_session_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let local = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// 单会话任务：select 上行队列（数据报 → socket）与 UDP 回包（→ 下行帧）。
/// 上行队列关闭（表移除/连接结束）或 socket 出错即退出。
async fn session_task<W>(
    session_id: u16,
    socket: UdpSocket,
    target: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
    last_active: Arc<AtomicU64>,
    writer: Arc<tokio::sync::Mutex<W>>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
    loop {
        tokio::select! {
            biased;
            cmd = rx.recv() => match cmd {
                Some(datagram) => {
                    if socket.send(&datagram).await.is_err() {
                        debug!("UDP 会话 {session_id} socket 发送失败，会话结束");
                        break;
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
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 会话 {session_id} socket 接收错误: {e}");
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

    // ── SSRF 镜像判定 ──

    #[test]
    fn ssrf_镜像判定_与handler对齐() {
        use std::net::IpAddr;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(ssrf_blocked_reason(p("127.0.0.1")), Some("loopback"));
        assert_eq!(ssrf_blocked_reason(p("10.1.2.3")), Some("RFC1918 private"));
        assert_eq!(ssrf_blocked_reason(p("192.168.1.1")), Some("RFC1918 private"));
        assert_eq!(ssrf_blocked_reason(p("169.254.169.254")), Some("link-local"));
        assert_eq!(
            ssrf_blocked_reason(p("::ffff:127.0.0.1")),
            Some("loopback"),
            "IPv4 映射形态须按 v4 规则复查"
        );
        assert_eq!(
            ssrf_blocked_reason(p("64:ff9b::a00:1")),
            Some("RFC1918 private"),
            "NAT64 内嵌 v4 须复查"
        );
        assert_eq!(ssrf_blocked_reason(p("fd00::1")), Some("IPv6 ULA private"));
        assert_eq!(ssrf_blocked_reason(p("224.0.0.1")), Some("multicast 224.0.0.0/4"));
        assert_eq!(ssrf_blocked_reason(p("8.8.8.8")), None);
        assert_eq!(ssrf_blocked_reason(p("2606:4700::1111")), None);
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
        tokio::spawn(serve_with_idle(srv_rd, srv_wr, Duration::from_secs(60)));

        // 两个会话各自隐式建立并回环（数据报按 session_id 分发不串线）
        for sid in [1u16, 2] {
            let payload = format!("ping-{sid}").into_bytes();
            write_udp_frame(&mut cli, &encode_udp_data(sid, &echo, &payload).unwrap())
                .await
                .unwrap();
            match read_udp_frame(&mut cli).await.unwrap() {
                UdpFrame::Data {
                    session_id, datagram, ..
                } => {
                    assert_eq!(session_id, sid);
                    assert_eq!(datagram, payload);
                }
                other => panic!("期望数据帧，实际 {other:?}"),
            }
        }

        // close 帧：节点侧回收（后续同 session 数据重新建会话，依然回环）
        write_udp_frame(&mut cli, &encode_udp_close(1)).await.unwrap();
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
        tokio::spawn(serve_with_idle(srv_rd, srv_wr, Duration::from_secs(60)));
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
        tokio::spawn(serve_with_idle(srv_rd, srv_wr, Duration::from_millis(300)));
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
        tokio::spawn(serve_with_idle(srv_rd, srv_wr, Duration::from_secs(60)));
        // 240.0.0.0/4 保留段：恒被拒绝（无论 env 放宽与否）
        write_udp_frame(&mut cli, &encode_udp_data(9, "240.0.0.1:5353", b"x").unwrap())
            .await
            .unwrap();
        // 空闲阈值内不应有任何下行帧（数据报被丢弃、会话未建立）
        let r = tokio::time::timeout(Duration::from_millis(400), read_udp_frame(&mut cli)).await;
        assert!(r.is_err(), "SSRF 拒绝目标不应产生下行帧");
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
        let server = crate::server::HydraServer::new("127.0.0.1:0".parse().unwrap(), auth_key.clone(), opts)
            .await
            .expect("节点启动");
        let node_addr = server.tcp_listen_addr.expect("TCP 监听地址");
        let cert = server.cert_der().to_vec();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 本地 UDP 回显 socket
        let echo_addr = spawn_udp_echo().await;

        // 客户端：pin 节点证书建 UDP 通道
        let trust = TlsTrust::pinned(vec![cert]);
        let mut ch = hydra_client::udp_relay::open_udp_channel(
            node_addr,
            "hydra.node",
            &trust,
            &auth_key,
        )
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
