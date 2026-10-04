use hydra_protocol::{mask_target, AuthToken, HydraError, Result, CLIENT_ID};
use quinn::{Connection, VarInt};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

/// 认证失败时静默关闭（不回显任何可区分的错误码，抵御主动探测）
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// 连接级认证宽限：宽限期内没有任何流完成认证则强制断开，
/// 防止未认证连接靠 keepalive 永久占用连接数配额
const AUTH_GRACE: Duration = Duration::from_secs(10);
/// 单个流允许的最大目标地址长度
const MAX_ADDR_LEN: usize = 256;

// ── 已认证流的应用层错误码（QUIC 应用错误码，RFC 9000 §20.2 对应用码无约束）──
// 仅在流完成认证后使用；客户端经 ReadError::Reset 读到后可区分"节点故障/目标故障"。
// 未认证路径保持零字节静默，不回显任何码（防主动探测）。
/// 0x11：节点无法连接目标（连接被拒/超时）
pub const ERR_TARGET_CONNECT: u32 = 0x11;
/// 0x12：节点侧 DNS 解析失败
pub const ERR_DNS_FAIL: u32 = 0x12;
/// 0x13：转发阶段 IO 错误（目标连接中断等）
pub const ERR_FORWARD_IO: u32 = 0x13;

// ── V3.4 单节点多流通道聚合（channel 模式）──
/// 认证后 1 字节模式标签：0x00=现行路径（地址帧，行为逐位不变），0x01=channel 模式
const MODE_LEGACY: u8 = 0x00;
const MODE_CHANNEL: u8 = 0x01;
/// channel 模式角色：0=创建流（携带目标地址声明），1=数据流
const ROLE_CREATOR: u8 = 0x00;
const ROLE_DATA: u8 = 0x01;
/// 通道帧头长度：`[channel_id 8B][seq 4B][len 2B]`
const CHANNEL_FRAME_HEADER: usize = 14;
/// 单帧 payload 上限（与现行转发缓冲一致的 64KB）
const CHANNEL_MAX_FRAME: usize = u16::MAX as usize; // 与客户端 MAX_FRAME 对称（u16 长度字段上限）
/// 上行有序写窗口上限（pending 字节数）：超过视为协议失步，通道失败。
/// 客户端侧重排窗口同为 4MB（对称有界）。
const CHANNEL_WINDOW: usize = 32 * 1024 * 1024;
/// 上行空洞等待兜底：next_seq 未到达超过该时长 → 通道失败（reset 0x13）
const CHANNEL_HOLE_TIMEOUT: Duration = Duration::from_secs(5);

/// 已认证流故障的显式中止：RESET_STREAM（对端读到 ReadError::Reset(code)）
/// + STOP_SENDING（对端 write 得到 WriteError::Stopped(code)），
/// 替代曾经的"静默 drop send"——那会产生优雅 FIN，客户端误把中断当正常结束。
fn abort_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u32) {
    let var_code = VarInt::from_u32(code);
    let _ = send.reset(var_code);
    let _ = recv.stop(var_code);
}

// ── SSRF 目标过滤（遗留 P1-3）──
// 已认证客户端可能把节点当跳板攻击内网服务或云元数据端点（169.254.169.254）。
// 对字面 IP 与 DNS 解析结果统一在 TCP 连接前检查，命中即拒绝。
// V3.4：channel 模式的创建流（role=0）目标地址走同一过滤，逐字节同语义。

/// `HYDRA_ALLOW_PRIVATE_TARGETS=1` 时放开私有目标（测试基线依赖 127.0.0.1 回显服务器）。
/// 默认拒绝。每次调用读取 env（per-stream 一次，相对网络 IO 开销可忽略），
/// 使测试可在进程内随时打开，无初始化顺序陷阱。
fn private_targets_allowed() -> bool {
    matches!(
        std::env::var("HYDRA_ALLOW_PRIVATE_TARGETS"),
        Ok(v) if v == "1"
    )
}

/// SSRF 黑名单判定：命中返回原因（供脱敏日志），未命中返回 None。
/// 覆盖：loopback（127.0.0.0/8、::1）、链路本地（169.254.0.0/16、fe80::/10）、
/// RFC1918 私网（10/8、172.16/12、192.168/16）、0.0.0.0/8、IPv6 未指定地址（::）
/// 与 IPv6 ULA（fc00::/7，RFC1918 的 IPv6 对应物）；
/// IPv4 映射地址（::ffff:a.b.c.d）与 NAT64（64:ff9b::/96）内嵌 IPv4 一并复查，防绕过。
fn classify_blocked_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.octets()[0] == 0 {
                Some("this-network 0.0.0.0/8")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_private() {
                Some("RFC1918 private")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d 等价于对应 IPv4 目标，按 IPv4 规则复查
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_blocked_ip(IpAddr::V4(v4));
            }
            // NAT64 64:ff9b::/96：尾 4 字节内嵌 IPv4，按 IPv4 规则复查
            let seg = v6.segments();
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return classify_blocked_ip(IpAddr::V4(v4));
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

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[test]
    fn loopback_blocked() {
        assert_eq!(
            classify_blocked_ip("127.0.0.1".parse().unwrap()),
            Some("loopback")
        );
        // 127.0.0.0/8 全段
        assert_eq!(
            classify_blocked_ip("127.9.9.9".parse().unwrap()),
            Some("loopback")
        );
        assert_eq!(
            classify_blocked_ip("::1".parse().unwrap()),
            Some("loopback")
        );
    }

    #[test]
    fn link_local_blocked() {
        assert_eq!(
            classify_blocked_ip("169.254.169.254".parse().unwrap()),
            Some("link-local")
        );
        assert_eq!(
            classify_blocked_ip("fe80::1".parse().unwrap()),
            Some("link-local")
        );
    }

    #[test]
    fn rfc1918_blocked() {
        assert_eq!(
            classify_blocked_ip("10.1.2.3".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("172.16.0.1".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("172.31.255.255".parse().unwrap()),
            Some("RFC1918 private")
        );
        assert_eq!(
            classify_blocked_ip("192.168.1.1".parse().unwrap()),
            Some("RFC1918 private")
        );
        // 172.16/12 边界外不误伤
        assert_eq!(classify_blocked_ip("172.32.0.1".parse().unwrap()), None);
    }

    #[test]
    fn unspecified_blocked() {
        assert_eq!(
            classify_blocked_ip("0.0.0.0".parse().unwrap()),
            Some("this-network 0.0.0.0/8")
        );
        assert_eq!(
            classify_blocked_ip("::".parse().unwrap()),
            Some("unspecified ::")
        );
    }

    #[test]
    fn ipv6_ula_blocked() {
        assert_eq!(
            classify_blocked_ip("fd00::1".parse().unwrap()),
            Some("IPv6 ULA private")
        );
        assert_eq!(
            classify_blocked_ip("fc00::1".parse().unwrap()),
            Some("IPv6 ULA private")
        );
    }

    #[test]
    fn embedded_ipv4_rechecked() {
        // IPv4 映射：内嵌回环/私网/链路本地必须被拦下（绕过向量）
        assert_eq!(
            classify_blocked_ip("::ffff:127.0.0.1".parse().unwrap()),
            Some("loopback")
        );
        assert_eq!(
            classify_blocked_ip("::ffff:169.254.169.254".parse().unwrap()),
            Some("link-local")
        );
        // NAT64 内嵌
        assert_eq!(
            classify_blocked_ip("64:ff9b::a00:1".parse().unwrap()),
            Some("RFC1918 private")
        );
        // 内嵌公网 IPv4 不拦
        assert_eq!(classify_blocked_ip("::ffff:8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn public_targets_pass() {
        assert_eq!(classify_blocked_ip("8.8.8.8".parse().unwrap()), None);
        assert_eq!(classify_blocked_ip("1.1.1.1".parse().unwrap()), None);
        assert_eq!(
            classify_blocked_ip("2606:4700::1111".parse().unwrap()),
            None
        );
    }
}

// ── V3.4 通道状态机 ─────────────────────────────────────────────────────

/// 上行（客户端 → 目标）有序收集器：按 seq 收集各数据流 chunk，
/// 顺序写给目标 TCP。重复 seq 去重（客户端流死亡重发时同 seq 同内容，
/// 已写出（seq < next）或已在 pending 中的一律不重复累计）。
#[derive(Default)]
struct UpOrderer {
    pending: BTreeMap<u32, Vec<u8>>,
    next: u32,
    bytes: usize,
}

enum InsertOutcome {
    Buffered,
    /// seq 已写出或已在 pending（去重，不累计字节）
    Duplicate,
}

impl UpOrderer {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, seq: u32, payload: Vec<u8>) -> InsertOutcome {
        if seq < self.next || self.pending.contains_key(&seq) {
            return InsertOutcome::Duplicate;
        }
        self.bytes += payload.len();
        self.pending.insert(seq, payload);
        InsertOutcome::Buffered
    }

    /// 弹出下一个有序可写块（next_seq 命中时）
    fn pop_ready(&mut self) -> Option<Vec<u8>> {
        let payload = self.pending.remove(&self.next)?;
        self.bytes -= payload.len();
        self.next = self.next.wrapping_add(1);
        Some(payload)
    }

    /// 是否存在空洞（有 pending 但 next 缺失）：等待超时兜底的对象
    fn has_hole(&self) -> bool {
        !self.pending.is_empty()
    }

    fn pending_bytes(&self) -> usize {
        self.bytes
    }

    fn next_seq(&self) -> u32 {
        self.next
    }
}

/// 上行有序门（orderer + 空洞超时计时），从写任务中提出以便单测覆盖
/// 强制门④：乱序窗口有界 + 超时兜底。
struct UpOrderGate {
    orderer: UpOrderer,
    hole_timeout: Duration,
    hole_deadline: Option<tokio::time::Instant>,
}

impl UpOrderGate {
    fn new() -> Self {
        Self::with_timeout(CHANNEL_HOLE_TIMEOUT)
    }

    fn with_timeout(hole_timeout: Duration) -> Self {
        Self {
            orderer: UpOrderer::new(),
            hole_timeout,
            hole_deadline: None,
        }
    }

    /// 收到一个 chunk。返回 Err(()) 表示超出窗口上限（协议失步，通道失败）。
    fn on_chunk(&mut self, seq: u32, payload: Vec<u8>) -> std::result::Result<(), ()> {
        if let InsertOutcome::Buffered = self.orderer.insert(seq, payload) {
            if self.orderer.pending_bytes() > CHANNEL_WINDOW {
                tracing::debug!(
                    "gate pending_bytes={} next={} (window={})",
                    self.orderer.pending_bytes(),
                    self.orderer.next_seq(),
                    CHANNEL_WINDOW
                );
                return Err(());
            }
            self.rearm_hole();
        }
        Ok(())
    }

    /// 排空所有就绪块（由调用方逐块写向目标 TCP）
    fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.orderer.pop_ready() {
            out.push(chunk);
        }
        self.rearm_hole();
        out
    }

    /// 空洞等待是否已超时（now 由调用方注入，便于单测；写任务走 sleep_until 同语义）
    #[allow(dead_code)]
    fn hole_expired(&self, now: tokio::time::Instant) -> bool {
        matches!(self.hole_deadline, Some(d) if d <= now)
    }

    fn rearm_hole(&mut self) {
        self.hole_deadline = if self.orderer.has_hole() {
            Some(tokio::time::Instant::now() + self.hole_timeout)
        } else {
            None
        };
    }
}

/// 通道结束状态（watch 广播给所有参与任务）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChannelEnd {
    /// 运行中
    Running,
    /// 下行已完整（目标 FIN）：所有存活流优雅 FIN，上行可能仍在进行
    DownComplete,
    /// 双向均完整结束：注销通道，一切任务退出
    CleanShutdown,
    /// 通道失败（窗口超限/空洞超时/IO 故障/协议违规/无可用流）：所有流 reset 0x13
    Failed,
}

/// 通道中的一条 QUIC 流（下行写端）。recv 端由各流任务自持。
struct StreamSlot {
    send: quinn::SendStream,
    alive: bool,
}

/// 单个通道的共享状态（同一条 QUIC 连接上 N 条流 → 一条目标 TCP）。
struct ChannelShared {
    cid: u64,
    target_masked: String,
    /// 下行分发目标流列表（含创建流）。
    /// tokio Mutex：分发器的写/FIN 持锁跨 await，std MutexGuard 非 Send 无法 spawn。
    slots: tokio::sync::Mutex<Vec<StreamSlot>>,
    rr: AtomicUsize,
    /// 上行 chunk 汇入点（各流任务 → 有序写任务）
    up_tx: mpsc::Sender<(u32, Vec<u8>)>,
    end: watch::Sender<ChannelEnd>,
    /// 全部流上行结束（EOF 或死亡）
    all_up_closed: watch::Sender<bool>,
    up_open: AtomicUsize,
    downstream_done: AtomicBool,
    /// 流死亡造成的下行丢帧待重发标志
    resend_needed: AtomicBool,
    /// 流集合变化唤醒分发器
    slot_events: tokio::sync::Notify,
}

impl ChannelShared {
    fn log(&self, msg: &str) {
        info!(
            "channel {:016x} ({}): {}",
            self.cid, self.target_masked, msg
        );
    }

    /// 注册一条流（返回槽位下标，供流任务标记死亡/上行关闭）
    async fn push_slot(&self, send: quinn::SendStream) -> usize {
        let idx = {
            let mut slots = self.slots.lock().await;
            slots.push(StreamSlot { send, alive: true });
            slots.len() - 1
        };
        self.up_open.fetch_add(1, Ordering::SeqCst);
        self.slot_events.notify_one();
        idx
    }

    async fn alive_count(&self) -> usize {
        self.slots.lock().await.iter().filter(|s| s.alive).count()
    }

    /// 流的接收端异常（客户端 reset/连接故障）：摘除下行槽位，
    /// 并请求分发器重发窗口缓存（该流在途帧已丢失）
    async fn slot_died(&self, idx: usize) {
        {
            let mut slots = self.slots.lock().await;
            if let Some(s) = slots.get_mut(idx) {
                s.alive = false;
            }
        }
        self.resend_needed.store(true, Ordering::SeqCst);
        self.upstream_closed_common();
        self.slot_events.notify_one();
    }

    /// 流的接收端干净 EOF（客户端半关闭）：保留下行槽位，仅结束其上行
    fn slot_upstream_eof(&self) {
        self.upstream_closed_common();
    }

    fn upstream_closed_common(&self) {
        if self.up_open.fetch_sub(1, Ordering::SeqCst) == 1 {
            let _ = self.all_up_closed.send(true);
            self.maybe_finish();
        }
    }

    /// 目标 FIN（下行完整）后由分发器调用
    fn downstream_finished(&self) {
        self.downstream_done.store(true, Ordering::SeqCst);
        self.maybe_finish();
    }

    fn fail(&self) {
        self.end.send_replace(ChannelEnd::Failed);
    }

    fn maybe_finish(&self) {
        if self.downstream_done.load(Ordering::SeqCst) && self.up_open.load(Ordering::SeqCst) == 0 {
            self.end.send_replace(ChannelEnd::CleanShutdown);
        }
    }
}

/// 每条 QUIC 连接的通道注册表：channel_id → 通道共享状态
type ChannelRegistry = Arc<Mutex<HashMap<u64, Arc<ChannelShared>>>>;

pub struct ConnectionHandler {
    auth_key: Vec<u8>,
}

impl ConnectionHandler {
    pub fn new(auth_key: Vec<u8>) -> Self {
        Self { auth_key }
    }

    pub async fn handle_connection(&self, connection: Connection) -> Result<()> {
        debug!("Waiting for bidirectional stream from client...");
        let authed = Arc::new(AtomicBool::new(false));
        let channels: ChannelRegistry = Arc::new(Mutex::new(HashMap::new()));
        let watchdog = {
            let authed = authed.clone();
            let conn = connection.clone();
            tokio::spawn(async move {
                tokio::time::sleep(AUTH_GRACE).await;
                if !authed.load(Ordering::Relaxed) {
                    info!("Connection failed to authenticate within grace period, closing");
                    conn.close(0u32.into(), b"auth timeout");
                }
            })
        };

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    debug!("Accepted bidirectional stream, spawning handler");
                    let auth_key = self.auth_key.clone();
                    let authed = authed.clone();
                    let channels = channels.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_stream(send, recv, auth_key, authed, channels).await
                        {
                            error!("Stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Connection closed by client");
                    break;
                }
                Err(e) => {
                    error!("Connection error: {}", e);
                    break;
                }
            }
        }

        watchdog.abort();
        Ok(())
    }

    async fn handle_stream(
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        auth_key: Vec<u8>,
        authed: Arc<AtomicBool>,
        channels: ChannelRegistry,
    ) -> Result<()> {
        // ── 第 1 步：认证。固定 64 字节 token，超时或验证失败一律静默关流。
        let mut token = [0u8; AuthToken::TOKEN_LEN];
        let valid = match tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut token)).await {
            Ok(Ok(())) => AuthToken::verify(&auth_key, &token, CLIENT_ID, 30).is_ok(),
            _ => false,
        };
        if !valid {
            debug!("Stream failed authentication, closing silently");
            return Ok(());
        }
        authed.store(true, Ordering::Relaxed);

        // ── 第 2 步（V3.4）：1 字节模式标签。
        // 与旧版 2 字节长度前缀逐字节兼容：旧客户端地址帧首字节即长度高字节，
        // 长度 <256 时恒为 0x00（=现行模式），节点随后按 1 字节读长度——
        // 对旧客户端而言线上字节与旧协议完全一致。已知边界：恰好 256 字节的
        // 目标地址（长度高字节 0x01）会被新节点误判为 channel 模式，
        // 属病态长度（open_target 上限同 256），如实记录、不再兼容。
        let mut tag = [0u8; 1];
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut tag))
            .await
            .is_err()
        {
            return Ok(());
        }
        match tag[0] {
            MODE_LEGACY => {
                // 现行路径：1 字节地址长度 + 地址（语义与旧版 [len_hi=0x00][len_lo] 等价）
                let mut len_buf = [0u8; 1];
                if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut len_buf))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                let addr_len = len_buf[0] as usize;
                if addr_len == 0 {
                    debug!("Invalid address length: {}", addr_len);
                    return Ok(());
                }
                let mut addr_buf = vec![0u8; addr_len];
                if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut addr_buf))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                let target_addr_str = String::from_utf8_lossy(&addr_buf).to_string();
                Self::forward_single(send, recv, target_addr_str).await
            }
            MODE_CHANNEL => Self::handle_channel_stream(send, recv, channels).await,
            _ => {
                debug!("Unknown mode tag 0x{:02x}, closing silently", tag[0]);
                Ok(())
            }
        }
    }

    /// 解析目标地址（字面 IP 或节点侧 DNS）并执行 SSRF 过滤 + 建立目标 TCP。
    /// 错误返回 (应用错误码, 已格式化错误)：0x12=DNS 失败、0x11=SSRF 拒绝/无法连接/超时。
    /// 现行单流路径与 channel 创建流共用（SSRF 过滤对 channel 目标地址同样生效）。
    async fn resolve_and_connect(
        target_addr_str: &str,
    ) -> std::result::Result<TcpStream, (u32, HydraError)> {
        // 日志脱敏（防追踪性）：info 级一律短哈希，完整明文仅 debug 级（RUST_LOG=debug）可见
        info!("Received target address: {}", mask_target(target_addr_str));
        debug!("Received target address (plaintext): {}", target_addr_str);

        // ── 解析为 SocketAddr，否则节点侧 DNS 解析
        let target_addr: SocketAddr = if let Ok(addr) = target_addr_str.parse() {
            addr
        } else {
            info!("Resolving DNS for: {}", mask_target(target_addr_str));
            match tokio::net::lookup_host(target_addr_str.to_string()).await {
                Ok(addrs) => {
                    let addrs_vec: Vec<_> = addrs.collect();
                    // 优先使用 IPv4 地址
                    let ipv4_addr = addrs_vec.iter().find(|a| a.is_ipv4());
                    match ipv4_addr {
                        Some(a) => *a,
                        None => match addrs_vec.first() {
                            Some(a) => *a,
                            None => {
                                error!(
                                    "DNS resolution failed for {}: no addresses",
                                    target_addr_str
                                );
                                return Err((
                                    ERR_DNS_FAIL,
                                    HydraError::ConnectionError(format!(
                                        "DNS resolution failed for {}",
                                        target_addr_str
                                    )),
                                ));
                            }
                        },
                    }
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", target_addr_str, e);
                    return Err((
                        ERR_DNS_FAIL,
                        HydraError::ConnectionError(format!(
                            "DNS resolution failed for {}: {}",
                            target_addr_str, e
                        )),
                    ));
                }
            }
        };

        info!(
            "Connecting to target: {} (with 15s timeout)",
            mask_target(&target_addr.to_string())
        );

        // ── SSRF 目标过滤（遗留 P1-3）：字面 IP 与 DNS 解析结果统一复查，命中即拒绝。
        // 默认拒绝；HYDRA_ALLOW_PRIVATE_TARGETS=1 放开（测试基线依赖 127.0.0.1 回显服务器）。
        if !private_targets_allowed() {
            if let Some(reason) = classify_blocked_ip(target_addr.ip()) {
                // 脱敏日志：只记短哈希，不落目标明文
                warn!(
                    "Blocked SSRF target (private/reserved: {}): {}",
                    reason,
                    mask_target(&target_addr.to_string())
                );
                // 走既有 0x11 错误路径（与"无法连接目标"同码，不给探测者额外指纹）
                return Err((
                    ERR_TARGET_CONNECT,
                    HydraError::ConnectionError(format!(
                        "Target blocked (private/reserved: {})",
                        reason
                    )),
                ));
            }
        }

        let connect_start = std::time::Instant::now();

        // Connect to target with timeout（须小于客户端 20s 应答超时，否则慢目标被误判为节点故障）
        match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(target_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let elapsed = connect_start.elapsed();
                info!(
                    "Connected to target: {} (took {}ms)",
                    mask_target(&target_addr.to_string()),
                    elapsed.as_millis()
                );
                Ok(stream)
            }
            Ok(Err(e)) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Failed to connect to {}: {} (took {}ms)",
                    target_addr,
                    e,
                    elapsed.as_millis()
                );
                Err((
                    ERR_TARGET_CONNECT,
                    HydraError::ConnectionError(format!(
                        "Failed to connect to {}: {}",
                        target_addr, e
                    )),
                ))
            }
            Err(_) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Timeout connecting to {} ({}ms)",
                    target_addr,
                    elapsed.as_millis()
                );
                Err((
                    ERR_TARGET_CONNECT,
                    HydraError::ConnectionError(format!("Timeout connecting to {}", target_addr)),
                ))
            }
        }
    }

    /// 现行单流转发路径（模式标签 0x00）：行为与 V3.4 之前逐位一致。
    async fn forward_single(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        target_addr_str: String,
    ) -> Result<()> {
        let target_stream = match Self::resolve_and_connect(&target_addr_str).await {
            Ok(stream) => stream,
            Err((code, e)) => {
                abort_stream(&mut send, &mut recv, code);
                return Err(e);
            }
        };

        // Send success response
        send.write_all(&[0x00, 0x00])
            .await
            .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;

        // Forward traffic bidirectionally (不记录每个数据包，只记录汇总信息)
        let (mut target_read, mut target_write) = target_stream.into_split();

        // 任一方向转发故障时唤醒另一方向立即显式清理，避免孤儿任务死等
        let (fail_tx, fail_rx) = tokio::sync::watch::channel(false);

        // 客户端 → 目标（拥有 recv 与 target_write）
        let quic_to_target = tokio::spawn({
            let mut fail_rx = fail_rx.clone();
            let fail_tx = fail_tx.clone();
            async move {
                let mut buf = vec![0u8; 65536];
                let mut total_bytes: u64 = 0;
                loop {
                    let n = tokio::select! {
                        r = recv.read(&mut buf) => match r {
                            // 客户端 FIN：半关闭——保留目标→客户端方向继续转发剩余响应
                            Ok(Some(0)) | Ok(None) => return Ok(total_bytes),
                            // 客户端中止其发送侧（Reset）：等同关闭，不算故障
                            Err(quinn::ReadError::Reset(_)) => return Ok(total_bytes),
                            Ok(Some(n)) => n,
                            // 连接级/传输层故障：连接即将消亡，停止转发
                            Err(_) => return Err(total_bytes),
                        },
                        _ = fail_rx.changed() => {
                            // 对侧转发故障：显式 STOP_SENDING(0x13)，客户端 write 侧得到 WriteError::Stopped(0x13)
                            let _ = recv.stop(VarInt::from_u32(ERR_FORWARD_IO));
                            return Err(total_bytes);
                        }
                    };
                    total_bytes += n as u64;
                    if target_write.write_all(&buf[..n]).await.is_err() {
                        let _ = fail_tx.send(true);
                        return Err(total_bytes);
                    }
                }
            }
        });

        // 目标 → 客户端（拥有 send 与 target_read）
        let target_to_quic = tokio::spawn({
            let mut fail_rx = fail_rx;
            async move {
                let mut buf = vec![0u8; 65536];
                let mut total_bytes: u64 = 0;
                loop {
                    let n = tokio::select! {
                        r = target_read.read(&mut buf) => match r {
                            // 目标 FIN：优雅关闭到客户端的发送侧
                            Ok(0) => {
                                let _ = send.finish().await;
                                return Ok(total_bytes);
                            }
                            Ok(n) => n,
                            Err(_) => {
                                // 目标侧 IO 错误：显式 RESET_STREAM(0x13)，客户端读到 ReadError::Reset(0x13)
                                let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                                let _ = fail_tx.send(true);
                                return Err(total_bytes);
                            }
                        },
                        _ = fail_rx.changed() => {
                            // 对侧转发故障：显式 RESET_STREAM(0x13)
                            let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                            return Err(total_bytes);
                        }
                    };
                    total_bytes += n as u64;
                    if send.write_all(&buf[..n]).await.is_err() {
                        let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                        let _ = fail_tx.send(true);
                        return Err(total_bytes);
                    }
                }
            }
        });

        let (quic_res, target_res) = tokio::join!(quic_to_target, target_to_quic);
        let is_fail = |r: &std::result::Result<
            std::result::Result<u64, u64>,
            tokio::task::JoinError,
        >| { !matches!(r, Ok(Ok(_))) };
        let forward_failed = is_fail(&quic_res) || is_fail(&target_res);
        if forward_failed {
            info!(
                "Forwarding to {} aborted with app error 0x{:02x}",
                mask_target(&target_addr_str),
                ERR_FORWARD_IO
            );
            return Err(HydraError::ConnectionError(format!(
                "forwarding IO error for {}",
                target_addr_str
            )));
        }

        let (quic_bytes, target_bytes) = (
            quic_res.ok().and_then(|r| r.ok()).unwrap_or(0),
            target_res.ok().and_then(|r| r.ok()).unwrap_or(0),
        );
        info!(
            "Connection to {} closed (QUIC->Target: {} bytes, Target->QUIC: {} bytes)",
            mask_target(&target_addr_str),
            quic_bytes,
            target_bytes
        );
        Ok(())
    }

    /// V3.4 channel 模式流入口：已读完认证 + 模式标签 0x01。
    /// 接着读 `[channel_id 8B][role 1B]`；role=0 创建通道（携带地址声明），
    /// role=1 加入已有通道（找不到=静默 reset）。
    async fn handle_channel_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        channels: ChannelRegistry,
    ) -> Result<()> {
        let mut hdr = [0u8; 9]; // channel_id 8B + role 1B
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut hdr))
            .await
            .is_err()
        {
            return Ok(());
        }
        let cid = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
        let role = hdr[8];

        match role {
            ROLE_CREATOR => Self::channel_creator(send, recv, channels, cid).await,
            ROLE_DATA => {
                let shared = channels.lock().unwrap().get(&cid).cloned();
                let Some(shared) = shared else {
                    // 找不到通道：静默 reset（与既有防探测语义一致，不回显可区分错误）
                    debug!(
                        "channel {:016x}: data stream for unknown channel, resetting silently",
                        cid
                    );
                    let _ = send.reset(VarInt::from_u32(0));
                    let _ = recv.stop(VarInt::from_u32(0));
                    return Ok(());
                };
                if *shared.end.borrow() != ChannelEnd::Running {
                    let _ = send.reset(VarInt::from_u32(0));
                    let _ = recv.stop(VarInt::from_u32(0));
                    return Ok(());
                }
                let idx = shared.push_slot(send).await;
                shared.log("data stream attached");
                Self::channel_read_loop(shared, idx, recv).await
            }
            _ => {
                debug!(
                    "channel {:016x}: invalid role {}, closing silently",
                    cid, role
                );
                Ok(())
            }
        }
    }

    /// 创建流（role=0）：读现行格式地址帧 → SSRF 过滤 + 建目标 TCP → 2B 成功应答
    /// → 建通道状态 → 进入帧读循环。
    async fn channel_creator(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        channels: ChannelRegistry,
        cid: u64,
    ) -> Result<()> {
        // 现行格式的地址帧：2 字节大端长度前缀 + 地址
        let mut len_buf = [0u8; 2];
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut len_buf))
            .await
            .is_err()
        {
            return Ok(());
        }
        let addr_len = u16::from_be_bytes(len_buf) as usize;
        if addr_len == 0 || addr_len > MAX_ADDR_LEN {
            debug!("channel {:016x}: invalid address length {}", cid, addr_len);
            return Ok(());
        }
        let mut addr_buf = vec![0u8; addr_len];
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut addr_buf))
            .await
            .is_err()
        {
            return Ok(());
        }
        let target_addr_str = String::from_utf8_lossy(&addr_buf).to_string();

        let target_stream = match Self::resolve_and_connect(&target_addr_str).await {
            Ok(stream) => stream,
            Err((code, e)) => {
                // 既有 0x11/0x12 错误语义：abort 创建流
                abort_stream(&mut send, &mut recv, code);
                return Err(e);
            }
        };

        // 成功应答码（与现行单流路径一致）
        if let Err(e) = send.write_all(&[0x00, 0x00]).await {
            return Err(HydraError::ProtocolError(format!("Write error: {}", e)));
        }

        // ── 建通道状态
        let (up_tx, up_rx) = mpsc::channel::<(u32, Vec<u8>)>(256);
        let (end_tx, end_rx) = watch::channel(ChannelEnd::Running);
        let (all_up_tx, all_up_rx) = watch::channel(false);
        let masked = mask_target(&target_addr_str).to_string();
        let shared = Arc::new(ChannelShared {
            cid,
            target_masked: masked,
            slots: tokio::sync::Mutex::new(Vec::new()),
            rr: AtomicUsize::new(0),
            up_tx,
            end: end_tx,
            all_up_closed: all_up_tx,
            up_open: AtomicUsize::new(0),
            downstream_done: AtomicBool::new(false),
            resend_needed: AtomicBool::new(false),
            slot_events: tokio::sync::Notify::new(),
        });
        channels.lock().unwrap().insert(cid, shared.clone());
        shared.log("channel created");

        // 终态清理：失败 → 存活流显式 reset 0x13 + 注销；完整结束 → 注销。
        // 让客户端在通道失败时得到显式错误而非静默挂起。
        {
            let shared = shared.clone();
            let channels = channels.clone();
            let mut end_rx = end_rx.clone();
            tokio::spawn(async move {
                loop {
                    if end_rx.changed().await.is_err() {
                        break;
                    }
                    // 先拷贝状态值：watch borrow guard 非 Send，不得跨 await
                    let state = *end_rx.borrow_and_update();
                    match state {
                        ChannelEnd::Failed => {
                            shared.log("channel failed, resetting all live streams with 0x13");
                            let mut slots = shared.slots.lock().await;
                            for s in slots.iter_mut() {
                                if s.alive {
                                    let _ = s.send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                                }
                            }
                            channels.lock().unwrap().remove(&shared.cid);
                            break;
                        }
                        ChannelEnd::CleanShutdown => {
                            shared.log("channel finished cleanly");
                            channels.lock().unwrap().remove(&shared.cid);
                            break;
                        }
                        // 下行完整但上行可能仍在进行：继续等待终态
                        ChannelEnd::DownComplete | ChannelEnd::Running => {}
                    }
                }
            });
        }

        let (target_read, target_write) = target_stream.into_split();
        Self::spawn_upstream_writer(
            shared.clone(),
            up_rx,
            end_rx.clone(),
            all_up_rx,
            target_write,
        );
        Self::spawn_downstream_distributor(shared.clone(), end_rx.clone(), target_read);

        // 创建流自身也进入帧读循环（参与上行收集；下行分发含创建流）
        let idx = shared.push_slot(send).await;
        Self::channel_read_loop(shared, idx, recv).await
    }

    /// 上行有序写任务：把各数据流汇入的 chunk 按 seq 顺序写给目标 TCP。
    /// 空洞等待 5s 兜底、窗口 4MB 上限，超限即通道失败（reset 0x13）。
    fn spawn_upstream_writer(
        shared: Arc<ChannelShared>,
        mut up_rx: mpsc::Receiver<(u32, Vec<u8>)>,
        mut end_rx: watch::Receiver<ChannelEnd>,
        mut all_up_rx: watch::Receiver<bool>,
        mut target_write: tokio::net::tcp::OwnedWriteHalf,
    ) {
        tokio::spawn(async move {
            let mut gate = UpOrderGate::new();
            let mut up_closed = false;
            loop {
                tokio::select! {
                    maybe = up_rx.recv(), if !up_closed => match maybe {
                        Some((seq, payload)) => {
                            if gate.on_chunk(seq, payload).is_err() {
                                shared.log("upstream window exceeded, failing channel");
                                shared.fail();
                                return;
                            }
                        }
                        // 所有读循环结束：上行终止
                        None => up_closed = true,
                    },
                    _ = all_up_rx.changed() => {
                        up_closed = true;
                    }
                    _ = end_rx.changed() => {
                        let state = *end_rx.borrow_and_update();
                        if up_closed || state == ChannelEnd::Failed {
                            return;
                        }
                    }
                    _ = async {
                        match gate.hole_deadline {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending().await,
                        }
                    } => {
                        shared.log("upstream hole timeout, failing channel");
                        shared.fail();
                        return;
                    }
                }
                // 上行终止时若仍有空洞：字节流不可能完整，判失败而非半关闭（防目标侧静默缺块）
                if up_closed && gate.orderer.has_hole() {
                    shared.log(&format!(
                        "upstream closed with hole: next_seq={}, pending={}",
                        gate.orderer.next_seq(),
                        gate.orderer.pending_bytes()
                    ));
                    shared.fail();
                    return;
                }
                for chunk in gate.drain() {
                    if target_write.write_all(&chunk).await.is_err() {
                        shared.log("target write failed, failing channel");
                        shared.fail();
                        return;
                    }
                }
                if up_closed {
                    // 上行完整：优雅半关闭目标写侧（保留下行继续转发剩余响应）
                    let _ = target_write.shutdown().await;
                    shared.maybe_finish();
                    return;
                }
            }
        });
    }

    /// 下行分发任务：从目标 TCP 读取，按 ≤64KB chunk 编 seq 后轮流分发到通道的
    /// 可用流（含创建流）；流死亡跳过换下一条，并以窗口缓存重发补齐在途丢帧。
    fn spawn_downstream_distributor(
        shared: Arc<ChannelShared>,
        mut end_rx: watch::Receiver<ChannelEnd>,
        mut target_read: tokio::net::tcp::OwnedReadHalf,
    ) {
        tokio::spawn(async move {
            let mut seq: u32 = 0;
            // 下行窗口缓存：最近 CHANNEL_WINDOW 字节的帧。流死亡导致的在途丢帧
            // 由此重发补齐（客户端按 seq 去重，重复无害）。
            let mut cache: VecDeque<(u32, Vec<u8>)> = VecDeque::new();
            let mut cache_bytes = 0usize;
            let mut buf = vec![0u8; CHANNEL_MAX_FRAME];
            loop {
                tokio::select! {
                    r = target_read.read(&mut buf) => match r {
                        // 目标 FIN：下行完整——所有存活流优雅 FIN（客户端按流 FIN 判定下行结束）
                        Ok(0) => {
                            shared.downstream_finished();
                            // tokio Mutex guard 可跨 await：持锁逐一优雅 FIN
                            let mut slots = shared.slots.lock().await;
                            for s in slots.iter_mut() {
                                if s.alive {
                                    let _ = s.send.finish().await;
                                }
                            }
                            shared.log("target closed, downstream complete");
                            shared.end.send_replace(ChannelEnd::DownComplete);
                            return;
                        }
                        Ok(n) => {
                            // 首帧 seq=0（客户端 DownState next 从 0 起等；先取值后自增）
                            let this_seq = seq;
                            seq = seq.wrapping_add(1);
                            let chunk = buf[..n].to_vec();
                            cache_bytes += n;
                            cache.push_back((this_seq, chunk.clone()));
                            while cache_bytes > CHANNEL_WINDOW {
                                if let Some((_, old)) = cache.pop_front() {
                                    cache_bytes -= old.len();
                                }
                            }
                            // 先补齐流死亡造成的丢帧窗口，再发新帧
                            if shared.resend_needed.swap(false, Ordering::SeqCst) {
                                if !Self::resend_cache(&shared, &cache).await {
                                    shared.log("no live stream for resend, failing channel");
                                    shared.fail();
                                    return;
                                }
                            }
                            let frame = encode_frame(shared.cid, this_seq, &chunk);
                            if Self::write_frame_round_robin(&shared, &frame).await.is_none() {
                                shared.log("no live stream for downstream, failing channel");
                                shared.fail();
                                return;
                            }
                        }
                        Err(e) => {
                            shared.log(&format!("target read failed: {}, failing channel", e));
                            shared.fail();
                            return;
                        }
                    },
                    _ = shared.slot_events.notified() => {
                        if shared.resend_needed.swap(false, Ordering::SeqCst) {
                            if !Self::resend_cache(&shared, &cache).await {
                                shared.log("no live stream for resend, failing channel");
                                shared.fail();
                                return;
                            }
                        }
                        if shared.alive_count().await == 0 {
                            shared.log("all streams dead, failing channel");
                            shared.fail();
                            return;
                        }
                    }
                    _ = end_rx.changed() => {
                        // 其它任务判死/整体结束：本任务退出（清理由终态任务统一执行）
                        return;
                    }
                }
            }
        });
    }

    /// 把一帧写到下一个可用流（轮转）；写失败则摘除该流换下一条重试。
    /// 返回 None 表示没有可用流。
    async fn write_frame_round_robin(shared: &Arc<ChannelShared>, frame: &[u8]) -> Option<()> {
        let start = shared.rr.fetch_add(1, Ordering::SeqCst);
        let slots_len = shared.slots.lock().await.len();
        if slots_len == 0 {
            return None;
        }
        for k in 0..slots_len {
            let idx = (start + k) % slots_len;
            let mut slots = shared.slots.lock().await;
            let Some(slot) = slots.get_mut(idx) else {
                continue;
            };
            if !slot.alive {
                continue;
            }
            match slot.send.write_all(frame).await {
                Ok(()) => return Some(()),
                Err(_) => {
                    // 流写失败：摘除并继续尝试下一条
                    slot.alive = false;
                    drop(slots);
                    shared.resend_needed.store(true, Ordering::SeqCst);
                    continue;
                }
            }
        }
        // 一圈下来没有可用流
        None
    }

    /// 重发下行窗口缓存（流死亡丢帧补齐）：按 seq 顺序写到可用流，
    /// 客户端按 seq 去重，重复帧无害。返回 false 表示无可用流。
    async fn resend_cache(shared: &Arc<ChannelShared>, cache: &VecDeque<(u32, Vec<u8>)>) -> bool {
        for (seq, chunk) in cache.iter() {
            let frame = encode_frame(shared.cid, *seq, chunk);
            if Self::write_frame_round_robin(shared, &frame)
                .await
                .is_none()
            {
                return false;
            }
        }
        true
    }

    /// 通道流的帧读循环：`[channel_id 8B][seq 4B][len 2B][payload]` → 上行汇入点。
    /// EOF=该流上行干净结束（保留下行槽位）；读错误=流死亡（摘除槽位+请求缓存重发）。
    async fn channel_read_loop(
        shared: Arc<ChannelShared>,
        idx: usize,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        let up_tx = shared.up_tx.clone();
        loop {
            let mut hdr = [0u8; CHANNEL_FRAME_HEADER];
            match recv.read_exact(&mut hdr).await {
                Ok(()) => {}
                // 干净 FIN：该流上行结束（半关闭语义：下行槽位保留）
                Err(quinn::ReadExactError::FinishedEarly) => {
                    shared.slot_upstream_eof();
                    return Ok(());
                }
                // 客户端 reset / 连接故障：该流死亡
                Err(quinn::ReadExactError::ReadError(e)) => {
                    debug!(
                        "channel {:016x}: stream read error ({}), detaching slot",
                        shared.cid, e
                    );
                    shared.slot_died(idx).await;
                    return Ok(());
                }
            }
            let fcid = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
            if fcid != shared.cid {
                shared.log("frame channel_id mismatch, failing channel");
                shared.fail();
                return Err(HydraError::ProtocolError("channel id mismatch".to_string()));
            }
            let seq = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
            let len = u16::from_be_bytes(hdr[12..14].try_into().unwrap()) as usize;
            if len == 0 || len > CHANNEL_MAX_FRAME {
                shared.log("invalid frame length, failing channel");
                shared.fail();
                return Err(HydraError::ProtocolError(
                    "invalid frame length".to_string(),
                ));
            }
            let mut payload = vec![0u8; len];
            match recv.read_exact(&mut payload).await {
                Ok(()) => {}
                Err(quinn::ReadExactError::FinishedEarly) => {
                    // 帧中途 EOF：字节流已破损，无法恢复——通道失败
                    shared.log("stream finished mid-frame, failing channel");
                    shared.slot_died(idx).await;
                    shared.fail();
                    return Ok(());
                }
                Err(quinn::ReadExactError::ReadError(_)) => {
                    shared.slot_died(idx).await;
                    return Ok(());
                }
            }
            // 有序写任务消失 = 通道已终结
            if up_tx.send((seq, payload)).await.is_err() {
                return Ok(());
            }
        }
    }
}

/// 编码通道帧 `[channel_id 8B][seq 4B][len 2B][payload]`
fn encode_frame(cid: u64, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(CHANNEL_FRAME_HEADER + payload.len());
    frame.extend_from_slice(&cid.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

// ── V3.4 强制门④单测：上行乱序窗口有界 + 空洞超时兜底 ────────────────────

#[cfg(test)]
mod channel_tests {
    use super::*;

    #[test]
    fn up_orderer_delivers_in_seq_order() {
        let mut o = UpOrderer::new();
        assert_eq!(o.pop_ready(), None);
        assert!(matches!(o.insert(2, vec![2]), InsertOutcome::Buffered));
        assert!(matches!(o.insert(0, vec![0]), InsertOutcome::Buffered));
        // next=0 命中
        assert_eq!(o.pop_ready(), Some(vec![0]));
        // next=1 空洞：不可弹出
        assert_eq!(o.pop_ready(), None);
        assert!(matches!(o.insert(1, vec![1]), InsertOutcome::Buffered));
        assert_eq!(o.pop_ready(), Some(vec![1]));
        assert_eq!(o.pop_ready(), Some(vec![2]));
        assert_eq!(o.pop_ready(), None);
        assert!(!o.has_hole());
    }

    #[test]
    fn up_orderer_dedups_retransmits() {
        let mut o = UpOrderer::new();
        assert!(matches!(o.insert(0, vec![1, 2]), InsertOutcome::Buffered));
        assert_eq!(o.pop_ready(), Some(vec![1, 2]));
        // 已写出的 seq 重发：去重
        assert!(matches!(o.insert(0, vec![1, 2]), InsertOutcome::Duplicate));
        // pending 中的同 seq 重发：去重（字节不重复累计）
        assert!(matches!(o.insert(2, vec![9]), InsertOutcome::Buffered));
        assert_eq!(o.pending_bytes(), 1);
        assert!(matches!(o.insert(2, vec![9]), InsertOutcome::Duplicate));
        assert_eq!(o.pending_bytes(), 1);
    }

    #[test]
    fn up_order_window_bounded() {
        let mut gate = UpOrderGate::new();
        // 灌入超过窗口上限的乱序块（next 停在 0，全部积压在 pending）
        let big = vec![0u8; CHANNEL_MAX_FRAME];
        for seq in 1..=(CHANNEL_WINDOW / CHANNEL_MAX_FRAME + 1) as u32 {
            let res = gate.on_chunk(seq, big.clone());
            if (seq as usize) * CHANNEL_MAX_FRAME > CHANNEL_WINDOW {
                assert!(res.is_err(), "seq {} 应触发窗口上限", seq);
                return;
            }
            assert!(res.is_ok());
        }
        panic!("窗口上限未被触发");
    }

    #[tokio::test]
    async fn up_order_hole_timeout_fires() {
        // 注入短时限（生产为 CHANNEL_HOLE_TIMEOUT=5s，语义相同）
        let mut gate = UpOrderGate::with_timeout(Duration::from_millis(20));
        // seq 0 缺失、seq 1 到达 → 空洞计时启动
        gate.on_chunk(1, vec![1]).unwrap();
        assert!(gate.orderer.has_hole());
        assert!(gate.hole_deadline.is_some());
        // 未到期限：不触发
        let deadline = gate.hole_deadline.unwrap();
        assert!(!gate.hole_expired(deadline - Duration::from_millis(1)));
        // 到期：触发兜底
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(gate.hole_expired(tokio::time::Instant::now()));
        // 空洞补齐后计时撤销
        gate.on_chunk(0, vec![0]).unwrap();
        assert_eq!(gate.drain().len(), 2);
        assert!(gate.hole_deadline.is_none());
    }

    #[test]
    fn frame_encode_matches_spec() {
        let frame = encode_frame(0x0102030405060708, 0x090a0b0c, &[0xde, 0xad]);
        assert_eq!(
            frame,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // channel_id 8B
                0x09, 0x0a, 0x0b, 0x0c, // seq 4B
                0x00, 0x02, // len 2B
                0xde, 0xad, // payload
            ]
        );
    }
}
