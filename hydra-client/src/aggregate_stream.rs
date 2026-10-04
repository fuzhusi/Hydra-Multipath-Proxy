//! V3.4 单节点多流通道聚合（客户端侧）。
//!
//! ## 语义（按施工方案裁决 6）
//!
//! - **默认关闭**：未设置 `HYDRA_CHANNELS` 时 [`channel_count`] 返回 None，
//!   open_target 走既有单流路径，线上字节与启用前逐位一致（回归保障③）。
//!   设为 `2..=16` 启用 N 流通道；非法值一律视为未设置（默认关闭）。
//! - **建流**：open_target 成功后，在同一节点连接上再开 N-1 条数据流，
//!   各自写 auth token + `[0x01][channel_id 8B][role=1]`；目标地址声明只由
//!   创建流（role=0）携带。数据帧格式 `[channel_id 8B][seq 4B][len 2B][payload]`。
//! - **上行**：按 chunk 轮转分发到可用流并分配单调 seq；本端维护 replay
//!   窗口（≤4MB），流死亡时把窗口内未确认块按原 seq 重发到存活流，
//!   节点按 seq 去重（`seq < next` 忽略、pending 同 seq 覆盖同内容）。
//! - **下行**：按 seq 重排（有界窗口 4MB + 5s 空洞超时兜底），重复 seq 丢弃；
//!   节点流死亡时以窗口缓存重发补齐在途丢帧。
//! - **接管（验收②）**：任一流 reset/失败 → 该流摘除、双向在途丢帧由
//!   replay/窗口重发补齐，其余流接管，通道不中断；全部流失败才通道级失败，
//!   按 A3 语义映射为 `RelayError::NodeAppError(0x13)` 显式断开浏览器连接。
//!   这是裁决 6"任一流 reset → 整个通道失败处理"二选一中"不中断（接管）"
//!   的如实实现（依赖 seq 去重 + 双侧重发窗口，无 ACK 协议扩展）。
//! - **半关闭**：浏览器关写侧 = 上行写端 finish 全部存活流；节点目标 FIN =
//!   各流 FIN，客户端按"全部流 EOF/死亡 且 重排窗口排空"判定下行完整。
//! - **计数语义**：每条通道流独立包 `CountingStream`（up/down 按实际承接
//!   节点归属），帧头开销按真实线上字节计入，与单流路径同一计数面。
//!   `ACTIVE_RELAYS` 计数不受影响（每浏览器连接仍恰好一次增减）。
//! - **节点版本偏差**：对不支持通道的旧节点，创建流会在应答等待阶段失败，
//!   open_target 对候选遍历耗尽后**回退普通单流路径重试一次**（集成测试覆盖）。
//! - **已知限制**：额外数据流经连接池 LIFO 复用，尽量落在与创建流相同的
//!   QUIC 连接上；偶发跨连接时节点按未知 channel 静默 reset，客户端把
//!   Reset(0) 数据流摘除降级（不中断通道）。

use crate::pool::ConnectionPool;
use crate::traffic::{ByteCounter, CountingStream, NodeTrafficEntry, TrafficMonitor};
use quinn::{RecvStream, SendStream, VarInt};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// 认证后模式标签：0x01 = channel 模式（与节点侧 handler.rs 一致）
pub const MODE_CHANNEL: u8 = 0x01;
/// channel 角色：0 = 创建流（携带目标地址声明），1 = 数据流
pub const ROLE_CREATOR: u8 = 0x00;
pub const ROLE_DATA: u8 = 0x01;
/// 帧头：`[channel_id 8B][seq 4B][len 2B]`
const FRAME_HEADER: usize = 14;
/// 单帧 payload 上限（与现行转发缓冲一致）
/// 单帧载荷上限：2 字节长度字段（u16）能编码的最大值。
/// 若取 65536，`as u16` 会静默回绕成 0——节点判 invalid frame length，通道全灭。
const MAX_FRAME: usize = u16::MAX as usize;
/// 乱序重排窗口上限（字节）：超过视为协议失步，通道失败（与节点侧对称）
pub const CHANNEL_WINDOW: usize = 32 * 1024 * 1024;
/// 空洞等待兜底：next_seq 未到达超过该时长 → 通道失败
pub const CHANNEL_HOLE_TIMEOUT: Duration = Duration::from_secs(5);
/// 节点转发阶段 IO 错误码（与 hydra-node 0x13 / proxy::NODE_ERR_FORWARD_IO 一致）
const NODE_ERR_FORWARD_IO: u64 = 0x13;
/// 客户端主动 reset 数据流时使用的应用错误码（测试钩子用，非 A3 语义码）
const SELF_RESET_CODE: u32 = 0x16;

// ── 开关：HYDRA_CHANNELS（默认关闭）──────────────────────────────────────

/// env 值解析（纯函数，单测覆盖）：仅 2..=16 的整数启用 N 流通道
pub fn channels_env_count(val: Option<&str>) -> Option<usize> {
    val.map(str::trim)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| (2..=16).contains(n))
}

/// 强制开关（测试/调试覆盖 env）：0=按 env 判断，1=强制关闭，n+2=强制启用 n
static FORCE: AtomicUsize = AtomicUsize::new(0);

/// 强制启用/关闭通道聚合（覆盖 env；供测试与调试）
pub fn force_channels(count: Option<usize>) {
    let v = match count {
        None => 1,
        Some(n) => {
            debug_assert!((2..=16).contains(&n), "通道流数须在 2..=16");
            n + 2
        }
    };
    FORCE.store(v, Ordering::Relaxed);
}

/// 当前通道流数配置：None = 关闭（走既有单流路径）
pub fn channel_count() -> Option<usize> {
    match FORCE.load(Ordering::Relaxed) {
        1 => None,
        0 => channels_env_count(std::env::var("HYDRA_CHANNELS").ok().as_deref()),
        v => Some(v - 2),
    }
}

/// 新通道 id（进程内计数器 + SipHash 扩散；节点按 (连接, channel_id) 寻址）
pub fn new_channel_id() -> u64 {
    // 标记"通道路径已被尝试"（含建流后失败回退的场景：SSRF 拒绝发生在
    // build_channel 之前，last_channel_info 观测不到，此处独立取证）
    CHANNEL_ATTEMPTED.store(true, std::sync::atomic::Ordering::Relaxed);
    use std::hash::{BuildHasher, Hasher};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(SEQ.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

// ── 观测与测试钩子（与 aggregate::record_node_served 同风格）────────────

struct ChannelObs {
    cid: u64,
    streams: usize,
    /// 测试钩子：请求 reset 第 k 条数据流（Some(槽位下标)），writer/reader 消费
    kill: watch::Sender<Option<usize>>,
}

static LAST_CHANNEL: OnceLock<Mutex<Option<ChannelObs>>> = OnceLock::new();

/// 通道路径尝试标记（含建流失败回退场景，SSRF 门测试取证用）
static CHANNEL_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// 是否曾尝试通道路径（HYDRA_CHANNELS 启用且创建流已发出）
pub fn channel_attempted() -> bool {
    CHANNEL_ATTEMPTED.load(Ordering::Relaxed)
}

fn last_channel() -> &'static Mutex<Option<ChannelObs>> {
    LAST_CHANNEL.get_or_init(|| Mutex::new(None))
}

/// 最近一次构建的通道信息：(channel_id, 流数)——集成测试断言"确实走了通道路径"
pub fn last_channel_info() -> Option<(u64, usize)> {
    last_channel()
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|o| (o.cid, o.streams)))
}

/// 测试钩子（验收②）：传输中 reset 第 `data_stream_index` 条数据流
/// （0 = 第一条 role=1 流，创建流除外）。执行 `SendStream::reset` +
/// `RecvStream::stop`，语义等同该流被外部杀掉；通道应接管不中断。
pub fn test_reset_data_stream(data_stream_index: usize) {
    if let Ok(g) = last_channel().lock() {
        if let Some(obs) = g.as_ref() {
            let _ = obs.kill.send(Some(data_stream_index + 1)); // 槽位 0 = 创建流
        }
    }
}

// ── 帧编解码与错误类型 ───────────────────────────────────────────────────

fn encode_frame(cid: u64, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER + payload.len());
    frame.extend_from_slice(&cid.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// 通道级错误（映射进 relay 的 RelayError 语义）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// 节点侧显式应用错误码（A3：节点 reset/stop 携带）
    NodeApp(u64),
    /// 传输层/协议失步/窗口超限等本端判定的通道失败
    Transport,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::NodeApp(code) => write!(f, "node app error 0x{:x}", code),
            ChannelError::Transport => write!(f, "channel transport failure"),
        }
    }
}

// ── 上行：多流写入器（write_all 语义 + seq 轮转 + replay 重发）──────────

/// replay 窗口：最近已写 chunk（seq, bytes），容量有界（强制门④：有界性单测）
#[derive(Default)]
struct ReplayBuf {
    items: VecDeque<(u32, Vec<u8>)>,
    bytes: usize,
}

impl ReplayBuf {
    fn push(&mut self, seq: u32, chunk: &[u8]) {
        self.bytes += chunk.len();
        self.items.push_back((seq, chunk.to_vec()));
        while self.bytes > CHANNEL_WINDOW {
            match self.items.pop_front() {
                Some((_, old)) => self.bytes -= old.len(),
                None => break,
            }
        }
    }
}

struct UpSlot {
    send: CountingStream<SendStream>,
    alive: bool,
}

/// 通道上行写端：实现 write_all 语义，内部把 chunk 轮转分发到可用流。
pub struct ChannelUpWriter {
    cid: u64,
    slots: Vec<UpSlot>,
    rr: usize,
    seq: u32,
    replay: ReplayBuf,
    kill_rx: watch::Receiver<Option<usize>>,
}

impl ChannelUpWriter {
    /// 检查并执行测试钩子的 reset 请求（kill 槽位 + 在途帧重发）
    async fn consume_kill(&mut self) -> std::result::Result<(), ChannelError> {
        // 发送端被 drop（通道拆除中）：按无 kill 处理
        if self.kill_rx.has_changed().unwrap_or(false) {
            let req = *self.kill_rx.borrow_and_update();
            if let Some(idx) = req {
                self.kill_slot(idx);
                self.resend_replay().await?;
            }
        }
        Ok(())
    }

    fn kill_slot(&mut self, idx: usize) {
        if let Some(slot) = self.slots.get_mut(idx) {
            if slot.alive {
                let _ = slot.send.get_mut().reset(VarInt::from_u32(SELF_RESET_CODE));
                slot.alive = false;
            }
        }
    }

    /// 把 replay 窗口内未确认块按原 seq 重发到存活流（节点按 seq 去重）
    async fn resend_replay(&mut self) -> std::result::Result<(), ChannelError> {
        // 先克隆窗口（write 需要可变借用自身）
        let items: Vec<(u32, Vec<u8>)> = self.replay.items.iter().cloned().collect();
        for (seq, chunk) in items.iter() {
            let frame = encode_frame(self.cid, *seq, chunk);
            self.write_frame_on_alive(&frame).await?;
        }
        Ok(())
    }

    /// 把一帧写到下一个存活流；失败则摘除该流换下一条。
    /// 返回 Err = 已无可用流（通道级失败）。
    async fn write_frame_on_alive(
        &mut self,
        frame: &[u8],
    ) -> std::result::Result<(), ChannelError> {
        for _ in 0..self.slots.len() {
            let idx = self.rr % self.slots.len();
            self.rr = self.rr.wrapping_add(1);
            let Some(slot) = self.slots.get_mut(idx) else {
                continue;
            };
            if !slot.alive {
                continue;
            }
            match slot.send.write_all(frame).await {
                Ok(()) => return Ok(()),
                Err(quinn::WriteError::Stopped(code)) => {
                    // 节点 STOP/STOP_SENDING（A3 错误码保真）
                    slot.alive = false;
                    debug!(
                        "channel {:016x}: stream {} stopped by node (0x{:x}), detaching",
                        self.cid,
                        idx,
                        u64::from(code)
                    );
                }
                Err(_) => {
                    slot.alive = false;
                }
            }
        }
        Err(ChannelError::NodeApp(NODE_ERR_FORWARD_IO))
    }

    /// write_all 语义：把浏览器上行数据按 ≤64KB chunk 编帧轮转写出
    pub(crate) async fn write_all(
        &mut self,
        mut data: &[u8],
    ) -> std::result::Result<(), ChannelError> {
        while !data.is_empty() {
            self.consume_kill().await?;
            let n = data.len().min(MAX_FRAME);
            // 首帧 seq=0（节点 UpOrderer next 从 0 起等；先取值后自增）
            let seq = self.seq;
            self.seq = self.seq.wrapping_add(1);
            let frame = encode_frame(self.cid, seq, &data[..n]);
            self.write_frame_on_alive(&frame).await?;
            self.replay.push(seq, &data[..n]);
            data = &data[n..];
        }
        Ok(())
    }

    /// 半关闭：上行写端 finish 全部存活流（A4 语义保真）
    pub(crate) async fn finish(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.alive {
                let _ = slot.send.finish().await;
            }
        }
    }
}

// ── 下行：按 seq 重排（有界窗口 + 超时兜底）─────────────────────────────

/// 重排核心（强制门④：窗口有界 + 去重 + 超时兜底，独立单测）
struct DownState {
    map: BTreeMap<u32, Vec<u8>>,
    next: u32,
    bytes: usize,
    eof: usize,
    dead: usize,
    total: usize,
    failed: Option<ChannelError>,
}

impl DownState {
    fn new(total: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            next: 0,
            bytes: 0,
            eof: 0,
            dead: 0,
            total,
            failed: None,
        }
    }

    fn feed(&mut self, seq: u32, payload: Vec<u8>) {
        if self.failed.is_some() {
            return;
        }
        // 去重：已弹出（seq < next）或已缓存的重复帧丢弃（节点重发窗口补齐时重复无害）
        if seq < self.next || self.map.contains_key(&seq) {
            return;
        }
        self.bytes += payload.len();
        if self.bytes > CHANNEL_WINDOW {
            self.failed = Some(ChannelError::Transport);
            self.map.clear();
            self.bytes = 0;
            return;
        }
        self.map.insert(seq, payload);
    }

    fn pop_ready(&mut self) -> Option<Vec<u8>> {
        let payload = self.map.remove(&self.next)?;
        self.bytes -= payload.len();
        self.next = self.next.wrapping_add(1);
        Some(payload)
    }

    fn has_hole(&self) -> bool {
        !self.map.is_empty()
    }

    /// 全部流已终态（EOF/死亡）且窗口排空：下行完整（EOF 给浏览器）。
    /// 全部死亡但窗口排空亦视为结束：节点侧已不可能再产出任何帧。
    fn finished(&self) -> bool {
        self.failed.is_none() && self.eof + self.dead >= self.total && self.map.is_empty()
    }
}

struct DownCore {
    state: Mutex<DownState>,
    notify: tokio::sync::Notify,
}

impl DownCore {
    fn new(total: usize) -> Self {
        Self {
            state: Mutex::new(DownState::new(total)),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn feed(&self, seq: u32, payload: Vec<u8>) {
        if let Ok(mut st) = self.state.lock() {
            st.feed(seq, payload);
        }
        self.notify.notify_one();
    }

    fn stream_eof(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.eof += 1;
        }
        self.notify.notify_one();
    }

    /// 流被本端 reset（测试钩子）或节点按未知通道 reset(0)：摘除，非通道失败
    fn stream_dead(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.dead += 1;
        }
        self.notify.notify_one();
    }

    /// 通道级失败（节点显式 0x13 reset / 连接级故障 / 窗口超限）
    fn fail(&self, e: ChannelError) {
        if let Ok(mut st) = self.state.lock() {
            if st.failed.is_none() {
                st.failed = Some(e);
            }
        }
        self.notify.notify_one();
    }
}

/// 单条通道流的下行帧读取任务：解析帧 → 重排核心；EOF/死亡/失败分流。
async fn down_read_task(
    idx: usize,
    mut recv: CountingStream<RecvStream>,
    core: Arc<DownCore>,
    mut kill_rx: watch::Receiver<Option<usize>>,
) {
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = recv.read(&mut buf) => match r {
                // 节点 FIN：该流下行完整
                Ok(Some(0)) | Ok(None) => {
                    debug!("down_read_task idx={} terminal read (Some(0)/None) -> stream_eof", idx);
                    core.stream_eof();
                    return;
                }
                Ok(Some(n)) => {
                    acc.extend_from_slice(&buf[..n]);
                    // 解出全部完整帧；残包留待下一轮
                    while acc.len() >= FRAME_HEADER {
                        let cid = u64::from_be_bytes(acc[0..8].try_into().unwrap());
                        let seq = u32::from_be_bytes(acc[8..12].try_into().unwrap());
                        let len = u16::from_be_bytes(acc[12..14].try_into().unwrap()) as usize;
                        if acc.len() < FRAME_HEADER + len {
                            break;
                        }
                        let payload = acc[FRAME_HEADER..FRAME_HEADER + len].to_vec();
                        acc.drain(..FRAME_HEADER + len);
                        let _ = cid; // 通道绑定由建流头确立，帧内 cid 由节点保证一致
                        if len == 0 {
                            core.fail(ChannelError::Transport);
                            return;
                        }
                        core.feed(seq, payload);
                    }
                }
                // 节点显式 0x13：转发阶段故障，通道级显式失败（A3 语义保真）
                Err(quinn::ReadError::Reset(code)) => {
                    let code = u64::from(code);
                    if code == 0 {
                        // 节点侧"未知通道"静默 reset（跨连接建流降级路径）：摘除该流
                        core.stream_dead();
                    } else {
                        core.fail(ChannelError::NodeApp(code));
                    }
                    return;
                }
                Err(_) => {
                    core.fail(ChannelError::Transport);
                    return;
                }
            },
            changed = kill_rx.changed() => {
                if changed.is_err() {
                    return; // 发送端 drop = 通道拆除中
                }
                if *kill_rx.borrow_and_update() == Some(idx) {
                    let _ = recv.get_mut().stop(VarInt::from_u32(0));
                    core.stream_dead();
                    return;
                }
            }
        }
    }
}

/// 重排装配任务：按 seq 出队送入 relay 读端；空洞超时兜底；终态判定。
/// hole_timeout 生产传 [`CHANNEL_HOLE_TIMEOUT`]，单测注入短时限。
async fn down_assemble_task(
    core: Arc<DownCore>,
    hole_timeout: Duration,
    tx: mpsc::Sender<std::result::Result<Vec<u8>, ChannelError>>,
) {
    let mut hole_deadline;
    loop {
        // 失败优先：显式报错（对齐单流路径 reset=显式断开语义）
        let failed = core.state.lock().ok().and_then(|st| st.failed.clone());
        if let Some(e) = failed {
            let _ = tx.send(Err(e)).await;
            return;
        }
        // 排空就绪块
        loop {
            let ready = core.state.lock().ok().and_then(|mut st| st.pop_ready());
            match ready {
                Some(chunk) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        return; // relay 已结束
                    }
                }
                None => break,
            }
        }
        // 终态判定：全部流 EOF/死亡且窗口排空 → 干净 EOF
        let done = core
            .state
            .lock()
            .ok()
            .map(|st| st.finished())
            .unwrap_or(false);
        if done {
            debug!("assemble: finished() true -> delivering EOF");
            drop(tx); // recv 端读到 None = EOF
            return;
        }
        // 空洞计时
        let has_hole = core
            .state
            .lock()
            .ok()
            .map(|st| st.has_hole())
            .unwrap_or(false);
        hole_deadline = if has_hole {
            Some(tokio::time::Instant::now() + hole_timeout)
        } else {
            None
        };
        tokio::select! {
            _ = core.notify.notified() => {}
            _ = async {
                match hole_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            } => {
                let _ = tx.send(Err(ChannelError::Transport)).await; // 空洞超时兜底
                return;
            }
        }
    }
}

/// 通道下行读端：relay 的 DownSource 通道臂
pub struct ChannelDownReader {
    rx: mpsc::Receiver<std::result::Result<Vec<u8>, ChannelError>>,
    pending: VecDeque<Vec<u8>>,
}

impl ChannelDownReader {
    /// read 语义：Ok(Some(n)) / Ok(None)=EOF / Err(ChannelError)
    pub(crate) async fn read(
        &mut self,
        buf: &mut [u8],
    ) -> std::result::Result<Option<usize>, ChannelError> {
        loop {
            if buf.is_empty() {
                return Ok(Some(0));
            }
            if let Some(chunk) = self.pending.front_mut() {
                let n = buf.len().min(chunk.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                chunk.drain(..n);
                if chunk.is_empty() {
                    self.pending.pop_front();
                }
                return Ok(Some(n));
            }
            match self.rx.recv().await {
                Some(Ok(chunk)) => self.pending.push_back(chunk),
                Some(Err(e)) => return Err(e),
                None => return Ok(None),
            }
        }
    }
}

/// 任务收敛守卫：relay 持有的 up/down 任一端析构（两者同生命周期）即 abort
/// 读帧/装配任务，杜绝孤儿任务（对齐 ACTIVE_RELAYS 收敛纪律）。
pub(crate) struct TaskGuard(Arc<Vec<tokio::task::JoinHandle<()>>>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        for h in self.0.iter() {
            h.abort();
        }
    }
}

/// 通道对：relay 的 UpSink/DownSource 通道臂 + 任务守卫
pub struct ChannelPair {
    pub(crate) up: ChannelUpWriter,
    pub(crate) down: ChannelDownReader,
    /// relay 持有至连接收敛；析构时 abort 读帧/装配任务
    pub(crate) _guard: TaskGuard,
}

/// 在同一节点连接上构建 N 流通道（创建流已通过 0x00 应答确认）。
/// 额外数据流建流失败时如实降级为更少流（≥1 即可用），不中断建连。
pub(crate) async fn build_channel(
    pool: &ConnectionPool,
    node_addr: SocketAddr,
    cid: u64,
    total_streams: usize,
    creator: (SendStream, RecvStream),
    traffic: &Arc<TrafficMonitor>,
    node_entry: Arc<NodeTrafficEntry>,
) -> ChannelPair {
    let up_counter = ByteCounter::up(Some(traffic.clone()), Some(node_entry.clone()));
    let down_counter = ByteCounter::down(Some(traffic.clone()), Some(node_entry.clone()));
    let mut sends = vec![CountingStream::new(creator.0, up_counter)];
    let mut recvs = vec![CountingStream::new(creator.1, down_counter)];

    // 同一节点连接上再开 N-1 条数据流：各自 auth（pool 内完成）+ 0x01 + cid + role=1
    for i in 1..total_streams {
        match pool.get_stream(node_addr).await {
            Ok((mut s, r)) => {
                let mut hdr = Vec::with_capacity(10);
                hdr.push(MODE_CHANNEL);
                hdr.extend_from_slice(&cid.to_be_bytes());
                hdr.push(ROLE_DATA);
                if let Err(e) = s.write_all(&hdr).await {
                    warn!(
                        "channel {:016x}: data stream {} header write failed ({}), degrading to {} streams",
                        cid, i, e, i
                    );
                    break;
                }
                let up = ByteCounter::up(Some(traffic.clone()), Some(node_entry.clone()));
                let down = ByteCounter::down(Some(traffic.clone()), Some(node_entry.clone()));
                sends.push(CountingStream::new(s, up));
                recvs.push(CountingStream::new(r, down));
            }
            Err(e) => {
                warn!(
                    "channel {:016x}: data stream {} open failed ({}), degrading to {} streams",
                    cid, i, e, i
                );
                break;
            }
        }
    }
    let streams = sends.len();
    if streams < total_streams {
        info!(
            "channel {:016x} built with {}/{} streams (degraded)",
            cid, streams, total_streams
        );
    } else {
        info!(
            "channel {:016x} built with {} streams on node {}",
            cid, streams, node_addr
        );
    }

    // 下行机制：每流一个读帧任务 + 一个装配任务
    let core = Arc::new(DownCore::new(streams));
    let (kill_tx, _) = watch::channel(None::<usize>);
    let (out_tx, out_rx) = mpsc::channel(64);
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    for (i, recv) in recvs.into_iter().enumerate() {
        handles.push(tokio::spawn(down_read_task(
            i,
            recv,
            core.clone(),
            kill_tx.subscribe(),
        )));
    }
    handles.push(tokio::spawn(down_assemble_task(
        core,
        CHANNEL_HOLE_TIMEOUT,
        out_tx,
    )));

    let up = ChannelUpWriter {
        cid,
        slots: sends
            .into_iter()
            .map(|send| UpSlot { send, alive: true })
            .collect(),
        rr: 0,
        seq: 0,
        replay: ReplayBuf::default(),
        kill_rx: kill_tx.subscribe(),
    };
    let down = ChannelDownReader {
        rx: out_rx,
        pending: VecDeque::new(),
    };

    // 观测/测试钩子注册（最近一次构建的通道）
    if let Ok(mut g) = last_channel().lock() {
        *g = Some(ChannelObs {
            cid,
            streams,
            kill: kill_tx,
        });
    }

    ChannelPair {
        up,
        down,
        _guard: TaskGuard(Arc::new(handles)),
    }
}

// ── 强制门④单测：乱序窗口有界 + 去重 + 超时兜底 + 开关解析 ─────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing_default_off() {
        // 未设置/非法值一律关闭（默认关闭语义）
        assert_eq!(channels_env_count(None), None);
        assert_eq!(channels_env_count(Some("")), None);
        assert_eq!(channels_env_count(Some("0")), None);
        assert_eq!(channels_env_count(Some("1")), None); // 1 流通道无意义，视为关闭
        assert_eq!(channels_env_count(Some("junk")), None);
        assert_eq!(channels_env_count(Some("17")), None);
        assert_eq!(channels_env_count(Some("-1")), None);
        assert_eq!(channels_env_count(Some(" 2 ")), Some(2));
        assert_eq!(channels_env_count(Some("4")), Some(4));
        assert_eq!(channels_env_count(Some("16")), Some(16));
    }

    #[test]
    fn force_channels_overrides_env_parse() {
        force_channels(None);
        assert_eq!(channel_count(), None);
        force_channels(Some(4));
        assert_eq!(channel_count(), Some(4));
        force_channels(None);
        assert_eq!(channel_count(), None);
    }

    #[test]
    fn replay_buf_bounded() {
        let mut rb = ReplayBuf::default();
        // 灌入超过窗口（40MiB > 32MiB 窗口）：仅保留最近 CHANNEL_WINDOW 字节
        let chunk = vec![0u8; 1024 * 1024];
        const PUSHED: u32 = 40;
        for i in 0..PUSHED {
            rb.push(i, &chunk);
        }
        assert!(rb.bytes <= CHANNEL_WINDOW);
        // 期望 front：从旧到新取 k 个 1MiB 使总和 <= 窗口（32MiB 窗口 → 保留 32 块）
        let kept = (CHANNEL_WINDOW / chunk.len()) as u32;
        let expect_front = PUSHED - kept;
        assert_eq!(rb.items.front().unwrap().0, expect_front);
        assert_eq!(rb.items.back().unwrap().0, PUSHED - 1);
        assert_eq!(rb.items.len() as u32, kept);
    }

    #[test]
    fn down_state_reorders_and_dedups() {
        let mut st = DownState::new(2);
        // 乱序到达：2、0 先到，1 缺失
        st.feed(2, vec![2]);
        st.feed(0, vec![0]);
        assert_eq!(st.pop_ready(), Some(vec![0]));
        assert_eq!(st.pop_ready(), None);
        assert!(st.has_hole());
        // 重复帧去重（节点窗口重发场景）
        st.feed(2, vec![2]);
        assert_eq!(st.bytes, 1);
        st.feed(0, vec![0]); // 已弹出 seq 重发：去重
        assert_eq!(st.bytes, 1);
        // 空洞补齐
        st.feed(1, vec![1]);
        assert_eq!(st.pop_ready(), Some(vec![1]));
        assert_eq!(st.pop_ready(), Some(vec![2]));
        assert_eq!(st.pop_ready(), None);
        assert!(!st.has_hole());
    }

    #[test]
    fn down_state_window_bounded_fails_channel() {
        let mut st = DownState::new(2);
        // 乱序灌入超过窗口上限 → 通道失败（窗口有界）
        let big = vec![0u8; 1024 * 1024];
        let mut seq = 1u32; // 留 0 为空洞，全部积压
                            // 退出条件必须含 failed：超窗后 feed 置 failed 并清零 bytes（此后为 no-op），
                            // 若只看 bytes 则 0 <= 窗口恒真 → 死循环
        while st.bytes <= CHANNEL_WINDOW && st.failed.is_none() {
            st.feed(seq, big.clone());
            seq += 1;
        }
        assert_eq!(st.failed, Some(ChannelError::Transport));
        assert!(st.map.is_empty());
    }

    #[test]
    fn down_state_finished_requires_all_terminal_and_drained() {
        let mut st = DownState::new(2);
        st.feed(0, vec![0]);
        st.eof += 1;
        assert!(!st.finished(), "还有 1 条流未终态");
        st.eof += 1;
        assert!(!st.finished(), "窗口未排空不应 EOF");
        assert_eq!(st.pop_ready(), Some(vec![0]));
        assert!(st.finished(), "全部 EOF 且排空 → 干净结束");
        // 失败优先于完成判定
        let mut st2 = DownState::new(1);
        st2.eof += 1;
        st2.failed = Some(ChannelError::NodeApp(0x13));
        assert!(!st2.finished());
    }

    /// 强制门④（客户端侧）：空洞超时兜底——next_seq 缺失超过时限 → 通道失败
    #[tokio::test]
    async fn down_hole_timeout_fires() {
        let core = Arc::new(DownCore::new(2));
        // seq 0 缺失、seq 1 到达 → 空洞挂起
        core.feed(1, vec![1]);
        let (tx, mut rx) = mpsc::channel(4);
        tokio::spawn(down_assemble_task(
            core.clone(),
            Duration::from_millis(30),
            tx,
        ));
        let t0 = std::time::Instant::now();
        let out = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("空洞超时兜底未触发")
            .expect("装配任务不应提前退出");
        assert_eq!(out, Err(ChannelError::Transport));
        assert!(
            t0.elapsed() >= Duration::from_millis(25),
            "兜底应在时限后触发而非立即"
        );
    }

    #[tokio::test]
    async fn down_assemble_delivers_in_order_and_eof() {
        let core = Arc::new(DownCore::new(2));
        core.feed(2, vec![2]);
        core.feed(0, vec![0]);
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(down_assemble_task(core.clone(), CHANNEL_HOLE_TIMEOUT, tx));
        // next=0 就绪，1 空洞挂起
        assert_eq!(rx.recv().await, Some(Ok(vec![0])));
        // 补齐后 1、2 依序交付
        core.feed(1, vec![1]);
        assert_eq!(rx.recv().await, Some(Ok(vec![1])));
        assert_eq!(rx.recv().await, Some(Ok(vec![2])));
        // 两流全部 EOF 且窗口排空 → 干净 EOF
        core.stream_eof();
        core.stream_eof();
        assert_eq!(rx.recv().await, None);
    }
}
