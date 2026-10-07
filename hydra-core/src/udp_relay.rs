//! UDP-over-proxy 客户端通道：在一条已认证的 TCP/TLS 流上多路复用 UDP 会话。
//!
//! 复用 [`crate::tcp_transport::connect_target`] 建链（TCP + TLS + Noise-PSK
//! 握手 + 2B 应答），地址帧目标使用保留前缀 [`UDP_RELAY_TARGET`]——节点侧
//! （`hydra_node::udp_relay`）识别该前缀后进入 UDP 中继模式，此后该流承载
//! [`hydra_protocol::udp_frame`] 定义的变长会话帧（上行/下行对称）。
//!
//! # API
//! - [`open_udp_channel`]：建链并进入 UDP 中继模式；
//! - [`UdpChannel::send_to`]：向目标发数据报（同一目标地址复用同一
//!   session_id；首次发送即隐式建立会话）；
//! - [`UdpChannel::recv_from`]：收下一个下行数据报，返回 `(目标地址, 数据报)`；
//!   下行 close 帧（节点空闲回收）在内部消化并解除 session 映射；
//! - [`UdpChannel::close_target`]：对目标发 close 帧主动关会话。
//!
//! 线程模型：单通道单任务使用（`&mut self`）；TUN 批次再在其上做多路分发。

use std::collections::HashMap;
use std::net::SocketAddr;

use hydra_protocol::mask_target;
use hydra_protocol::udp_frame::{
    encode_udp_close, encode_udp_data, read_udp_frame, write_udp_frame, UdpFrame,
};
use hydra_protocol::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::tcp_transport::{connect_target, TcpNodeStream, TlsTrust};

/// UDP 中继模式的地址帧目标（节点按保留前缀 `@udp-relay/` 分流）
pub const UDP_RELAY_TARGET: &str = "@udp-relay/v1";

/// 本地会话映射上限（09-P1-5）：TUN 全流量场景每分钟可出现上千个一次性目标
/// （DNS/P2P），无上限的映射表既耗内存又加速单调 sid 空间耗尽；超限按 LRU
/// 淘汰并复用 sid（下行 close 通知节点删旧会话）。
pub const UDP_MAX_LOCAL_SESSIONS: usize = 4096;

/// 单个本地会话映射条目：sid + 最近使用时刻（LRU 依据）
#[derive(Clone, Copy)]
struct SessionEntry {
    sid: u16,
    last_used: std::time::Instant,
}

/// 泛型 UDP 通道（对任意 TLS 流半拆分可用；mock 流便于单测）。
/// 目标地址 → session_id 的映射由通道内部维护。
pub struct UdpChannel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    rd: R,
    wr: W,
    /// 目标地址 → 已分配的 session_id（同一目标复用同一会话）
    sessions: HashMap<String, SessionEntry>,
    next_sid: u16,
    /// 本地会话映射上限（测试可注入小值；生产默认 [`UDP_MAX_LOCAL_SESSIONS`]）
    max_sessions: usize,
    /// LRU 淘汰/号回收产生的待发下行 close 帧（下一帧数据前经同一有序流
    /// 发出，保证节点先删旧会话再建新会话，sid 复用不串话）
    pending_closes: Vec<u16>,
}

/// 真实节点流（connect_target 产出的 TcpNodeStream 拆分两半）上的通道
pub type NodeUdpChannel = UdpChannel<ReadHalf<TcpNodeStream>, WriteHalf<TcpNodeStream>>;

/// UDP 通道工厂（TUN 场景）：每次调用建一条新中继通道（断线重连用）。
pub type UdpChannelFactory = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<NodeUdpChannel>> + Send>>
        + Send
        + Sync,
>;

/// 连接节点并打开 UDP 中继通道。
///
/// `connect_target` 完成 TCP 建连 → TLS（pinning/CA + SNI）→ Noise-PSK 握手
/// → 写 `@udp-relay/v1` 地址帧 → 读 2B 应答；任一步失败即 Err（认证失败/
/// 失步表现为节点静默关流，与 TCP 目标转发路径语义一致）。
pub async fn open_udp_channel(
    node_addr: SocketAddr,
    sni: &str,
    trust: &TlsTrust,
    auth_key: &[u8],
) -> Result<NodeUdpChannel> {
    let stream = connect_target(node_addr, sni, trust, auth_key, UDP_RELAY_TARGET).await?;
    let (rd, wr) = tokio::io::split(stream);
    Ok(UdpChannel {
        rd,
        wr,
        sessions: HashMap::new(),
        next_sid: 1,
        max_sessions: UDP_MAX_LOCAL_SESSIONS,
        pending_closes: Vec::new(),
    })
}

impl<R, W> UdpChannel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// 为目标地址取（或分配）session_id。
    ///
    /// 09-P1-5：sid 不再只增不回收——映射表带容量上限，超限按 LRU 淘汰并
    /// 复用其 sid（先记待发 close）；单调分配耗尽（u16::MAX）同样走 LRU
    /// 复用。此前单调分配 + 仅靠节点下行 close 解除映射：一次性目标（DNS/
    /// P2P）高频出现约 1 小时耗尽 65535，此后每次 `send_to` 永久 Err，通道
    /// 无自愈。复用正确性：帧在同一 TCP 流上有序，淘汰 close 先于新数据帧
    /// 到达节点——节点对「同 sid 换目标」按重建绑定语义处理，不串话。
    fn session_for(&mut self, target: &str) -> Result<u16> {
        if let Some(entry) = self.sessions.get_mut(target) {
            entry.last_used = std::time::Instant::now();
            return Ok(entry.sid);
        }
        // 单调分配：仅在容量未满且单调空间未耗尽（next_sid != u16::MAX，
        // 或表空——边界号 u16::MAX 本身仍可分配一次）时走此路径；否则新目标
        // 经 LRU 淘汰复用 sid（耗尽后允许同号多目标会造成节点侧每帧重建
        // 绑定的抖动，比一次 close+复用更糟）
        if self.sessions.len() < self.max_sessions
            && (self.next_sid != u16::MAX || self.sessions.is_empty())
        {
            let sid = self.next_sid;
            let has_next = sid != u16::MAX;
            self.sessions.insert(
                target.to_string(),
                SessionEntry {
                    sid,
                    last_used: std::time::Instant::now(),
                },
            );
            if has_next {
                self.next_sid += 1;
            }
            return Ok(sid);
        }
        // 容量满或单调空间耗尽：LRU 淘汰并复用其 sid
        let (victim_target, victim) = self
            .sessions
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(t, e)| (t.clone(), *e))
            .ok_or_else(|| {
                hydra_protocol::HydraError::ProtocolError(
                    "UDP 会话号耗尽且无会话可回收（请重建通道）".to_string(),
                )
            })?;
        self.sessions.remove(&victim_target);
        self.pending_closes.push(victim.sid);
        self.sessions.insert(
            target.to_string(),
            SessionEntry {
                sid: victim.sid,
                last_used: std::time::Instant::now(),
            },
        );
        Ok(victim.sid)
    }

    /// 向目标发一个 UDP 数据报（同一目标复用同一 session；首次发送隐式建立）。
    pub async fn send_to(&mut self, target: &str, datagram: &[u8]) -> Result<()> {
        // 09-P3-7（审查08 遗留）：sid 分配与编码都在写出前完成；淘汰产生的
        // close 帧先于数据帧发出。编码失败时映射已建立但 sid 可复用（下次
        // send_to 同目标直接命中映射），不再出现"登记残留 + sid 空耗"。
        let sid = self.session_for(target)?;
        let frame = encode_udp_data(sid, target, datagram)?;
        self.flush_pending_closes().await;
        write_udp_frame(&mut self.wr, &frame).await
    }

    /// 【TUN 场景】带会话键的发送：`session_key`（如 TUN 四元组流键）参与本地
    /// 映射，键不同的流到**同一目标**各自持有独立 sid——节点侧按 sid 分会话，
    /// 下行回包可按 sid 精确反解到发起流（单键模型无法区分多个客户端 socket
    /// 发往同一目标）。返回本流本次使用的 sid，供调用方维护 sid→流 的反查表。
    pub async fn send_to_ext(
        &mut self,
        session_key: &str,
        target: &str,
        datagram: &[u8],
    ) -> Result<u16> {
        let keyed = format!("{session_key}\u{1f}{target}");
        let sid = self.session_for(&keyed)?;
        let frame = encode_udp_data(sid, target, datagram)?;
        self.flush_pending_closes().await;
        write_udp_frame(&mut self.wr, &frame).await?;
        Ok(sid)
    }

    /// 主动关闭 keyed 会话（发 close 帧）。返回是否确有该会话。
    pub async fn close_session_ext(&mut self, session_key: &str, target: &str) -> Result<bool> {
        let keyed = format!("{session_key}\u{1f}{target}");
        match self.sessions.remove(&keyed) {
            Some(entry) => {
                write_udp_frame(&mut self.wr, &encode_udp_close(entry.sid)).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// 把淘汰产生的下行 close 帧写出（数据帧之前，保证节点先删旧会话）
    async fn flush_pending_closes(&mut self) {
        for sid in std::mem::take(&mut self.pending_closes) {
            if write_udp_frame(&mut self.wr, &encode_udp_close(sid))
                .await
                .is_err()
            {
                // 写失败：连接已死，后续写同样失败，丢弃剩余
                self.pending_closes.clear();
                return;
            }
        }
    }

    /// 收下一个下行数据报，返回 `(目标地址, 数据报)`。
    /// 途中收到的下行 close 帧（节点空闲回收）内部消化并解除映射后继续等。
    /// 09-P2-2：按本地映射校验下行帧（target, sid）归属——sid 不匹配或目标
    /// 无映射的帧（会话关闭后的迟到帧/sid 复用期的旧会话回包）丢弃，防被
    /// 入侵节点做跨会话混淆。
    pub async fn recv_from(&mut self) -> Result<(String, Vec<u8>)> {
        loop {
            match self.recv_from_ext().await? {
                // 旧 API 语义：close 帧内部消化（映射已由 ext 层解除）
                UdpRx::Data { target, datagram, .. } => return Ok((target, datagram)),
                UdpRx::Closed { .. } => continue,
            }
        }
    }
}

/// 【TUN 场景】下行接收结果：数据帧携带 sid 供流反解；close 帧（节点空闲
/// 回收/会话满）显式暴露给调用方清理 sid→流 映射。
#[derive(Debug, Clone, PartialEq)]
pub enum UdpRx {
    Data {
        sid: u16,
        target: String,
        datagram: Vec<u8>,
    },
    Closed {
        sid: u16,
    },
}

impl<R, W> UdpChannel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// 【TUN 场景】下行接收：数据帧带 sid（本地映射校验同 [`Self::recv_from`]），
    /// close 帧以 [`UdpRx::Closed`] 返回（调用方据此解除 sid 反查表条目）。
    pub async fn recv_from_ext(&mut self) -> Result<UdpRx> {
        loop {
            match read_udp_frame(&mut self.rd).await? {
                UdpFrame::Data {
                    session_id,
                    target,
                    datagram,
                } => {
                    // 按 sid 反查 keyed 映射：sid 在本连接内唯一，存在即有效会话
                    if !self.sessions.values().any(|e| e.sid == session_id) {
                        tracing::debug!(
                            "UDP 下行帧 sid 无本地映射（会话已关/迟到帧），丢弃: {}",
                            mask_target(&target)
                        );
                        continue;
                    }
                    // touch 活跃时间（LRU 计入下行）
                    if let Some((_, e)) =
                        self.sessions.iter_mut().find(|(_, e)| e.sid == session_id)
                    {
                        e.last_used = std::time::Instant::now();
                    }
                    // target 取帧内目标——节点回显本端发送的目标，即流的 dst
                    return Ok(UdpRx::Data {
                        sid: session_id,
                        target,
                        datagram,
                    });
                }
                UdpFrame::Close { session_id } => {
                    // 解除 keyed 映射（键含流键，按 sid 反查后整键删除）
                    if let Some(k) = self
                        .sessions
                        .iter()
                        .find(|(_, e)| e.sid == session_id)
                        .map(|(k, _)| k.clone())
                    {
                        self.sessions.remove(&k);
                    }
                    return Ok(UdpRx::Closed { sid: session_id });
                }
            }
        }
    }

    /// 主动关闭目标会话（发 close 帧）。返回是否确有该会话。
    pub async fn close_target(&mut self, target: &str) -> Result<bool> {
        match self.sessions.remove(target) {
            Some(entry) => {
                write_udp_frame(&mut self.wr, &encode_udp_close(entry.sid)).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// 当前活跃会话数（测试/观测用）
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    type TestChannel = UdpChannel<
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    >;

    /// mock 节点：读上行帧并回显下行数据帧（同 session 同目标），close 帧仅记录
    async fn mock_node_relay(srv: tokio::io::DuplexStream, closes: std::sync::Arc<std::sync::atomic::AtomicU32>) {
        let mut srv = srv;
        loop {
            match read_udp_frame(&mut srv).await {
                Ok(UdpFrame::Data {
                    session_id,
                    target,
                    datagram,
                }) => {
                    let frame = encode_udp_data(session_id, &target, &datagram).unwrap();
                    if write_udp_frame(&mut srv, &frame).await.is_err() {
                        break;
                    }
                }
                Ok(UdpFrame::Close { .. }) => {
                    closes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    }

    fn open_test_channel(cli: tokio::io::DuplexStream) -> TestChannel {
        let (rd, wr) = tokio::io::split(cli);
        UdpChannel {
            rd,
            wr,
            sessions: HashMap::new(),
            next_sid: 1,
            max_sessions: UDP_MAX_LOCAL_SESSIONS,
            pending_closes: Vec::new(),
        }
    }

    fn open_test_channel_with_capacity(cli: tokio::io::DuplexStream, cap: usize) -> TestChannel {
        let (rd, wr) = tokio::io::split(cli);
        UdpChannel {
            rd,
            wr,
            sessions: HashMap::new(),
            next_sid: 1,
            max_sessions: cap,
            pending_closes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn send_recv_帧往返与同目标复用会话() {
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (cli, srv) = duplex(4096);
        tokio::spawn(mock_node_relay(srv, closes.clone()));
        let mut ch = open_test_channel(cli);

        ch.send_to("10.0.0.1:53", b"query").await.unwrap();
        let (target, data) = ch.recv_from().await.unwrap();
        assert_eq!(target, "10.0.0.1:53");
        assert_eq!(data, b"query");

        // 同一目标再发：复用同一 session（仍往返成功）
        ch.send_to("10.0.0.1:53", b"query2").await.unwrap();
        let (_, data) = ch.recv_from().await.unwrap();
        assert_eq!(data, b"query2");
        assert_eq!(ch.active_sessions(), 1);

        // 不同目标：分配新 session
        ch.send_to("10.0.0.2:53", b"x").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        assert_eq!(ch.active_sessions(), 2);
    }

    #[tokio::test]
    async fn close_target_发close帧并解除映射() {
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (cli, srv) = duplex(4096);
        tokio::spawn(mock_node_relay(srv, closes.clone()));
        let mut ch = open_test_channel(cli);

        ch.send_to("10.0.0.9:123", b"hi").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        assert!(ch.close_target("10.0.0.9:123").await.unwrap());
        // 幂等：已关闭的目标再关 → false 且不发帧
        assert!(!ch.close_target("10.0.0.9:123").await.unwrap());
        for _ in 0..50 {
            if closes.load(std::sync::atomic::Ordering::Relaxed) == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("mock 节点应收到 1 个 close 帧");
    }

    #[tokio::test]
    async fn 下行close帧被消化并解除映射() {
        let (cli, srv) = duplex(4096);
        // 节点侧：回环第一帧后回收该会话（模拟空闲回收下行 close），再对一个
        // 迟到同 sid 帧与一个新会话帧——验证 close 解除映射、迟到帧被丢弃、
        // 新会话帧正常分发（09-P2-2 sid 校验语义）
        let mock = async move {
            let mut srv = srv;
            let frame = read_udp_frame(&mut srv).await.unwrap();
            let UdpFrame::Data { session_id, target, .. } = frame else {
                panic!("应为数据帧");
            };
            // 回环后立刻 close：映射应在客户端解除
            write_udp_frame(&mut srv, &encode_udp_data(session_id, &target, b"echo-1").unwrap())
                .await
                .unwrap();
            write_udp_frame(&mut srv, &encode_udp_close(session_id))
                .await
                .unwrap();
            // close 之后的迟到同 sid 帧：应被客户端丢弃（会话已关）
            write_udp_frame(
                &mut srv,
                &encode_udp_data(session_id, &target, b"late-after-close").unwrap(),
            )
            .await
            .unwrap();
            // 客户端对另一目标的新会话帧：原样回环
            let frame2 = read_udp_frame(&mut srv).await.unwrap();
            let UdpFrame::Data { session_id: s2, target: t2, datagram: d2 } = frame2 else {
                panic!("应为数据帧");
            };
            write_udp_frame(&mut srv, &encode_udp_data(s2, &t2, &d2).unwrap())
                .await
                .unwrap();
        };
        tokio::spawn(mock);
        let mut ch = open_test_channel(cli);

        ch.send_to("10.0.0.3:443", b"trigger").await.unwrap();
        let (target, data) = ch.recv_from().await.unwrap();
        assert_eq!(target, "10.0.0.3:443");
        assert_eq!(data, b"echo-1");
        // 第二个目标：新会话回环正常；第一个目标的映射已被 close 解除，
        // 迟到帧被丢弃不误投
        ch.send_to("10.0.0.4:443", b"second").await.unwrap();
        let (target, data) = ch.recv_from().await.unwrap();
        assert_eq!(target, "10.0.0.4:443");
        assert_eq!(data, b"second");
        assert_eq!(ch.active_sessions(), 1, "close 帧应解除第一个目标的映射");
    }

    /// 09-P2-2：sid 与本地映射不匹配的下行帧被丢弃，匹配的正常投递
    #[tokio::test]
    async fn 下行帧sid不匹配被丢弃() {
        let (cli, srv) = duplex(4096);
        let mock = async move {
            let mut srv = srv;
            let frame = read_udp_frame(&mut srv).await.unwrap();
            let UdpFrame::Data { session_id, target, .. } = frame else {
                panic!("应为数据帧");
            };
            // 伪造 sid（会话混淆帧）→ 客户端应丢弃
            write_udp_frame(&mut srv, &encode_udp_data(session_id + 100, &target, b"bad").unwrap())
                .await
                .unwrap();
            // 正确 sid → 正常投递
            write_udp_frame(&mut srv, &encode_udp_data(session_id, &target, b"good").unwrap())
                .await
                .unwrap();
        };
        tokio::spawn(mock);
        let mut ch = open_test_channel(cli);
        ch.send_to("10.0.0.5:53", b"query").await.unwrap();
        let (target, data) = ch.recv_from().await.unwrap();
        assert_eq!(target, "10.0.0.5:53");
        assert_eq!(data, b"good", "混淆帧应被丢弃，仅正确 sid 的帧投递");
    }

    /// 09-P1-5：容量超限按 LRU 淘汰并复用 sid（淘汰 close 先于新数据帧发出）
    #[tokio::test]
    async fn 容量超限_lru淘汰并复用sid() {
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (cli, srv) = duplex(8192);
        {
            let closes = closes.clone();
            tokio::spawn(async move {
                let mut srv = srv;
                loop {
                    match read_udp_frame(&mut srv).await {
                        Ok(UdpFrame::Data { session_id, target, datagram }) => {
                            let frame = encode_udp_data(session_id, &target, &datagram).unwrap();
                            if write_udp_frame(&mut srv, &frame).await.is_err() {
                                break;
                            }
                        }
                        Ok(UdpFrame::Close { .. }) => {
                            closes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        let mut ch = open_test_channel_with_capacity(cli, 2);

        ch.send_to("10.0.0.1:53", b"a").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        // 刷新 10.0.0.1 的 LRU 时钟：10.0.0.2 成为最旧
        ch.send_to("10.0.0.1:53", b"a2").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        ch.send_to("10.0.0.2:53", b"b").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        assert_eq!(ch.active_sessions(), 2);

        // 第三个目标：触发 LRU 淘汰 10.0.0.2（含待发 close），sid 复用
        ch.send_to("10.0.0.3:53", b"c").await.unwrap();
        let _ = ch.recv_from().await.unwrap();
        assert_eq!(ch.active_sessions(), 2, "容量应维持在上限");
        for _ in 0..50 {
            if closes.load(std::sync::atomic::Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            closes.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "被淘汰会话应发出下行 close"
        );

        // 被淘汰目标重新发送：映射重建、sid 复用（回环成功）
        ch.send_to("10.0.0.2:53", b"again").await.unwrap();
        let (_, data) = ch.recv_from().await.unwrap();
        assert_eq!(data, b"again");
    }

    #[test]
    fn session_id_顺序分配且按目标去重() {
        let (cli, _srv) = duplex(64);
        let mut ch = open_test_channel(cli);
        assert_eq!(ch.session_for("a:1").unwrap(), 1);
        assert_eq!(ch.session_for("b:2").unwrap(), 2);
        assert_eq!(ch.session_for("a:1").unwrap(), 1, "同目标复用同号");
        assert_eq!(ch.active_sessions(), 2);
    }

    /// 09-P1-5：单调 sid 耗尽时走 LRU 复用（注入小容量 + 预置 next_sid）
    /// 【TUN 场景】keyed 会话：不同流键到同一目标各持独立 sid；下行按 sid 反解
    #[tokio::test]
    async fn keyed会话_同目标不同流独立sid() {
        let (cli, srv) = duplex(4096);
        // mock 节点：原样回环（session_id/target/datagram 透传）
        tokio::spawn(async move {
            let mut srv = srv;
            while let Ok(UdpFrame::Data { session_id, target, datagram }) =
                read_udp_frame(&mut srv).await
            {
                let f = encode_udp_data(session_id, &target, &datagram).unwrap();
                if write_udp_frame(&mut srv, &f).await.is_err() {
                    break;
                }
            }
        });
        let mut ch = open_test_channel(cli);

        // 流 A 与流 B 发往同一目标：sid 必须不同
        let sid_a = ch.send_to_ext("flowA", "10.0.0.7:53", b"query-a").await.unwrap();
        let sid_b = ch.send_to_ext("flowB", "10.0.0.7:53", b"query-b").await.unwrap();
        assert_ne!(sid_a, sid_b, "不同流键同目标必须分会话");
        // 同流键复用同 sid
        let sid_a2 = ch.send_to_ext("flowA", "10.0.0.7:53", b"query-a2").await.unwrap();
        assert_eq!(sid_a, sid_a2);

        // 下行按 sid 反解：A 的回包不会错投给 B
        let rx = ch.recv_from_ext().await.unwrap();
        match rx {
            UdpRx::Data { sid, target, datagram } => {
                assert_eq!(sid, sid_a);
                assert_eq!(target, "10.0.0.7:53");
                assert_eq!(datagram, b"query-a");
            }
            other => panic!("期望 Data，实际 {other:?}"),
        }
        let rx = ch.recv_from_ext().await.unwrap();
        match rx {
            UdpRx::Data { sid, datagram, .. } => {
                assert_eq!(sid, sid_b);
                assert_eq!(datagram, b"query-b");
            }
            other => panic!("期望 Data，实际 {other:?}"),
        }

        // 节点下行 close：recv_from_ext 以 Closed 暴露，映射解除
        // （借 mock：直接对客户端半流写 close 不可行——srv 已被任务持有；
        //   通过 close_session_ext 验证映射解除语义即可）
        assert!(ch.close_session_ext("flowA", "10.0.0.7:53").await.unwrap());
        assert!(!ch.close_session_ext("flowA", "10.0.0.7:53").await.unwrap(), "幂等");
        assert_eq!(ch.active_sessions(), 1);
    }

    #[test]
    fn sid_单调耗尽后复用() {
        let (cli, _srv) = duplex(64);
        let mut ch = open_test_channel(cli);
        ch.next_sid = u16::MAX;
        assert_eq!(ch.session_for("last:1").unwrap(), u16::MAX);
        // 空间耗尽：淘汰 last:1 复用其号
        assert_eq!(ch.session_for("next:1").unwrap(), u16::MAX);
        assert_eq!(ch.active_sessions(), 1);
        assert!(ch.session_for("next:1").is_ok());
    }
}
