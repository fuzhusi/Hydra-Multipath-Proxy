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

use hydra_protocol::udp_frame::{
    encode_udp_close, encode_udp_data, read_udp_frame, write_udp_frame, UdpFrame,
};
use hydra_protocol::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::tcp_transport::{connect_target, TcpNodeStream, TlsTrust};

/// UDP 中继模式的地址帧目标（节点按保留前缀 `@udp-relay/` 分流）
pub const UDP_RELAY_TARGET: &str = "@udp-relay/v1";

/// 会话号耗尽前保留的最大值（u16 全空间；按目标地址数配额，远超实际需要）
const MAX_SESSION_ID: u16 = u16::MAX;

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
    sessions: HashMap<String, u16>,
    next_sid: u16,
}

/// 真实节点流（connect_target 产出的 TcpNodeStream 拆分两半）上的通道
pub type NodeUdpChannel = UdpChannel<ReadHalf<TcpNodeStream>, WriteHalf<TcpNodeStream>>;

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
    })
}

impl<R, W> UdpChannel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// 为目标地址取（或分配）session_id。
    fn session_for(&mut self, target: &str) -> Result<u16> {
        if let Some(&sid) = self.sessions.get(target) {
            return Ok(sid);
        }
        // 会话号顺序分配；节点回收的 close 会解除映射，但号本身不回收
        // （简单优先：u16 空间 65535 个，按目标数远够）
        if self.next_sid == 0 || self.next_sid > MAX_SESSION_ID {
            return Err(hydra_protocol::HydraError::ProtocolError(
                "UDP 会话号耗尽（请重建通道）".to_string(),
            ));
        }
        let sid = self.next_sid;
        self.next_sid = self.next_sid.wrapping_add(1);
        self.sessions.insert(target.to_string(), sid);
        Ok(sid)
    }

    /// 向目标发一个 UDP 数据报（同一目标复用同一 session；首次发送隐式建立）。
    pub async fn send_to(&mut self, target: &str, datagram: &[u8]) -> Result<()> {
        let sid = self.session_for(target)?;
        let frame = encode_udp_data(sid, target, datagram)?;
        write_udp_frame(&mut self.wr, &frame).await
    }

    /// 收下一个下行数据报，返回 `(目标地址, 数据报)`。
    /// 途中收到的下行 close 帧（节点空闲回收）内部消化并解除映射后继续等。
    pub async fn recv_from(&mut self) -> Result<(String, Vec<u8>)> {
        loop {
            match read_udp_frame(&mut self.rd).await? {
                UdpFrame::Data {
                    session_id,
                    target,
                    datagram,
                } => return Ok((target, datagram)),
                UdpFrame::Close { session_id } => {
                    // 回收映射（保持 next_sid 单调，不回收号）
                    if let Some(t) =
                        self.sessions.iter().find(|(_, &s)| s == session_id).map(|(t, _)| t.clone())
                    {
                        self.sessions.remove(&t);
                    }
                    continue;
                }
            }
        }
    }

    /// 主动关闭目标会话（发 close 帧）。返回是否确有该会话。
    pub async fn close_target(&mut self, target: &str) -> Result<bool> {
        match self.sessions.remove(target) {
            Some(sid) => {
                write_udp_frame(&mut self.wr, &encode_udp_close(sid)).await?;
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
        use tokio::io::AsyncReadExt;
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
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let (cli, srv) = duplex(4096);
        // 节点侧：收到一帧后主动回收该会话（模拟空闲回收下行 close），再回一个
        // 新会话数据帧，验证 recv_from 跳过 close 继续收数据
        let mock = async move {
            let mut srv = srv;
            let frame = read_udp_frame(&mut srv).await.unwrap();
            let UdpFrame::Data { session_id, target, .. } = frame else {
                panic!("应为数据帧");
            };
            write_udp_frame(&mut srv, &encode_udp_close(session_id))
                .await
                .unwrap();
            write_udp_frame(
                &mut srv,
                &encode_udp_data(session_id + 1, &target, b"after-close"),
            )
            .await
            .unwrap();
        };
        tokio::spawn(mock);
        let mut ch = open_test_channel(cli);

        ch.send_to("10.0.0.3:443", b"trigger").await.unwrap();
        let (target, data) = ch.recv_from().await.unwrap();
        assert_eq!(target, "10.0.0.3:443");
        assert_eq!(data, b"after-close");
        assert_eq!(ch.active_sessions(), 0, "close 帧应解除映射");
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
}
