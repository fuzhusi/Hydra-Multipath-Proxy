//! UDP-over-proxy 帧编解码（协议层能力，为 TUN 模式的 UDP 转发打地基）。
//!
//! 在**已认证**的同一条 TCP/TLS 流上多路复用 UDP 会话。地址帧目标以保留前缀
//! `@udp-relay/` 开头时进入本模式（节点侧 `@hydra-p2p/` 信令分流同款）：
//! 节点先回 2B OK 应答（复用 [`crate::tcp_frame`] 应答帧），随后该流不再走
//! TCP 目标转发，改承载本模块定义的变长 UDP 会话帧。
//!
//! # 帧格式（上行=客户端→节点，下行=节点→客户端，完全对称）
//!
//! ```text
//! ┌──────────────┬───────────────┬─────────────────────────────┐
//! │ session_id   │ payload_len   │ payload                     │
//! │ u16 大端     │ u16 大端      │ 首字节 kind + 内容          │
//! └──────────────┴───────────────┴─────────────────────────────┘
//!
//! kind = 0x00（数据帧，建会话与传数据合一，首包隐式建立会话）：
//! ┌──────┬────────────────────┬───────────────┐
//! │ 0x00 │ [tlen u16 BE][地址] │ 数据报字节    │   ← [目标地址帧] 即 tcp_frame 同款
//! └──────┴────────────────────┴───────────────┘
//!
//! kind = 0x01（close 帧，客户端主动关会话；节点空闲回收时亦下行 close）：
//! ┌──────┐
//! │ 0x01 │
//! └──────┘
//! ```
//!
//! - 客户端对每个 UDP 会话使用唯一 session_id；首次发数据即隐式建立。
//! - 节点侧每个 session_id 维护一个绑定到目标地址的 UDP socket；同一
//!   session 换目标地址 = 更新绑定（旧 socket 回收、按新目标重建）。
//! - 数据报上限与 UDP 协议一致（65507）；叠加帧头/地址帧后 payload_len
//!   不得超 u16，超限在编码期拒绝（节点侧丢弃并计数）。
//! - 本模块只做字节级编解码；会话表/空闲回收/SSRF 过滤在节点
//!   `hydra_node::udp_relay`，客户端封装在 `hydra_client::udp_relay`。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tcp_frame::MAX_TARGET_LEN;
use crate::{HydraError, Result};

/// payload 首字节 kind：数据帧（后跟目标地址帧 + 数据报字节）
pub const UDP_KIND_DATA: u8 = 0x00;
/// payload 首字节 kind：close 帧（单向通知，无响应）
pub const UDP_KIND_CLOSE: u8 = 0x01;

/// 帧头长度：`[session_id u16][payload_len u16]`
pub const UDP_HEADER_LEN: usize = 4;

/// UDP 数据报字节上限（RFC 768 / IPv4 UDP 长度字段决定的事实上限）
pub const MAX_DATAGRAM_LEN: usize = 65507;

/// 解码后的 UDP 会话帧（上行/下行同构）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpFrame {
    /// 数据帧：session_id + 目标地址 + 数据报字节
    Data {
        session_id: u16,
        target: String,
        datagram: Vec<u8>,
    },
    /// close 帧：请求/通知回收该会话
    Close { session_id: u16 },
}

/// 校验会话级字段后编码数据帧（上行/下行对称，同一编码）。
///
/// 防御：目标地址长度 1..=[`MAX_TARGET_LEN`]；数据报 ≤[`MAX_DATAGRAM_LEN`]；
/// 总 payload（1B kind + 地址帧 + 数据报）必须 ≤ u16::MAX，否则 Err——
/// 调用方（节点侧）对超限数据报应丢弃并计数，而非断流。
pub fn encode_udp_data(session_id: u16, target: &str, datagram: &[u8]) -> Result<Vec<u8>> {
    let addr = target.as_bytes();
    if addr.is_empty() || addr.len() > MAX_TARGET_LEN {
        return Err(HydraError::ProtocolError(format!(
            "UDP 数据帧目标地址长度非法：{} 字节（1..={MAX_TARGET_LEN}）",
            addr.len()
        )));
    }
    if datagram.len() > MAX_DATAGRAM_LEN {
        return Err(HydraError::ProtocolError(format!(
            "UDP 数据报超限：{} 字节（≤{MAX_DATAGRAM_LEN}）",
            datagram.len()
        )));
    }
    let payload_len = 1 + 2 + addr.len() + datagram.len();
    if payload_len > u16::MAX as usize {
        return Err(HydraError::ProtocolError(format!(
            "UDP 帧 payload 超限：{payload_len} 字节（≤{}）",
            u16::MAX
        )));
    }
    let mut frame = Vec::with_capacity(UDP_HEADER_LEN + payload_len);
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.push(UDP_KIND_DATA);
    frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(addr);
    frame.extend_from_slice(datagram);
    Ok(frame)
}

/// 编码 close 帧（4B 头 + 1B kind）。
pub fn encode_udp_close(session_id: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(UDP_HEADER_LEN + 1);
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.push(UDP_KIND_CLOSE);
    frame
}

/// 从完整帧字节切片解码（严格模式：payload 长度必须恰好匹配，防失步）。
///
/// 未知 kind / 长度声明与实际不符 / 目标地址非法 → Err。
pub fn decode_udp_frame(buf: &[u8]) -> Result<UdpFrame> {
    if buf.len() < UDP_HEADER_LEN + 1 {
        return Err(HydraError::ProtocolError(format!(
            "UDP 帧截断：{} 字节（≥{}）",
            buf.len(),
            UDP_HEADER_LEN + 1
        )));
    }
    let session_id = u16::from_be_bytes([buf[0], buf[1]]);
    let payload_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let payload = &buf[UDP_HEADER_LEN..];
    if payload.len() != payload_len {
        return Err(HydraError::ProtocolError(format!(
            "UDP 帧 payload 长度不符：声明 {payload_len}，实际 {}",
            payload.len()
        )));
    }
    match payload[0] {
        UDP_KIND_DATA => {
            let rest = &payload[1..];
            if rest.len() < 2 {
                return Err(HydraError::ProtocolError(
                    "UDP 数据帧截断（缺地址帧长度）".to_string(),
                ));
            }
            let tlen = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if tlen == 0 || tlen > MAX_TARGET_LEN {
                return Err(HydraError::ProtocolError(format!(
                    "UDP 数据帧目标地址长度非法: {tlen}"
                )));
            }
            let total = 2 + tlen;
            if rest.len() < total {
                return Err(HydraError::ProtocolError(
                    "UDP 数据帧截断（目标地址不完整）".to_string(),
                ));
            }
            let target = String::from_utf8(rest[2..total].to_vec()).map_err(|e| {
                HydraError::ProtocolError(format!("UDP 目标地址非 UTF-8: {e}"))
            })?;
            Ok(UdpFrame::Data {
                session_id,
                target,
                datagram: rest[total..].to_vec(),
            })
        }
        UDP_KIND_CLOSE => {
            if payload.len() != 1 {
                return Err(HydraError::ProtocolError(format!(
                    "UDP close 帧 payload 应为 1 字节，实际 {}",
                    payload.len()
                )));
            }
            Ok(UdpFrame::Close { session_id })
        }
        other => Err(HydraError::ProtocolError(format!(
            "UDP 帧未知 kind: 0x{other:02x}"
        ))),
    }
}

/// 从流中读取一帧（精确读 4B 头 + payload_len 字节，杜绝粘包/半包歧义）。
/// EOF/截断/解码失败 → Err；超时控制由调用方包裹。
pub async fn read_udp_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<UdpFrame> {
    let mut header = [0u8; UDP_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("读取 UDP 帧头失败: {e}")))?;
    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0u8; payload_len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("读取 UDP 帧 payload 失败: {e}")))?;
    let mut buf = Vec::with_capacity(UDP_HEADER_LEN + payload_len);
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&payload);
    decode_udp_frame(&buf)
}

/// 将已编码帧字节写入流并 flush。
pub async fn write_udp_frame<W: AsyncWrite + Unpin>(send: &mut W, frame: &[u8]) -> Result<()> {
    send.write_all(frame)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("写入 UDP 帧失败: {e}")))?;
    send.flush()
        .await
        .map_err(|e| HydraError::ProtocolError(format!("flush UDP 帧失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_roundtrip_and_layout() {
        let frame = encode_udp_data(0x0102, "example.com:443", b"ping").unwrap();
        // 布局：4B 头 + 1B kind + 2B 地址长 + 地址 + 数据报
        assert_eq!(&frame[..2], &[0x01, 0x02]); // session_id BE
        assert_eq!(&frame[2..4], &[0x00, 1 + 2 + 15 + 4]); // payload_len BE
        assert_eq!(frame[4], UDP_KIND_DATA);
        assert_eq!(&frame[5..7], &[0x00, 15]);
        assert_eq!(&frame[7..22], b"example.com:443");
        assert_eq!(&frame[22..], b"ping");
        match decode_udp_frame(&frame).unwrap() {
            UdpFrame::Data {
                session_id,
                target,
                datagram,
            } => {
                assert_eq!(session_id, 0x0102);
                assert_eq!(target, "example.com:443");
                assert_eq!(datagram, b"ping");
            }
            other => panic!("应为数据帧，实际 {other:?}"),
        }
    }

    #[test]
    fn close_frame_roundtrip_and_layout() {
        let frame = encode_udp_close(0xBEEF);
        assert_eq!(frame, vec![0xBE, 0xEF, 0x00, 0x01, UDP_KIND_CLOSE]);
        match decode_udp_frame(&frame).unwrap() {
            UdpFrame::Close { session_id } => assert_eq!(session_id, 0xBEEF),
            other => panic!("应为 close 帧，实际 {other:?}"),
        }
    }

    #[test]
    fn zero_length_datagram_allowed() {
        // 零长 UDP 数据报合法（如 DNS 不存在此形态但 QUIC 打探等有用）
        let f = encode_udp_data(1, "1.2.3.4:53", b"").unwrap();
        assert!(matches!(
            decode_udp_frame(&f).unwrap(),
            UdpFrame::Data { datagram, .. } if datagram.is_empty()
        ));
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let f = encode_udp_data(1, "1.2.3.4:53", b"payload").unwrap();
        for cut in [0, 3, 4, 5, 6, 8, f.len() - 1] {
            assert!(
                decode_udp_frame(&f[..cut]).is_err(),
                "截断到 {cut} 字节应报错"
            );
        }
        // 头部声明 payload_len 大于实际 → 严格模式报错
        let mut bad = f.clone();
        bad[2..4].copy_from_slice(&999u16.to_be_bytes());
        assert!(decode_udp_frame(&bad).is_err());
    }

    #[test]
    fn overlong_datagram_is_rejected_at_encode() {
        assert!(encode_udp_data(1, "1.2.3.4:53", &vec![0u8; MAX_DATAGRAM_LEN + 1]).is_err());
        // 恰好 65507 合法（payload 1+2+9+65507 ≤ u16::MAX）
        assert!(encode_udp_data(1, "1.2.3.4:53", &vec![0u8; MAX_DATAGRAM_LEN]).is_ok());
        // 长域名挤压 payload 空间：总 payload 超 u16 应拒绝
        let long_target = format!("{}.example.com:443", "a".repeat(1000));
        assert!(encode_udp_data(1, &long_target, &vec![0u8; MAX_DATAGRAM_LEN]).is_err());
    }

    #[test]
    fn bad_target_lengths_are_rejected() {
        assert!(encode_udp_data(1, "", b"x").is_err());
        assert!(encode_udp_data(1, &"a".repeat(MAX_TARGET_LEN + 1), b"x").is_err());
        // 解码侧：地址长度声明 0 / 超 1024 / 截断的地址
        let mk = |tlen: u16, addr: &[u8]| {
            let mut v = vec![0, 1, 0, 0];
            let payload_len = 1 + 2 + addr.len();
            v[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
            v.push(UDP_KIND_DATA);
            v.extend_from_slice(&tlen.to_be_bytes());
            v.extend_from_slice(addr);
            v
        };
        assert!(decode_udp_frame(&mk(0, b"")).is_err());
        assert!(decode_udp_frame(&mk(MAX_TARGET_LEN as u16 + 1, b"aaaaaaaaaa")).is_err());
        assert!(decode_udp_frame(&mk(10, b"short")).is_err());
        // 非 UTF-8 目标地址
        assert!(decode_udp_frame(&mk(2, &[0xFF, 0xFE])).is_err());
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let mut f = encode_udp_close(7);
        *f.last_mut().unwrap() = 0x7F;
        assert!(decode_udp_frame(&f).is_err());
        // close 帧 payload 多一字节也拒绝（严格匹配）
        let mut f2 = encode_udp_close(7);
        f2[2..4].copy_from_slice(&2u16.to_be_bytes());
        f2.push(0x00);
        assert!(decode_udp_frame(&f2).is_err());
    }

    #[tokio::test]
    async fn stream_roundtrip_data_and_close() {
        use tokio::io::duplex;
        let (mut c, mut s) = duplex(4096);
        write_udp_frame(&mut c, &encode_udp_data(9, "10.0.0.1:5353", b"abc").unwrap())
            .await
            .unwrap();
        write_udp_frame(&mut c, &encode_udp_close(9)).await.unwrap();
        drop(c);
        match read_udp_frame(&mut s).await.unwrap() {
            UdpFrame::Data {
                session_id,
                target,
                datagram,
            } => {
                assert_eq!(session_id, 9);
                assert_eq!(target, "10.0.0.1:5353");
                assert_eq!(datagram, b"abc");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            read_udp_frame(&mut s).await.unwrap(),
            UdpFrame::Close { session_id: 9 }
        );
        // EOF → Err（不 panic）
        assert!(read_udp_frame(&mut s).await.is_err());
    }
}
