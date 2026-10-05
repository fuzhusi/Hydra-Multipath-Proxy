//! STUN（RFC 5389）over TCP 消息编解码 + NAT 映射行为分类。
//!
//! NAT 穿透方案 §3.1：客户端/节点经 TCP STUN Binding 获知自身公网映射地址，
//! 并对两个不同 STUN 服务器的探测结果做简化分类（同映射 → EIM 可打洞，
//! 不同 → 对称型，回落中继）。
//!
//! 线格式严格按 RFC 5389：**20B 固定头（type 2 + msg_len 2 + MAGIC_COOKIE 4 +
//! 事务 ID 12）**，与公网标准 STUN 服务器互通。TCP 流式读取 = 先读头解析
//! msg_len，再读属性区（超长防御：msg_len > 2048 拒绝）。无新依赖：
//! FINGERPRINT 的 CRC32（IEEE 802.3）用内置逐位实现（仅属性存在时尽力校验）。

use std::net::SocketAddr;
use crate::{HydraError, Result};

/// RFC 5389 MAGIC_COOKIE（固定值）
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding Request 消息类型
const BINDING_REQUEST: u16 = 0x0001;
/// Binding Response 消息类型
const BINDING_SUCCESS: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS 属性类型
const ATTR_XOR_MAPPED: u16 = 0x0020;
/// MAPPED-ADDRESS 属性类型（旧式，兼容读取）
const ATTR_MAPPED: u16 = 0x0001;
/// FINGERPRINT 属性类型（CRC32，存在时尽力校验）
const ATTR_FINGERPRINT: u16 = 0x8028;
/// 事务 ID 长度：RFC 5389 固定 **12 字节**（与公网 STUN 服务器互通的硬约束）
const TX_ID_LEN: usize = 12;
/// STUN 固定头长度（type 2 + msg_len 2 + cookie 4 + tx_id 12 = 20）
const HEADER_LEN: usize = 20;
/// msg_len 超长防御上限（Binding 响应实际远小于此）
const MAX_MSG_LEN: usize = 2048;

/// NAT 映射行为分类（简化 RFC 4787：TCP 同时打开只关心映射行为）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 端点无关映射（EIM）：可尝试 TCP 同时打开打洞
    Eim,
    /// 对称型（SDM/ADM）：打洞成功率低，回落中继
    Symmetric,
}

/// 简易熵源（不引 rand 依赖）：时间纳秒 + 栈地址 + 进程级计数器，xorshift 混合。
/// 事务 ID 只需「本次探测内唯一」，不承担密码学职责（响应按 tx_id 匹配防串扰）。
fn random_tx_id() -> [u8; TX_ID_LEN] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEAD_BEEF)
        ^ (&COUNTER as *const _ as u64)
        ^ (COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut id = [0u8; TX_ID_LEN];
    for chunk in id.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    id
}

/// 构造 Binding Request（RFC 5389：20B 头 = 类型 0x0001 + msg_len 0 +
/// MAGIC_COOKIE + 随机 **12B** 事务 ID；Binding Request 无属性）。
/// 返回 (报文, 事务 ID)——事务 ID 由调用方保留用于响应匹配。
pub fn build_binding_request() -> (Vec<u8>, [u8; TX_ID_LEN]) {
    let tx_id = random_tx_id();
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // msg_len = 0
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&tx_id);
    debug_assert_eq!(buf.len(), HEADER_LEN);
    (buf, tx_id)
}

/// 解析 Binding Success Response：校验类型与事务 ID，提取
/// XOR-MAPPED-ADDRESS（0x0020），兼容 MAPPED-ADDRESS（0x0001）；
/// FINGERPRINT（0x8028）存在时尽力校验 CRC32（解析失败视为无该属性）。
pub fn parse_binding_response(buf: &[u8], tx_id: &[u8; TX_ID_LEN]) -> Result<SocketAddr> {
    if buf.len() < HEADER_LEN {
        return Err(HydraError::ProtocolError(format!(
            "STUN 报文过短: {} 字节",
            buf.len()
        )));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err(HydraError::ProtocolError(format!(
            "非 Binding Success Response: 类型 0x{msg_type:04x}"
        )));
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < HEADER_LEN + msg_len {
        return Err(HydraError::ProtocolError(format!(
            "STUN 报文不完整: 声明 {} 字节属性区，实际 {}",
            msg_len,
            buf.len() - HEADER_LEN
        )));
    }
    if buf[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return Err(HydraError::ProtocolError("MAGIC_COOKIE 不匹配".into()));
    }
    if &buf[8..8 + TX_ID_LEN] != tx_id {
        return Err(HydraError::ProtocolError("事务 ID 不匹配".into()));
    }

    // 逐属性解析（每属性 4B 头，载荷 4 字节对齐）
    let mut mapped: Option<SocketAddr> = None;
    let body = &buf[HEADER_LEN..HEADER_LEN + msg_len];
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let attr_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let val_off = off + 4;
        if val_off + attr_len > body.len() {
            break; // 属性越界：停止解析（已解析到的 mapped 仍可用）
        }
        let val = &body[val_off..val_off + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED | ATTR_MAPPED => {
                if let Some(addr) = parse_mapped_address(val, attr_type == ATTR_XOR_MAPPED, tx_id)
                {
                    mapped = Some(addr);
                }
            }
            ATTR_FINGERPRINT
                // 尽力校验：CRC32 覆盖报文头 + 本属性之前的全部属性区
                // （RFC 5389 §15.5：FINGERPRINT 的 CRC 输入含属性头，但不含 CRC 本身）
                if attr_len == 4 => {
                    let expect = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                    let crc = crc32_ieee(&buf[..HEADER_LEN + off]) ^ 0x5354_554E;
                    if crc != expect {
                        return Err(HydraError::ProtocolError(
                            "STUN FINGERPRINT CRC32 校验失败".into(),
                        ));
                    }
                }
            _ => {} // 其他属性（SOFTWARE 等）忽略
        }
        // 载荷按 4 字节对齐推进
        off = val_off + attr_len.div_ceil(4) * 4;
    }

    mapped.ok_or_else(|| {
        HydraError::ProtocolError("STUN 响应无 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS".into())
    })
}

/// 解析地址属性载荷：1B 保留 + 1B family + 2B 端口 + 4B/16B 地址。
/// `xor` = true 时按 XOR-MAPPED-ADDRESS 规则异或（端口 ^ cookie 高 16 位；
/// IPv4 地址 ^ cookie；IPv6 地址 ^ cookie+tx_id 拼接，cookie 4B + tx 12B = 16B 恰好）。
fn parse_mapped_address(val: &[u8], xor: bool, tx_id: &[u8; TX_ID_LEN]) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = if xor {
        xport ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        xport
    };
    match family {
        0x01 => {
            if val.len() < 8 {
                return None;
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&val[4..8]);
            if xor {
                let c = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    oct[i] ^= c[i];
                }
            }
            Some(SocketAddr::from((std::net::Ipv4Addr::from(oct), port)))
        }
        0x02 => {
            if val.len() < 20 {
                return None;
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&val[4..20]);
            if xor {
                // IPv6：异或 MAGIC_COOKIE || tx_id（4B + 12B = 16 字节）
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(tx_id);
                for i in 0..16 {
                    oct[i] ^= mask[i];
                }
            }
            Some(SocketAddr::from((std::net::Ipv6Addr::from(oct), port)))
        }
        _ => None, // 未知 address family：忽略该属性
    }
}

/// 比较两次探测（不同 STUN 服务器）得到的映射地址：相同 → EIM，不同 → Symmetric。
pub fn classify(mapped_a: SocketAddr, mapped_b: SocketAddr) -> NatType {
    if mapped_a == mapped_b {
        NatType::Eim
    } else {
        NatType::Symmetric
    }
}

/// 从 TCP 流读取一条完整 STUN 报文：先读 20B 固定头解析 msg_len，
/// 再读属性区（msg_len > 2048 拒绝，防恶意超长帧耗资源）。
pub async fn read_stun_message<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header).await?;
    let msg_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if msg_len > MAX_MSG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("STUN msg_len 超长: {msg_len} > {MAX_MSG_LEN}"),
        ));
    }
    let mut buf = Vec::with_capacity(HEADER_LEN + msg_len);
    buf.extend_from_slice(&header);
    buf.resize(HEADER_LEN + msg_len, 0);
    r.read_exact(&mut buf[HEADER_LEN..]).await?;
    Ok(buf)
}

/// CRC32（IEEE 802.3，反射输入/输出，poly 0xEDB88320）逐位实现。
/// 仅用于 STUN FINGERPRINT 尽力校验，无吞吐要求，不值得引入新依赖。
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// 手工构造一段含 XOR-MAPPED-ADDRESS 的 Binding Success Response。
    /// XOR 值按 RFC 5389 §15.2 规则独立计算（不调用实现内函数）。
    fn build_response(tx_id: &[u8; TX_ID_LEN], addr: SocketAddr) -> Vec<u8> {
        let (ip, port) = (match addr { SocketAddr::V4(v) => *v.ip(), _ => unreachable!() }, addr.port());
        // 端口异或 cookie 高 16 位（0x2112）；地址逐字节异或 cookie 大端 4 字节
        let xport = port ^ 0x2112;
        let oct = ip.octets();
        let xaddr = [
            oct[0] ^ 0x21,
            oct[1] ^ 0x12,
            oct[2] ^ 0xA4,
            oct[3] ^ 0x42,
        ];
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes()); // 属性区 = 4B 属性头 + 8B 载荷
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(tx_id);
        // XOR-MAPPED-ADDRESS 属性：type 0x0020, len 8, 0x00, family 0x01, xport, xaddr
        buf.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&xport.to_be_bytes());
        buf.extend_from_slice(&xaddr);
        buf
    }

    #[test]
    fn 报文构造与解析往返() {
        let (req, tx_id) = build_binding_request();
        // RFC 5389 请求结构：20B 头 = 类型 0x0001 / msg_len 0 / cookie / 12B 事务 ID
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &0x0001u16.to_be_bytes());
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &tx_id);

        let expected = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 54321));
        let resp = build_response(&tx_id, expected);
        let got = parse_binding_response(&resp, &tx_id).expect("解析应成功");
        assert_eq!(got, expected);
    }

    #[test]
    fn 已知值的_xor_手工构造() {
        // 完全硬编码的已知值：tx_id 全零，映射地址 192.0.2.1:32853（RFC 5737 文档段）
        // 端口 32853 = 0x8055，^ 0x2112 = 0xA147
        // 地址 192.0.2.1 = C0 00 02 01，^ 21 12 A4 42 = E1 12 A6 43
        let tx_id = [0u8; TX_ID_LEN];
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&0x2112A442u32.to_be_bytes());
        resp.extend_from_slice(&tx_id); // 12B 事务 ID（RFC 5389，头长 20B）
        resp.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01);
        resp.extend_from_slice(&0xA147u16.to_be_bytes());
        resp.extend_from_slice(&[0xE1, 0x12, 0xA6, 0x43]);
        let got = parse_binding_response(&resp, &tx_id).expect("解析应成功");
        assert_eq!(
            got,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 32853))
        );
    }

    #[test]
    fn mapped_address_旧式属性兼容() {
        // MAPPED-ADDRESS（0x0001）：载荷不异或，直接明文
        let tx_id = [7u8; TX_ID_LEN];
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tx_id);
        resp.extend_from_slice(&ATTR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01);
        resp.extend_from_slice(&19851u16.to_be_bytes()); // 端口明文
        resp.extend_from_slice(&[198, 51, 100, 7]); // 198.51.100.7 明文
        let got = parse_binding_response(&resp, &tx_id).expect("解析应成功");
        assert_eq!(
            got,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 19851))
        );
    }

    #[test]
    fn 事务id不匹配报错() {
        let (req, tx_id) = build_binding_request();
        let _ = req;
        let other_id = [0xAA; TX_ID_LEN];
        let resp = build_response(&tx_id, "1.2.3.4:80".parse().unwrap());
        let err = parse_binding_response(&resp, &other_id).unwrap_err();
        assert!(err.to_string().contains("事务 ID"), "应为事务 ID 错误: {err}");
    }

    #[test]
    fn classify_两分支() {
        let a: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        // 两个不同 STUN 服务器探测到的「映射地址」相同 → EIM
        assert_eq!(classify(a, "203.0.113.7:40000".parse().unwrap()), NatType::Eim);
        // 映射地址不同 → 对称型（回落中继）
        assert_eq!(classify(a, "203.0.113.9:40001".parse().unwrap()), NatType::Symmetric);
    }

    #[test]
    fn read_stun_message_超长防御() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // msg_len = 3000 > 2048：应报 InvalidData 而非挂起/分配
            let mut malicious = Vec::new();
            malicious.extend_from_slice(&0x0101u16.to_be_bytes());
            malicious.extend_from_slice(&3000u16.to_be_bytes());
            malicious.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            malicious.extend_from_slice(&[0u8; TX_ID_LEN]);
            let mut cursor = std::io::Cursor::new(malicious);
            let err = read_stun_message(&mut cursor).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn read_stun_message_完整报文读取() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (req, _) = build_binding_request();
            let mut cursor = std::io::Cursor::new(req.clone());
            let got = read_stun_message(&mut cursor).await.unwrap();
            assert_eq!(got, req);
        });
    }

    #[test]
    fn fingerprint_crc_存在时校验() {
        let tx_id = [3u8; TX_ID_LEN];
        let addr: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let mut resp = build_response(&tx_id, addr);
        // 追加 FINGERPRINT：CRC32 覆盖头 + 属性头之前的属性区，异或 0x5354554E
        let fp_len_pos = resp.len();
        resp.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        // msg_len 需补上属性头(4B)+载荷(4B)
        let total_len = (u16::from_be_bytes([resp[2], resp[3]]) + 8).to_be_bytes();
        resp[2..4].copy_from_slice(&total_len);
        let crc = crc32_ieee(&resp[..fp_len_pos]) ^ 0x5354_554E;
        resp.extend_from_slice(&crc.to_be_bytes());
        assert!(parse_binding_response(&resp, &tx_id).is_ok(), "正确 CRC 应通过");
        // 篡改 CRC → 报错
        let last = resp.len() - 1;
        resp[last] ^= 0xFF;
        assert!(parse_binding_response(&resp, &tx_id).is_err(), "错误 CRC 应拒绝");
    }
}
