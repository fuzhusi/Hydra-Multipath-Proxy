//! 最小正确的 STUN 客户端（RFC5389 Binding Request）。
//!
//! 背景（施工方案遗留四大项之③，诚实降级）：完整 P2P 打洞推迟到 V3.5
//! （需要信令服务器设计，自建公网 VPS 场景收益为零）。本期只做：
//! 节点可选配置 `HYDRA_STUN_ADDR`（ip:port），启动时及每 10 分钟向该
//! STUN 服务器发送 Binding Request，解析 XOR-MAPPED-ADDRESS 得到公网
//! 映射地址，展示在 `/health` 的 `public_addr` 字段。
//!
//! 协议要点（修复旧 nat_traversal.rs 死代码的已知 parse 崩溃）：
//! - 消息头 20B：`[type 2B][msg_len 2B][magic_cookie 4B][txn_id 12B]`
//! - Binding Request type=0x0001，成功响应 type=0x0101
//! - MAGIC_COOKIE = 0x2112A442，响应必须回带同一事务 ID（不匹配 = 丢弃）
//! - XOR-MAPPED-ADDRESS (0x0020)：端口/地址与 cookie（v4）或
//!   cookie||txn_id（v6）异或编码
//! - 未知属性跳过（FINGERPRINT 等可选属性不校验 CRC）
//!
//! 联网冒烟测试标 `#[ignore]`（见 tests/test_stun.rs），CI 只跑离线单测。

use crate::health::SharedPublicAddr;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tracing::{info, warn};

/// STUN 服务器地址的环境变量名（ip:port 字面量，不做 DNS 解析；未设置 = 功能关闭）
pub const HYDRA_STUN_ADDR_ENV: &str = "HYDRA_STUN_ADDR";

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// 单次尝试的超时（RFC 5389 建议量级）
pub const STUN_TIMEOUT: Duration = Duration::from_secs(3);
/// 超时后的重试次数（共 3 次尝试）
pub const STUN_RETRIES: u32 = 2;
/// 公网映射地址刷新周期
pub const PUBLIC_ADDR_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// RFC5389 96bit 随机事务 ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    /// 密码学安全随机（ring SystemRandom）
    pub fn random() -> Self {
        use ring::rand::SecureRandom;
        let mut id = [0u8; 12];
        ring::rand::SystemRandom::new()
            .fill(&mut id)
            .expect("SystemRandom 不可用（事务 ID 必须随机，拒绝降级）");
        Self(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    #[error("STUN 网络错误: {0}")]
    Io(String),
    #[error("STUN 请求超时（{STUN_TIMEOUT:?} × {} 次尝试）", STUN_RETRIES + 1)]
    Timeout,
    #[error("STUN 响应畸形: {0}")]
    Malformed(&'static str),
    #[error("STUN 响应事务 ID 不匹配（丢弃）")]
    TransactionMismatch,
    #[error("STUN 非成功响应（消息类型 0x{0:04X}）")]
    NotSuccessResponse(u16),
    #[error("STUN 响应缺少 XOR-MAPPED-ADDRESS")]
    NoMappedAddress,
}

/// 构造 Binding Request（无属性，20 字节）
pub fn build_binding_request(txn: &TransactionId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // msg_len：无属性
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txn.0);
    msg
}

/// 解析 Binding Success Response，校验事务 ID，返回公网映射地址。
///
/// 事务 ID 不匹配 / 畸形包 = 拒绝（调用方在网络上应丢弃该包继续等）。
/// 属性区只读 `msg_len` 声明的范围，超出部分（如链路层填充）忽略。
pub fn parse_binding_response(buf: &[u8], txn: &TransactionId) -> Result<SocketAddr, StunError> {
    if buf.len() < 20 {
        return Err(StunError::Malformed("短于 20 字节消息头"));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::NotSuccessResponse(msg_type));
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 20 + msg_len {
        return Err(StunError::Malformed("msg_len 超出数据报实际长度"));
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::Malformed("MAGIC_COOKIE 不匹配"));
    }
    if buf[8..20] != txn.0 {
        return Err(StunError::TransactionMismatch);
    }

    let mut attrs = &buf[20..20 + msg_len];
    let mut mapped: Option<SocketAddr> = None;
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(StunError::Malformed("属性头不完整"));
        }
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + attr_len {
            return Err(StunError::Malformed("属性值超出消息边界"));
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS && mapped.is_none() {
            mapped = Some(xor_mapped_address(&attrs[4..4 + attr_len], txn)?);
        }
        // 属性总长 = 4B 头 + 值（值按 4 字节对齐，RFC5389 §5）
        let padded = (attr_len + 3) / 4 * 4;
        let advance = 4 + padded;
        if advance > attrs.len() {
            return Err(StunError::Malformed("属性填充超出消息边界"));
        }
        attrs = &attrs[advance..];
    }
    mapped.ok_or(StunError::NoMappedAddress)
}

/// 解码 XOR-MAPPED-ADDRESS 属性值：`[保留 1B][family 1B][xport 2B][xaddr 4B/16B]`
fn xor_mapped_address(value: &[u8], txn: &TransactionId) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Malformed("XOR-MAPPED-ADDRESS 头不完整"));
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match family {
        FAMILY_IPV4 => {
            if value.len() != 8 {
                return Err(StunError::Malformed("IPv4 地址长度错误"));
            }
            let xip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok(SocketAddr::V4(SocketAddrV4::new(
                (xip ^ MAGIC_COOKIE).into(),
                xport,
            )))
        }
        FAMILY_IPV6 => {
            if value.len() != 20 {
                return Err(StunError::Malformed("IPv6 地址长度错误"));
            }
            // v6 掩码 = MAGIC_COOKIE || txn_id（共 16 字节）
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&txn.0);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                octets.into(),
                xport,
                0,
                0,
            )))
        }
        _ => Err(StunError::Malformed("未知地址族")),
    }
}

/// 向 STUN 服务器发送 Binding Request，返回公网映射地址。
/// 超时 3s，重试 2 次；期间事务 ID 不匹配 / 畸形的包一律丢弃继续等。
pub async fn discover_public_addr(server: SocketAddr) -> Result<SocketAddr, StunError> {
    let bind: &str = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| StunError::Io(e.to_string()))?;
    let txn = TransactionId::random();
    let req = build_binding_request(&txn);

    for _attempt in 0..=STUN_RETRIES {
        socket
            .send_to(&req, server)
            .await
            .map_err(|e| StunError::Io(e.to_string()))?;
        let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break; // 本轮超时，进入下一次重试
            }
            let mut buf = vec![0u8; 1500];
            match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Err(_) => break, // 超时
                Ok(Err(e)) => return Err(StunError::Io(e.to_string())),
                Ok(Ok((n, _src))) => match parse_binding_response(&buf[..n], &txn) {
                    Ok(addr) => return Ok(addr),
                    // 不匹配 / 畸形 = 丢弃，继续等剩余窗口内的下一个包
                    Err(_) => continue,
                },
            }
        }
    }
    Err(StunError::Timeout)
}

/// 启动后台任务：立即做一次公网地址发现，之后每 10 分钟刷新。
/// 失败时把槽位清空（/health 的 `public_addr` 变 null），绝不展示过期地址。
pub fn spawn_public_addr_refresher(stun_addr: SocketAddr, slot: SharedPublicAddr) {
    tokio::spawn(async move {
        loop {
            match discover_public_addr(stun_addr).await {
                Ok(addr) => {
                    info!(
                        "STUN 公网映射地址: {}（STUN 服务器 {}，每 {:?} 刷新）",
                        addr, stun_addr, PUBLIC_ADDR_REFRESH_INTERVAL
                    );
                    *slot.write().expect("public_addr 锁中毒") = Some(addr);
                }
                Err(e) => {
                    warn!(
                        "STUN 公网地址发现失败（STUN 服务器 {}）: {}；public_addr 置空",
                        stun_addr, e
                    );
                    *slot.write().expect("public_addr 锁中毒") = None;
                }
            }
            tokio::time::sleep(PUBLIC_ADDR_REFRESH_INTERVAL).await;
        }
    });
}
