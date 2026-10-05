//! TCP 转型（Wave 1）：TLS 之上的应用层私有帧协议。
//!
//! 转型方案定版（老板拍板）：**TLS 1.3（证书 pinning / 兼容 ACME）+ V3.2
//! Noise-PSK 应用层握手 + 私有帧协议**。TLS 管机密性/前向安全/伪装（流量形态 =
//! 标准 HTTPS），Noise-PSK（[`crate::handshake`]）管双向认证 + 抗重放 + 无时钟窗；
//! 本模块只负责握手成功之后的**数据面前置帧**：
//!
//! ```text
//! [TLS 1.3 建立后]
//! 客户端 → 节点：  [0x03][Noise msg1][msg2 交换][confirm_c/confirm_s]（handshake.rs）
//! 客户端 → 节点：  [target_len u16 大端][target]        地址帧（本模块）
//! 节点 → 客户端：  [2B 应答码]                           本模块
//! 双向：           裸字节流（TCP 半关闭语义见 tcp_server/copy_bidirectional）
//! ```
//!
//! 与 QUIC 路径的 1B 模式标签 + 1B 地址长度不同：TCP 下无 channel 多流模式
//! （TCP 自带可靠有序，无需流级复用），地址长度升为 u16（域名最长 253 + 端口，
//! 上限 1024 已远超实际需要，同时防恶意长度声明）。
//!
//! 应答码沿用 QUIC 路径语义：0x00 成功 / 0x01 目标连接失败（含 SSRF 拒绝）/
//! 0x02 节点侧 DNS 失败。握手/认证失败不回显任何应答（静默关流，防探测语义不变）。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{HydraError, Result};

/// 地址帧版本判别字节：0x03 = Noise-PSK 握手（与 [`crate::handshake`] 共用判别值；
/// 握手在流首，本模块的地址帧紧随其后）。
pub const TCP_VERSION_BYTE: u8 = crate::handshake::HANDSHAKE_VERSION_BYTE;

/// 目标地址长度上限（字节）。域名最长 253，IP:port 最长 45+6；
/// 1024 拒绝恶意长度声明，同时给 IPv6 字面量 + 端口留足余量。
pub const MAX_TARGET_LEN: usize = 1024;

/// 应答码：成功（与 QUIC 路径 0x00 语义一致）
pub const REPLY_OK: u8 = 0x00;
/// 应答码：目标连接失败（含 SSRF 拒绝，与 QUIC 路径 0x11 折叠语义一致——
/// 不给探测者区分"拒绝原因"的指纹）
pub const REPLY_TARGET_FAIL: u8 = 0x01;
/// 应答码：节点侧 DNS 解析失败
pub const REPLY_DNS_FAIL: u8 = 0x02;

/// 应答固定 2 字节：`[0x00][code]`。首字节保留 0x00，为未来扩展留位，
/// 同时与 QUIC 路径的 `[0x00,0x00]` 成功应答线缆兼容。
pub const REPLY_LEN: usize = 2;

/// 校验目标地址合法性并编码为地址帧：`[len u16 大端][addr]`。
pub fn encode_target(target: &str) -> Result<Vec<u8>> {
    let addr = target.as_bytes();
    if addr.is_empty() || addr.len() > MAX_TARGET_LEN {
        return Err(HydraError::ProtocolError(format!(
            "目标地址长度非法：{} 字节（1..={}）",
            addr.len(),
            MAX_TARGET_LEN
        )));
    }
    let mut frame = Vec::with_capacity(2 + addr.len());
    frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(addr);
    Ok(frame)
}

/// 从流中读取地址帧，返回目标地址字符串（UTF-8 失败/长度非法/EOF → Err）。
/// 超时控制由调用方包裹（节点侧 AUTH_TIMEOUT / 客户侧 RESPONSE_TIMEOUT）。
pub async fn read_target<R: AsyncRead + Unpin>(recv: &mut R) -> Result<String> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("读取地址帧长度失败: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_TARGET_LEN {
        return Err(HydraError::ProtocolError(format!(
            "地址帧长度非法: {len}"
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("读取地址帧失败: {e}")))?;
    String::from_utf8(buf)
        .map_err(|e| HydraError::ProtocolError(format!("目标地址非 UTF-8: {e}")))
}

/// 写地址帧到流。
pub async fn write_target<W: AsyncWrite + Unpin>(send: &mut W, target: &str) -> Result<()> {
    let frame = encode_target(target)?;
    send.write_all(&frame)
        .await
        .map_err(|e| HydraError::ProtocolError(format!("写入地址帧失败: {e}")))
}

/// 编码 2B 应答（`[0x00][code]`）。
pub fn encode_reply(code: u8) -> [u8; REPLY_LEN] {
    [0x00, code]
}

/// 写应答到流。
pub async fn write_reply<W: AsyncWrite + Unpin>(send: &mut W, code: u8) -> Result<()> {
    send.write_all(&encode_reply(code))
        .await
        .map_err(|e| HydraError::ProtocolError(format!("写入应答失败: {e}")))
}

/// 从流中读取并判定节点应答。0x00 → Ok(())；0x01/0x02 → 带语义的 ConnectionError；
/// EOF → 静默关流（节点侧握手失败/协议失步，防探测语义下无错误回显）；
/// 其他码 → ProtocolError。
pub async fn read_reply<R: AsyncRead + Unpin>(recv: &mut R) -> Result<()> {
    let mut resp = [0u8; REPLY_LEN];
    match recv.read_exact(&mut resp).await {
        Ok(_) => {}
        // 节点静默关闭 = 握手/认证失败或协议失步（无应用错误码通道，如实报错）
        Err(e) => {
            return Err(HydraError::ConnectionError(format!(
                "节点静默关闭连接（认证失败或协议失步）: {e}"
            )))
        }
    }
    if resp[0] != 0x00 {
        return Err(HydraError::ProtocolError(format!(
            "节点应答首字节异常: 0x{:02x}",
            resp[0]
        )));
    }
    match resp[1] {
        REPLY_OK => Ok(()),
        // TargetUnreachable：节点存活但目标侧失败——故障切换层据此不计节点故障
        REPLY_TARGET_FAIL => Err(HydraError::TargetUnreachable(
            "节点报告目标连接失败（含 SSRF 拒绝）".to_string(),
        )),
        REPLY_DNS_FAIL => Err(HydraError::TargetUnreachable(
            "节点报告目标域名解析失败".to_string(),
        )),
        other => Err(HydraError::ProtocolError(format!(
            "节点应答码未知: 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn encode_target_roundtrip_layout() {
        let frame = encode_target("example.com:443").unwrap();
        assert_eq!(frame.len(), 2 + 15);
        assert_eq!(&frame[..2], &[0x00, 15]); // u16 BE
        assert_eq!(&frame[2..], b"example.com:443");
    }

    #[test]
    fn encode_target_rejects_empty_and_overlong() {
        assert!(encode_target("").is_err());
        assert!(encode_target(&"a".repeat(MAX_TARGET_LEN + 1)).is_err());
        // 恰好 1024：放行（边界一致）
        assert!(encode_target(&"a".repeat(MAX_TARGET_LEN)).is_ok());
    }

    #[tokio::test]
    async fn target_frame_roundtrip_through_stream() {
        let (mut c, mut s) = duplex(4096);
        write_target(&mut c, "203.0.113.7:8080").await.unwrap();
        drop(c);
        let t = read_target(&mut s).await.unwrap();
        assert_eq!(t, "203.0.113.7:8080");
    }

    #[tokio::test]
    async fn read_target_rejects_bad_length_and_bad_utf8() {
        let (mut c, mut s) = duplex(64);
        c.write_all(&[0x00, 0x00]).await.unwrap(); // 长度 0
        drop(c);
        assert!(read_target(&mut s).await.is_err());

        let (mut c, mut s) = duplex(64);
        c.write_all(&[0xFF, 0xFF]).await.unwrap(); // 超上限
        drop(c);
        assert!(read_target(&mut s).await.is_err());

        let (mut c, mut s) = duplex(64);
        c.write_all(&[0x00, 0x02, 0xFF, 0xFE]).await.unwrap(); // 非 UTF-8
        drop(c);
        assert!(read_target(&mut s).await.is_err());
    }

    #[tokio::test]
    async fn reply_codes_map_to_semantic_errors() {
        for (code, ok) in [
            (REPLY_OK, true),
            (REPLY_TARGET_FAIL, false),
            (REPLY_DNS_FAIL, false),
            (0x7F, false),
        ] {
            let (mut c, mut s) = duplex(16);
            write_reply(&mut c, code).await.unwrap();
            drop(c);
            assert_eq!(read_reply(&mut s).await.is_ok(), ok, "code=0x{code:02x}");
        }
        // EOF（节点静默关流）→ 报错且不 panic
        let (_c, mut s) = duplex(16);
        drop(_c);
        assert!(read_reply(&mut s).await.is_err());
    }

    #[test]
    fn reply_wire_format_is_2b_prefixed_zero() {
        assert_eq!(encode_reply(REPLY_OK), [0x00, 0x00]);
        assert_eq!(encode_reply(REPLY_TARGET_FAIL), [0x00, 0x01]);
        assert_eq!(encode_reply(REPLY_DNS_FAIL), [0x00, 0x02]);
    }
}
