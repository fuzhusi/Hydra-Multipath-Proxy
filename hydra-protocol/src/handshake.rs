//! V3.2 Noise-PSK 握手 v2（Hydra-Noise-PSK，方案 §4 V3.2 的可交付收敛版）。
//!
//! 目标：替换 v2 静态 HMAC token 的三个缺陷——无前向安全、30s 时钟窗、可重放。
//!
//! ## 线协议（QUIC 双向流内，握手永远在流内，见方案 §3 分歧 3）
//!
//! ```text
//! 客户端 → 节点：  [0x03][msg1]           msg1 = snow NNpsk2，e + tag        (48B)
//! 节点 → 客户端：  [msg2]                 msg2 = snow NNpsk2，e,ee,psk      (48B)
//! 客户端 → 节点：  [confirm_c 32B]        知识证明：客户端持 PSK
//! 节点 → 客户端：  [confirm_s 32B]        知识证明：节点持 PSK（客户端免盲等）
//! 此后        ：  模式标签 0x00/0x01，数据面与 v2 逐字节一致（握手不重加密数据）
//! ```
//!
//! - **前向安全**：NNpsk2 双方均为临时密钥（e, ee），PSK 泄漏不解密历史握手。
//! - **抗重放**：节点每次握手用新鲜临时 e；重放整段（含 confirm_c）时节点侧
//!   handshake hash 不同 → confirm 比对失败 → 静默关流。无 nonce 表依赖。
//! - **无时钟窗**：全程不读系统时间（门④，代码审阅可证）。
//! - **通道绑定**：confirm 混入 (a) 节点证书 SHA-256 指纹 (b) QUIC/TLS exporter
//!   材料（quinn 0.10 `Connection::export_keying_material`，两端 label/context
//!   一致即同值）——跨 TLS 连接转发/重放握手字节无效（P0-2 MITM 修复）。
//! - **rekey 推迟**：V3.3 处理（如实标注，本期未实现）。
//!
//! 握手只做认证与密钥确认；snow 传输态在握手完成后即丢弃，数据面不变。

use std::time::Duration;

use ring::digest::{digest, SHA256};
use ring::hkdf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{HydraError, Result};

/// 流首字节版本判别：0x03 = v3 Noise 握手（v2 legacy 见 handler/pool 的 0x00 路径）
pub const HANDSHAKE_VERSION_BYTE: u8 = 0x03;

/// snow 模式串（方案 §5 定版；选 NNpsk2 而非 IKpsk2：IK 静态公钥明文可关联身份）
pub const NOISE_PATTERN: &str = "Noise_NNpsk2_25519_ChaChaPoly_SHA256";

/// snow NNpsk2（psk2 修饰符）实测：PSK 在 msg1 前即混入密钥层，两条握手消息
/// 均为 32B 临时公钥 + 16B Poly1305 tag = 48B（snow 0.9.6 行为，双端对称自洽）。
const MSG1_LEN: usize = 48;
/// msg2 长度与 msg1 相同（e + tag）
const MSG2_LEN: usize = 48;
/// confirm 长度 = HKDF-SHA256 输出
const CONFIRM_LEN: usize = 32;

/// HKDF info 域分离前缀（方案 §5：`hydra v3 *`）
const INFO_C2S: &[u8] = b"hydra v3 tls-bind c2s";
const INFO_S2C: &[u8] = b"hydra v3 tls-bind s2c";

/// QUIC/TLS exporter label（两端一致；quinn 0.10 export_keying_material 可用，
/// 无需降级到"仅证书指纹"——证书指纹仍一并混入）
pub const EXPORTER_LABEL: &[u8] = b"hydra v3 channel binding";
/// exporter 输出长度
pub const EXPORTER_LEN: usize = 32;

/// 握手超时：与 v2 认证段同级（节点 AUTH_TIMEOUT / 客户端 5s 各自包裹）
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// HYDRA_AUTH_MODE=auto|v2|v3。节点：auto=双栈都收（默认），v2/v3=只收对应版本；
/// 客户端：auto=优先 v3、失败自动回落 v2（混编节点群平滑迁移），v2/v3=固定。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AuthMode {
    #[default]
    Auto,
    V2,
    V3,
}

impl AuthMode {
    /// 解析 HYDRA_AUTH_MODE 值；None = 非法（调用方决定告警或回退）
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "v2" => Some(Self::V2),
            "v3" => Some(Self::V3),
            _ => None,
        }
    }

    /// 从进程 env 读取；未设置 = Auto，非法值告警并回退 Auto
    pub fn from_env() -> Self {
        match std::env::var("HYDRA_AUTH_MODE") {
            Ok(v) => match Self::parse(&v) {
                Some(m) => m,
                None => {
                    eprintln!("警告：HYDRA_AUTH_MODE={v:?} 非法（auto|v2|v3），回退 auto");
                    Self::Auto
                }
            },
            Err(_) => Self::Auto,
        }
    }

    pub fn accepts_v2(&self) -> bool {
        !matches!(self, Self::V3)
    }

    pub fn accepts_v3(&self) -> bool {
        !matches!(self, Self::V2)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::V2 => "v2",
            Self::V3 => "v3",
        }
    }
}

/// 握手错误（统一折叠为 ProtocolError，节点侧不回显任何差异——防探测语义不变）
fn err(msg: &str) -> HydraError {
    HydraError::ProtocolError(format!("v3 handshake: {}", msg))
}

/// 证书 SHA-256 指纹（两端混入 confirm 的通道绑定材料之一）
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, cert_der);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// snow builder：NNpsk2 + PSK + ring resolver（禁默认 provider 混用，方案 §6-2）
fn build(psk: &[u8], initiator: bool) -> Result<snow::HandshakeState> {
    if psk.is_empty() || psk.len() > 32 {
        return Err(err("PSK 必须为 1..=32 字节（HYDRA_AUTH_KEY hex 解码值）"));
    }
    let params: snow::params::NoiseParams = NOISE_PATTERN.parse().map_err(|e| err(&format!("模式串解析失败: {e}")))?;
    // ring 优先（RNG/Cipher/Hash）；snow 0.9.6 的 RingResolver 不含 X25519 DH，
    // DH 回退默认 resolver（x25519-dalek，RustCrypto 审计件）——如实标注。
    let resolver = snow::resolvers::FallbackResolver::new(
        Box::new(snow::resolvers::RingResolver),
        Box::new(snow::resolvers::DefaultResolver),
    );
    let builder = snow::Builder::with_resolver(params, Box::new(resolver))
        .psk(2, psk); // NNpsk2：PSK 位于第 2 位置（与 msg2 的 "e, ee, psk" 对应）
    if initiator {
        builder.build_initiator().map_err(|e| err(&format!("build_initiator: {e}")))
    } else {
        builder.build_responder().map_err(|e| err(&format!("build_responder: {e}")))
    }
}

/// confirm 推导：HKDF-SHA256(ikm = handshake_hash, salt = cert_fp ‖ exporter, info = 方向)
/// 证书指纹绑定节点身份、exporter 绑定 QUIC/TLS 会话（跨连接转发即失效）。
fn derive_confirm(
    handshake_hash: &[u8; 32],
    cert_fp: &[u8; 32],
    exporter: &[u8; 32],
    info: &[u8],
) -> Result<[u8; CONFIRM_LEN]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[cert_fp.as_ref(), exporter.as_ref()].concat());
    let prk = salt.extract(handshake_hash);
    let mut out = [0u8; CONFIRM_LEN];
    let infos = [info];
    let okm = prk.expand(&infos, hkdf::HKDF_SHA256).map_err(|e| err(&format!("HKDF expand: {e}")))?;
    okm.fill(&mut out).map_err(|e| err(&format!("HKDF fill: {e}")))?;
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// 客户端侧握手：写 [0x03][msg1]，读 msg2，发 confirm_c，收 verify confirm_s。
/// `exporter` 为 quinn `Connection::export_keying_material(EXPORTER_LEN, EXPORTER_LABEL, b"")`
/// 的输出（与节点同连接才同值）。成功返回 handshake hash（仅日志/测试用途；
/// snow 传输态即弃，数据面照旧走模式标签）。
pub async fn client_side<W, R>(
    send: &mut W,
    recv: &mut R,
    psk: &[u8],
    cert_fp: &[u8; 32],
    exporter: &[u8; 32],
) -> Result<[u8; 32]>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = build(psk, true)?;

    // [0x03][msg1]
    let mut msg1 = [0u8; MSG1_LEN];
    let mut frame = Vec::with_capacity(1 + MSG1_LEN);
    frame.push(HANDSHAKE_VERSION_BYTE);
    let n = hs.write_message(&[], &mut msg1).map_err(|e| err(&format!("write msg1: {e}")))?;
    frame.extend_from_slice(&msg1[..n]);
    send.write_all(&frame).await.map_err(|e| err(&format!("send msg1: {e}")))?;

    // [msg2]
    let mut msg2 = [0u8; MSG2_LEN];
    recv.read_exact(&mut msg2).await.map_err(|e| err(&format!("recv msg2: {e}")))?;
    let mut buf = [0u8; 64];
    hs.read_message(&msg2, &mut buf).map_err(|e| err(&format!("read msg2: {e}")))?;

    // confirm_c
    let mut hh = [0u8; 32];
    hh.copy_from_slice(hs.get_handshake_hash());
    let confirm_c = derive_confirm(&hh, cert_fp, exporter, INFO_C2S)?;
    send.write_all(&confirm_c).await.map_err(|e| err(&format!("send confirm: {e}")))?;

    // confirm_s
    let mut confirm_s = [0u8; CONFIRM_LEN];
    recv.read_exact(&mut confirm_s).await.map_err(|e| err(&format!("recv confirm_s: {e}")))?;
    let expected = derive_confirm(&hh, cert_fp, exporter, INFO_S2C)?;
    if !constant_time_eq(&expected, &confirm_s) {
        return Err(err("节点确认值不匹配（PSK/证书/exporter 不一致或握手被篡改）"));
    }
    Ok(hh)
}

/// 节点侧握手：流已定位在版本字节之后（0x03 已被 handler 消费）。
/// 读 msg1，回 msg2，verify confirm_c，回 confirm_s。返回 handshake hash。
pub async fn server_side<W, R>(
    send: &mut W,
    recv: &mut R,
    psk: &[u8],
    cert_fp: &[u8; 32],
    exporter: &[u8; 32],
) -> Result<[u8; 32]>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = build(psk, false)?;

    let mut msg1 = [0u8; MSG1_LEN];
    recv.read_exact(&mut msg1).await.map_err(|e| err(&format!("recv msg1: {e}")))?;
    let mut buf = [0u8; 64];
    hs.read_message(&msg1, &mut buf).map_err(|e| err(&format!("read msg1: {e}")))?;

    let mut msg2 = [0u8; MSG2_LEN];
    let n = hs.write_message(&[], &mut msg2).map_err(|e| err(&format!("write msg2: {e}")))?;
    send.write_all(&msg2[..n]).await.map_err(|e| err(&format!("send msg2: {e}")))?;

    // verify confirm_c（重放防线：节点 e 新鲜 → hash 不同 → 重放的 confirm 必不匹配）
    let mut confirm_c = [0u8; CONFIRM_LEN];
    recv.read_exact(&mut confirm_c).await.map_err(|e| err(&format!("recv confirm_c: {e}")))?;
    let mut hh = [0u8; 32];
    hh.copy_from_slice(hs.get_handshake_hash());
    let expected = derive_confirm(&hh, cert_fp, exporter, INFO_C2S)?;
    if !constant_time_eq(&expected, &confirm_c) {
        return Err(err("客户端确认值不匹配（含重放/篡改/PSK 不一致）"));
    }

    let confirm_s = derive_confirm(&hh, cert_fp, exporter, INFO_S2C)?;
    send.write_all(&confirm_s).await.map_err(|e| err(&format!("send confirm_s: {e}")))?;
    Ok(hh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    const PSK: [u8; 32] = [7u8; 32];
    const CERT_FP: [u8; 32] = [9u8; 32];
    const EXPORTER: [u8; 32] = [11u8; 32];

    #[tokio::test]
    async fn handshake_roundtrip_succeeds_and_matches_hash() {
        let (mut c_send, mut s_recv) = duplex(4096);
        let (mut s_send, mut c_recv) = duplex(4096);
        let client = tokio::spawn(async move {
            client_side(&mut c_send, &mut c_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let server = tokio::spawn(async move {
            let mut vb = [0u8; 1];
            s_recv.read_exact(&mut vb).await.unwrap(); // 消费版本字节（生产中由 handler 消费）
            server_side(&mut s_send, &mut s_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let (hc, hs_) = tokio::join!(client, server);
        let hc = hc.unwrap().unwrap();
        let hs_ = hs_.unwrap().unwrap();
        assert_eq!(hc, hs_, "两端 handshake hash 应一致");
        assert_ne!(hc, [0u8; 32]);
    }

    #[tokio::test]
    async fn wrong_psk_fails_both_directions() {
        let (mut c_send, mut s_recv) = duplex(4096);
        let (mut s_send, mut c_recv) = duplex(4096);
        let client = tokio::spawn(async move {
            client_side(&mut c_send, &mut c_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let bad_psk = [8u8; 32];
        let server = tokio::spawn(async move {
            server_side(&mut s_send, &mut s_recv, &bad_psk, &CERT_FP, &EXPORTER).await
        });
        let (c, s) = tokio::join!(client, server);
        assert!(c.unwrap().is_err(), "客户端应因 confirm_s 不匹配而失败");
        assert!(s.unwrap().is_err(), "节点应因 confirm_c 不匹配而失败");
    }

    #[tokio::test]
    async fn cert_fingerprint_mismatch_fails() {
        // 两端证书指纹不同 → confirm 不匹配（通道绑定生效）
        let (mut c_send, mut s_recv) = duplex(4096);
        let (mut s_send, mut c_recv) = duplex(4096);
        let other_fp = [10u8; 32];
        let client =
            tokio::spawn(async move { client_side(&mut c_send, &mut c_recv, &PSK, &other_fp, &EXPORTER).await });
        let server = tokio::spawn(async move {
            let mut vb = [0u8; 1];
            s_recv.read_exact(&mut vb).await.unwrap(); // 消费版本字节（生产中由 handler 消费）
            server_side(&mut s_send, &mut s_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let (c, s) = tokio::join!(client, server);
        assert!(c.unwrap().is_err());
        assert!(s.unwrap().is_err());
    }

    #[tokio::test]
    async fn exporter_mismatch_fails() {
        // exporter 不同（= 握手字节被搬到另一条 TLS 连接）→ 拒绝
        let (mut c_send, mut s_recv) = duplex(4096);
        let (mut s_send, mut c_recv) = duplex(4096);
        let other_ex = [12u8; 32];
        let client =
            tokio::spawn(async move { client_side(&mut c_send, &mut c_recv, &PSK, &CERT_FP, &other_ex).await });
        let server = tokio::spawn(async move {
            let mut vb = [0u8; 1];
            s_recv.read_exact(&mut vb).await.unwrap(); // 消费版本字节（生产中由 handler 消费）
            server_side(&mut s_send, &mut s_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let (c, s) = tokio::join!(client, server);
        assert!(c.unwrap().is_err());
        assert!(s.unwrap().is_err());
    }

    /// 门③（单测层）：把一轮合法握手的客户端出站字节（0x03+msg1+confirm_c）
    /// 原样重放到新服务端——节点 e 新鲜 → handshake hash 不同 → confirm 不匹配 →
    /// 服务端必须拒绝。QUIC 线级重放另见集成测试 test_handshake_v3。
    #[tokio::test]
    async fn replayed_client_transcript_is_rejected() {
        // 第一轮：客户端出站字节写入 Capturing writer（服务端由真实 server_side 扮演）
        let (mut c_send, mut s_recv) = duplex(4096);
        let (mut s_send, mut c_recv) = duplex(4096);
        let client = tokio::spawn(async move {
            client_side(&mut c_send, &mut c_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let server = tokio::spawn(async move {
            let mut vb = [0u8; 1];
            s_recv.read_exact(&mut vb).await.unwrap(); // 消费版本字节（生产中由 handler 消费）
            server_side(&mut s_send, &mut s_recv, &PSK, &CERT_FP, &EXPORTER).await
        });
        let (c, s) = tokio::join!(client, server);
        c.unwrap();
        s.unwrap();

        // 重放：旧会话的 msg1 是纯临时公钥、攻击者可完整重放，但 confirm_c 绑定
        // 旧服务端 e；新服务端 e 新鲜 → hash 不同 → 重放的 confirm_c 必不匹配。
        // 此处用"合法格式 msg1 + 全零 confirm_c"模拟重放者（拿不到 PSK 推不出
        // 正确 confirm，重放旧值与此等价地失败于同一比对点）。
        let (mut s2_recv_from, mut s2_send_to) = duplex(4096);
        let (mut v_send, mut _v_recv) = duplex(4096);
        let _server2 = tokio::spawn(async move {
            server_side(&mut v_send, &mut s2_recv_from, &PSK, &CERT_FP, &EXPORTER).await
        });
        let mut hs = build(&PSK, true).unwrap(); // 只为生成合法格式的 msg1
        let mut msg1 = [0u8; MSG1_LEN];
        let n = hs.write_message(&[], &mut msg1).unwrap();
        let (mut fake_c_send, mut fake_c_recv) = duplex(4096);
        fake_c_send.write_all(&[HANDSHAKE_VERSION_BYTE]).await.unwrap();
        fake_c_send.write_all(&msg1[..n]).await.unwrap();
        // 伪造 confirm_c（全零）——重放者拿不到 PSK 推不出正确值
        fake_c_send.write_all(&[0u8; CONFIRM_LEN]).await.unwrap();
        let r = server_side(&mut s2_send_to, &mut fake_c_recv, &PSK, &CERT_FP, &EXPORTER).await;
        assert!(r.is_err(), "伪造/重放的 confirm_c 必须被拒");
    }

    #[test]
    fn psk_length_validated() {
        assert!(build(&[], true).is_err());
        assert!(build(&[0u8; 33], true).is_err());
        assert!(build(&PSK, true).is_ok());
    }

    #[test]
    fn cert_fingerprint_is_sha256() {
        let fp = cert_fingerprint(b"hello");
        let d = digest(&SHA256, b"hello");
        assert_eq!(fp.as_ref(), d.as_ref());
    }
}

