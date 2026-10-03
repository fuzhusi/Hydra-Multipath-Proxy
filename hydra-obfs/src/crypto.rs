//! 混淆层核心：日派生密钥、每包 keystream 变换、QUIC 形状判定、每源限速。
//!
//! 线缆格式：`[12B salt][ChaCha20 keystream XOR 报文]`（V3 方案 §3 附注定版）。
//!
//! ## 密钥派生（按 UTC 日）
//!
//! ```text
//! PRK = HKDF-Extract(salt = "", IKM = HYDRA_OBFS_KEY 密码字节)
//! key(D) = HKDF-Expand(PRK, info = "hydra v3 obfs YYYY-MM-DD"(D 的 UTC 日期), L = 32)
//! ```
//!
//! 发送方用"今天"的 key；接收方按 **[今/明/昨]** 三把尝试，容忍 ±1 天时钟差
//! （01 方案沿袭，V3 方案 §3 附注确认）。|时钟差| ≥ 2 天则无法互通——如实记录为限制。
//!
//! ## 判定与丢弃（混淆层不认证）
//!
//! 每把候选 key 解包后用 [`looks_like_quic`] 启发式判定形状：命中即采用并上交内层
//! QUIC；三把全不命中 → 记入每源限速表并**静默丢弃**。形状判定只是选 key 的启发式：
//! - 真 QUIC 报文（正确 key）**必然**命中 → 正常路径每包恰 1 次 keystream 运算；
//! - 错 key 解出的随机垃圾命中（长包头 ≈2⁻³³、短包头 = 1/4）→ 上交后由内层 QUIC 的
//!   AEAD/包号/CID 校验丢弃，混淆层安全无恙；
//! - 该 1/4 只在 ±1 天时钟错配的窗口内让部分短包头数据包丢失（QUIC 重传兜底，
//!   握手包为长包头不受影响）——是纯 XOR 变换（无认证）下"试三把 key"的固有代价。
//!
//! ## 性能（性能红线：obfs on 吞吐损失 <5%）
//!
//! - 正常路径每包：1 次 ChaCha20 keystream + 1 次限速表哈希查找，无逐包堆分配；
//! - 盐源用 ChaCha20 CSPRNG 缓冲（4KB 批量生成），避免每包一次 getrandom 系统调用；
//! - 日密钥缓存于 Mutex，每天翻新一次（非每包）。

use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use quinn::udp::RecvMeta;
use ring::hkdf;
use ring::rand::SecureRandom;

use crate::limiter::{SourceLimiter, DEFAULT_BUDGET, DEFAULT_CAPACITY, DEFAULT_WINDOW_MS};
use crate::mode::HYDRA_OBFS_KEY_ENV;

/// 线缆格式中 salt 前缀长度（= ChaCha20 96-bit nonce，取满 12B 防生日界 keystream 复用）
pub const SALT_LEN: usize = 12;
/// 日派生 info 的固定前缀（"hydra v3 obfs "）
const HKDF_INFO_PREFIX: &[u8] = b"hydra v3 obfs ";
/// 单个盐源缓冲的字节数（~341 个 salt/批）
const SALT_BUF: usize = 4096;

/// HKDF-SHA256 按日派生 32B 混淆密钥（纯函数，两侧实现必须逐字节一致）。
///
/// `info = "hydra v3 obfs " + "YYYY-MM-DD"`（UTC 日期，day 0 = 1970-01-01）。
pub fn derive_day_key(ikm: &[u8], day: u64) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"").extract(ikm);
    let (y, m, d) = day_to_ymd(day as i64);
    let mut info = [0u8; HKDF_INFO_PREFIX.len() + 10];
    info[..HKDF_INFO_PREFIX.len()].copy_from_slice(HKDF_INFO_PREFIX);
    // "YYYY-MM-DD"：年 4 位，月/日 2 位补零
    let mut tail = [b'0'; 10];
    write_u32_pad4(&mut tail[0..4], y as u32);
    tail[4] = b'-';
    write_u32_pad2(&mut tail[5..7], m);
    tail[7] = b'-';
    write_u32_pad2(&mut tail[8..10], d);
    info[HKDF_INFO_PREFIX.len()..].copy_from_slice(&tail);

    let mut out = [0u8; 32];
    // ring 0.16：expand 的长度参数即算法（SHA256 → 32B 输出）
    prk.expand(&[&info], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF-SHA256 派生 32B 不会失败");
    out
}

/// 无 alloc 十进制写入（调用方保证缓冲恰好容纳）
fn write_u32_pad4(buf: &mut [u8], v: u32) {
    debug_assert_eq!(buf.len(), 4);
    let mut v = v;
    for i in (0..4).rev() {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
}
fn write_u32_pad2(buf: &mut [u8], v: u32) {
    debug_assert_eq!(buf.len(), 2);
    buf[0] = b'0' + (v / 10) as u8;
    buf[1] = b'0' + (v % 10) as u8;
}

/// 当前 UTC 日号（1970-01-01 = 0）
pub fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

/// UTC 日号 → (年, 月, 日)。Howard Hinnant 的 civil_from_days 算法。
pub fn day_to_ymd(day: i64) -> (i64, u32, u32) {
    let z = day + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// ChaCha20 keystream 原地 XOR（`apply_keystream`；再应用一次即恢复——流密码自逆）。
pub fn xor_segment(key: &[u8; 32], salt: &[u8; SALT_LEN], buf: &mut [u8]) {
    let mut cipher = ChaCha20::new(Key::from_slice(key), Nonce::from_slice(salt));
    cipher.apply_keystream(buf);
}

/// 对按 `stride` 分段的 GRO 批量缓冲逐段 XOR（每段头 12B 为该段自己的 salt）。
fn xor_strided(buf: &mut [u8], stride: usize, key: &[u8; 32]) {
    let mut pos = 0;
    while pos < buf.len() {
        let seg = stride.min(buf.len() - pos);
        if seg < SALT_LEN {
            // 残段无完整 salt：保持原样（外层会按垃圾/残段处理）
            return;
        }
        let salt: [u8; SALT_LEN] = buf[pos..pos + SALT_LEN].try_into().expect("seg ≥ SALT_LEN");
        xor_segment(key, &salt, &mut buf[pos + SALT_LEN..pos + seg]);
        pos += stride;
    }
}

/// QUIC 报文形状启发式（选 key 用，非协议门禁——详见模块文档）。
///
/// 本项目节点/客户端均为 quinn 0.10（QUIC v1 only）：
/// - 长包头：首两比特 = 0b11（form + fixed）且 version == 0x00000001（错 key 误判率 ≈ 2⁻³⁴）；
///   版本协商包（version=0）在 v1-only 端点间不出现，判为垃圾；
/// - 短包头：首两比特 = 0b01（form=0, fixed=1）（错 key 误判率 = 1/4，见模块文档权衡）。
pub fn looks_like_quic(p: &[u8]) -> bool {
    if p.len() < 5 {
        return false;
    }
    let b0 = p[0];
    if b0 & 0x80 != 0 {
        (b0 & 0x40) == 0x40 && p[1..5] == [0x00, 0x00, 0x00, 0x01]
    } else {
        b0 & 0x40 != 0
    }
}

/// 盐源 CSPRNG：ChaCha20 计数器流缓冲化，避免每包一次 getrandom 系统调用。
///
/// 种子来自 `ring::rand::SystemRandom`（每实例 32B）；计数器单调递增，盐值不重复。
struct SaltRng {
    cipher: ChaCha20,
    buf: [u8; SALT_BUF],
    pos: usize,
}

impl SaltRng {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut seed)
            .expect("SystemRandom 不可用");
        Self::from_seed(seed)
    }

    /// 固定种子构造（单测确定性：卡方检验等）
    fn from_seed(seed: [u8; 32]) -> Self {
        // nonce 用固定 domain-separation 常量（"HYDRASALT" 前 8B）——种子本身随机 256bit，
        // 单实例计数器单调，同 (seed, nonce) 流不会在两个实例间重复
        let nonce: [u8; 12] = [0x48, 0x59, 0x44, 0x52, 0x41, 0x53, 0x41, 0x4C, 0, 0, 0, 0];
        Self {
            cipher: ChaCha20::new(Key::from_slice(&seed), Nonce::from_slice(&nonce)),
            buf: [0u8; SALT_BUF],
            pos: SALT_BUF, // 首次 fill 触发 refill
        }
    }

    fn fill(&mut self, out: &mut [u8; SALT_LEN]) {
        if self.pos + SALT_LEN > SALT_BUF {
            self.buf = [0u8; SALT_BUF];
            self.cipher.apply_keystream(&mut self.buf);
            self.pos = 0;
        }
        out.copy_from_slice(&self.buf[self.pos..self.pos + SALT_LEN]);
        self.pos += SALT_LEN;
    }
}

/// 日密钥缓存：[今, 明, 昨]（发送用 keys[0]；接收按此顺序试解）
struct DayCache {
    day: u64,
    keys: [[u8; 32]; 3],
}

/// 混淆层会话：密钥派生 + 变换 + 每源限速。发送/接收方向共用一个实例。
pub struct ObfsCrypto {
    ikm: Vec<u8>,
    cache: Mutex<DayCache>,
    salt_rng: Mutex<SaltRng>,
    limiter: Mutex<SourceLimiter>,
    start: Instant,
}

impl fmt::Debug for ObfsCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 不输出密码本体
        f.debug_struct("ObfsCrypto")
            .field("ikm", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ObfsCrypto {
    /// 用独立混淆密码构造（两端必须设置完全一致的密码）
    pub fn new(passphrase: &[u8]) -> Self {
        Self {
            ikm: passphrase.to_vec(),
            cache: Mutex::new(DayCache {
                day: u64::MAX,
                keys: [[0; 32]; 3],
            }),
            salt_rng: Mutex::new(SaltRng::new()),
            limiter: Mutex::new(SourceLimiter::new(
                DEFAULT_CAPACITY,
                DEFAULT_WINDOW_MS,
                DEFAULT_BUDGET,
            )),
            start: Instant::now(),
        }
    }

    /// 从 env 读取独立密码构造。未设置/空白 → Err（obfs 模式启动失败，任务书 C2 规格）。
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(HYDRA_OBFS_KEY_ENV) {
            Ok(v) if !v.trim().is_empty() => Ok(Self::new(v.as_bytes())),
            Ok(_) => Err(format!(
                "{HYDRA_OBFS_KEY_ENV} 已设置但为空白，无法作为混淆密码"
            )),
            Err(_) => Err(format!(
                "obfs 模式要求设置 {HYDRA_OBFS_KEY_ENV}（独立于认证密钥的第二密码，两端一致）"
            )),
        }
    }

    /// 测试专用：固定盐源种子 + 自定义限速器参数
    #[cfg(test)]
    fn new_with_seed(passphrase: &[u8], seed: [u8; 32]) -> Self {
        let c = Self::new(passphrase);
        *c.salt_rng.lock().unwrap() = SaltRng::from_seed(seed);
        c
    }

    fn day_keys(&self) -> [[u8; 32]; 3] {
        let today = current_day();
        let mut cache = self.cache.lock().unwrap();
        if cache.day != today {
            cache.keys = [
                derive_day_key(&self.ikm, today),
                derive_day_key(&self.ikm, today + 1),
                derive_day_key(&self.ikm, today.wrapping_sub(1)),
            ];
            cache.day = today;
        }
        cache.keys
    }

    /// 取发送参数：今天的日派生密钥 + 新鲜随机盐
    fn wrap_params(&self) -> ([u8; 32], [u8; SALT_LEN]) {
        let key = self.day_keys()[0];
        let mut salt = [0u8; SALT_LEN];
        self.salt_rng.lock().unwrap().fill(&mut salt);
        (key, salt)
    }

    /// 把一段报文变换后追加到 `out`：先写 12B salt，再对报文副本做 keystream XOR。
    /// 输入 `seg` 为不可变借用（quinn Transmit 的共享 Bytes），一次内存拷贝不可避免；
    /// 本函数自身零堆分配（容量由调用方的批量缓冲复用）。
    pub fn wrap_segment_into(&self, seg: &[u8], out: &mut bytes::BytesMut) {
        let (key, salt) = self.wrap_params();
        out.extend_from_slice(&salt);
        let start = out.len();
        out.extend_from_slice(seg);
        xor_segment(&key, &salt, &mut out[start..]);
    }

    /// 接收方向：对一个已收 datagram（含 GRO stride 语义）剥 salt + 按日试解。
    ///
    /// 成功 → 原地压实（剥掉每段 12B salt）并更新 `meta`（len/stride 相应缩小，
    /// addr/ecn/dst_ip 保持），返回 true；失败（垃圾/残段/该源超预算）→ 返回 false，
    /// 调用方整体丢弃该 datagram。
    pub fn unwrap_datagram(&self, buf: &mut [u8], meta: &mut RecvMeta) -> bool {
        let src: IpAddr = meta.addr.ip();
        let now_ms = self.start.elapsed().as_millis() as u64;
        // 超预算的垃圾源：不做任何变换直接丢（每源每窗口混淆层 CPU 封顶）
        if self.limiter.lock().unwrap().blocked(src, now_ms) {
            return false;
        }
        let len = buf.len();
        let stride = if meta.stride == 0 { len } else { meta.stride };
        if len < SALT_LEN + 1 || stride < SALT_LEN + 1 {
            self.note_garbage(src, now_ms);
            return false;
        }

        let keys = self.day_keys();
        let mut matched = false;
        for key in &keys {
            xor_strided(buf, stride, key);
            // 首段解包后的载荷位于 buf[SALT_LEN..seg0]（salt 前缀之后）
            let seg0 = stride.min(len);
            if looks_like_quic(&buf[SALT_LEN..seg0]) {
                matched = true;
                break;
            }
            // 未命中：keystream 自逆，恢复后试下一把
            xor_strided(buf, stride, key);
        }
        if !matched {
            self.note_garbage(src, now_ms);
            return false;
        }

        // 压实：剥掉每段前 12B salt（目标区不会越过源区，copy_within 重叠安全）
        let mut wpos = 0usize;
        let mut rpos = 0usize;
        while rpos < len {
            let seg = stride.min(len - rpos);
            if seg < SALT_LEN + 1 {
                // 防御性残段（正常 GRO 批不会出现）：整包按垃圾丢弃
                self.note_garbage(src, now_ms);
                return false;
            }
            buf.copy_within(rpos + SALT_LEN..rpos + seg, wpos);
            wpos += seg - SALT_LEN;
            rpos += stride;
        }
        debug_assert_eq!(wpos, len - (len / stride) * SALT_LEN);
        meta.len = wpos;
        meta.stride = stride - SALT_LEN;
        true
    }

    fn note_garbage(&self, src: IpAddr, now_ms: u64) {
        self.limiter.lock().unwrap().note_garbage(src, now_ms);
    }

    /// 该源当前是否被限速拦截（测试/观测用）
    #[cfg(test)]
    fn source_blocked(&self, src: IpAddr) -> bool {
        self.limiter
            .lock()
            .unwrap()
            .blocked(src, self.start.elapsed().as_millis() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_crypto() -> ObfsCrypto {
        // 固定盐源种子保证测试确定性
        ObfsCrypto::new_with_seed(b"unit-test-passphrase", [7u8; 32])
    }

    /// 伪 QUIC 长包头（version=1）载荷
    fn long_header_payload(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0xE3; // form=1, fixed=1, 其余为包号/PN 标志等
        p[1..5].copy_from_slice(&1u32.to_be_bytes());
        for (i, b) in p[5..].iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        p
    }

    fn meta_for(len: usize) -> RecvMeta {
        RecvMeta {
            addr: "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        }
    }

    #[test]
    fn day_key_is_deterministic_and_day_and_password_sensitive() {
        let a0 = derive_day_key(b"pw", 20_000);
        assert_eq!(
            a0,
            derive_day_key(b"pw", 20_000),
            "同参数必须逐字节一致（两端互通前提）"
        );
        assert_ne!(a0, derive_day_key(b"pw", 20_001), "相邻两天必须不同 key");
        assert_ne!(a0, derive_day_key(b"px", 20_000), "不同密码必须不同 key");
    }

    #[test]
    fn day_to_ymd_known_dates() {
        assert_eq!(day_to_ymd(0), (1970, 1, 1));
        assert_eq!(day_to_ymd(19_723), (2024, 1, 1));
        assert_eq!(day_to_ymd(20_729), (2026, 10, 3));
        assert_eq!(day_to_ymd(19_722), (2023, 12, 31));
    }

    #[test]
    fn looks_like_quic_shapes() {
        let long = long_header_payload(64);
        assert!(looks_like_quic(&long));
        // 短包头：form=0, fixed=1
        let mut short = vec![0u8; 32];
        short[0] = 0x43;
        assert!(looks_like_quic(&short));
        // 版本协商（version=0）拒绝
        let mut vn = long.clone();
        vn[1..5].copy_from_slice(&[0, 0, 0, 0]);
        assert!(!looks_like_quic(&vn));
        // 全零/过短拒绝
        assert!(!looks_like_quic(&[0u8; 32]));
        assert!(!looks_like_quic(&[0xE3, 0x00]));
        // 长包头但 fixed 位为 0（0x80 形态非法）拒绝
        let mut bad_long = long.clone();
        bad_long[0] = 0x83;
        assert!(!looks_like_quic(&bad_long));
    }

    #[test]
    fn wrap_unwrap_roundtrip_restores_payload() {
        let c = test_crypto();
        let payload = long_header_payload(1200);
        let mut wire = bytes::BytesMut::new();
        c.wrap_segment_into(&payload, &mut wire);
        assert_eq!(
            wire.len(),
            payload.len() + SALT_LEN,
            "线缆长度 = 报文 + 12B salt"
        );

        let mut meta = meta_for(wire.len());
        let mut buf = wire.to_vec();
        assert!(c.unwrap_datagram(&mut buf, &mut meta));
        assert_eq!(&buf[..meta.len], &payload[..], "解包必须逐字节还原");
        assert_eq!(meta.len, payload.len());
        assert_eq!(meta.stride, payload.len());
    }

    #[test]
    fn day_tolerance_unwraps_yesterday_and_tomorrow_keys() {
        let c = test_crypto();
        let ikm = b"unit-test-passphrase";
        let today = current_day();
        for skew in [-1i64, 1] {
            let day = (today as i64 + skew) as u64;
            let key = derive_day_key(ikm, day);
            let payload = long_header_payload(400);
            // 试解到达正确 key 前，错 key 的随机垃圾可能以 1/4 概率先命中短包头形状
            // （文档化的固有权衡）。因此发 32 个新盐包，断言至少一个被精确还原
            // （全失败概率 ≈ 0.44^32 < 1e-11，QUIC 重传在真实链路上同理兜底）。
            let mut restored = false;
            for _ in 0..32 {
                let mut wire = Vec::with_capacity(payload.len() + SALT_LEN);
                let mut salt = [0u8; SALT_LEN];
                ring::rand::SystemRandom::new().fill(&mut salt).unwrap();
                wire.extend_from_slice(&salt);
                wire.extend_from_slice(&payload);
                xor_segment(&key, &salt, &mut wire[SALT_LEN..]);
                let mut meta = meta_for(wire.len());
                if c.unwrap_datagram(&mut wire, &mut meta) && &wire[..meta.len] == &payload[..] {
                    restored = true;
                    break;
                }
            }
            assert!(restored, "+{skew} 天时钟差必须在重试内精确还原");
        }
    }

    #[test]
    fn wrong_password_never_yields_payload() {
        let c = test_crypto();
        // 错误密码对端（混淆层不认证——评审定版语义）：
        // 三把 key 试解出的是随机垃圾，形状启发式可能命中（短包头 1/4/把，见模块文档）。
        // 不变式：绝不还原出原载荷——未命中 → 本层丢弃；命中 → 交给内层 QUIC 由
        // AEAD/包号/CID 校验丢弃。两端断言都合法。
        let other = ObfsCrypto::new_with_seed(b"other-password", [7u8; 32]);
        let payload = long_header_payload(400);
        for _ in 0..16 {
            let mut wire = bytes::BytesMut::new();
            other.wrap_segment_into(&payload, &mut wire);
            let mut meta = meta_for(wire.len());
            let mut buf = wire.to_vec();
            if c.unwrap_datagram(&mut buf, &mut meta) {
                // 垃圾被形状启发式放过：内容必须 != 原载荷（交给内层 QUIC 丢弃）
                assert_ne!(&buf[..meta.len], &payload[..], "错密码绝不能还原出原载荷");
                assert_eq!(meta.len, payload.len());
            }
        }

        // 过短（< 12B salt + 1B）必丢
        let mut tiny = vec![1u8; 5];
        let mut meta = meta_for(5);
        assert!(!c.unwrap_datagram(&mut tiny, &mut meta));

        // 随机垃圾（非 QUIC 形状）必丢
        let mut junk = vec![0u8; 300];
        junk[0] = 0x12; // form=0, fixed=0 → 永不命中
        let mut meta = meta_for(300);
        assert!(!c.unwrap_datagram(&mut junk, &mut meta));
    }

    #[test]
    fn per_source_garbage_budget_gates_and_normal_traffic_unaffected() {
        let c = test_crypto();
        let junk = vec![0x12u8; 300]; // 永不命中的形状
        let mut meta = meta_for(junk.len());
        for i in 0..DEFAULT_BUDGET {
            let mut buf = junk.clone();
            assert!(
                !c.unwrap_datagram(&mut buf, &mut meta),
                "第 {i} 个垃圾包应丢弃"
            );
        }
        // 预算耗尽：同一源后续包不解包直接丢（限速器拦截）
        assert!(c.source_blocked("127.0.0.1".parse().unwrap()));
        // 正常流量路径不产生记账（上面对同一源的垃圾已耗尽预算，换一个源验证）
        let other = ObfsCrypto::new(b"unit-test-passphrase");
        let payload = long_header_payload(400);
        let mut wire = bytes::BytesMut::new();
        other.wrap_segment_into(&payload, &mut wire);
        let mut meta = meta_for(wire.len());
        let mut buf = wire.to_vec();
        assert!(other.unwrap_datagram(&mut buf, &mut meta));
    }

    /// C1 验收：线缆字节过卡方随机性检验。
    /// 256 bins，N ≥ 64KiB，df = 255，p<0.01 → χ² < 311 通过（任务书 C1 规格）。
    #[test]
    fn wrapped_stream_passes_chi_square_uniformity() {
        let c = ObfsCrypto::new_with_seed(b"chi2-passphrase", [42u8; 32]);
        let n_packets = 64usize;
        let payload_len = 1024usize;
        let mut out = bytes::BytesMut::with_capacity(n_packets * (payload_len + SALT_LEN));
        for i in 0..n_packets {
            let payload: Vec<u8> = (0..payload_len)
                .map(|j| ((i * 131 + j) % 251) as u8)
                .collect();
            c.wrap_segment_into(&payload, &mut out);
        }
        assert!(
            out.len() >= 64 * 1024,
            "样本量 N ≥ 64KiB，实际 {}",
            out.len()
        );

        let mut bins = [0u64; 256];
        for &b in out.iter() {
            bins[b as usize] += 1;
        }
        let e = out.len() as f64 / 256.0;
        let chi2: f64 = bins
            .iter()
            .map(|&o| {
                let d = o as f64 - e;
                d * d / e
            })
            .sum();
        println!(
            "chi2 = {chi2:.1}（n={}B，{} 包，df=255，阈值 311）",
            out.len(),
            n_packets
        );
        assert!(chi2 < 311.0, "χ²={chi2} ≥ 311：线缆字节未通过均匀性检验");
    }

    /// 简单吞吐基准（可选性能自测）：100MB 内存态 wrap+unwrap。
    /// 运行：cargo test -p hydra-obfs obfs_throughput -- --ignored --nocapture
    #[test]
    #[ignore]
    fn obfs_throughput_bench_100mb() {
        let c = test_crypto();
        let payload = long_header_payload(1200);
        let rounds = 100 * 1024 * 1024 / payload.len();
        let mut out = bytes::BytesMut::with_capacity(payload.len() + SALT_LEN + 64);
        let t0 = Instant::now();
        for _ in 0..rounds {
            out.clear();
            c.wrap_segment_into(&payload, &mut out);
        }
        let wrap_mb = (rounds * payload.len()) as f64 / 1_048_576.0;
        let wrap_t = t0.elapsed().as_secs_f64();

        let mut buf = out.to_vec();
        let mut meta = meta_for(buf.len());
        let t1 = Instant::now();
        for _ in 0..rounds {
            buf.copy_from_slice(&out);
            assert!(c.unwrap_datagram(&mut buf, &mut meta));
            // 复位供下一轮（unwrap 会把 len/stride 缩为载荷长度）
            meta.len = payload.len() + SALT_LEN;
            meta.stride = payload.len() + SALT_LEN;
        }
        let unwrap_t = t1.elapsed().as_secs_f64();
        println!(
            "wrap:  {wrap_mb:.0} MB in {wrap_t:.3}s = {:.0} MB/s",
            wrap_mb / wrap_t
        );
        println!(
            "unwrap: {wrap_mb:.0} MB in {unwrap_t:.3}s = {:.0} MB/s",
            wrap_mb / unwrap_t
        );
    }
}
