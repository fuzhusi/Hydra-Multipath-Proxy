//! obfs 模式的 [`quinn::AsyncUdpSocket`] 实现（C1 关键路径）与双模式 Endpoint 构造入口。
//!
//! 实现完全镜像 quinn 0.10 自带的 tokio socket 包装（`runtime/tokio.rs`），在其上叠加：
//!
//! - **发送**：每个 `Transmit` 的 payload 先按 `segment_size` 切分为逻辑报文，逐段
//!   `wrap`（XOR + 12B salt 前缀）后重组为新的 Transmit（`segment_size` 相应 +12B）。
//!   **这是评审查实的关键坑**：Linux GSO 下 quinn-proto 会把多个 MTU 段合并进一个
//!   Transmit（`segment_size = Some(mtu)`、contents 为 k×mtu 字节）——不切分就逐包变换
//!   等于对"多个报文拼接体"整体做一次 keystream 变换，每个报文的 salt 与 keystream
//!   错位 = 接收端无法还原 = 发包损坏。Windows 不启用 GSO，此 bug 在 Windows 上
//!   测不出来，必须靠代码评审 + 单测保障（见 `wrap_transmit_contents` 单测）。
//! - **接收**：先经 quinn-udp 收包（其平台实现负责 GRO/pktinfo/ecn），再对每个返回的
//!   buf 做剥 salt + 按日三把 key 试解；解包失败的 datagram 从返回数组中压实剔除
//!   （quinn 端点驱动按 `meta.len`/`meta.stride` 切分处理，绝不接收 len=0/stride=0 条目）。
//!   GRO 批（`stride < len`）逐段处理并保持 stride 语义（每段 -12B）。
//!
//! ## 分配策略（无逐包堆分配）
//!
//! - 接收：全部原地变换 + `copy_within` 压实，零堆分配；
//! - 发送：quinn-udp 0.4 的 `Transmit.contents` 是拥有所有权的 `bytes::Bytes`（quinn-proto
//!   以共享 Bytes 传入、不可原地改写），变换副本必须自带所有权。策略 = 每次
//!   `poll_send` 批量共用一个 `BytesMut`（Mutex 持有、容量跨调用复用，`split().freeze()`
//!   切片共享同一分配）——**每次 flush 1 次分配而非每包 1 次**；flush 频率与 quinn 自身
//!   的事件循环相当，实测开销可忽略（见 crypto 模块 100MB 基准）。

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::BytesMut;
use quinn::udp::{Transmit, UdpSocketState};
use tracing::debug;

use crate::crypto::{ObfsCrypto, SALT_LEN};

/// obfs 模式 UDP socket：quinn-udp 状态机 + 混淆变换层。
#[derive(Debug)]
pub struct ObfsUdpSocket {
    io: tokio::net::UdpSocket,
    inner: UdpSocketState,
    crypto: Arc<ObfsCrypto>,
    /// 发送批量变换缓冲（容量跨 poll_send 调用复用；每次 flush 内 split().freeze() 产出）
    scratch: std::sync::Mutex<BytesMut>,
}

impl ObfsUdpSocket {
    /// 包装一个已绑定的 std UDP socket（configure 与 quinn 自带路径一致）
    pub fn from_std(sock: std::net::UdpSocket, crypto: Arc<ObfsCrypto>) -> io::Result<Self> {
        UdpSocketState::configure((&sock).into())?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(sock)?,
            inner: UdpSocketState::new(),
            crypto,
            scratch: std::sync::Mutex::new(BytesMut::new()),
        })
    }

    /// 绑定到 `addr` 并包装
    pub fn bind(addr: SocketAddr, crypto: Arc<ObfsCrypto>) -> io::Result<Self> {
        Self::from_std(std::net::UdpSocket::bind(addr)?, crypto)
    }

    fn poll_send_inner(
        &self,
        state: &quinn::udp::UdpState,
        transmits: &[Transmit],
    ) -> io::Result<usize> {
        // 变换全部 Transmit → 产出列表（含每输入对应的输出数，用于保守映射返回计数）
        let mut wrapped = Vec::with_capacity(transmits.len());
        let mut outputs_per_input = Vec::with_capacity(transmits.len());
        {
            let mut scratch = self.scratch.lock().unwrap();
            for t in transmits {
                let before = wrapped.len();
                let (main_len, new_seg) =
                    wrap_transmit_contents(&self.crypto, &t.contents, t.segment_size, &mut scratch);
                let data = scratch.split().freeze();
                if main_len > 0 {
                    wrapped.push(Transmit {
                        destination: t.destination,
                        ecn: t.ecn,
                        contents: data.slice(..main_len),
                        segment_size: Some(new_seg),
                        src_ip: t.src_ip,
                    });
                }
                if main_len < data.len() {
                    // 防御性尾段（quinn-proto 的 GSO 批恒整除，正常不触发）：单报文发送
                    wrapped.push(Transmit {
                        destination: t.destination,
                        ecn: t.ecn,
                        contents: data.slice(main_len..),
                        segment_size: None,
                        src_ip: t.src_ip,
                    });
                }
                outputs_per_input.push(wrapped.len() - before);
            }
        }
        let sent = self.inner.send((&self.io).into(), state, &wrapped)?;
        // 保守映射回"已发送的输入 Transmit 数"（尾段未发出则该输入不计入——
        // quinn 会重发，最多产生重复报文，由内层 QUIC 按包号去重，无害）
        let mut done = 0usize;
        let mut acc = 0usize;
        for n in &outputs_per_input {
            if acc >= sent {
                break;
            }
            acc += n;
            done += 1;
        }
        Ok(done)
    }

    fn poll_recv_inner(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> io::Result<usize> {
        let count = self.inner.recv((&self.io).into(), bufs, meta)?;
        // 逐 datagram 变换 + 丢弃垃圾（压实返回数组；quinn 绝不接受 len=0/stride=0 条目）
        let mut w = 0;
        for r in 0..count {
            let len = meta[r].len;
            if self
                .crypto
                .unwrap_datagram(&mut bufs[r][..len], &mut meta[r])
            {
                if w != r {
                    bufs.swap(w, r);
                    meta.swap(w, r);
                }
                w += 1;
            }
        }
        Ok(w)
    }
}

impl quinn::AsyncUdpSocket for ObfsUdpSocket {
    fn poll_send(
        &self,
        state: &quinn::udp::UdpState,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_send_ready(cx))?;
            if let Ok(res) = self.io.try_io(tokio::io::Interest::WRITABLE, || {
                self.poll_send_inner(state, transmits)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(tokio::io::Interest::READABLE, || {
                self.poll_recv_inner(bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        quinn::udp::may_fragment()
    }
}

/// 变换一个 Transmit 的 contents 并追加到 `out`（纯逻辑，独立成函数供单测覆盖切分）。
///
/// 返回 `(main_len, new_seg)`：
/// - `segment_size = Some(seg)`（GSO 批，k = contents.len()/seg 个整段）：主体 =
///   k 段逐段变换拼接（`main_len = k*(seg+12)`），`new_seg = seg + 12`；残尾
///   （contents.len() 非 seg 整除时的防御性分支，正常 quinn-proto GSO 批恒整除）
///   追加在主体之后，调用方以 `segment_size: None` 单独发送；
/// - `segment_size = None`（单报文）：整包变换一次，返回 `(0, 0)`，调用方以
///   `segment_size: None` 发送（保持 None → None 语义，不进 GSO 路径）。
///
/// 长度不变性：每个逻辑报文恒 +12B salt 前缀，混淆层不改变逻辑报文长度。
fn wrap_transmit_contents(
    crypto: &ObfsCrypto,
    contents: &[u8],
    segment_size: Option<usize>,
    out: &mut BytesMut,
) -> (usize, usize) {
    let seg = match segment_size {
        Some(s) => s.max(1),
        None => {
            crypto.wrap_segment_into(contents, out);
            return (0, 0);
        }
    };
    let full = contents.len() / seg * seg;
    let mut main_len = 0usize;
    for i in 0..(full / seg) {
        crypto.wrap_segment_into(&contents[i * seg..(i + 1) * seg], out);
        main_len += seg + SALT_LEN;
    }
    if contents.len() > full {
        // 残尾：单报文语义追加（调用方以 None 发送）
        crypto.wrap_segment_into(&contents[full..], out);
    }
    (main_len, seg + SALT_LEN)
}

/// C2 双模式统一入口：用 obfs 模式构造 quinn Endpoint（client 传 `None`，node 传 `Some`）。
///
/// masquerade 模式**不走本函数**——两侧分别继续使用 `Endpoint::client` / `Endpoint::server`
/// 原路径，保证默认行为零改动。
pub fn new_obfs_endpoint(
    addr: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    crypto: Arc<ObfsCrypto>,
) -> io::Result<quinn::Endpoint> {
    let socket = ObfsUdpSocket::bind(addr, crypto)?;
    // RFC 9287 QUIC-bit grease 会随机化短包头 fixed 位（约 1/8 包），与混淆层的
    // looks_like_quic 形状判定（选 key 用）不兼容：fixed=0 的合法包会被误判为
    // "错 key 解包失败"，回落到错 key 的随机垃圾（1/4 概率命中短包头形状），
    // 进而被上交给 quinn 触发 stateless reset 风暴。obfs 模式线缆本来就是
    // 均匀随机字节，grease 失去意义——两端统一关闭。
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.grease_quic_bit(false);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config,
        server_config,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    debug!(
        "obfs endpoint bound on {} (wire = [12B salt][ChaCha20 XOR])",
        addr
    );
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> ObfsCrypto {
        // 与 crypto 模块测试同款：固定盐源种子（构造路径走 #[cfg(test)] new_with_seed 不可达，
        // 这里用随机种子即可——切分逻辑与盐值无关）
        ObfsCrypto::new(b"socket-unit-test")
    }

    /// 长包头形状载荷（保证可被 unwrap 判定命中）
    fn payload(len: usize, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; len];
        p[0] = 0xE3;
        p[1..5].copy_from_slice(&1u32.to_be_bytes());
        p
    }

    fn unwrap_all(crypto: &ObfsCrypto, wire: &[u8], stride: usize) -> Vec<u8> {
        use std::net::SocketAddr;
        let mut buf = wire.to_vec();
        let mut meta = quinn::udp::RecvMeta {
            addr: "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
            len: wire.len(),
            stride,
            ecn: None,
            dst_ip: None,
        };
        assert!(crypto.unwrap_datagram(&mut buf, &mut meta), "必须可解");
        assert_eq!(meta.len, meta.stride * (wire.len() / stride));
        buf[..meta.len].to_vec()
    }

    #[test]
    fn single_datagram_wrapunwrap() {
        let c = crypto();
        let p = payload(1000, 0xAB);
        let mut out = BytesMut::new();
        let (main_len, new_seg) = wrap_transmit_contents(&c, &p, None, &mut out);
        assert_eq!(main_len, 0, "None 无 GSO 主体");
        assert_eq!(new_seg, 0, "None → None 语义，不进 GSO 路径");
        assert_eq!(out.len(), p.len() + SALT_LEN);
        assert_eq!(unwrap_all(&c, &out, out.len()), p, "单报文往返必须还原");
    }

    /// 关键单测：GSO 批量 Transmit 必须逐段切分变换（Windows 测不出，靠此单测保障 Linux 语义）
    #[test]
    fn gso_batch_split_per_segment() {
        let c = crypto();
        let seg = 1200usize;
        let k = 4usize;
        let mut contents = Vec::with_capacity(seg * k);
        for i in 0..k {
            contents.extend(payload(seg, 0x10 * i as u8 + 1));
        }
        let mut out = BytesMut::new();
        let (main_len, new_seg) = wrap_transmit_contents(&c, &contents, Some(seg), &mut out);

        // 主体 = k 段 × (seg+12)，段大小 = seg+12
        assert_eq!(main_len, k * (seg + SALT_LEN));
        assert_eq!(new_seg, seg + SALT_LEN);
        assert_eq!(out.len(), main_len, "整除批无残尾");

        // 以 GRO 接收语义还原：stride = seg+12，逐段剥 salt 后拼接 == 原 contents
        let restored = unwrap_all(&c, &out, seg + SALT_LEN);
        assert_eq!(restored, contents, "GSO 批逐段往返必须逐字节还原");
    }

    #[test]
    fn non_multiple_tail_is_split_as_single_datagram() {
        let c = crypto();
        let seg = 100usize;
        let mut contents = payload(seg * 2, 0x33);
        contents.extend(payload(37, 0x44)); // 残尾
        let mut out = BytesMut::new();
        let (main_len, new_seg) = wrap_transmit_contents(&c, &contents, Some(seg), &mut out);
        assert_eq!(main_len, 2 * (seg + SALT_LEN));
        assert_eq!(new_seg, seg + SALT_LEN);
        assert_eq!(out.len(), main_len + 37 + SALT_LEN, "主体 + 残尾(37B)");

        // 主体：GRO 语义还原
        let main = &out[..main_len];
        assert_eq!(unwrap_all(&c, main, seg + SALT_LEN), &contents[..2 * seg]);
        // 残尾：单报文语义还原
        let tail = &out[main_len..];
        assert_eq!(unwrap_all(&c, tail, tail.len()), &contents[2 * seg..]);
    }

    #[test]
    fn wire_bytes_keep_uniform_length_growth() {
        // 混淆层不改变逻辑报文长度：每包恒 +12B（长度不变性是与 QUIC padding 联合设计的前提）
        let c = crypto();
        for len in [13usize, 100, 1200, 1400] {
            let p = payload(len, 0x55);
            let mut out = BytesMut::new();
            let (main_len, new_seg) = wrap_transmit_contents(&c, &p, None, &mut out);
            assert_eq!(main_len, 0);
            assert_eq!(out.len(), len + SALT_LEN, "每包恒 +12B salt");
            assert_eq!(new_seg, 0);
        }
    }
}
