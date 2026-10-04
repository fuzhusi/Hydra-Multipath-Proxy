//! # hydra-obfs —— V3.1 双模式传输的混淆基础设施（WS-C C1/C3）
//!
//! 线缆格式（[V3 方案 §3 附注](../../docs/design/自研协议HydraV3方案.md) 定版）：
//!
//! ```text
//! 每个 UDP 报文：[12B salt][ChaCha20 keystream XOR 报文]
//!                salt 即 ChaCha20 96-bit nonce（取满 12B，否则生日界 2^32 包即 keystream 复用）
//! ```
//!
//! - **变换**：发送方向对每个 QUIC 报文生成随机 salt，用日派生密钥的 ChaCha20 keystream
//!   对报文原地 XOR 后前置 salt；接收方向剥 salt、XOR 还原。每包恰一次流密码运算，
//!   长度不变（除 salt 前缀），无逐包堆分配（接收方向原地压实；发送方向每次 flush
//!   批量一个临时缓冲——quinn-udp 0.4 的 `Transmit.contents` 为 `bytes::Bytes`，必须
//!   产出拥有所有权的变换副本，见 `socket` 模块说明）。
//! - **密钥**：`HKDF-SHA256(独立密码 HYDRA_OBFS_KEY, info="hydra v3 obfs YYYY-MM-DD")`
//!   按 UTC 日派生；解包方按 [今/明/昨] 三把尝试，容忍 ±1 天时钟差（见 `crypto`）。
//! - **混淆 ≠ 加密**：混淆层不认证。无密钥者伪造的包解出垃圾，经 [`crypto::looks_like_quic`]
//!   启发式判为非 QUIC 后**静默丢弃**；漏判的垃圾在内层 QUIC（AEAD/包号/CID 校验）被丢。
//!   机密性由内层 QUIC/TLS 1.3 承担。
//! - **每源限速**（吸收 P1-2）：仅对"解包失败"的垃圾包记账（[`limiter::SourceLimiter`]），
//!   有界 HashMap 按源 IP 记录，容量上限 + 窗口过期淘汰；正常流量零记账零开销。
//!   1 万垃圾 UDP 包零回应、内存/CPU 有界。
//! - **GSO/GRO 语义**（评审查实的坑，Windows 上测不出）：`poll_send` 必须按
//!   `Transmit::segment_size` 切分逐包变换再重组（Linux GSO 会把多个 MTU 段合并进一个
//!   Transmit，不切分逐包变换＝发包损坏）；`poll_recv` 按 `RecvMeta::stride` 逐段剥 salt
//!   并压实，保持"单包单逻辑报文"语义（见 `socket` 模块单测）。
//!
//! ## 双模式（C2）
//!
//! `mode=masquerade`（默认，缺省零改动）｜`mode=obfs`（逃生舱，显式开启）。
//! 两模式互斥不叠加，连接建立前由 env/分享链接确定。**两端 mode 不匹配时，对端报文
//! 无法通过解包校验，行为 = 静默丢包**（连接超时，无任何错误提示——这是有意设计，
//! 与认证失败静默一致，不给探测者可区分信号）。
//!
//! ## C3 masquerade 模式与真 h3 站点探测差异审计表
//!
//! masquerade 模式的伪装项现状对照（探测视角逐项标注）：
//!
//! | 项 | 状态 | 说明 |
//! |---|---|---|
//! | ALPN = `h3` | 已伪装 ✓ | 与真 h3 站一致；非标 ALPN 是单规则 DPI 指纹（TUIC 教训） |
//! | UDP 443 / SNI 可配置 | 已伪装 ✓ | 默认 SNI `hydra.node`，证书 SAN 对齐 |
//! | 证书校验 | 已伪装 ✓ | 客户端 SPKI pinning（webpki 校验，拒绝无验证连接） |
//! | 认证失败行为 | 已伪装 ✓ | 未认证流零字节静默关闭，不回错误码 |
//! | QUIC 传输参数 | 已伪装 ✓ | keepalive 7–12s 随机抖动，无固定周期 beacon |
//! | 证书链 | **固有差异** | 自签证书可被被动区分于"真站"（真证书/ACME 属老板级开放问题，V3 方案 §7-2） |
//! | 对垃圾 UDP 的回应 | **固有差异** | 本节点零回应；真 h3 站对畸形包同样大多静默忽略，主动探测可区分度低，**接受** |
//! | 关流行为 | **固有差异·方案①留档** | 现状 = 双向流零字节优雅关闭（客户端读到干净 EOF）。真 h3 服务器会在控制流上回
//!   完整 h3 SETTINGS 帧后再关。往双向流回 `[0x04,0x00]` 的帧伪装已被评审**否决**：SETTINGS 只能出现在
//!   本端单向控制流首帧，真 h3 客户端视之为 `H3_FRAME_UNEXPECTED`，反而降低保真 |
//! | h3 控制流 | **方案②远期可选** | 节点自开单向控制流并写完整合法 h3 SETTINGS 序列，可消除上述关流差异；
//!   本版不做，列为远期可选项 |
//!
//! 诚实定位（03 抗检测草案 §2.2）：obfs 的熵检验可区分"均匀随机流"与"真实网站流量分布"。
//! 逃生舱模式的定位是**特征匹配下不可识别**（不被精准封禁），不是统计下不可疑
//! （可能被整段限速）——"活着比好看重要"。

pub mod cc;
pub mod crypto;
pub mod limiter;
pub mod mode;
pub mod socket;
pub mod tuning;

pub use cc::{
    apply_bbr_congestion_control, apply_brutal_congestion_control,
    apply_congestion_control_from_env, resolve_congestion_control, Brutal, BrutalConfig,
    CongestionControlChoice, HYDRA_BRUTAL_MBPS_ENV, HYDRA_CC_ENV,
};
pub use crypto::{derive_day_key, looks_like_quic, ObfsCrypto, SALT_LEN};
pub use limiter::SourceLimiter;
pub use mode::{TransportMode, HYDRA_MODE_ENV, HYDRA_OBFS_KEY_ENV};
pub use socket::{new_obfs_endpoint, ObfsUdpSocket};
