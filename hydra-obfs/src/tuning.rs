//! B1 QUIC 流控窗口调优（从 `hydra-client/src/transport.rs` 迁入）。
//!
//! **两侧复用**：客户端（`hydra-client::transport::create_shared_endpoint*`）与节点侧
//! （`hydra-node::server::configure_server`）都调用 [`apply_transport_tuning`]，
//! 保证两端窗口语义一致。迁入 hydra-obfs 的原因：server 侧不能依赖 hydra-client，
//! 而 hydra-obfs 是 C2 双模式两侧共同的底层 crate。本模块只设置接收窗口，
//! 不触碰 ALPN / idle timeout / keepalive 等其它传输参数，可在任意已配置的
//! TransportConfig 上叠加调用。
//!
//! 单元测试保留在 `hydra-client/src/transport.rs`（经 re-export 路径测试，覆盖不变）。

use tracing::{info, warn};

pub const MIB: u64 = 1024 * 1024;

/// 单流接收窗口默认值（MB）。
/// 这是吞吐杠杆：quinn 默认 1.25MB 在 150ms RTT 下仅≈66Mbps，不够 4K 视频，提至 8MB。
pub const DEFAULT_STREAM_WINDOW_MB: u64 = 8;

/// 连接级接收窗口默认值（MB）。
/// quinn 默认 `VarInt::MAX`（无上限）；调 32MB 是**内存封顶**，不是吞吐提升。
pub const DEFAULT_CONN_WINDOW_MB: u64 = 32;

/// 单流窗口下限（MB）
pub const MIN_STREAM_WINDOW_MB: u64 = 1;
/// 单流窗口上限（MB）
pub const MAX_STREAM_WINDOW_MB: u64 = 64;

/// B1 解析结果（字节数），独立结构便于单测断言（quinn 0.10 的 TransportConfig 无 getter）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTuning {
    /// 单流接收窗口（字节）
    pub stream_receive_window: u64,
    /// 连接级接收窗口（字节）
    pub receive_window: u64,
}

/// 解析单个 MB 单位窗口 env 值（纯函数）：
/// 未设置/空白 → 默认值（不告警）；非整数 → 告警 + 默认值；越界 → 告警 + clamp 到 [min, max]。
fn parse_window_mb(
    name: &str,
    raw: Option<&str>,
    default_mb: u64,
    min_mb: u64,
    max_mb: u64,
) -> u64 {
    let raw = match raw.map(str::trim) {
        Some(s) if !s.is_empty() => s,
        _ => return default_mb,
    };
    match raw.parse::<u64>() {
        Ok(v) if v < min_mb => {
            warn!("{name}={raw} 低于下限 {min_mb}MB，取 {min_mb}MB");
            min_mb
        }
        Ok(v) if v > max_mb => {
            warn!("{name}={raw} 高于上限 {max_mb}MB，取 {max_mb}MB");
            max_mb
        }
        Ok(v) => v,
        Err(_) => {
            warn!("{name}={raw} 不是合法的 MB 整数，回退默认 {default_mb}MB");
            default_mb
        }
    }
}

/// 依据环境变量解析 B1 流控窗口（纯函数；env 以闭包注入，避免全局 env 污染单测）。
///
/// # env 语义（client 与节点侧共用同一份，MB 单位）
/// - `HYDRA_STREAM_WINDOW`：单流接收窗口，clamp 1..=64，默认 8
/// - `HYDRA_CONN_WINDOW`：连接级接收窗口，下限 = 生效的单流窗口（保证 receive_window ≥ stream_receive_window），默认 32
///
/// 内存上界：每条连接最坏接收内存 = min(单流窗口 × 活跃流数, 连接级窗口)。
pub fn resolve_transport_tuning(getenv: impl Fn(&str) -> Option<String>) -> TransportTuning {
    let stream_mb = parse_window_mb(
        "HYDRA_STREAM_WINDOW",
        getenv("HYDRA_STREAM_WINDOW").as_deref(),
        DEFAULT_STREAM_WINDOW_MB,
        MIN_STREAM_WINDOW_MB,
        MAX_STREAM_WINDOW_MB,
    );
    // 连接级下限取“生效后的”单流窗口，天然满足 receive_window ≥ stream_receive_window
    let conn_mb = parse_window_mb(
        "HYDRA_CONN_WINDOW",
        getenv("HYDRA_CONN_WINDOW").as_deref(),
        DEFAULT_CONN_WINDOW_MB,
        stream_mb,
        u64::MAX,
    );
    TransportTuning {
        stream_receive_window: stream_mb.saturating_mul(MIB),
        receive_window: conn_mb.saturating_mul(MIB),
    }
}

/// 字节数 → VarInt；越界（≥2^62，仅极端 env 值可达）回退默认并告警。
/// fallback 来自常量，必然可表示。
pub fn window_varint(bytes: u64, fallback_mb: u64, source: &str) -> quinn::VarInt {
    match quinn::VarInt::from_u64(bytes) {
        Ok(v) => v,
        Err(_) => {
            warn!(
                "{source} 窗口值 {bytes} 字节超出 VarInt 表示范围（≥2^62），回退默认 {fallback_mb}MB"
            );
            quinn::VarInt::from_u32((fallback_mb * MIB) as u32)
        }
    }
}

/// 将 B1 流控窗口调优应用到 [`quinn::TransportConfig`]。
///
/// # env 语义（详见 [`resolve_transport_tuning`]）
/// - `HYDRA_STREAM_WINDOW`：单流接收窗口（MB），clamp 1..=64，默认 8
/// - `HYDRA_CONN_WINDOW`：连接级接收窗口（MB），≥ 单流窗口，默认 32
///
/// # quinn 事实（总则 6）
/// - `stream_receive_window` 是唯一的吞吐杠杆（quinn 默认 1.25MB ≈ 150ms RTT 下 66Mbps）
/// - 连接级 `receive_window` 默认 `VarInt::MAX` 无上限，设 32MB 是内存封顶
/// - 每条连接最坏接收内存 = min(单流窗口 × 活跃流数, 连接级窗口)
pub fn apply_transport_tuning(transport: &mut quinn::TransportConfig) {
    let tuning = resolve_transport_tuning(|name| std::env::var(name).ok());
    let stream_win = window_varint(
        tuning.stream_receive_window,
        DEFAULT_STREAM_WINDOW_MB,
        "HYDRA_STREAM_WINDOW",
    );
    let conn_win = window_varint(
        tuning.receive_window,
        DEFAULT_CONN_WINDOW_MB,
        "HYDRA_CONN_WINDOW",
    );
    transport.stream_receive_window(stream_win);
    transport.receive_window(conn_win);
    info!(
        "QUIC flow control tuned: stream_receive_window={}MiB receive_window={}MiB",
        tuning.stream_receive_window / MIB,
        tuning.receive_window / MIB
    );
}
