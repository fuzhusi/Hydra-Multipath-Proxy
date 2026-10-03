use hydra_protocol::{HydraError, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";

pub struct Transport {
    endpoint: Endpoint,
    sni: String,
}

impl Transport {
    pub async fn new_client(node_certs: Vec<Vec<u8>>, sni: &str) -> Result<Self> {
        let (endpoint, _) = Self::create_shared_endpoint(node_certs, sni)?;
        Ok(Self {
            endpoint,
            sni: sni.to_string(),
        })
    }

    /// 创建共享的客户端 Endpoint 与 ClientConfig。
    ///
    /// node_certs 中的节点自签证书会被加入本地信任根，执行标准 webpki 校验
    /// （证书 pinning），替代曾经的 SkipVerification——那是零门槛的中间人。
    pub fn create_shared_endpoint(
        node_certs: Vec<Vec<u8>>,
        sni: &str,
    ) -> Result<(Endpoint, ClientConfig)> {
        if node_certs.is_empty() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书，拒绝建立不经验证的连接".to_string(),
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for der in &node_certs {
            roots
                .add(&rustls::Certificate(der.clone()))
                .map_err(|e| HydraError::ProtocolError(format!("无效的节点证书: {:?}", e)))?;
        }

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // ALPN 与节点侧一致，使用标准 h3（QUIC Initial 明文可见，非标 ALPN 是单规则 DPI 指纹）
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        // 禁用会话恢复：防止 session ticket 被用于跨连接关联追踪
        crypto.resumption = rustls::client::Resumption::disabled();

        let mut client_config = ClientConfig::new(Arc::new(crypto));

        // 设置 QUIC 传输参数：keepalive 加随机抖动，避免整周期 beacon 特征
        let mut transport_config = quinn::TransportConfig::default();
        // B1: 流控窗口调优（吞吐杠杆 + 连接级内存封顶）。
        // 独立函数，节点侧（WS-C C2 改 server.rs 时）复用同一份逻辑。
        apply_transport_tuning(&mut transport_config);
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(Duration::from_secs(jittered_keepalive_secs())));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config.clone());

        info!(
            "Created shared QUIC client endpoint on {} (sni={}, trusted_certs={})",
            endpoint.local_addr()?,
            sni,
            node_certs.len()
        );
        Ok((endpoint, client_config))
    }

    /// 连接到节点（带 5 秒超时，避免死节点挂起调用方）
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        info!("Attempting QUIC connection to {}...", addr);
        let connecting = self.endpoint.connect(addr, &self.sni)?;
        match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(connection)) => {
                info!("QUIC connection established to {}", addr);
                Ok(connection)
            }
            Ok(Err(e)) => {
                error!("QUIC connection failed to {}: {}", addr, e);
                Err(e.into())
            }
            Err(_) => {
                error!("QUIC connection to {} timed out", addr);
                Err(HydraError::ConnectionError(format!(
                    "Connection to {} timed out",
                    addr
                )))
            }
        }
    }

    /// Test connectivity to a node with timeout
    pub async fn test_connection(&self, addr: SocketAddr, timeout_ms: u64) -> bool {
        let connect_future = self.connect(addr);
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), connect_future)
            .await
        {
            Ok(Ok(_connection)) => {
                info!("Test connection to {} succeeded", addr);
                true
            }
            Ok(Err(e)) => {
                error!("Test connection to {} failed: {}", addr, e);
                false
            }
            Err(_) => {
                error!(
                    "Test connection to {} timed out after {}ms",
                    addr, timeout_ms
                );
                false
            }
        }
    }
}

/// 7..=12 秒随机 keepalive 间隔（防固定周期心跳的被动检测）
fn jittered_keepalive_secs() -> u64 {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 4];
    let _ = rng.fill(&mut buf);
    7 + (u32::from_be_bytes(buf) % 6) as u64
}

// ===================== B1 QUIC 流控窗口调优 =====================

const MIB: u64 = 1024 * 1024;

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
fn window_varint(bytes: u64, fallback_mb: u64, source: &str) -> quinn::VarInt {
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
/// **两侧复用**：客户端（`create_shared_endpoint`）与节点侧（WS-C C2 改 server.rs 的
/// TransportConfig 时）都调用本函数，保证两端窗口语义一致。本函数只设置接收窗口，
/// 不触碰 ALPN / idle timeout / keepalive 等其它传输参数，可在任意已配置的
/// TransportConfig 上叠加调用。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造注入式 env 查询闭包（不触碰进程全局 env，避免并行测试污染）
    fn env_of<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            map.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn b1_default_windows_without_env() {
        let t = resolve_transport_tuning(|_| None);
        assert_eq!(t.stream_receive_window, 8 * MIB);
        assert_eq!(t.receive_window, 32 * MIB);
    }

    #[test]
    fn b1_env_override_applied() {
        let t = resolve_transport_tuning(env_of(&[("HYDRA_STREAM_WINDOW", "16")]));
        assert_eq!(t.stream_receive_window, 16 * MIB);
        assert_eq!(t.receive_window, 32 * MIB);

        let t = resolve_transport_tuning(env_of(&[("HYDRA_CONN_WINDOW", "64")]));
        assert_eq!(t.stream_receive_window, 8 * MIB);
        assert_eq!(t.receive_window, 64 * MIB);
    }

    #[test]
    fn b1_stream_window_clamped_1_to_64() {
        let low = resolve_transport_tuning(env_of(&[("HYDRA_STREAM_WINDOW", "0")]));
        assert_eq!(low.stream_receive_window, MIB);

        let high = resolve_transport_tuning(env_of(&[("HYDRA_STREAM_WINDOW", "4096")]));
        assert_eq!(high.stream_receive_window, 64 * MIB);
    }

    #[test]
    fn b1_conn_window_floored_at_effective_stream_window() {
        let t = resolve_transport_tuning(env_of(&[
            ("HYDRA_STREAM_WINDOW", "48"),
            ("HYDRA_CONN_WINDOW", "8"),
        ]));
        assert_eq!(t.stream_receive_window, 48 * MIB);
        assert_eq!(t.receive_window, 48 * MIB);
    }

    #[test]
    fn b1_invalid_env_falls_back_to_default() {
        // 非整数（含负数/小数）回退默认；空白视为未设置
        for bad in ["abc", "-3", "8.5", "0x10"] {
            let t = resolve_transport_tuning(env_of(&[
                ("HYDRA_STREAM_WINDOW", bad),
                ("HYDRA_CONN_WINDOW", bad),
            ]));
            assert_eq!(t.stream_receive_window, 8 * MIB, "stream env={bad}");
            assert_eq!(t.receive_window, 32 * MIB, "conn env={bad}");
        }
        let blank = resolve_transport_tuning(env_of(&[("HYDRA_STREAM_WINDOW", "   ")]));
        assert_eq!(blank.stream_receive_window, 8 * MIB);
    }

    #[test]
    fn b1_varint_overflow_falls_back_to_default() {
        let v = window_varint(u64::MAX, DEFAULT_STREAM_WINDOW_MB, "test");
        assert_eq!(v, quinn::VarInt::from_u64(8 * MIB).unwrap());

        let v = window_varint(1 << 62, DEFAULT_CONN_WINDOW_MB, "test");
        assert_eq!(v, quinn::VarInt::from_u64(32 * MIB).unwrap());
    }

    #[test]
    fn b1_apply_transport_tuning_smoke() {
        // quinn 0.10 TransportConfig 无 getter，窗口数值由 resolve/window_varint 单测覆盖；
        // 这里只断言真实应用路径（含默认 env）不 panic
        let mut cfg = quinn::TransportConfig::default();
        apply_transport_tuning(&mut cfg);
    }
}
