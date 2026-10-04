use hydra_obfs::TransportMode;
use hydra_protocol::{HydraError, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// 拥塞控制选择（Exec-B Brutal / Team-C HYDRA_CC 三选一）。
/// 经 `#[path]` 挂为本文件子模块：文件所有权制下不改 lib.rs 的模块声明。
/// env `HYDRA_CC=brutal|bbr|cubic` 显式选算法（非法值/brutal 缺带宽 → 启动报错）；
/// 未设置时保留 Wave4 行为：有合法 `HYDRA_BRUTAL_MBPS` 则 Brutal，否则 quinn 默认 CUBIC（零改动）。
#[path = "cc.rs"]
pub mod cc;

/// B1 流控窗口调优实现迁入 hydra-obfs（节点侧不可依赖 hydra-client，见 hydra-obfs::tuning）。
/// 此处 re-export 保持既有公开 API 与单测路径不变。
pub use hydra_obfs::tuning::{
    apply_transport_tuning, resolve_transport_tuning, window_varint, TransportTuning,
    DEFAULT_CONN_WINDOW_MB, DEFAULT_STREAM_WINDOW_MB, MAX_STREAM_WINDOW_MB, MIB,
    MIN_STREAM_WINDOW_MB,
};

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

    /// 用给定 endpoint 构造 Transport（C2 双模式显式构造用，如测试/工具）。
    pub fn from_endpoint(endpoint: Endpoint, sni: &str) -> Self {
        Self {
            endpoint,
            sni: sni.to_string(),
        }
    }

    /// 创建共享的客户端 Endpoint 与 ClientConfig。
    ///
    /// C2 双模式：模式经 `HYDRA_MODE` env 解析（未设置 = masquerade = 本项目 V2 行为零改动）。
    /// 显式指定模式请用 [`Self::create_shared_endpoint_in_mode`]。
    ///
    /// node_certs 中的节点自签证书会被加入本地信任根，执行标准 webpki 校验
    /// （证书 pinning），替代曾经的 SkipVerification——那是零门槛的中间人。
    pub fn create_shared_endpoint(
        node_certs: Vec<Vec<u8>>,
        sni: &str,
    ) -> Result<(Endpoint, ClientConfig)> {
        let mode = TransportMode::from_env().map_err(HydraError::ProtocolError)?;
        Self::create_shared_endpoint_in_mode(node_certs, sni, mode)
    }

    /// 以显式模式创建共享的客户端 Endpoint 与 ClientConfig（env 无关）。
    ///
    /// QUIC/TLS 配置两种模式完全一致（ALPN=h3、SPKI pinning、窗口调优）；差异只在
    /// UDP socket：masquerade 走普通 `Endpoint::client` 原路径，obfs 走
    /// [`hydra_obfs::new_obfs_endpoint`]（线缆 = `[12B salt][ChaCha20 XOR]`）。
    pub fn create_shared_endpoint_in_mode(
        node_certs: Vec<Vec<u8>>,
        sni: &str,
        mode: TransportMode,
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
        // 拥塞控制（Team-C 三选一）：HYDRA_CC=brutal|bbr|cubic 显式指定；
        // 未设置保留 Wave4 行为（有合法 HYDRA_BRUTAL_MBPS → Brutal，否则 quinn 默认 CUBIC）。
        // HYDRA_CC 非法值、或 HYDRA_CC=brutal 而无带宽 → 此处返回 Err（启动显式报错退出）。
        // 注意：拥塞控制只约束本端发送方向；双向提速需两端都设（节点侧接线归总控/WS-C），
        // 且对端接收窗口（HYDRA_STREAM_WINDOW，默认 8MB）须 ≥ 带宽×RTT 才不成为新瓶颈
        //（经验：HYDRA_STREAM_WINDOW(MB) ≥ 带宽(Mbps) × RTT(s) / 8）。详见 cc 模块文档。
        cc::apply_congestion_control_from_env(&mut transport_config, |name| {
            std::env::var(name).ok()
        })
        .map_err(HydraError::ProtocolError)?;
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(Duration::from_secs(jittered_keepalive_secs())));
        client_config.transport_config(Arc::new(transport_config));

        // C2 双模式接线：masquerade 走原路径（零改动）；obfs 走抽象 socket
        let endpoint = match mode {
            TransportMode::Masquerade => {
                let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
                endpoint.set_default_client_config(client_config.clone());
                endpoint
            }
            TransportMode::Obfs => {
                // obfs 模式要求独立第二密码（HYDRA_OBFS_KEY），未设置 → 启动失败
                let obfs = hydra_obfs::ObfsCrypto::from_env()
                    .map_err(|e| HydraError::ProtocolError(format!("obfs 模式启动失败: {}", e)))?;
                let mut endpoint = hydra_obfs::new_obfs_endpoint(
                    "0.0.0.0:0".parse().unwrap(),
                    None,
                    Arc::new(obfs),
                )
                .map_err(|e| {
                    HydraError::ConnectionError(format!("创建 obfs 客户端 endpoint 失败: {}", e))
                })?;
                endpoint.set_default_client_config(client_config.clone());
                endpoint
            }
        };

        info!(
            "Created shared QUIC client endpoint on {} (sni={}, trusted_certs={}, mode={})",
            endpoint.local_addr()?,
            sni,
            node_certs.len(),
            mode.as_str()
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

    // ===================== C2 双模式接线 =====================

    fn test_cert_der() -> Vec<u8> {
        let cert = rcgen::generate_simple_self_signed(vec!["hydra.node".to_string()]).unwrap();
        cert.serialize_der().unwrap()
    }

    #[tokio::test]
    async fn c2_explicit_masquerade_endpoint_builds() {
        let (ep, _cfg) = Transport::create_shared_endpoint_in_mode(
            vec![test_cert_der()],
            DEFAULT_SNI,
            TransportMode::Masquerade,
        )
        .unwrap();
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn c2_obfs_mode_requires_and_honors_independent_key() {
        let certs = vec![test_cert_der()];
        // 未设置 HYDRA_OBFS_KEY → 启动必须报错（任务书 C2 规格）。
        // 本测试独占该 env 变量（同进程内无其他测试读取它；集成测试为独立进程）。
        std::env::remove_var(hydra_obfs::HYDRA_OBFS_KEY_ENV);
        let result = Transport::create_shared_endpoint_in_mode(
            certs.clone(),
            DEFAULT_SNI,
            TransportMode::Obfs,
        );
        assert!(result.is_err(), "无独立密码时 obfs 必须拒绝启用");

        // 有 key → endpoint 构造成功
        std::env::set_var(hydra_obfs::HYDRA_OBFS_KEY_ENV, "c2-unit-test-key");
        let (ep, _cfg) =
            Transport::create_shared_endpoint_in_mode(certs, DEFAULT_SNI, TransportMode::Obfs)
                .unwrap();
        assert_ne!(ep.local_addr().unwrap().port(), 0);
        let _ = _cfg;
    }

    // ============= 拥塞控制接线（Exec-B Brutal / Team-C HYDRA_CC）=============

    #[tokio::test]
    async fn cc_env_unset_builds_endpoint_unchanged() {
        // 回归保障：HYDRA_CC 与 HYDRA_BRUTAL_MBPS 均未设置 → 不动 factory，全路径与现状一致
        std::env::remove_var(cc::HYDRA_CC_ENV);
        std::env::remove_var(cc::HYDRA_BRUTAL_MBPS_ENV);
        let (ep, _cfg) = Transport::create_shared_endpoint_in_mode(
            vec![test_cert_der()],
            DEFAULT_SNI,
            TransportMode::Masquerade,
        )
        .unwrap();
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn brutal_env_set_builds_endpoint_with_controller() {
        // 设置带宽（HYDRA_CC 未设 → 隐含 brutal）→ endpoint 照常构造；结束后还原 env。
        // 注意：并行测试中其他 endpoint 构造若读到该值，仅额外启用 Brutal，不影响其断言。
        std::env::remove_var(cc::HYDRA_CC_ENV);
        std::env::set_var(cc::HYDRA_BRUTAL_MBPS_ENV, "16");
        let result = Transport::create_shared_endpoint_in_mode(
            vec![test_cert_der()],
            DEFAULT_SNI,
            TransportMode::Masquerade,
        );
        std::env::remove_var(cc::HYDRA_BRUTAL_MBPS_ENV);
        let (ep, _cfg) = result.unwrap();
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn cc_bbr_builds_endpoint_with_controller() {
        // HYDRA_CC=bbr → quinn 内置 BBR factory 挂载成功（bbr 值本身无害，
        // 并行测试读到也不改变其断言路径）
        std::env::remove_var(cc::HYDRA_BRUTAL_MBPS_ENV);
        std::env::set_var(cc::HYDRA_CC_ENV, "bbr");
        let result = Transport::create_shared_endpoint_in_mode(
            vec![test_cert_der()],
            DEFAULT_SNI,
            TransportMode::Masquerade,
        );
        std::env::remove_var(cc::HYDRA_CC_ENV);
        let (ep, _cfg) = result.unwrap();
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn brutal_apply_directly_on_transport_config_smoke() {
        // 绕过 env 直接验证 factory 应用路径（quinn 0.10 无 getter，行为由 cc.rs 单测覆盖）
        let mut cfg = quinn::TransportConfig::default();
        cc::apply_brutal_congestion_control(&mut cfg, cc::BrutalConfig::new(1_562_500));
    }

    #[test]
    fn bbr_apply_directly_on_transport_config_smoke() {
        // 绕过 env 验证 BBR factory 应用路径（上游标注 Experimental，应用本身不 panic 即可通过）
        let mut cfg = quinn::TransportConfig::default();
        cc::apply_bbr_congestion_control(&mut cfg);
    }
}
