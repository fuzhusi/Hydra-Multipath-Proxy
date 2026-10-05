//! TCP 转型（Wave 1）：TCP/TLS 传输模式客户端侧——新协议核心实现。
//!
//! 线缆协议（与节点侧 `hydra_node::tcp_server` 对称）：
//! ```text
//! TCP 建连 → TLS 1.3（证书 pinning + SNI，无 ALPN，禁会话恢复）
//! → [0x03][Noise-PSK 握手 4 消息]（hydra_protocol::handshake，TLS exporter 通道绑定）
//! → [地址帧: u16 BE len + addr] → [2B 应答] → 双向裸转发（半关闭语义）
//! ```
//!
//! - **认证**：V3.2 Noise-PSK（前向安全、抗重放、无时钟窗），复用 QUIC 路径同一
//!   握手实现；PSK = HYDRA_AUTH_KEY。
//! - **防中间人**：节点自签证书加入本地信任根（webpki 校验），同 QUIC 路径。
//! - **禁会话恢复**：session ticket 不被用于跨连接关联追踪。
//! - 无 obfs（UDP 概念，不适用 TCP）。
//!
//! 返回 `tokio::io::split` 的读写两半：调用方（代理转发层）用带半关闭的泵
//! （源 EOF → 写端 shutdown）完成双向转发。

use crate::transport::DEFAULT_SNI;
use hydra_protocol::handshake;
use hydra_protocol::tcp_frame::{read_reply, write_target};
use hydra_protocol::{mask_target, HydraError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// 传输模式选择（分享链接 `tp` 字段值；QUIC 路径已随 TCP 转型 Wave 3 移除，
/// 枚举保留用于分享链接兼容解析）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportChoice {
    /// QUIC/UDP（legacy：已移除，仅为分享链接 `tp=quic` 的显式报错保留）
    Quic,
    /// TCP/TLS（默认传输）
    Tcp,
}

impl TransportChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportChoice::Quic => "quic",
            TransportChoice::Tcp => "tcp",
        }
    }

    /// 解析传输字符串（分享链接 tp 字段值）；非法值显式报错
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "quic" => Ok(TransportChoice::Quic),
            "tcp" => Ok(TransportChoice::Tcp),
            other => Err(HydraError::ProtocolError(format!(
                "Invalid transport '{}': expected quic|tcp",
                other
            ))),
        }
    }
}

/// 默认传输 = TCP（TCP 转型 Wave 2 定版；分享链接缺省 tp 视为 tcp）
pub const DEFAULT_TRANSPORT: TransportChoice = TransportChoice::Tcp;

/// 全局传输选择 env（`HYDRA_TRANSPORT=tcp|quic`；quic 为 legacy 提示——QUIC 路径
/// 已随 TCP 转型移除，显式设置 quic 时告警并回退 tcp）
pub const HYDRA_TRANSPORT_ENV: &str = "HYDRA_TRANSPORT";

/// 读取全局传输选择（默认 TCP；legacy `quic` 值告警回退，保证旧配置不黑洞）。
/// 审查 R-30 收尾：CLI main 启动时调用一次，兑现 README"设 quic 会告警回退"的
/// 行为承诺；eprintln 改 tracing::warn（R-43：GUI 场景可见）。
pub fn transport_from_env() -> TransportChoice {
    match std::env::var(HYDRA_TRANSPORT_ENV).as_deref() {
        Ok("quic") => {
            tracing::warn!("HYDRA_TRANSPORT=quic（legacy）的 QUIC/UDP 路径已移除，回退 tcp");
            TransportChoice::Tcp
        }
        _ => TransportChoice::Tcp,
    }
}

/// 客户端侧 TCP/TLS 节点流
pub type TcpNodeStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
/// 节点流读半（源=节点方向）
pub type TcpReadHalf = tokio::io::ReadHalf<TcpNodeStream>;
/// 节点流写半（去往节点方向）
pub type TcpWriteHalf = tokio::io::WriteHalf<TcpNodeStream>;

/// 建连超时（TCP + TLS 两段各 5s）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 握手 + 应答等待超时（须大于节点侧目标连接超时 15s，同 QUIC 路径 20s）
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// TLS 信任配置（TCP 转型交付版：自签 pinning 与真证书双路线）。
///
/// - `Pinned`（默认）：节点自签证书加入本地信任根（pinning），对应自签部署；
/// - `PublicCa`：信任 webpki 公共 CA 根 + SNI 校验，对应 ACME 真证书部署
///   （节点侧 `HYDRA_CERT_FILE/HYDRA_KEY_FILE` 指向 Let's Encrypt 证书，支持 PEM）；
///   可选 `leaf_pin_sha256_hex` 对叶证书做 SHA-256 硬 pin（防公共 CA 误签发）。
///
/// `pinned_certs` 为 `Arc<Vec<_>>`（审查 R-13 / Wave1-6）：`TlsTrust::clone` 退化为
/// 引用计数递增，热路径（每连接 open_target / 测速探测）不再深拷贝整张证书表。
#[derive(Clone, Debug, Default)]
pub struct TlsTrust {
    /// pin 模式信任根（全部节点证书 DER，Arc 共享零拷贝克隆）
    pub pinned_certs: Arc<Vec<Vec<u8>>>,
    /// true = 信任公共 CA（webpki roots）；false = 仅信任 pinned_certs
    pub use_public_ca: bool,
    /// 可选叶证书 SHA-256 硬 pin（hex，64 字符；对 TLS 协商出的对端叶证书校验）
    pub leaf_pin_sha256_hex: Option<String>,
}

impl TlsTrust {
    /// 自签 pinning 模式（现状默认）
    pub fn pinned(certs: Vec<Vec<u8>>) -> Self {
        Self {
            pinned_certs: Arc::new(certs),
            use_public_ca: false,
            leaf_pin_sha256_hex: None,
        }
    }

    /// 真证书模式（公共 CA + 可选叶证书硬 pin）
    pub fn public_ca(leaf_pin_sha256_hex: Option<String>) -> Self {
        Self {
            pinned_certs: Arc::new(Vec::new()),
            use_public_ca: true,
            leaf_pin_sha256_hex,
        }
    }

    /// 信任配置内容指纹（缓存键）：覆盖全部影响 ClientConfig 的字段
    /// （信任根 DER 序列 / CA 开关 / 叶 pin）。SHA-256 碰撞概率可忽略。
    fn cache_fingerprint(&self) -> [u8; 32] {
        use ring::digest::SHA256;
        let mut ctx = ring::digest::Context::new(&SHA256);
        ctx.update(&[self.use_public_ca as u8]);
        if let Some(pin) = &self.leaf_pin_sha256_hex {
            ctx.update(pin.as_bytes());
        }
        for der in self.pinned_certs.iter() {
            let len = (der.len() as u64).to_le_bytes();
            ctx.update(&len);
            ctx.update(der);
        }
        let out = ctx.finish();
        let mut h = [0u8; 32];
        h.copy_from_slice(out.as_ref());
        h
    }
}

/// TLS 连接器进程级缓存（审查 R-12 / Wave1-5）：`ClientConfig` 构建含证书解析与
/// 若干堆分配，主链路 `connect_target` 与测速 `probe_connect` 每连接重建既浪费
/// （0.5-2ms CPU/连接）又有配置漂移风险。同一信任内容（按内容指纹）复用同一份
/// `Arc<TlsConnector>`；SNI 与节点地址在 connect 时传入，不影响复用。
static CONNECTOR_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<TlsConnector>>>,
> = std::sync::OnceLock::new();

/// 由 [`TlsTrust`] 构建（或命中缓存取回）共享 TLS 连接器。
/// pin 模式且无证书时返回 Err（拒绝建立不经验证的连接，语义与原实现一致）。
pub(crate) fn build_tls_connector(trust: &TlsTrust) -> Result<Arc<TlsConnector>> {
    let fp = trust.cache_fingerprint();
    let cache =
        CONNECTOR_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(c) = map.get(&fp) {
            return Ok(c.clone());
        }
    }
    let connector = Arc::new(build_tls_connector_uncached(trust)?);
    if let Ok(mut map) = cache.lock() {
        map.insert(fp, connector.clone());
    }
    Ok(connector)
}

/// 缓存未命中时的实际构建（原 connect_target / probe_connect 的重复 ~30 行合并为此一份）
fn build_tls_connector_uncached(trust: &TlsTrust) -> Result<TlsConnector> {
    // 信任根：pin 模式 = 节点自签证书入本地信任根；CA 模式 = webpki 公共根
    let mut roots = rustls::RootCertStore::empty();
    if trust.use_public_ca {
        // rustls 0.23（Wave 3）：webpki-roots 0.26 的 TrustAnchor 与
        // rustls-pki-types 统一，直接 extend（OwnedTrustAnchor 已成历史类型）
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        if trust.pinned_certs.is_empty() {
            return Err(HydraError::ConnectionError(
                "未提供节点证书，拒绝建立不经验证的连接（pin 模式需 HYDRA_NODE_CERT/HYDRA_NODE_CERTS，\
                 真证书部署请设 HYDRA_TRUST=ca）"
                    .to_string(),
            ));
        }
        for der in trust.pinned_certs.iter() {
            // 证书 pinning 语义不变：自签叶证书作为唯一信任根入 store（webpki 标准校验）
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .map_err(|e| HydraError::ProtocolError(format!("无效的节点证书: {:?}", e)))?;
        }
    }
    // rustls 0.23（Wave 3）：显式指定 ring provider（工作区统一 ring 0.17），
    // 不依赖进程级默认——避免 ureq 经特性统一启用 aws_lc_rs 后的多 provider 歧义。
    // 协议版本 = 安全默认（TLS 1.2 + 1.3，与 0.21 with_safe_defaults 等价）。
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| HydraError::ProtocolError(format!("TLS 协议版本配置失败: {:?}", e)))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // 不做 ALPN（同节点侧）；禁会话恢复防跨连接关联追踪
    crypto.alpn_protocols = Vec::new();
    crypto.resumption = rustls::client::Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(crypto)))
}

/// 从 TLS 会话取对端叶证书 DER（两种信任模式下都已被 TLS 握手认证）。
fn peer_leaf_cert(tls: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Result<Vec<u8>> {
    tls.get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        // rustls 0.23：CertificateDer（pki-types），as_ref 取 DER 字节
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| {
            HydraError::ConnectionError("TLS 会话未提供对端证书（无法做通道绑定）".to_string())
        })
}

/// 经 TCP+TLS 连接节点并打开目标转发。
///
/// 步骤：TCP 建连（5s）→ TLS 握手（[`TlsTrust`]：pinning 或公共 CA + SNI，5s）
/// → Noise-PSK 握手（TLS exporter 通道绑定）→ 写地址帧 → 读 2B 应答（20s）。
///
/// **Noise 指纹取 TLS 协商出的对端叶证书**（两种模式下该证书都已被 TLS 握手
/// 认证）：这从结构上消除了"多节点证书按客户端侧配置配对错误"这一整类故障
/// （审查 R-02），也让证书轮换不再破坏 pinning。
/// 成功返回已认证、已收到成功应答的 [`TcpNodeStream`]，可直接用于双向转发。
/// 握手/认证失败：节点静默关流 → 本函数以"认证失败或协议失步"报错。
pub async fn connect_target(
    node_addr: SocketAddr,
    sni: &str,
    trust: &TlsTrust,
    auth_key: &[u8],
    target: &str,
) -> Result<TcpNodeStream> {
    let sni = if sni.is_empty() {
        // 审查 06-P3-6（Wave 3）：空 SNI 静默回退会掩盖"证书不含 hydra.node"这类
        // 配置错误——显式留痕（warn 级；CA 模式下真证书 SAN 必须包含该域名）
        tracing::warn!(
            "SNI 未配置，回退默认 {}（CA 模式下证书 SAN 必须包含该域名）",
            DEFAULT_SNI
        );
        DEFAULT_SNI
    } else {
        sni
    };

    // 共享 TLS 连接器（审查 R-12：同信任内容复用同一份 ClientConfig，消除每连接
    // 重建的 CPU/分配开销与探测/主链路配置漂移）
    let connector = build_tls_connector(trust)?;

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|e| HydraError::ProtocolError(format!("Invalid SNI '{}': {:?}", sni, e)))?;

    debug!(
        "Attempting TCP/TLS connection to {} (sni={})...",
        node_addr, sni
    );
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(node_addr))
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "TCP connect to {} failed: {}",
                node_addr, e
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "TCP connect to {} timed out",
                node_addr
            )))
        }
    };
    let tls = match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp)).await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "TLS handshake with {} failed: {}",
                node_addr, e
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "TLS handshake with {} timed out",
                node_addr
            )))
        }
    };
    // 禁 Nagle：本协议无连接复用，小包（握手/应答/交互式流量）延迟敏感
    let _ = tls.get_ref().0.set_nodelay(true);

    // TLS exporter 通道绑定材料（两端同 label/context 即同值）
    let mut exporter = [0u8; handshake::EXPORTER_LEN];
    if tls
        .get_ref()
        .1
        .export_keying_material(&mut exporter, handshake::EXPORTER_LABEL, Some(b""))
        .is_err()
    {
        return Err(HydraError::ConnectionError(
            "TLS exporter 不可用，无法完成 v3 通道绑定".to_string(),
        ));
    }

    // Noise-PSK 握手：client_side 自己写 [0x03][msg1]；失败 = PSK/篡改/证书不匹配。
    // 指纹取 TLS 协商出的对端叶证书（已被本连接的 TLS 认证，见函数文档）。
    let peer_leaf = peer_leaf_cert(&tls)?;
    if let Some(pin_hex) = &trust.leaf_pin_sha256_hex {
        use ring::digest::{digest, SHA256};
        let fp = crate::share_link::hex_encode_lower(digest(&SHA256, &peer_leaf).as_ref());
        if !fp.eq_ignore_ascii_case(pin_hex.trim()) {
            return Err(HydraError::ConnectionError(
                "对端叶证书指纹与 HYDRA_CERT_SHA256 不匹配（防 CA 误签发硬 pin 生效）".to_string(),
            ));
        }
    }
    let cert_fp = handshake::cert_fingerprint(&peer_leaf);
    let (mut rd, mut wr) = tokio::io::split(tls);
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        handshake::client_side(&mut wr, &mut rd, auth_key, &cert_fp, &exporter),
    )
    .await
    .map_err(|_| HydraError::ConnectionError(format!("Noise 握手超时: {}", node_addr)))?
    .map_err(|e| HydraError::ConnectionError(format!("Noise 握手失败: {}", e)))?;
    // 地址帧 + 2B 应答
    write_target(&mut wr, target).await.map_err(|e| {
        HydraError::ConnectionError(format!("write request to {} failed: {}", node_addr, e))
    })?;
    match tokio::time::timeout(RESPONSE_TIMEOUT, read_reply(&mut rd)).await {
        // 保留错误类型：TargetUnreachable 供故障切换层区分「节点故障」与「目标不可达」
        Ok(r) => r?,
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "Node {} response timeout",
                node_addr
            )))
        }
    }

    // 握手/帧交互完成，读写两半合回流（同一 split 产物，unsplit 必成功）
    let tls = rd.unsplit(wr);
    // 日志脱敏：info 级不落目标明文（审查 R-08）
    info!(
        "✓ TCP/TLS target {} opened via node {}",
        mask_target(target),
        node_addr
    );
    Ok(tls)
}

/// 带半关闭的单向泵：源 EOF 后显式 shutdown 写端（与节点侧 pump 语义对称）。
pub async fn pump<R, W>(mut r: R, mut w: W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut r, &mut w).await?;
    let _ = w.shutdown().await;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_choice_parse() {
        assert_eq!(
            TransportChoice::parse("quic").unwrap(),
            TransportChoice::Quic
        );
        assert_eq!(TransportChoice::parse("tcp").unwrap(), TransportChoice::Tcp);
        assert!(TransportChoice::parse("obfs").is_err());
    }

    #[test]
    fn default_transport_is_tcp() {
        assert_eq!(DEFAULT_TRANSPORT, TransportChoice::Tcp);
    }

    /// 审查 R-12（Wave1-5）：同信任内容复用同一份连接器（Arc 指针相等）；
    /// 不同信任内容各自独立；pin 模式空证书/非法证书仍拒绝。
    /// （pinned 合法证书路径由 test_tcp_transport 集成测试以真实节点证书覆盖。）
    #[test]
    fn tls_connector_按信任内容复用缓存() {
        // CA 模式（无需本地证书即可构建）同内容命中同一缓存条目
        let ca = build_tls_connector(&TlsTrust::public_ca(None)).unwrap();
        let ca2 = build_tls_connector(&TlsTrust::public_ca(None)).unwrap();
        assert!(Arc::ptr_eq(&ca, &ca2), "同信任内容应命中同一缓存条目");

        // 叶 pin 不同 → 指纹不同 → 独立连接器
        let ca_pin = build_tls_connector(&TlsTrust::public_ca(Some("ab".repeat(32)))).unwrap();
        assert!(!Arc::ptr_eq(&ca, &ca_pin), "不同信任内容不得复用连接器");
        // use_public_ca 不同 → 指纹不同 → 独立连接器（此处 pinned 空证书先在
        // build 前拒绝，用指纹函数直接验证区分度）
        let mut t1 = TlsTrust::public_ca(None);
        let mut t2 = TlsTrust::public_ca(None);
        t2.use_public_ca = false;
        assert_ne!(t1.cache_fingerprint(), t2.cache_fingerprint());
        t1.leaf_pin_sha256_hex = Some("cd".repeat(32));
        assert_ne!(t1.cache_fingerprint(), t2.cache_fingerprint());
        assert_ne!(
            TlsTrust::pinned(vec![vec![1u8]]).cache_fingerprint(),
            TlsTrust::pinned(vec![vec![2u8]]).cache_fingerprint()
        );

        // pin 模式空证书：拒绝建立不经验证的连接（语义保持）
        assert!(build_tls_connector(&TlsTrust::pinned(Vec::new())).is_err());
        // pin 模式非法证书 DER：构建期即报错
        assert!(build_tls_connector(&TlsTrust::pinned(vec![vec![1u8, 2, 3]])).is_err());
    }
}
