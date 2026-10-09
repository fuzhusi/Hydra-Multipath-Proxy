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
//! - **ClientHello 指纹最大近似**（feature `fingerprint`，默认开启）：chrome 模式
//!   （默认，`HYDRA_FINGERPRINT=chrome|none` 可切）将 stock rustls 可调项向 Chrome
//!   对齐（ALPN h2,http/1.1、certCompression-brotli、TLS1.3 套件顺序）；扩展顺序/
//!   key_share 等 rustls 不可调，故为"最大近似"而非 Chrome 同款 JA3/JA4——
//!   调研与局限见 docs/design/ClientHello指纹模仿方案与实施.md。
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

/// ClientHello 指纹模式（`HYDRA_FINGERPRINT`；详见模块末"指纹模仿"注释与
/// docs/design/ClientHello指纹模仿方案与实施.md）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FingerprintMode {
    /// Chrome 近似指纹：stock rustls 全部可调项向 Chrome 对齐（ALPN h2,http/1.1、
    /// 密码套件顺序、certCompression-brotli）。feature `fingerprint`（默认开启）
    /// 才可用；feature 关闭时退化为 None。
    #[default]
    Chrome,
    /// stock rustls 原行为（无 ALPN、默认套件顺序）——原"普通 HTTPS 客户端"伪装
    None,
}

/// 指纹模式 env（`HYDRA_FINGERPRINT=chrome|none`；缺省 chrome）
pub const HYDRA_FINGERPRINT_ENV: &str = "HYDRA_FINGERPRINT";

/// 解析指纹模式；`chrome` 在 fingerprint feature 关闭时告警回退 stock（none）。
/// 审查 P3-4：trim + 大小写不敏感比较；空白值视为未设置（此前 `"None"`、
/// `" none "` 会被当非法值回退默认 chrome，与用户关闭指纹的意图相反）。
pub fn fingerprint_mode_from_env() -> FingerprintMode {
    let parsed = match std::env::var(HYDRA_FINGERPRINT_ENV) {
        Ok(v) => match v.trim() {
            "" => None,
            s if s.eq_ignore_ascii_case("none") => Some(FingerprintMode::None),
            s if s.eq_ignore_ascii_case("chrome") => Some(FingerprintMode::Chrome),
            other => {
                tracing::warn!("HYDRA_FINGERPRINT={other} 非法（chrome|none），回退默认 chrome");
                None
            }
        },
        Err(_) => None,
    };
    match parsed {
        Some(m) => m,
        // 缺省值受 feature 约束：feature 关闭时 chrome profile 不参与编译
        None => {
            #[cfg(feature = "fingerprint")]
            {
                FingerprintMode::Chrome
            }
            #[cfg(not(feature = "fingerprint"))]
            {
                FingerprintMode::None
            }
        }
    }
}

/// 显式 `chrome` 请求按 feature 可用性收敛（env 解析与显式请求共用该规则）
fn resolve_chrome(m: FingerprintMode) -> FingerprintMode {
    #[cfg(not(feature = "fingerprint"))]
    if m == FingerprintMode::Chrome {
        tracing::warn!("HYDRA_FINGERPRINT=chrome 但 fingerprint feature 未启用，回退 stock rustls");
        return FingerprintMode::None;
    }
    m
}

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

/// Chrome 密码套件顺序：TLS 1.3 三套件按 1301/1302/1303 前置，其余（TLS 1.2
/// ECDHE 套件）稳定跟随 provider 原顺序。独立函数便于单测断言排序。
fn chrome_order_cipher_suites(
    base: Vec<rustls::SupportedCipherSuite>,
) -> Vec<rustls::SupportedCipherSuite> {
    let rank = |cs: &rustls::SupportedCipherSuite| match cs.suite() {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 0, // 0x1301
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 1, // 0x1302
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2, // 0x1303
        _ => 3,
    };
    let mut suites = base;
    suites.sort_by_key(rank);
    suites
}

/// 由 [`TlsTrust`] 构建（或命中缓存取回）共享 TLS 连接器。
/// pin 模式且无证书时返回 Err（拒绝建立不经验证的连接，语义与原实现一致）。
pub(crate) fn build_tls_connector(trust: &TlsTrust) -> Result<Arc<TlsConnector>> {
    let mode = resolve_chrome(fingerprint_mode_from_env());
    // 指纹模式参与缓存键：同信任内容、不同模式不得复用同一份 ClientConfig
    let mut fp = trust.cache_fingerprint();
    fp[0] ^= mode as u8; // 仅两模式，单字节混入足够区分
    let cache =
        CONNECTOR_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(c) = map.get(&fp) {
            return Ok(c.clone());
        }
    }
    let connector = Arc::new(build_tls_connector_uncached(trust, mode)?);
    if let Ok(mut map) = cache.lock() {
        map.insert(fp, connector.clone());
    }
    Ok(connector)
}

/// 缓存未命中时的实际构建（原 connect_target / probe_connect 的重复 ~30 行合并为此一份）
///
/// `mode = Chrome` 时应用"Chrome 近似指纹"（stock rustls 可调项全集，Route C）：
/// - ALPN `h2, http/1.1`（Chrome 顺序；节点侧 rustls server 未配 ALPN 不会选择，
///   客户端 `check_selected_alpn` 仅在校验"服务器选了但不在我方列表"时才报错，
///   服务器不选即通过——连通性不受影响）；
/// - 密码套件顺序：TLS 1.3 三套件按 Chrome 顺序前置（1301/1302/1303）；
/// - certCompression：启用 brotli 解压器（feature `fingerprint` → rustls/brotli）；
/// - 不可调项（扩展顺序、GREASE、key_share/签名算法顺序、padding）如实保留
///   rustls 形态——见设计文档"局限"一节。
fn build_tls_connector_uncached(trust: &TlsTrust, mode: FingerprintMode) -> Result<TlsConnector> {
    Ok(TlsConnector::from(Arc::new(build_client_config(
        trust, mode,
    )?)))
}

/// 构建共享 `ClientConfig`（[`build_tls_connector_uncached`] 的配置主体，
/// 独立暴露供单测对 ALPN/解压器/套件顺序直接断言——`TlsConnector` 不透出字段）。
fn build_client_config(trust: &TlsTrust, mode: FingerprintMode) -> Result<rustls::ClientConfig> {
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
    let mut provider = rustls::crypto::ring::default_provider();
    if mode == FingerprintMode::Chrome {
        provider.cipher_suites = chrome_order_cipher_suites(provider.cipher_suites);
    }
    let provider = Arc::new(provider);
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| HydraError::ProtocolError(format!("TLS 协议版本配置失败: {:?}", e)))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    match mode {
        // Chrome 近似：ALPN = 浏览器标准（h2 优先）。取舍见函数文档与设计文档。
        FingerprintMode::Chrome => {
            crypto.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            // certCompression：feature fingerprint → rustls/brotli → 声明 brotli
            // 解压器（与 Chrome certCompression 对齐；zstd Chrome 有而 rustls 无，
            // 如实缺席）
            crypto.cert_decompressors = rustls::compress::default_cert_decompressors().to_vec();
        }
        // stock rustls：原"无 ALPN = 普通 HTTPS 客户端"伪装策略不变
        FingerprintMode::None => {
            crypto.alpn_protocols = Vec::new();
        }
    }
    // 禁会话恢复防跨连接关联追踪（两模式一致；与 Chrome 行为不同，如实差异）
    crypto.resumption = rustls::client::Resumption::disabled();
    Ok(crypto)
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

/// 为出站 TCP 流启用参数化 keepalive（09-P1-2）。
///
/// 客户端中继循环（proxy.rs）无空闲超时——对端**静默死亡**（掉电/拔线/NAT
/// 空闲回收映射且不回 RST）时双向 read 永久挂起，任务+缓冲+注册表条目泄漏；
/// keepalive 让内核在约 idle + interval×系统重试次数（Windows 固定 10 次，
/// Linux 取默认）内检出死链并以错误唤醒 read。语义上优于应用层空闲超时：
/// 合法的长空闲但健康连接（SSH/长轮询）不会被误杀。设置失败仅记录（非致命，
/// 防御纵深不受单点影响）。
pub(crate) fn enable_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let ka = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10));
    if let Err(e) = SockRef::from(stream).set_tcp_keepalive(&ka) {
        tracing::debug!("TCP keepalive 设置失败（忽略）: {}", e);
    }
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
    let tcp = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        crate::socket_protect::connect_tcp_protected(node_addr),
    )
    .await
    {
        Ok(Ok(s)) => {
            // 09-P1-2：出站节点连接启用 keepalive（静默死亡连接检测）
            enable_tcp_keepalive(&s);
            s
        }
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
    // 地址帧 + 2B 应答（09-P3-1：write_target 是建链序列中唯一无超时 I/O，
    // 恶意节点完成 Noise 后停读可挂住写端——补 CONNECT_TIMEOUT 与同序列对齐）
    tokio::time::timeout(CONNECT_TIMEOUT, write_target(&mut wr, target))
        .await
        .map_err(|_| {
            HydraError::ConnectionError(format!("write request to {} timed out", node_addr))
        })?
        .map_err(|e| {
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

    /// 指纹模式显式收敛规则：None 恒等；Chrome 由 feature 可用性决定
    /// （feature 关闭时降级 None 并告警）。env 缺省值逻辑见
    /// fingerprint_mode_from_env（不在此处改进程 env，测试并发安全）。
    #[test]
    fn fingerprint_mode_解析与收敛() {
        assert_eq!(resolve_chrome(FingerprintMode::None), FingerprintMode::None);
        let _ = fingerprint_mode_from_env; // 公开 API 可达性
    }

    #[cfg(feature = "fingerprint")]
    #[test]
    fn chrome_order_cipher_suites_1301_1302_1303前置() {
        let base = rustls::crypto::ring::default_provider().cipher_suites;
        let ordered = chrome_order_cipher_suites(base.clone());
        // 前三个 = Chrome TLS 1.3 顺序；其余保持原相对顺序（稳定排序）
        let want = [
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        for (cs, w) in ordered.iter().zip(want.iter()) {
            assert_eq!(cs.suite(), *w);
        }
        let rest_in: Vec<_> = base.iter().map(|c| c.suite()).collect();
        let rest_out: Vec<_> = ordered[3..].iter().map(|c| c.suite()).collect();
        let rest_in_rest: Vec<_> = rest_in
            .iter()
            .filter(|s| !want.contains(s))
            .copied()
            .collect();
        assert_eq!(rest_in_rest, rest_out);
    }

    /// feature fingerprint 下：chrome 模式 ALPN=h2,http/1.1 且声明 brotli 证书
    /// 解压器；none 模式 = stock（无 ALPN）。证书 pinning 语义两模式一致。
    #[cfg(feature = "fingerprint")]
    #[test]
    fn chrome_与none_配置断言() {
        let trust = TlsTrust::public_ca(None);
        let chrome = build_client_config(&trust, FingerprintMode::Chrome).unwrap();
        assert_eq!(
            chrome.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(
            !chrome.cert_decompressors.is_empty(),
            "chrome 模式应声明 certCompression 解压器（brotli）"
        );
        let none = build_client_config(&trust, FingerprintMode::None).unwrap();
        assert!(none.alpn_protocols.is_empty(), "none 模式保持无 ALPN");
        // 禁会话恢复两模式一致（resumption 无公开读取口，禁恢复由既有行为覆盖）
        let _ = (&chrome, &none);
    }
}
