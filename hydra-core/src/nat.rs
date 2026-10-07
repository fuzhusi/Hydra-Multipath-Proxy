//! NAT 穿透客户端侧（NAT 穿透方案 §3.1 / §3.3）。**状态：已交付 v1**
//! （信令限速、属主证明、多候选/自连防护均已落地；真实 NAT 组合环境
//! ——hairpin/EIF/端口漂移——需人工实网验证，见方案文档 §7）。
//!
//! **安全边界声明**（安全分审查 P3-2，Wave 3）：本模块为 P2P 直连路径，
//! STUN 探测与打洞阶段的信令/nonce 交互为**明文**（设计决策：不隐藏流量形态），
//! **无任何抗检测/抗审查设计**——对抗性网络环境（DPI/审查）请勿启用 NAT 打洞
//! （不设 `HYDRA_STUN_ADDRS` 即整体关闭，代理流量走常规 TCP/TLS 路径）。
//!
//! 职责三块：
//! 1. **公网地址发现 + NAT 分类**：经 TCP STUN（`hydra_protocol::stun`，RFC 5389）
//!    对前两个 STUN 服务器各发一次 Binding Request，比较两次映射地址 →
//!    EIM（可打洞）/ Symmetric（回落中继）。任一步失败报错，由调用方回落中继。
//!    STUN 服务器来自 `HYDRA_STUN_ADDRS`（逗号分隔 ip:port，需支持 TCP 的公共
//!    STUN，如 `stun.nextcloud.com:443`）；未设置 = 功能关闭（返回特定错误）。
//!    只配置一个服务器时无法做两次映射比较，**按保守语义处理为 Symmetric**
//!    （宁可回落中继，不做无依据的打洞尝试）。
//! 2. **打洞编排**：经节点信令（`@hydra-p2p/<peer_id>`，复用认证路径）交换候选，
//!    然后 TCP 同时打开（simultaneous open）：本端在 STUN 探测所用本地端口上
//!    监听（SO_REUSEADDR），同时向对方候选发起 connect；任一连接建成后做
//!    **Noise-PSK 握手 + 32B 随机 nonce 回显校验**（防连到扫描者/自连）。
//!    10s 总窗口失败 → 关闭全部尝试返回 None，调用方走现有 connect_target 中继
//!    路径（零改动）。
//! 3. **对等端间安全**：P2P 直连不经 TLS，Noise-PSK 握手的通道绑定材料
//!    （证书指纹/exporter）在原始 TCP 上不存在，双方统一用全零占位（文档化决定）；
//!    身份与防篡改仍由 PSK 与握手 hash 保证，nonce 回显防自连/反射。
//!
//! 连接用完即关：STUN Binding 是一次性事务，探测 socket 用后即弃；
//! 打洞期间未选中的尝试连接全部显式关闭。

use crate::tcp_transport::{connect_target, TcpNodeStream, TlsTrust};
use hydra_protocol::handshake;
use hydra_protocol::stun::{self, NatType};
use hydra_protocol::{HydraError, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── 常量与环境变量 ──────────────────────────────────────────────────────────

/// STUN 服务器列表环境变量（逗号分隔 ip:port）
pub const HYDRA_STUN_ADDRS_ENV: &str = "HYDRA_STUN_ADDRS";
/// STUN TCP connect 超时
const STUN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// STUN 响应读取超时
const STUN_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 打洞总窗口（同时打开 + 握手 + nonce 校验）
pub const PUNCH_WINDOW: Duration = Duration::from_secs(10);
/// 信令交换（invite 重试 + 等 accepted）总时限
const SIGNAL_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);
/// 角色判定等待：注册后短等 incoming，等不到即按发起方 invite（双向同时启动也收敛）
const ROLE_WAIT: Duration = Duration::from_millis(1500);
/// peer_offline 重试间隔
const INVITE_RETRY: Duration = Duration::from_millis(300);
/// 信令下行单行长度上限（09-P2-3：防无换行长行无限耗内存；与节点侧
/// signal.rs 的 4096 上限对齐）
const SIGNAL_MAX_LINE_LEN: usize = 4096;
/// 打洞候选数量上限（09-P2-3：防被入侵节点下发海量候选逐条 spawn 任务）
const MAX_PEER_CANDIDATES: usize = 32;

/// 从 `HYDRA_STUN_ADDRS` 读取 STUN 服务器列表。
/// 未设置/为空/解析失败均为特定错误（调用方据此提示「功能关闭」或配置问题）。
pub fn stun_addrs_from_env() -> Result<Vec<SocketAddr>> {
    let raw = std::env::var(HYDRA_STUN_ADDRS_ENV).map_err(|_| {
        HydraError::ConnectionError(format!(
            "未设置 {HYDRA_STUN_ADDRS_ENV}，STUN 公网地址发现功能关闭；\
             设为逗号分隔 ip:port（需支持 TCP 的公共 STUN，如 stun.nextcloud.com:443）"
        ))
    })?;
    parse_stun_addrs(&raw)
}

/// 解析 `HYDRA_STUN_ADDRS`（审查 06-P2-4）：支持文档示例的域名写法
/// （如 `stun.nextcloud.com:443`）——IP 字面量直接解析；域名经 tokio DNS
/// 解析取首个地址（5s 超时，仍 fail-fast 报错，不静默跳过）。
pub async fn stun_addrs_from_env_resolved() -> Result<Vec<SocketAddr>> {
    let raw = std::env::var(HYDRA_STUN_ADDRS_ENV).map_err(|_| {
        HydraError::ConnectionError(format!(
            "未设置 {HYDRA_STUN_ADDRS_ENV}，STUN 公网地址发现功能关闭；\
             设为逗分隔 ip:port 或域名:port（需支持 TCP 的公共 STUN，如 stun.nextcloud.com:443）"
        ))
    })?;
    resolve_stun_addrs(&raw).await
}

/// 逐条解析 ip:port / 域名:port（域名走 lookup_host，取首个地址）
pub async fn resolve_stun_addrs(raw: &str) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for s in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Ok(a) = s.parse::<SocketAddr>() {
            out.push(a);
            continue;
        }
        // 非字面量：按域名解析（审查 06-P2-4：文档主路径此前必然解析失败）
        match tokio::time::timeout(STUN_CONNECT_TIMEOUT, tokio::net::lookup_host(s.to_string()))
            .await
        {
            Ok(Ok(mut addrs)) => match addrs.next() {
                Some(a) => {
                    info!("STUN 地址 '{s}' 经 DNS 解析为 {a}");
                    out.push(a);
                }
                None => {
                    return Err(HydraError::ProtocolError(format!(
                        "HYDRA_STUN_ADDRS 中的地址 '{s}' DNS 解析无结果"
                    )))
                }
            },
            Ok(Err(e)) => {
                return Err(HydraError::ProtocolError(format!(
                    "HYDRA_STUN_ADDRS 中的地址 '{s}' DNS 解析失败: {e}"
                )))
            }
            Err(_) => {
                return Err(HydraError::ProtocolError(format!(
                    "HYDRA_STUN_ADDRS 中的地址 '{s}' DNS 解析超时（{STUN_CONNECT_TIMEOUT:?}）"
                )))
            }
        }
    }
    if out.is_empty() {
        return Err(HydraError::ProtocolError(
            "HYDRA_STUN_ADDRS 为空，STUN 公网地址发现功能关闭".into(),
        ));
    }
    Ok(out)
}

/// 解析逗号分隔的 ip:port 列表（容忍空白；空列表报错）
pub fn parse_stun_addrs(raw: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse().map_err(|_| {
                HydraError::ProtocolError(format!("HYDRA_STUN_ADDRS 中的非法地址: '{s}'"))
            })
        })
        .collect::<Result<_>>()?;
    if addrs.is_empty() {
        return Err(HydraError::ProtocolError(
            "HYDRA_STUN_ADDRS 为空，STUN 公网地址发现功能关闭".into(),
        ));
    }
    Ok(addrs)
}

// ── 公网地址发现 + NAT 分类 ────────────────────────────────────────────────

/// 单次探测结果：公网映射地址 + 探测所用本地 socket 地址（打洞时监听同一端口）
#[derive(Debug, Clone)]
pub struct Discovery {
    /// NAT 后的公网映射地址（打洞候选）
    pub mapped: SocketAddr,
    /// STUN 探测所用本地 socket 地址（打洞 listener 绑定其端口）
    pub local: SocketAddr,
    /// 映射行为分类
    pub nat: NatType,
}

/// 单服务器探测：TCP connect（5s）→ 写 Binding Request → 读响应（10s）→ 解析。
pub async fn probe_one(stun_server: SocketAddr) -> Result<Discovery> {
    let tcp = match tokio::time::timeout(
        STUN_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(stun_server),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "STUN {stun_server} connect 失败: {e}"
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "STUN {stun_server} connect 超时（{STUN_CONNECT_TIMEOUT:?}）"
            )))
        }
    };
    let _ = tcp.set_nodelay(true);
    // 记录本地 socket：打洞时把 listener 绑到同一端口（NAT 映射按本地端口建立）
    let local = tcp
        .local_addr()
        .map_err(|e| HydraError::ConnectionError(format!("STUN 探测本地地址不可得: {e}")))?;
    let (mut rd, mut wr) = tcp.into_split();
    let (req, tx_id) = stun::build_binding_request();
    wr.write_all(&req)
        .await
        .map_err(|e| HydraError::ConnectionError(format!("STUN {stun_server} 写请求失败: {e}")))?;
    let msg = match tokio::time::timeout(STUN_READ_TIMEOUT, stun::read_stun_message(&mut rd)).await
    {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            return Err(HydraError::ConnectionError(format!(
                "STUN {stun_server} 读响应失败: {e}"
            )))
        }
        Err(_) => {
            return Err(HydraError::ConnectionError(format!(
                "STUN {stun_server} 读响应超时（{STUN_READ_TIMEOUT:?}）"
            )))
        }
    };
    let mapped = stun::parse_binding_response(&msg, &tx_id)?;
    debug!("STUN {stun_server}: local={local} mapped={mapped}");
    Ok(Discovery {
        mapped,
        local,
        nat: NatType::Symmetric, // 占位，由 discover_full 填充
    })
}

/// 公网地址发现 + NAT 分类（方案 §3.1）。
///
/// - 取前两个 STUN 服务器并发探测，两次映射地址相同 → EIM，不同 → Symmetric；
/// - 只有一个服务器：无法比较，**按 Symmetric 保守处理**（见模块文档）；
/// - 任一步失败 → Err（调用方回落中继）。探测连接用完即关（Binding 一次性事务）。
pub async fn discover_public_address(stun_addrs: &[SocketAddr]) -> Result<(SocketAddr, NatType)> {
    let d = discover_full(stun_addrs).await?;
    Ok((d.mapped, d.nat))
}

/// 同 [`discover_public_address`]，额外返回探测所用本地 socket 地址
/// （打洞时 listener 须绑定同一端口以复用 NAT 映射）。
/// 公网地址发现 + NAT 行为分类。
///
/// 09-P3-3：并发探测**前 3 个**服务器（此前只取前 2 个且 `try_join!` 任一失败
/// 整体失败——第 1 个服务器宕机会把打洞功能整体打入中继回落）。收集全部成功
/// 结果后两两比对：任何一对映射不一致即判 Symmetric；全部一致才判 EIM。
/// 单服务器成功 → 保守 Symmetric（无法比较映射行为）。
pub async fn discover_full(stun_addrs: &[SocketAddr]) -> Result<Discovery> {
    if stun_addrs.is_empty() {
        return Err(HydraError::ConnectionError(
            "无可用 STUN 服务器，公网地址发现失败（检查 HYDRA_STUN_ADDRS）".into(),
        ));
    }
    let mut set = tokio::task::JoinSet::new();
    for &s in stun_addrs.iter().take(3) {
        set.spawn(probe_one(s));
    }
    let mut ok: Vec<Discovery> = Vec::new();
    let mut first_err: Option<String> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(d)) => ok.push(d),
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(format!("探测任务失败: {e}"));
                }
            }
        }
    }
    match ok.len() {
        0 => Err(HydraError::ConnectionError(format!(
            "全部 STUN 服务器探测失败（{} 个；首个错误: {}）",
            stun_addrs.len().min(3),
            first_err.unwrap_or_else(|| "未知".into())
        ))),
        1 => {
            let mut d = ok.remove(0);
            d.nat = NatType::Symmetric; // 单服务器无法比较映射行为：保守回落中继
            Ok(d)
        }
        _ => {
            let mut d = ok.remove(0);
            let mut nat = stun::classify(d.mapped, ok[0].mapped);
            for other in &ok[1..] {
                // 任一服务器对映射不一致 → 对称型（多服务器交叉验证，防
                // "恰好抽到两个一致的服务器"漏判）
                if matches!(stun::classify(d.mapped, other.mapped), NatType::Symmetric) {
                    nat = NatType::Symmetric;
                    break;
                }
            }
            d.nat = nat;
            Ok(d)
        }
    }
}

// ── 节点信令（客户端侧最小实现，与 hydra_node::signal 线格式一致）──────────

/// 客户端 → 节点 上行消息（JSON 行；结构对齐 hydra_node::signal::SignalMessage，
/// 客户端侧独立定义以避免 hydra-client 运行期依赖 hydra-node）
#[derive(Debug, serde::Serialize)]
#[serde(tag = "op")]
enum SignalUp {
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        mapped: String,
        /// peer_id 属主证明（hydra_protocol::p2p_owner_proof，PSK 派生）：
        /// 防同 peer_id 重注册顶替——节点侧校验，伪造 proof 的注册被拒
        proof: String,
    },
    #[serde(rename = "invite")]
    Invite { peer_id: String, cand: Vec<String> },
    #[serde(rename = "accept")]
    Accept { to: String, cand: Vec<String> },
}

/// 节点 → 客户端 下行消息（对齐 hydra_node::signal::SignalDownMessage）
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "op")]
enum SignalDown {
    #[serde(rename = "incoming")]
    Incoming { from: String, cand: Vec<String> },
    #[serde(rename = "accepted")]
    Accepted {
        // 线格式保留字段（对端身份，日志可读性）；客户端目前不消费
        #[allow(dead_code)]
        from: String,
        cand: Vec<String>,
    },
    #[serde(rename = "error")]
    Error {
        code: String,
        #[serde(default)]
        peer: Option<String>,
    },
}

/// 一条已认证的信令会话（connect_target 到 `@hydra-p2p/<peer_id>` 后的 JSON 行流）
struct SignalSession {
    rd: BufReader<ReadHalf<TcpNodeStream>>,
    wr: WriteHalf<TcpNodeStream>,
}

impl SignalSession {
    async fn connect(
        node_addr: SocketAddr,
        sni: &str,
        trust: &TlsTrust,
        auth_key: &[u8],
        my_peer_id: &str,
    ) -> Result<Self> {
        let stream = connect_target(
            node_addr,
            sni,
            trust,
            auth_key,
            &format!("@hydra-p2p/{my_peer_id}"),
        )
        .await?;
        let (rd, wr) = tokio::io::split(stream);
        Ok(Self {
            rd: BufReader::new(rd),
            wr,
        })
    }

    async fn send(&mut self, msg: &SignalUp) -> Result<()> {
        let line = serde_json::to_string(msg)
            .map_err(|e| HydraError::ProtocolError(format!("信令序列化失败: {e}")))?;
        self.wr.write_all(line.as_bytes()).await?;
        self.wr.write_all(b"\n").await?;
        self.wr.flush().await?;
        Ok(())
    }

    /// 读一条下行 JSON 行（无数据到达返回 Err/超时由调用方包裹）。
    /// 09-P2-3：带行长上限的逐字节读——此前 `read_line` 无上限累积 String，
    /// 被入侵节点/链路劫持者以无换行长行可无限耗内存。
    async fn recv(&mut self) -> Result<SignalDown> {
        let mut line = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            let n = self.rd.read(&mut byte).await?;
            if n == 0 {
                return Err(HydraError::ConnectionError("信令连接被节点关闭".into()));
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > SIGNAL_MAX_LINE_LEN {
                return Err(HydraError::ProtocolError(format!(
                    "信令下行行超长（>{}B）",
                    SIGNAL_MAX_LINE_LEN
                )));
            }
        }
        let line = String::from_utf8(line)
            .map_err(|_| HydraError::ProtocolError("信令下行非 UTF-8".into()))?;
        serde_json::from_str(&line)
            .map_err(|e| HydraError::ProtocolError(format!("信令下行解析失败: {e}")))
    }
}

// ── 打洞核心：同时打开 + Noise-PSK 握手 + nonce 回显校验 ──────────────────

/// 随机 32B nonce（仅防自连/反射比对，非密钥材料）
fn random_nonce() -> [u8; 32] {
    rand::random()
}

/// P2P 对等端间握手 + nonce 回显校验。
///
/// - `initiator` = true 表示本端是该 TCP 连接的拨号方：先跑 Noise-PSK
///   `client_side`；拨号方/接听方角色在单条连接上天然对偶，两端一致。
/// - 证书指纹/exporter 用全零占位（原始 TCP 无 TLS exporter；两端同为占位即可
///   通过，认证由 PSK 承担——文档化决定，见模块头注释）。
/// - 握手后互发 32B 随机 nonce：**对端 nonce 与自己相同 → 判为自连**（nonce 由
///   [`punch_open_and_verify`] 顶部每端生成一次并传入全部验证任务——同进程自连
///   时两端读到相同 nonce 即拒绝；跨进程随机必然不同），否则回显对端 nonce 并
///   校验收到的回显 == 自己的 nonce（防连到不遵守协议的扫描者）。
async fn verify_stream(
    initiator: bool,
    stream: tokio::net::TcpStream,
    auth_key: &[u8],
    mine: [u8; 32],
) -> std::io::Result<tokio::net::TcpStream> {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    const ZERO: [u8; 32] = [0u8; 32];
    let hs = if initiator {
        handshake::client_side(&mut wr, &mut rd, auth_key, &ZERO, &ZERO).await
    } else {
        // 接听方：先消费版本字节（client_side 一次性写 [0x03][msg1]）
        let mut ver = [0u8; 1];
        rd.read_exact(&mut ver).await?;
        if ver[0] != handshake::HANDSHAKE_VERSION_BYTE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("对等端版本字节非法: 0x{:02x}", ver[0]),
            ));
        }
        handshake::server_side(&mut wr, &mut rd, auth_key, &ZERO, &ZERO).await
    };
    hs.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("P2P Noise 握手失败: {e}"),
        )
    })?;

    // nonce 回显校验（握手后明文小交互；mine 由调用方每端生成一次）
    wr.write_all(&mine).await?;
    let mut theirs = [0u8; 32];
    rd.read_exact(&mut theirs).await?;
    if theirs == mine {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "对端 nonce 与本端相同：判定为自连，拒绝",
        ));
    }
    wr.write_all(&theirs).await?; // 回显对端 nonce
    let mut echo = [0u8; 32];
    rd.read_exact(&mut echo).await?;
    if echo != mine {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "对端未正确回显本端 nonce（疑似扫描者/协议不符）",
        ));
    }
    rd.reunite(wr)
        .map_err(|e| std::io::Error::other(format!("流 reunite 失败: {e}")))
}

/// TCP 同时打开 + 握手校验（打洞编排的可复用核心，便于 loopback 自动化测试）。
///
/// - 在 `local_bind`（= STUN 探测本地端口）上监听（SO_REUSEADDR），同时向
///   `peer_cands` 每条候选发起 connect（各自受总窗口约束）；
/// - accept/connect 建成的连接先过滤自连（对端地址 == 本端 listener 地址），
///   再做 [`verify_stream`]；任一条验证通过立即返回，其余尝试全部丢弃关闭；
/// - `window` 内无一条通过 → 返回 None（调用方回落中继）。
pub async fn punch_open_and_verify(
    local_bind: SocketAddr,
    peer_cands: &[SocketAddr],
    auth_key: &[u8],
    window: Duration,
) -> Option<tokio::net::TcpStream> {
    let deadline = Instant::now() + window;
    // 派生任务需要 'static：PSK 克隆一份供验证任务使用
    let auth_key: std::sync::Arc<[u8]> = auth_key.into();
    // 本端 nonce：每端生成一次、传入全部验证任务（自连判定依赖：同进程自连时
    // 两端共享同一值 → theirs == mine 必然成立被拒；跨进程随机必不同）
    let mine = random_nonce();
    // 验证结果通道：每条候选连接一个验证任务，通过后送回主循环（见下方说明，
    // 验证必须并发进行——同时打开时两条连接的握手互相依赖对方的处理进度）
    let (verified_tx, mut verified_rx) = mpsc::channel::<tokio::net::TcpStream>(16);

    // 本端 listener（绑 STUN 探测所用本地端口；SO_REUSEADDR 允许探测 socket
    // 刚关闭后立即重绑同端口——Windows 上 TIME_WAIT/绑定语义所需）
    let (accept_tx, mut accept_rx) = mpsc::channel::<(tokio::net::TcpStream, SocketAddr)>(16);
    match tokio::net::TcpSocket::new_v4() {
        Ok(sock) => {
            if sock.set_reuseaddr(true).is_ok() && sock.bind(local_bind).is_ok() {
                if let Ok(listener) = sock.listen(16) {
                    let laddr = listener.local_addr().ok();
                    debug!("打洞 listener 绑定 {local_bind}");
                    tokio::spawn(async move {
                        // while let 形式（clippy）：accept Err = listener 关闭，退出任务
                        while let Ok((s, peer)) = listener.accept().await {
                            // 自连过滤第一层：对端地址 == 本端 listener 地址
                            if Some(peer) == laddr {
                                debug!("打洞 accept 命中自连（{}），丢弃", peer);
                                continue;
                            }
                            if accept_tx.send((s, peer)).await.is_err() {
                                break;
                            }
                        }
                    });
                } else {
                    // 未进入 accept 任务：显式关闭通道（命名绑定会存活到函数结束，
                    // 不 drop 接收端永远等不到 None）
                    drop(accept_tx);
                    warn!("打洞 listener listen 失败（{}）：仅出站尝试", local_bind);
                }
            } else {
                drop(accept_tx);
                warn!("打洞 listener 绑定 {} 失败：仅出站尝试", local_bind);
            }
        }
        Err(_) => {
            drop(accept_tx);
            warn!("TcpSocket 创建失败：仅出站尝试")
        }
    }

    // 出站 connect：向每条候选各起一个任务（10s 窗口内）。
    // 同时打开要求出站 SYN 从与 listener 相同的本地端口发出（RFC 5128 §2.4）：
    // 出站 socket 绑定 local_bind（SO_REUSEADDR 允许与 listener 共存），使两端
    // 的 SYN 在 NAT 映射上相遇；否则经 EIM NAT 后出站连接获得另一独立映射，
    // 对端发往 mapped 端口的 SYN 只能赌 NAT 的过滤行为放行（EIF）。
    let (conn_tx, mut conn_rx) = mpsc::channel::<tokio::net::TcpStream>(16);
    for cand in peer_cands {
        let cand = *cand;
        let tx = conn_tx.clone();
        let bind = local_bind;
        tokio::spawn(async move {
            // 优先绑 local_bind 端口；绑定失败（平台语义/端口被占）降级为普通
            // connect——打洞成功率下降但功能保留（注释如实）
            let s = match tokio::net::TcpSocket::new_v4() {
                Ok(sock) if sock.set_reuseaddr(true).is_ok() && sock.bind(bind).is_ok() => {
                    tokio::time::timeout(window, sock.connect(cand)).await
                }
                _ => {
                    debug!("打洞出站绑定 {bind} 失败，降级普通 connect: {cand}");
                    tokio::time::timeout(window, tokio::net::TcpStream::connect(cand)).await
                }
            };
            match s {
                Ok(Ok(s)) => {
                    debug!("打洞出站 connect 建成: {cand}");
                    let _ = tx.send(s).await;
                }
                Ok(Err(e)) => debug!("打洞出站 connect 失败: {cand}: {e}"),
                Err(_) => debug!("打洞出站 connect 超时: {cand}"),
            }
        });
    }
    drop(conn_tx);

    // 主循环：来源连接交给并发验证任务；任一验证通过立即返回，窗口耗尽 → 放弃。
    // （不能在循环内联 await 验证：同时打开产生的两条连接，两端各自先拿到哪条
    // 是随机的，串行验证会互相等待对方的握手字节而双死锁——必须并发握手。）
    let spawn_verify = |initiator: bool,
                        s: tokio::net::TcpStream,
                        tx: mpsc::Sender<tokio::net::TcpStream>,
                        key: std::sync::Arc<[u8]>,
                        my_nonce: [u8; 32],
                        remain: Duration| {
        tokio::spawn(async move {
            // if let 形式（clippy）：其余分支均为"丢弃该尝试"（流随之关闭）
            if let Ok(Ok(v)) =
                tokio::time::timeout(remain, verify_stream(initiator, s, &key, my_nonce)).await
            {
                let _ = tx.send(v).await;
            } // 握手失败/超时/自连拒绝：丢弃该尝试
        });
    };
    // 通道存活标志：recv() 返回 None（已关闭且为空）后把该臂从 select 移除，
    // 否则 None 立即就绪形成无眠忙循环（审查 P1-3：单核打满整个窗口）
    let mut conn_closed = false;
    let mut accept_closed = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if conn_closed && accept_closed {
            break; // 两个来源通道皆耗尽：不再有新尝试可等待
        }
        let remain = deadline - now;
        tokio::select! {
            r = accept_rx.recv(), if !accept_closed => match r {
                Some((s, peer)) => {
                    debug!("打洞 accept 来自 {peer}，开始握手校验");
                    spawn_verify(false, s, verified_tx.clone(), auth_key.clone(), mine, remain);
                }
                None => accept_closed = true, // listener 任务结束：不再等 accept 侧
            },
            r = conn_rx.recv(), if !conn_closed => match r {
                Some(s) => {
                    let peer = s.peer_addr().ok();
                    debug!("打洞 connect 建成（peer={peer:?}），开始握手校验");
                    spawn_verify(true, s, verified_tx.clone(), auth_key.clone(), mine, remain);
                }
                None => conn_closed = true, // 全部 connect 任务结束：不再等出站侧
            },
            r = verified_rx.recv() => match r {
                Some(v) => {
                    info!("P2P 同时打开成功（经 Noise-PSK 握手 + nonce 校验）");
                    return Some(v);
                }
                None => break, // 全部验证任务结束且无成功
            },
            _ = tokio::time::sleep_until(deadline.into()) => break,
        }
    }
    warn!("打洞窗口（{window:?}）内未建成经验证的直连，回落中继");
    None
}

// ── 打洞编排（信令 + 同时打开）─────────────────────────────────────────────

/// 打洞编排参数
pub struct PunchParams<'a> {
    /// 节点（信令 + 中继兜底）地址
    pub node_addr: SocketAddr,
    /// SNI（同中继路径；空串用默认）
    pub sni: &'a str,
    /// 节点 TLS 信任配置（信令连接复用认证路径）
    pub trust: &'a TlsTrust,
    /// PSK（信令认证与 P2P 握手共用）
    pub auth_key: &'a [u8],
    /// STUN 服务器列表（前两个生效）
    pub stun_addrs: &'a [SocketAddr],
    /// 本端 peer_id（信令路由键，随机 16B hex，每次会话可换）
    pub my_peer_id: &'a str,
    /// 对端 peer_id
    pub peer_id: &'a str,
}

/// 打洞编排（自动发现 + 自动角色）。
/// 返回 None = 走中继（NAT 不适合 / 信令或窗口失败）；Some = 已握手校验的直连。
pub async fn punch_direct(p: &PunchParams<'_>) -> Option<tokio::net::TcpStream> {
    match discover_full(p.stun_addrs).await {
        Ok(d) => punch_direct_with_discovery(p, d).await,
        Err(e) => {
            warn!("公网地址发现失败，回落中继: {e}");
            None
        }
    }
}

/// 同 [`punch_direct`]，但复用调用方已完成的发现结果（避免 CLI/测试二次探测）。
pub async fn punch_direct_with_discovery(
    p: &PunchParams<'_>,
    disc: Discovery,
) -> Option<tokio::net::TcpStream> {
    if disc.nat != NatType::Eim {
        info!(
            "NAT 映射行为非 EIM（{:?}），直接回落中继（mapped={}）",
            disc.nat, disc.mapped
        );
        return None;
    }
    let mut sess =
        match SignalSession::connect(p.node_addr, p.sni, p.trust, p.auth_key, p.my_peer_id).await {
            Ok(s) => s,
            Err(e) => {
                warn!("信令连接失败，回落中继: {e}");
                return None;
            }
        };
    let my_cand = disc.mapped.to_string();
    if let Err(e) = sess
        .send(&SignalUp::Register {
            peer_id: p.my_peer_id.to_string(),
            mapped: my_cand.clone(),
            // 属主证明：PSK HMAC 派生，节点复算校验（防 peer_id 冒用顶替）
            proof: hydra_protocol::p2p_owner_proof(p.auth_key, p.my_peer_id),
        })
        .await
    {
        warn!("信令注册失败，回落中继: {e}");
        return None;
    }

    let peer_cands = signal_exchange(&mut sess, p, &my_cand).await?;
    if peer_cands.is_empty() {
        warn!("对端候选为空，回落中继");
        return None;
    }

    // listener 绑 STUN 探测所用本地端口（复用 NAT 映射）
    let local_bind = disc.local;
    debug!("打洞阶段：local_bind={local_bind} 对端候选={peer_cands:?}");
    punch_open_and_verify(local_bind, &peer_cands, p.auth_key, PUNCH_WINDOW).await
}

/// 信令候选交换。角色自动：
/// - 注册后短等 incoming → 本端为应答方：回 accept，候选来自 incoming；
/// - 等不到（或先收到 error）→ 本端为发起方：invite（peer_offline 退避重试）→
///   等 accepted；期间收到的 incoming（双向同时发起）也回 accept 并暂存候选，
///   accepted 迟迟不到时用暂存候选——保证两端同时启动也能收敛。
async fn signal_exchange(
    sess: &mut SignalSession,
    p: &PunchParams<'_>,
    my_cand: &str,
) -> Option<Vec<SocketAddr>> {
    // 阶段一：角色判定
    match tokio::time::timeout(ROLE_WAIT, sess.recv()).await {
        Err(_) => {} // 短等超时 → 发起方
        Ok(Err(e)) => {
            warn!("信令下行读失败: {e}");
            return None;
        }
        Ok(Ok(SignalDown::Incoming { from, cand })) if from == p.peer_id => {
            debug!("收到 incoming（from={from}），本端为应答方");
            if sess
                .send(&SignalUp::Accept {
                    to: from,
                    cand: vec![my_cand.to_string()],
                })
                .await
                .is_err()
            {
                warn!("信令 accept 写失败，回落中继");
                return None;
            }
            return Some(parse_cands(cand));
        }
        // 审查 06-P2-6：incoming 来源必须与目标 peer_id 一致——同 PSK 恶意对端
        // 可伪造 incoming 诱导本端向任意地址 connect（内网探测/轻量 DoS），
        // 来源不符一律忽略
        Ok(Ok(SignalDown::Incoming { from, .. })) => {
            debug!(
                "忽略来源不符的 incoming（from={from} ≠ 目标 peer_id={}）",
                p.peer_id
            );
        }
        Ok(Ok(SignalDown::Error { code, .. })) => {
            debug!("角色判定期收到 error({code})，转入发起方");
        }
        Ok(Ok(_)) => {} // 其他下行罕见，忽略转入发起方
    }

    // 阶段二：发起方 invite → accepted（容忍双向同时发起）
    let deadline = Instant::now() + SIGNAL_EXCHANGE_TIMEOUT;
    let mut stashed: Option<Vec<String>> = None;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if sess
            .send(&SignalUp::Invite {
                peer_id: p.peer_id.to_string(),
                cand: vec![my_cand.to_string()],
            })
            .await
            .is_err()
        {
            warn!("信令 invite 写失败，回落中继");
            return None;
        }
        match tokio::time::timeout(deadline - now, sess.recv()).await {
            Err(_) => break, // 等 accepted 超时：靠暂存候选或失败
            Ok(Err(e)) => {
                warn!("信令下行读失败: {e}");
                return None;
            }
            Ok(Ok(SignalDown::Accepted { cand, .. })) => {
                let mut all = cand;
                if all.is_empty() {
                    all = stashed.unwrap_or_default();
                }
                return Some(parse_cands(all));
            }
            Ok(Ok(SignalDown::Incoming { from, cand })) if from == p.peer_id => {
                // 对端同时也发起了 invite：回 accept，暂存其候选继续等 accepted
                debug!("等 accepted 期间收到 incoming（from={from}）：双向同时发起，回 accept");
                let _ = sess
                    .send(&SignalUp::Accept {
                        to: from,
                        cand: vec![my_cand.to_string()],
                    })
                    .await;
                if stashed.is_none() {
                    stashed = Some(cand);
                }
            }
            // 审查 06-P2-6：来源不符的 incoming 一律忽略（不 accept、不暂存候选）
            Ok(Ok(SignalDown::Incoming { from, .. })) => {
                debug!(
                    "忽略来源不符的 incoming（from={from} ≠ 目标 peer_id={}）",
                    p.peer_id
                );
            }
            Ok(Ok(SignalDown::Error { code, .. })) if code == "peer_offline" => {
                tokio::time::sleep(INVITE_RETRY).await; // 对端尚未注册：退避重试
            }
            Ok(Ok(SignalDown::Error { code, peer })) => {
                warn!("信令错误（code={code}，peer={peer:?}），回落中继");
                return None;
            }
        }
    }
    match stashed {
        Some(c) => Some(parse_cands(c)),
        None => {
            warn!("信令交换未获得对端候选（超时 {SIGNAL_EXCHANGE_TIMEOUT:?}），回落中继");
            None
        }
    }
}

/// 候选字符串 → SocketAddr（解析失败的条目丢弃）。
/// 09-P2-3：上限 [`MAX_PEER_CANDIDATES`] 条——共享 PSK 信任模型下被入侵节点
/// 可下发海量候选，此前逐条 spawn connect 任务（10 万条候选 → 10 万 socket/任务）。
/// 打洞只需少数候选，截断即可。
fn parse_cands(cand: Vec<String>) -> Vec<SocketAddr> {
    cand.iter()
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .take(MAX_PEER_CANDIDATES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stun_addrs_各分支() {
        assert!(parse_stun_addrs("").is_err());
        assert!(parse_stun_addrs("  , ").is_err());
        assert!(parse_stun_addrs("not-an-addr").is_err());
        let v = parse_stun_addrs("127.0.0.1:3478, [::1]:3479").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
        assert_eq!(v[1], "[::1]:3479".parse::<SocketAddr>().unwrap());
    }

    /// 审查 06-P2-4：resolve_stun_addrs 对 IP 字面量零开销直通
    #[tokio::test]
    async fn resolve_stun_addrs_ip字面量直通() {
        let v = resolve_stun_addrs("127.0.0.1:3478, [::1]:3479")
            .await
            .unwrap();
        assert_eq!(v.len(), 2);
        assert!(resolve_stun_addrs("  , ").await.is_err());
        assert!(resolve_stun_addrs("not-an-addr").await.is_err()); // 无端口/非域名非 IP
    }

    /// 审查 06-P2-4：域名写法经 DNS 解析（loopback 域名走系统解析器，无外网依赖）
    #[tokio::test]
    async fn resolve_stun_addrs_域名可解析() {
        let v = resolve_stun_addrs("localhost:3478").await.unwrap();
        assert_eq!(v.len(), 1, "localhost 应解析出一个地址，得到 {v:?}");
    }

    /// 自连拒绝分支（审查 P1-4）：nonce 每端一次后，同一进程内自连的两端
    /// 共享同一 nonce——verify_stream 两端都必须以 InvalidData 拒绝。
    #[tokio::test]
    async fn verify_stream_自连同nonce被拒() {
        // Noise-PSK 要求恰好 32 字节
        let key = [7u8; 32].to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(tokio::net::TcpStream::connect(addr), async {
            let (s, _) = listener.accept().await.unwrap();
            s
        });
        let (a, b) = (a.unwrap(), b);
        let mine = random_nonce();
        let (ra, rb) = tokio::join!(
            verify_stream(true, a, &key, mine),
            verify_stream(false, b, &key, mine)
        );
        for r in [ra, rb] {
            let err = r.expect_err("自连（两端同 nonce）必须被拒绝");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    /// 对端不同 nonce（正常跨进程场景）：校验应通过。
    #[tokio::test]
    async fn verify_stream_不同nonce通过() {
        // Noise-PSK 要求恰好 32 字节
        let key = [9u8; 32].to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(tokio::net::TcpStream::connect(addr), async {
            let (s, _) = listener.accept().await.unwrap();
            s
        });
        let (a, b) = (a.unwrap(), b);
        // 两端各生成一次（模拟跨进程随机必不同）
        let (ra, rb) = tokio::join!(
            verify_stream(true, a, &key, random_nonce()),
            verify_stream(false, b, &key, random_nonce())
        );
        assert!(ra.is_ok(), "不同 nonce 应校验通过: {ra:?}");
        assert!(rb.is_ok(), "不同 nonce 应校验通过: {rb:?}");
    }

    /// 热自旋回归（审查 P1-3）：conn/accept 两通道都关闭后主循环必须提前退出，
    /// 不得忙转至窗口耗尽（修复前 select 的 None 臂立即就绪，无眠忙循环）。
    #[tokio::test(flavor = "multi_thread")]
    async fn punch_通道耗尽_提前退出不忙等() {
        // 候选 = 本机真实监听端口：connect 毫秒级建成并被取走 → conn 通道排空
        // 关闭；local_bind 用 IPv6 地址 → v4 TcpSocket bind 必然失败（确定性）→
        // listener 不存在、accept 通道立即关闭 → 两通道皆关 → break
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cand = live.local_addr().unwrap();
        let bind: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        let start = Instant::now();
        let r = punch_open_and_verify(bind, &[cand], &[0u8; 32], Duration::from_secs(5)).await;
        assert!(r.is_none(), "无有效握手不应返回连接");
        // 修复后两通道关闭即 break；修复前会忙转满 5s 窗口并 peg 满一核
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "两通道皆关后应提前退出，而非忙等至窗口耗尽（耗时 {:?}）",
            start.elapsed()
        );
    }
}
