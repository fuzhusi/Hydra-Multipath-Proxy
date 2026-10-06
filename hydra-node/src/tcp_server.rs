//! TCP 转型（Wave 1）：TCP/TLS 传输模式节点侧——新协议核心实现。
//!
//! 线缆协议（TLS 1.3 建立后）：
//! ```text
//! [0x03][Noise-PSK 握手 4 消息] → [地址帧: u16 BE len + addr] → [2B 应答] → 双向裸转发
//! ```
//!
//! - **认证**：V3.2 Noise-PSK（[`hydra_protocol::handshake`]，通用 AsyncRead/Write
//!   实现直接平移到 TCP 流）。通道绑定 = 节点证书指纹 + TLS exporter（rustls
//!   `export_keying_material`，两端同 label/context 即同值）。
//! - **防探测**：版本字节非 0x03 / 握手失败 / 认证失败——默认**零字节静默关流**
//!   （不回显应答码，与 QUIC 未认证路径语义一致）；开启 `fallback_page`
//!   （env `HYDRA_FALLBACK_PAGE=1`）后，TLS 已建立的认证失败路径改回内置
//!   静态页（[`crate::fallback`]，反代伪装；两种策略各有指纹，权衡见该
//!   模块文档与 README 部署指南）。TLS 握手本身失败恒静默（无层可回退）。
//! - **SSRF 过滤 / DNS / 建连**：复用 [`ConnectionHandler::resolve_and_connect`]。
//!   目标失败属已认证后的应用层错误，可回 2B 应答码（0x01 连接失败 / 0x02 DNS 失败）。
//! - **半关闭**：`copy_bidirectional` 一侧 EOF 时显式 shutdown 对侧写端（验收门③）。
//! - 无 ALPN（流量形态 = 普通 HTTPS）；无 obfs（UDP 概念，不适用 TCP）。

use crate::handler::ConnectionHandler;
use crate::signal::{self, SignalRegistry};
use hydra_protocol::handshake::{self};
use hydra_protocol::tcp_frame::{
    read_target, write_reply, REPLY_DNS_FAIL, REPLY_OK, REPLY_TARGET_FAIL, TCP_VERSION_BYTE,
};
use hydra_protocol::{mask_target, Result};
// rustls 0.23（Wave 3）：pki-types 的 DER 新类型取代旧的 Certificate/PrivateKey 元组结构体
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// 认证阶段超时（版本字节 + 握手 + 地址帧共用；与 QUIC 路径 AUTH_TIMEOUT 同级）
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// TLS 握手超时（审查：认证前 slowloris 防护——握手阶段此前无任何超时，
/// 慢速滴入 ClientHello 可无限期占用连接额度）
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// 转发阶段空闲超时（审查：已认证连接无限期占用 permit/fd 的资源耗尽路径；
/// 连接级判定——两个方向的 pump 共享最后活跃时间戳，任一方向有数据即刷新，
/// 双向均无数据达此时长才静默双向关闭）。env `HYDRA_IDLE_TIMEOUT_SECS` 可调。
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
const IDLE_TIMEOUT_ENV: &str = "HYDRA_IDLE_TIMEOUT_SECS";

fn idle_timeout() -> std::time::Duration {
    let secs = std::env::var(IDLE_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
        .clamp(30, 86400);
    std::time::Duration::from_secs(secs)
}

/// 解析生效的 idle 超时（07-P2-4）：显式注入（NodeOptions.idle_timeout）优先，
/// 未注入时回落 env `HYDRA_IDLE_TIMEOUT_SECS`——测试通过注入避免进程级
/// set_var/remove_var 与并行测试线程的数据竞争。
fn effective_idle_timeout(injected: Option<std::time::Duration>) -> std::time::Duration {
    injected.unwrap_or_else(idle_timeout)
}
/// 信令模式的保留目标前缀（NAT 穿透方案 §3.2）：`@hydra-p2p/<peer_id>`
const P2P_SIGNAL_PREFIX: &str = "@hydra-p2p/";

/// peer_id 校验：非空、≤64 字节、仅 hex 字符（客户端自选 16 字节 hex）
fn validate_peer_id(peer_id: &str) -> bool {
    !peer_id.is_empty() && peer_id.len() <= 64 && peer_id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 启动 TCP/TLS 监听（后台任务运行接受循环），返回实际绑定的本地地址。
/// `cert_chain` 为整条证书链（叶在前；07-P1-1：真证书部署必须下发中间链）。
/// 证书/密钥与主路径同一份（cert.rs 产物）；`max_connections` 用 Semaphore 强制。
/// `p2p_signal` = 是否开启信令模式（NAT 穿透 §3.2；默认关闭 = 零行为变化）。
/// `idle_timeout` = 转发空闲看门狗显式注入（07-P2-4；None = env/默认值）。
/// `fallback_page` = 反代静态页回退开关（抗主动探测增强）：true 时 TLS 建立
/// 后的认证失败路径回复内置静态页而非静默关流（默认 false = 行为零变化；
/// 权衡见 [`crate::fallback`] 模块文档）。
#[allow(clippy::too_many_arguments)]
pub async fn spawn_tcp_listener(
    addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    handler: Arc<ConnectionHandler>,
    max_connections: usize,
    p2p_signal: bool,
    fallback_page: bool,
    idle_timeout: Option<std::time::Duration>,
) -> Result<SocketAddr> {
    // rustls 0.23（Wave 3）：显式 ring provider（与客户端同一选择，全工作区 ring 0.17）；
    // 协议版本 = 安全默认（TLS 1.2 + 1.3）。
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            hydra_protocol::HydraError::ProtocolError(format!("TLS 协议版本配置失败: {e}"))
        })?
        .with_no_client_auth()
        // 07-P1-1：整链下发（自签路径链长 1，行为不变）
        .with_single_cert(cert_chain, key)
        .map_err(|e| {
            hydra_protocol::HydraError::ProtocolError(format!("TCP/TLS 证书配置失败: {e}"))
        })?;
    // 不做 ALPN：非标 ALPN 是单规则 DPI 指纹；留空 = 普通 HTTPS 客户端形态
    config.alpn_protocols = Vec::new();
    config.max_early_data_size = 0;
    // 07-P3-1 零成本顺修：禁服务端会话恢复/ticket 下发（与客户端
    // Resumption::disabled() 对齐，兑现"禁会话恢复两端保持"承诺）
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let sem = Arc::new(Semaphore::new(max_connections.max(1)));
    // 07-P2-4：idle 超时在监听启动时解析一次（显式注入优先，回落 env/默认值），
    // 经 Arc 随连接任务传递——不再每连接读 env
    let idle = Arc::new(effective_idle_timeout(idle_timeout));
    // 信令注册表：开启信令模式时创建（跨连接共享）；关闭时 None = 零开销
    let registry = if p2p_signal {
        Some(Arc::new(SignalRegistry::new()))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!("Hydra TCP/TLS transport (Noise-PSK) listening on {}", local);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    // 禁 Nagle：握手与交互式流量的小包延迟敏感
                    let _ = stream.set_nodelay(true);
                    // 快速失败（sheding）：额度满时立即丢弃新连接而非让其在内核
                    // backlog 里无限排队（客户端有自己的故障切换/超时语义）
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        debug!("Connection limit reached, dropping incoming {}", peer);
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    let registry = registry.clone(); // 每连接一份 Arc 克隆（避免 move 出循环）
                    let idle = idle.clone();
                    let fallback = fallback_page;
                    tokio::spawn(async move {
                        let _permit = permit; // 连接结束自动归还
                                              // TLS 握手超时：认证前 slowloris 防护（超时静默 drop，语义不变）
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                            .await
                        {
                            Ok(Ok(tls)) => {
                                handle_tls_stream(tls, handler, registry.clone(), fallback, idle)
                                    .await
                            }
                            Ok(Err(e)) => {
                                // 握手失败（扫描/探测）不回显任何信息，仅 debug 记录
                                debug!("TLS handshake from {} failed: {}", peer, e)
                            }
                            Err(_) => debug!("TLS handshake from {} timed out", peer),
                        }
                    });
                }
                Err(e) => error!("TCP accept error: {}", e),
            }
        }
    });

    Ok(local)
}

/// 单条 TLS 流的服务：Noise-PSK 认证 → 地址帧 → 建目标 → 2B 应答 → 双向裸转发。
/// 认证/握手失败：静默关闭（无任何回显）；目标失败：回应答码后关闭。
/// `fallback_page` = true 时，TLS 建立后的认证失败路径（版本字节非 0x03 /
/// Noise 握手失败 / 地址帧失步）改回内置静态页（反代伪装，见
/// [`crate::fallback`]）；TLS 握手本身失败仍静默（无 TLS 层可承载回退响应）。
/// 回退路径复用既有认证阶段超时（`AUTH_TIMEOUT`）与连接额度语义，不新增
/// 资源驻留面。
/// `signal_registry` = Some 时，目标为 `@hydra-p2p/<peer_id>` 的连接进入信令会话
/// （NAT 穿透方案 §3.2；None/未启用时该前缀走普通 connect 路径，语义不变）。
async fn handle_tls_stream(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    handler: Arc<ConnectionHandler>,
    signal_registry: Option<Arc<SignalRegistry>>,
    fallback_page: bool,
    idle: Arc<std::time::Duration>,
) {
    // ── 第 1 步：版本字节判别（0x03 = Noise-PSK；其他值按开关回退页/静默关流）
    let mut version = [0u8; 1];
    match tokio::time::timeout(AUTH_TIMEOUT, tls.read_exact(&mut version)).await {
        Ok(Ok(_)) if version[0] == TCP_VERSION_BYTE && handler.auth_mode().accepts_v3() => {}
        _ => {
            debug!("TCP stream bad version byte or v3 disabled");
            // 反代静态页回退：任何非代理流量都得到同一页面（标准反代行为，
            // 不要求输入构成合法 HTTP 请求）。受 AUTH_TIMEOUT 读超时与连接
            // 额度保护；TLS 握手已建立故可承载响应。
            if fallback_page {
                let _ = crate::fallback::http_serve_fallback(&mut tls).await;
            } else {
                debug!("closing silently (fallback_page off)");
            }
            return;
        }
    }

    // ── 第 2 步：TLS exporter 通道绑定材料（两端同 label/context 即同值）
    let mut exporter = [0u8; handshake::EXPORTER_LEN];
    if tls
        .get_ref()
        .1
        .export_keying_material(&mut exporter, handshake::EXPORTER_LABEL, Some(b""))
        .is_err()
    {
        // TLS 层内部故障（非探测者可见路径）：保持静默，不参与回退页语义
        warn!("export_keying_material unavailable; closing silently");
        return;
    }

    // 读写半分离：握手阶段两个方向独立借用；转发阶段沿用两半做双向泵
    let (mut rd, mut wr) = tokio::io::split(tls);

    // ── 第 3 步：Noise-PSK 握手（失败 = 静默关流，含重放/篡改/PSK 不一致）
    let hs = tokio::time::timeout(
        AUTH_TIMEOUT,
        handshake::server_side(
            &mut wr,
            &mut rd,
            handler.auth_key(),
            handler.cert_fingerprint(),
            &exporter,
        ),
    )
    .await;
    match hs {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            // 审查 P2：握手失败点可能已写出部分 Noise 二进制消息（如 msg2 已发
            // 出后 msg3 校验失败）——此时回退 HTTP 页会拼成「二进制+HTTP」混合
            // 流，反而构成可区分指纹。故握手失败一律静默关流，不参与回退页。
            debug!("TCP Noise handshake failed: {}", e);
            return;
        }
        Err(_) => {
            // 审查 P1：失败分支必须 return——否则落入第 4 步对未认证流
            // read_target，白白多占连接额度 10s，fallback 开启时还会写出
            // 第二份 HTTP 响应拼在第一份之后。
            debug!("TCP Noise handshake timed out");
            return;
        }
    }

    // ── 第 4 步：地址帧（已认证，读失败按协议失步按开关回退页/静默关流）
    let target = match tokio::time::timeout(AUTH_TIMEOUT, read_target(&mut rd)).await {
        Ok(Ok(t)) => t,
        _ => {
            debug!("TCP stream bad target frame");
            // 已通过 Noise 认证后的失步：真客户端不会走到这里，回退页/静默均可
            if fallback_page {
                let _ = crate::fallback::http_serve_fallback(&mut wr).await;
            } else {
                debug!("closing silently (fallback_page off)");
            }
            return;
        }
    };

    // ── 第 5 步（分流）：信令保留前缀 → 信令会话；其余走普通目标路径
    if let Some(registry) = signal_registry {
        if let Some(peer_id) = target.strip_prefix(P2P_SIGNAL_PREFIX) {
            if !validate_peer_id(peer_id) {
                debug!(
                    "信令目标 peer_id 非法（{}），静默关流",
                    mask_target(&target)
                );
                return;
            }
            // 与普通目标路径对称：先回 2B OK（客户端认证路径读完应答才进入信令收发）
            if write_reply(&mut wr, REPLY_OK).await.is_err() {
                return;
            }
            // 信令会话：读超时 90s 覆盖空闲（serve_signal_stream 内部看门狗）；
            // auth_key 供 register 属主 proof 的独立复算校验（防 peer_id 冒用顶替）
            signal::serve_signal_stream(
                registry,
                peer_id.to_string(),
                handler.auth_key().to_vec(),
                rd,
                wr,
            )
            .await;
            return;
        }
    }

    // ── 第 5.5 步（分流）：UDP 中继保留前缀 → UDP 会话多路复用（同款模式见
    // `@hydra-p2p/` 信令分流）。回 2B OK 后该流不再走 TCP 目标转发，改承载
    // hydra_protocol::udp_frame 定义的变长 UDP 会话帧；空闲/资源/SSRF 语义见
    // udp_relay 模块文档。普通 TCP 目标路径零改动。
    if target.strip_prefix(crate::udp_relay::UDP_RELAY_PREFIX).is_some() {
        if write_reply(&mut wr, REPLY_OK).await.is_err() {
            return;
        }
        crate::udp_relay::serve(rd, wr).await;
        return;
    }

    // ── 第 6 步：SSRF 过滤 + DNS + 建目标（复用 handler 逻辑）
    let target_stream = match ConnectionHandler::resolve_and_connect(&target).await {
        Ok(s) => s,
        Err((code, e)) => {
            debug!(
                "TCP target failure (code 0x{:02x}) for {}: {}",
                code,
                mask_target(&target),
                e
            );
            let reply = if code == crate::handler::ERR_DNS_FAIL {
                REPLY_DNS_FAIL
            } else {
                REPLY_TARGET_FAIL
            };
            let _ = write_reply(&mut wr, reply).await;
            return;
        }
    };

    // ── 第 7 步：成功应答 + 双向裸转发（带半关闭语义，验收门③ + idle 看门狗）
    if write_reply(&mut wr, REPLY_OK).await.is_err() {
        return;
    }
    // 07-P2-4：idle 超时由监听器启动时注入（显式注入优先于 env）
    let idle = *idle;
    // 双向共享的最后活跃时间戳（AtomicU64 毫秒）：任一方向读到数据即刷新，
    // 空闲判定看「连接整体」而非单方向——否则长下载/长上传（单方向连续数百秒
    // 纯接收）会在 idle 处被误杀。
    let last_active = Arc::new(std::sync::atomic::AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    ));
    let (c2t, t2c) = {
        let (t_rd, t_wr) = tokio::io::split(target_stream);
        // 审查 06-P2-2：两泵共享退出通知——任一泵结束（EOF/错误/idle）即唤醒对侧，
        // 对侧 shutdown 自己的写端并退出，避免 join! 下另一方向空挂至 idle 超时、
        // 白白占用连接额度与 fd。
        let exit_notify = Arc::new(tokio::sync::Notify::new());
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::join!(
            pump(
                rd,
                t_wr,
                idle,
                last_active.clone(),
                exit_notify.clone(),
                exited.clone()
            ),
            pump(t_rd, wr, idle, last_active, exit_notify, exited)
        )
    };
    let (up, down) = (c2t.unwrap_or(0), t2c.unwrap_or(0));
    info!(
        "TCP connection to {} closed (Client->Target: {} bytes, Target->Client: {} bytes)",
        mask_target(&target),
        up,
        down
    );
}

/// 单向泵：持续转发直至源 EOF，然后显式 shutdown 写端（半关闭：让对端读到
/// EOF 而非保持挂起——copy_bidirectional 的语义等价实现，tokio 1.53 的
/// split 两半无 reunite，故手写）。
///
/// `idle` + `last_active` 组成连接级空闲看门狗：两个方向的 pump 共享同一
/// 最后活跃时间戳，任一方向读到数据即刷新；只有连接整体（双向均）超过 `idle`
/// 无数据才 shutdown 写端并结束（审查：无 idle 超时时已认证零流量连接可
/// 无限期占用连接额度与 fd；单方向独立计时会误杀长下载/长上传）。
///
/// `peer_exit`/`peer_done`（审查 06-P2-2）：对侧泵结束（EOF/错误/idle）时置位
/// 并通知本侧立即 shutdown 退出；写错误路径不再跳过 shutdown——所有出口
/// （EOF/错误/idle/对侧退出）统一走到 shutdown 后返回。
async fn pump<R, W>(
    mut r: R,
    mut w: W,
    idle: std::time::Duration,
    last_active: Arc<std::sync::atomic::AtomicU64>,
    peer_exit: Arc<tokio::sync::Notify>,
    peer_done: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    let mut total = 0u64;
    let mut buf = vec![0u8; 16 * 1024]; // 与 TLS 1.3 单记录上限对齐（审查 R-14 同源）
    let result = loop {
        // 对侧泵已结束：立即收尾（下行先结束/写错误等场景不再空挂）
        if peer_done.load(Ordering::Relaxed) {
            break Ok(total);
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = last_active.load(Ordering::Relaxed);
        let idle_ms = idle.as_millis() as u64;
        if now_ms.saturating_sub(last) >= idle_ms {
            debug!(
                "relay idle timeout ({}s), closing connection",
                idle.as_secs()
            );
            break Ok(total);
        }
        // read 包超时兜底唤醒（到期后由上方共享时间戳判定是否真正全局空闲）；
        // 对侧退出通知可随时打断阻塞中的 read
        let budget = idle_ms - now_ms.saturating_sub(last);
        let n = tokio::select! {
            biased;
            _ = peer_exit.notified() => {
                if peer_done.load(Ordering::Relaxed) {
                    break Ok(total);
                }
                continue;
            }
            x = tokio::time::timeout(
                std::time::Duration::from_millis(budget),
                r.read(&mut buf),
            ) => {
                match x {
                    Ok(x) => match x {
                        Ok(n) => n,
                        Err(e) => break Err(e), // 读错误：记录后在统一出口 shutdown
                    },
                    Err(_) => continue, // 超时醒来：回到循环顶部按共享时间戳重新判定
                }
            }
        };
        if n == 0 {
            break Ok(total); // 源 EOF → 半关闭：shutdown 写端
        }
        // 任一方向读到数据：刷新共享时间戳（另一方向的空闲计时随之重置）
        last_active.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            Ordering::Relaxed,
        );
        if let Err(e) = w.write_all(&buf[..n]).await {
            break Err(e); // 写错误（审查 06-P2-2）：不再直接 ? 跳过 shutdown
        }
        total += n as u64;
    };
    // 统一出口：EOF/错误/idle/对侧退出——一律 shutdown 写端。
    // 注意（半关闭语义）：EOF 正常结束**不**通知对侧——对侧方向仍需继续排水
    // 直至自身 EOF/idle（否则下行在途数据被截断，回环回显测试可复现）。
    // 仅在**错误**路径通知对侧立即收尾（审查 06-P2-2：写错误后连接已死，
    // 对侧不再空挂至 idle 超时）。
    let _ = w.shutdown().await;
    if result.is_err() {
        peer_done.store(true, Ordering::Relaxed);
        peer_exit.notify_one();
    }
    result.map(|_| total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 双 pump 共享时间戳：一个方向持续活跃（读到数据刷新共享时间戳），另一个
    /// 方向长期静默——静默方向不得因自己的空闲计时被关闭；活跃方停止后双向均
    /// 静默达到 idle，两个 pump 都应结束。
    #[tokio::test]
    async fn pump_共享活跃时间戳_单方向静默不误杀() {
        use std::sync::atomic::AtomicU64;
        use tokio::io::duplex;

        fn now_ms() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        }

        let last_active = Arc::new(AtomicU64::new(now_ms()));
        let idle = std::time::Duration::from_millis(300);

        // 活跃方向：测试侧持续往 a_cli 写 → pump_a 读 a_srv 刷新时间戳
        let (mut a_cli, a_srv) = duplex(64);
        // 静默方向：b_cli 由测试持有（不写不关）→ pump_b 读 b_srv 永远 pending
        let (_b_cli, b_srv) = duplex(64);

        let exit_notify = Arc::new(tokio::sync::Notify::new());
        let peer_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pump_b = tokio::spawn(pump(
            b_srv,
            tokio::io::sink(),
            idle,
            last_active.clone(),
            exit_notify.clone(),
            peer_done.clone(),
        ));
        let pump_a = tokio::spawn(pump(
            a_srv,
            tokio::io::sink(),
            idle,
            last_active,
            exit_notify,
            peer_done,
        ));

        // 静默 pump 运行 1s（约为 idle 的 3 倍），期间活跃 pump 持续喂数据
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            use tokio::io::AsyncWriteExt;
            if a_cli.write_all(b"x").await.is_err() {
                break; // 活跃 pump 已结束
            }
            let _ = a_cli.flush().await;
        }

        // 静默方向 pump 不应因「自身方向空闲超过 idle」而提前结束
        assert!(
            !pump_b.is_finished(),
            "单方向静默不应触发连接级空闲关闭（共享时间戳被活跃方向持续刷新）"
        );

        // 活跃方停止后，双向静默超过 idle：两个 pump 都应结束
        drop(a_cli);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let _ = pump_a.await;
            let _ = pump_b.await;
        })
        .await
        .expect("双向静默达到 idle 后 pump 应结束");
    }
}
