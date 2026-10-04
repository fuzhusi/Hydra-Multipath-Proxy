use hydra_protocol::{mask_target, AuthToken, HydraError, Result, CLIENT_ID};
use quinn::{Connection, VarInt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// 认证失败时静默关闭（不回显任何可区分的错误码，抵御主动探测）
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// 连接级认证宽限：宽限期内没有任何流完成认证则强制断开，
/// 防止未认证连接靠 keepalive 永久占用连接数配额
const AUTH_GRACE: Duration = Duration::from_secs(10);
/// 单个流允许的最大目标地址长度
const MAX_ADDR_LEN: usize = 256;

// ── 已认证流的应用层错误码（QUIC 应用错误码，RFC 9000 §20.2 对应用码无约束）──
// 仅在流完成认证后使用；客户端经 ReadError::Reset 读到后可区分"节点故障/目标故障"。
// 未认证路径保持零字节静默，不回显任何码（防主动探测）。
/// 0x11：节点无法连接目标（连接被拒/超时）
pub const ERR_TARGET_CONNECT: u32 = 0x11;
/// 0x12：节点侧 DNS 解析失败
pub const ERR_DNS_FAIL: u32 = 0x12;
/// 0x13：转发阶段 IO 错误（目标连接中断等）
pub const ERR_FORWARD_IO: u32 = 0x13;

/// 已认证流故障的显式中止：RESET_STREAM（对端读到 ReadError::Reset(code)）
/// + STOP_SENDING（对端 write 得到 WriteError::Stopped(code)），
/// 替代曾经的"静默 drop send"——那会产生优雅 FIN，客户端误把中断当正常结束。
fn abort_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u32) {
    let var_code = VarInt::from_u32(code);
    let _ = send.reset(var_code);
    let _ = recv.stop(var_code);
}

pub struct ConnectionHandler {
    auth_key: Vec<u8>,
}

impl ConnectionHandler {
    pub fn new(auth_key: Vec<u8>) -> Self {
        Self { auth_key }
    }

    pub async fn handle_connection(&self, connection: Connection) -> Result<()> {
        debug!("Waiting for bidirectional stream from client...");
        let authed = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let authed = authed.clone();
            let conn = connection.clone();
            tokio::spawn(async move {
                tokio::time::sleep(AUTH_GRACE).await;
                if !authed.load(Ordering::Relaxed) {
                    info!("Connection failed to authenticate within grace period, closing");
                    conn.close(0u32.into(), b"auth timeout");
                }
            })
        };

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    debug!("Accepted bidirectional stream, spawning handler");
                    let auth_key = self.auth_key.clone();
                    let authed = authed.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_stream(send, recv, auth_key, authed).await {
                            error!("Stream error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Connection closed by client");
                    break;
                }
                Err(e) => {
                    error!("Connection error: {}", e);
                    break;
                }
            }
        }

        watchdog.abort();
        Ok(())
    }

    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        auth_key: Vec<u8>,
        authed: Arc<AtomicBool>,
    ) -> Result<()> {
        // ── 第 1 步：认证。固定 64 字节 token，超时或验证失败一律静默关流。
        let mut token = [0u8; AuthToken::TOKEN_LEN];
        let valid = match tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut token)).await {
            Ok(Ok(())) => AuthToken::verify(&auth_key, &token, CLIENT_ID, 30).is_ok(),
            _ => false,
        };
        if !valid {
            debug!("Stream failed authentication, closing silently");
            return Ok(());
        }
        authed.store(true, Ordering::Relaxed);

        // ── 第 2 步：读取目标地址（2 字节大端长度前缀 + 内容），修复单次 read 可能截断的问题。
        let mut len_buf = [0u8; 2];
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut len_buf))
            .await
            .is_err()
        {
            return Ok(());
        }
        let addr_len = u16::from_be_bytes(len_buf) as usize;
        if addr_len == 0 || addr_len > MAX_ADDR_LEN {
            debug!("Invalid address length: {}", addr_len);
            return Ok(());
        }
        let mut addr_buf = vec![0u8; addr_len];
        if tokio::time::timeout(AUTH_TIMEOUT, recv.read_exact(&mut addr_buf))
            .await
            .is_err()
        {
            return Ok(());
        }
        let target_addr_str = String::from_utf8_lossy(&addr_buf).to_string();
        // 日志脱敏（防追踪性）：info 级一律短哈希，完整明文仅 debug 级（RUST_LOG=debug）可见
        info!("Received target address: {}", mask_target(&target_addr_str));
        debug!("Received target address (plaintext): {}", target_addr_str);

        // ── 第 3 步：解析为 SocketAddr，否则节点侧 DNS 解析
        let target_addr: std::net::SocketAddr = if let Ok(addr) = target_addr_str.parse() {
            addr
        } else {
            info!("Resolving DNS for: {}", mask_target(&target_addr_str));
            match tokio::net::lookup_host(target_addr_str.to_string()).await {
                Ok(addrs) => {
                    let addrs_vec: Vec<_> = addrs.collect();
                    // 优先使用 IPv4 地址
                    let ipv4_addr = addrs_vec.iter().find(|a| a.is_ipv4());
                    match ipv4_addr {
                        Some(a) => *a,
                        None => match addrs_vec.first() {
                            Some(a) => *a,
                            None => {
                                error!(
                                    "DNS resolution failed for {}: no addresses",
                                    target_addr_str
                                );
                                // 显式错误码 0x12 = 节点侧 DNS 解析失败
                                abort_stream(&mut send, &mut recv, ERR_DNS_FAIL);
                                return Err(HydraError::ConnectionError(format!(
                                    "DNS resolution failed for {}",
                                    target_addr_str
                                )));
                            }
                        },
                    }
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", target_addr_str, e);
                    // 显式错误码 0x12 = 节点侧 DNS 解析失败
                    abort_stream(&mut send, &mut recv, ERR_DNS_FAIL);
                    return Err(HydraError::ConnectionError(format!(
                        "DNS resolution failed for {}: {}",
                        target_addr_str, e
                    )));
                }
            }
        };

        info!(
            "Connecting to target: {} (with 15s timeout)",
            mask_target(&target_addr.to_string())
        );
        let connect_start = std::time::Instant::now();

        // Connect to target with timeout（须小于客户端 20s 应答超时，否则慢目标被误判为节点故障）
        let target_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(target_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let elapsed = connect_start.elapsed();
                info!(
                    "Connected to target: {} (took {}ms)",
                    mask_target(&target_addr.to_string()),
                    elapsed.as_millis()
                );
                // Send success response
                send.write_all(&[0x00, 0x00])
                    .await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                stream
            }
            Ok(Err(e)) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Failed to connect to {}: {} (took {}ms)",
                    target_addr,
                    e,
                    elapsed.as_millis()
                );
                // 显式错误码 0x11 = 节点无法连接目标
                abort_stream(&mut send, &mut recv, ERR_TARGET_CONNECT);
                return Err(HydraError::ConnectionError(format!(
                    "Failed to connect to {}: {}",
                    target_addr, e
                )));
            }
            Err(_) => {
                let elapsed = connect_start.elapsed();
                error!(
                    "Timeout connecting to {} ({}ms)",
                    target_addr,
                    elapsed.as_millis()
                );
                // 显式错误码 0x11 = 节点无法连接目标
                abort_stream(&mut send, &mut recv, ERR_TARGET_CONNECT);
                return Err(HydraError::ConnectionError(format!(
                    "Timeout connecting to {}",
                    target_addr
                )));
            }
        };

        // Forward traffic bidirectionally (不记录每个数据包，只记录汇总信息)
        let (mut target_read, mut target_write) = target_stream.into_split();

        // 任一方向转发故障时唤醒另一方向立即显式清理，避免孤儿任务死等
        let (fail_tx, fail_rx) = tokio::sync::watch::channel(false);

        // 客户端 → 目标（拥有 recv 与 target_write）
        let quic_to_target = tokio::spawn({
            let mut fail_rx = fail_rx.clone();
            let fail_tx = fail_tx.clone();
            async move {
                let mut buf = vec![0u8; 65536];
                let mut total_bytes: u64 = 0;
                loop {
                    let n = tokio::select! {
                        r = recv.read(&mut buf) => match r {
                            // 客户端 FIN：半关闭——保留目标→客户端方向继续转发剩余响应
                            Ok(Some(0)) | Ok(None) => return Ok(total_bytes),
                            // 客户端中止其发送侧（Reset）：等同关闭，不算故障
                            Err(quinn::ReadError::Reset(_)) => return Ok(total_bytes),
                            Ok(Some(n)) => n,
                            // 连接级/传输层故障：连接即将消亡，停止转发
                            Err(_) => return Err(total_bytes),
                        },
                        _ = fail_rx.changed() => {
                            // 对侧转发故障：显式 STOP_SENDING(0x13)，客户端 write 侧得到 WriteError::Stopped(0x13)
                            let _ = recv.stop(VarInt::from_u32(ERR_FORWARD_IO));
                            return Err(total_bytes);
                        }
                    };
                    total_bytes += n as u64;
                    if target_write.write_all(&buf[..n]).await.is_err() {
                        let _ = fail_tx.send(true);
                        return Err(total_bytes);
                    }
                }
            }
        });

        // 目标 → 客户端（拥有 send 与 target_read）
        let target_to_quic = tokio::spawn({
            let mut fail_rx = fail_rx;
            async move {
                let mut buf = vec![0u8; 65536];
                let mut total_bytes: u64 = 0;
                loop {
                    let n = tokio::select! {
                        r = target_read.read(&mut buf) => match r {
                            // 目标 FIN：优雅关闭到客户端的发送侧
                            Ok(0) => {
                                let _ = send.finish().await;
                                return Ok(total_bytes);
                            }
                            Ok(n) => n,
                            Err(_) => {
                                // 目标侧 IO 错误：显式 RESET_STREAM(0x13)，客户端读到 ReadError::Reset(0x13)
                                let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                                let _ = fail_tx.send(true);
                                return Err(total_bytes);
                            }
                        },
                        _ = fail_rx.changed() => {
                            // 对侧转发故障：显式 RESET_STREAM(0x13)
                            let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                            return Err(total_bytes);
                        }
                    };
                    total_bytes += n as u64;
                    if send.write_all(&buf[..n]).await.is_err() {
                        let _ = send.reset(VarInt::from_u32(ERR_FORWARD_IO));
                        let _ = fail_tx.send(true);
                        return Err(total_bytes);
                    }
                }
            }
        });

        let (quic_res, target_res) = tokio::join!(quic_to_target, target_to_quic);
        let is_fail = |r: &std::result::Result<
            std::result::Result<u64, u64>,
            tokio::task::JoinError,
        >| { !matches!(r, Ok(Ok(_))) };
        let forward_failed = is_fail(&quic_res) || is_fail(&target_res);
        if forward_failed {
            info!(
                "Forwarding to {} aborted with app error 0x{:02x}",
                mask_target(&target_addr.to_string()),
                ERR_FORWARD_IO
            );
            return Err(HydraError::ConnectionError(format!(
                "forwarding IO error for {}",
                target_addr
            )));
        }

        let (quic_bytes, target_bytes) = (
            quic_res.ok().and_then(|r| r.ok()).unwrap_or(0),
            target_res.ok().and_then(|r| r.ok()).unwrap_or(0),
        );
        info!(
            "Connection to {} closed (QUIC->Target: {} bytes, Target->QUIC: {} bytes)",
            mask_target(&target_addr.to_string()),
            quic_bytes, target_bytes
        );
        Ok(())
    }
}
