use quinn::Connection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, error};
use hydra_protocol::{AuthToken, CLIENT_ID, HydraError, Result};

/// 认证失败时静默关闭（不回显任何可区分的错误码，抵御主动探测）
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// 连接级认证宽限：宽限期内没有任何流完成认证则强制断开，
/// 防止未认证连接靠 keepalive 永久占用连接数配额
const AUTH_GRACE: Duration = Duration::from_secs(10);
/// 单个流允许的最大目标地址长度
const MAX_ADDR_LEN: usize = 256;

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
        info!("Received target address: {}", target_addr_str);

        // ── 第 3 步：解析为 SocketAddr，否则节点侧 DNS 解析
        let target_addr: std::net::SocketAddr = if let Ok(addr) = target_addr_str.parse() {
            addr
        } else {
            info!("Resolving DNS for: {}", target_addr_str);
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
                                error!("DNS resolution failed for {}: no addresses", target_addr_str);
                                // 返回特殊错误码 0x02 = DNS 解析失败
                                send.write_all(&[0x02, 0x00]).await
                                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                                return Err(HydraError::ConnectionError(format!("DNS resolution failed for {}", target_addr_str)));
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", target_addr_str, e);
                    // 返回特殊错误码 0x02 = DNS 解析失败
                    send.write_all(&[0x02, 0x00]).await
                        .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                    return Err(HydraError::ConnectionError(format!("DNS resolution failed for {}: {}", target_addr_str, e)));
                }
            }
        };

        info!("Connecting to target: {} (with 15s timeout)", target_addr);
        let connect_start = std::time::Instant::now();

        // Connect to target with timeout（须小于客户端 20s 应答超时，否则慢目标被误判为节点故障）
        let target_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(target_addr)
        ).await {
            Ok(Ok(stream)) => {
                let elapsed = connect_start.elapsed();
                info!("Connected to target: {} (took {}ms)", target_addr, elapsed.as_millis());
                // Send success response
                send.write_all(&[0x00, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                stream
            }
            Ok(Err(e)) => {
                let elapsed = connect_start.elapsed();
                error!("Failed to connect to {}: {} (took {}ms)", target_addr, e, elapsed.as_millis());
                // Send failure response
                send.write_all(&[0x01, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                return Err(HydraError::ConnectionError(format!("Failed to connect to {}: {}", target_addr, e)));
            }
            Err(_) => {
                let elapsed = connect_start.elapsed();
                error!("Timeout connecting to {} ({}ms)", target_addr, elapsed.as_millis());
                // Send failure response
                send.write_all(&[0x01, 0x00]).await
                    .map_err(|e| HydraError::ProtocolError(format!("Write error: {}", e)))?;
                return Err(HydraError::ConnectionError(format!("Timeout connecting to {}", target_addr)));
            }
        };

        // Forward traffic bidirectionally (不记录每个数据包，只记录汇总信息)
        let (mut target_read, mut target_write) = target_stream.into_split();

        let quic_to_target = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total_bytes: u64 = 0;
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => {
                        total_bytes += n as u64;
                        if target_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            total_bytes
        });

        let target_to_quic = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total_bytes: u64 = 0;
            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total_bytes += n as u64;
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            total_bytes
        });

        // Wait for either direction to finish
        let (quic_bytes, target_bytes) = tokio::join!(quic_to_target, target_to_quic);

        info!("Connection to {} closed (QUIC->Target: {} bytes, Target->QUIC: {} bytes)",
            target_addr,
            quic_bytes.unwrap_or(0),
            target_bytes.unwrap_or(0)
        );
        Ok(())
    }
}
