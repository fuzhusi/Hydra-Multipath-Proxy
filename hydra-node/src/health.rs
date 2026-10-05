//! 极小 TCP/HTTP 健康检查端点（可选，默认关闭）。
//!
//! TCP 转型（Wave 3）后节点唯一传输 = TCP/TLS，本模块不变；STUN 公网地址
//! 发现已随 QUIC/UDP 死路径移除，响应中不再有 `public_addr` 字段，
//! `mode` 固定为 `"tcp"`。
//!
//! - 环境变量 `HYDRA_HEALTH_ADDR`（如 `127.0.0.1:8081`）；未设置 = 关闭。
//! - `GET /health` → 200 + JSON：
//!   `{"status":"ok","mode":"tcp","uptime_secs":N,"version":"x.y.z"}`
//! - 其他路径 → 404；`/health` 上的非 GET 方法 → 405。
//! - 健康端点只应绑定回环地址（127.0.0.1），不要暴露到公网——
//!   uptime/version 虽非机密，但公网开放多一个可扫描面。
//! - 独立 listener + 独立 task，不阻塞主监听循环。

use std::net::SocketAddr;
use std::time::Instant;
use tracing::{info, warn};

/// 健康端点地址的环境变量名
pub const HYDRA_HEALTH_ADDR_ENV: &str = "HYDRA_HEALTH_ADDR";

/// 解析健康端点地址（非法值显式报错——静默关闭会让"以为开了健康检查"的用户得到黑洞）
pub fn parse_health_addr(v: &str) -> Result<SocketAddr, String> {
    v.trim().parse::<SocketAddr>().map_err(|e| {
        format!(
            "{} 非法（期望形如 127.0.0.1:8081）: {}",
            HYDRA_HEALTH_ADDR_ENV, e
        )
    })
}

/// 从环境变量读取；未设置/空 = None（关闭）
pub fn health_addr_from_env() -> Result<Option<SocketAddr>, String> {
    match std::env::var(HYDRA_HEALTH_ADDR_ENV) {
        Ok(v) if !v.trim().is_empty() => parse_health_addr(&v).map(Some),
        _ => Ok(None),
    }
}

/// 构造完整 HTTP 响应文本（纯函数，无网络也可单测）。
/// 传输模式固定 `"tcp"`（TCP 为唯一传输）。
pub fn build_response(method: &str, path: &str, uptime_secs: u64) -> String {
    if path == "/health" {
        if !method.eq_ignore_ascii_case("GET") {
            return simple_response(
                405,
                "Method Not Allowed",
                "text/plain",
                "method not allowed\n",
            );
        }
        let body = format!(
            "{{\"status\":\"ok\",\"mode\":\"tcp\",\"uptime_secs\":{},\"version\":\"{}\"}}",
            uptime_secs,
            env!("CARGO_PKG_VERSION")
        );
        simple_response(200, "OK", "application/json", &body)
    } else {
        simple_response(404, "Not Found", "text/plain", "not found\n")
    }
}

fn simple_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason,
        content_type,
        body.len(),
        body
    )
}

/// 健康检查服务器：绑定独立 TCP listener 并 spawn 后台 accept 循环
pub struct HealthServer {
    addr: SocketAddr,
    started: Instant,
}

impl HealthServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            started: Instant::now(),
        }
    }

    /// 绑定并 spawn 独立 accept 循环（主 TCP 监听循环不受影响）。
    /// 绑定失败返回 Err（调用方应显式退出：显式配置的地址起不来，
    /// 静默吞掉会让运维以为拨测已接入）。
    pub async fn spawn(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        info!(
            "Health endpoint listening on http://{} (/health)",
            self.addr
        );
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _peer)) => {
                        let started = self.started;
                        tokio::spawn(Self::serve_one(stream, started));
                    }
                    Err(e) => {
                        // 瞬时错误（如 fd 耗尽）：记日志稍后重试，不让健康检查循环死掉
                        warn!("Health endpoint accept error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        Ok(())
    }

    /// 处理单个连接：只读首行请求行，写响应即关闭（不处理 body/keep-alive）
    async fn serve_one(mut stream: tokio::net::TcpStream, started: Instant) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // 首行足够；上限 1KB 防御异常客户端
        let mut buf = vec![0u8; 1024];
        let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        let request_line = req.lines().next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let full_path = parts.next().unwrap_or("");
        let path = full_path.split('?').next().unwrap_or("");
        let resp = build_response(method, path, started.elapsed().as_secs());
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok_json_format() {
        let resp = build_response("GET", "/health", 42);
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Type: application/json\r\n"));
        // 头部结束于空行，随后是 body
        let (headers, body) = resp.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains("Connection: close"));
        assert_eq!(
            body,
            format!(
                "{{\"status\":\"ok\",\"mode\":\"tcp\",\"uptime_secs\":42,\"version\":\"{}\"}}",
                env!("CARGO_PKG_VERSION")
            )
        );
        // Content-Length 与 body 字节数一致
        let cl: usize = resp
            .lines()
            .find(|l| l.starts_with("Content-Length: "))
            .unwrap()
            .trim_start_matches("Content-Length: ")
            .parse()
            .unwrap();
        assert_eq!(cl, body.len());
    }

    #[test]
    fn mode_is_always_tcp() {
        assert!(build_response("GET", "/health", 0).contains("\"mode\":\"tcp\""));
    }

    #[test]
    fn other_path_is_404() {
        let resp = build_response("GET", "/", 1);
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let resp = build_response("GET", "/healthz", 1);
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn non_get_on_health_is_405() {
        let resp = build_response("POST", "/health", 1);
        assert!(resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let resp = build_response("HEAD", "/health", 1);
        assert!(resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    }

    #[test]
    fn parse_health_addr_valid_and_invalid() {
        let a = parse_health_addr("127.0.0.1:8081").unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:8081");
        assert!(parse_health_addr("127.0.0.1").is_err());
        assert!(parse_health_addr("not-an-addr").is_err());
        assert!(parse_health_addr("localhost:8081").is_err()); // 只接受字面量，不做 DNS
    }

    #[test]
    fn health_addr_from_env_unset_is_none() {
        // 未设置 = 关闭（本测试进程不设该变量；若并发测试设置了也会解析成功，仅断言不 panic）
        let r = health_addr_from_env();
        assert!(r.is_ok());
    }
}
