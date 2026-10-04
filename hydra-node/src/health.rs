//! 极小 TCP/HTTP 健康检查端点（可选，默认关闭）。
//!
//! 背景（docs/assessment/部署运维评估.md）：节点是纯 QUIC/UDP，
//! 无任何 TCP 监听，负载均衡/拨测/存活检查无法接入。本模块用
//! std `format!` 手写最小 HTTP 响应（不引入 HTTP 框架依赖）。
//!
//! - 环境变量 `HYDRA_HEALTH_ADDR`（如 `127.0.0.1:8081`）；未设置 = 关闭。
//! - `GET /health` → 200 + JSON：
//!   `{"status":"ok","mode":"masquerade","uptime_secs":N,"version":"x.y.z","public_addr":...}`
//!   `public_addr` 来自 STUN 公网地址发现（`HYDRA_STUN_ADDR` 配置时由
//!   stun.rs 后台任务填充）；未配置/失败时为 `null`。旧字段顺序不变，
//!   只在尾部追加，向后兼容。
//! - 其他路径 → 404；`/health` 上的非 GET 方法 → 405。
//! - 健康端点只应绑定回环地址（127.0.0.1），不要暴露到公网——
//!   uptime/version/public_addr 虽非机密，但公网开放多一个可扫描面。
//! - 独立 listener + 独立 task，不阻塞 QUIC 的 `endpoint.accept()` 循环。

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{info, warn};

/// STUN 公网映射地址的共享槽位：stun.rs 后台任务写入，HTTP 响应读取。
/// std RwLock 足够（临界区仅一次 Option 拷贝），不需要 tokio 锁。
pub type SharedPublicAddr = Arc<RwLock<Option<SocketAddr>>>;

/// 创建空槽位（public_addr = null）
pub fn new_public_addr_slot() -> SharedPublicAddr {
    Arc::new(RwLock::new(None))
}

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
/// `public_addr`：STUN 发现的公网映射地址；None → `"public_addr":null`。
pub fn build_response(
    method: &str,
    path: &str,
    mode: &str,
    uptime_secs: u64,
    public_addr: Option<SocketAddr>,
) -> String {
    if path == "/health" {
        if !method.eq_ignore_ascii_case("GET") {
            return simple_response(
                405,
                "Method Not Allowed",
                "text/plain",
                "method not allowed\n",
            );
        }
        // mode/version/公网地址均为受控字符串（SocketAddr Display），无需 JSON 转义
        let pub_json = match public_addr {
            Some(a) => format!("\"{}\"", a),
            None => "null".to_string(),
        };
        let body = format!(
            "{{\"status\":\"ok\",\"mode\":\"{}\",\"uptime_secs\":{},\"version\":\"{}\",\"public_addr\":{}}}",
            mode,
            uptime_secs,
            env!("CARGO_PKG_VERSION"),
            pub_json
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
    mode: String,
    started: Instant,
    public_addr: SharedPublicAddr,
}

impl HealthServer {
    pub fn new(addr: SocketAddr, mode: String, public_addr: SharedPublicAddr) -> Self {
        Self {
            addr,
            mode,
            started: Instant::now(),
            public_addr,
        }
    }

    /// 绑定并 spawn 独立 accept 循环（QUIC accept 循环不受影响）。
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
                        let mode = self.mode.clone();
                        let started = self.started;
                        let public_addr = self.public_addr.clone();
                        tokio::spawn(Self::serve_one(stream, mode, started, public_addr));
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
    async fn serve_one(
        mut stream: tokio::net::TcpStream,
        mode: String,
        started: Instant,
        public_addr: SharedPublicAddr,
    ) {
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
        let pub_addr = *public_addr.read().expect("public_addr 锁中毒");
        let resp = build_response(method, path, &mode, started.elapsed().as_secs(), pub_addr);
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试用公网地址样例（203.0.113.0/24 文档段）
    fn addr() -> Option<SocketAddr> {
        Some(SocketAddr::from(([203, 0, 113, 7], 45000)))
    }

    #[test]
    fn health_ok_json_format() {
        let resp = build_response("GET", "/health", "masquerade", 42, None);
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Type: application/json\r\n"));
        // 头部结束于空行，随后是 body
        let (headers, body) = resp.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains("Connection: close"));
        assert_eq!(
            body,
            format!(
                "{{\"status\":\"ok\",\"mode\":\"masquerade\",\"uptime_secs\":42,\"version\":\"{}\",\"public_addr\":null}}",
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
    fn health_ok_obfs_mode() {
        let resp = build_response("GET", "/health", "obfs", 0, None);
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("\"mode\":\"obfs\""));
        assert!(resp.contains("\"uptime_secs\":0"));
        assert!(resp.contains("\"status\":\"ok\""));
    }

    #[test]
    fn public_addr_field_present_when_discovered() {
        let resp = build_response("GET", "/health", "masquerade", 1, addr());
        assert!(resp.contains("\"public_addr\":\"203.0.113.7:45000\""));
        assert!(!resp.contains("\"public_addr\":null"));
        // 旧字段顺序不动（向后兼容：status/mode/uptime_secs/version 在前）
        let (headers, body) = resp.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        let status_pos = body.find("\"status\"").unwrap();
        let pub_pos = body.find("\"public_addr\"").unwrap();
        assert!(status_pos < pub_pos);
    }

    #[test]
    fn public_addr_null_when_not_configured() {
        let resp = build_response("GET", "/health", "masquerade", 1, None);
        assert!(resp.contains("\"public_addr\":null"));
    }

    #[test]
    fn other_path_is_404() {
        let resp = build_response("GET", "/", "masquerade", 1, None);
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let resp = build_response("GET", "/healthz", "masquerade", 1, None);
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn non_get_on_health_is_405() {
        let resp = build_response("POST", "/health", "masquerade", 1, None);
        assert!(resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let resp = build_response("HEAD", "/health", "masquerade", 1, None);
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

    #[test]
    fn public_addr_slot_default_is_empty() {
        let slot = new_public_addr_slot();
        assert!(*slot.read().unwrap() == None);
        *slot.write().unwrap() = addr();
        assert_eq!(*slot.read().unwrap(), addr());
    }
}
