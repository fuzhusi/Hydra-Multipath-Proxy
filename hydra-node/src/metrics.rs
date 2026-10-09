//! 进程级指标（Prometheus 文本格式，挂 `/metrics`，随健康端点开关）。
//!
//! - 无第三方依赖：手写文本渲染（OpenMetrics 基本型：`# HELP/# TYPE` + 样本行）；
//! - 计数面（全部原子，热路径 `fetch_add` 零锁）：
//!   - `hydra_connections_total`：TCP accept 成功数
//!   - `hydra_connections_active`：当前在服务连接数（任务进出守卫）
//!   - `hydra_connections_rejected_total`：per-IP 超限 / 连接额度耗尽拒入数
//!   - `hydra_target_connect_ok_total` / `hydra_target_connect_fail_total`：
//!     目标建连成败（含 DNS/SSRF/超时）
//!   - `hydra_udp_relay_connections_total`：UDP 中继连接进入数
//! - 暴露建议：与 `/health` 同端口同访问策略（只绑回环，或置于内网/反代之后），
//!   Prometheus 抓 `/metrics`，Grafana 出面板。
//!
//! 渲染纯函数化（`render` 无网络依赖）可单测。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// 进程级指标单例（热路径无锁自增）
pub struct Metrics {
    pub conn_total: AtomicU64,
    pub conn_active: AtomicU64,
    pub conn_rejected: AtomicU64,
    pub target_ok: AtomicU64,
    pub target_fail: AtomicU64,
    pub udp_relay_total: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            conn_total: AtomicU64::new(0),
            conn_active: AtomicU64::new(0),
            conn_rejected: AtomicU64::new(0),
            target_ok: AtomicU64::new(0),
            target_fail: AtomicU64::new(0),
            udp_relay_total: AtomicU64::new(0),
        }
    }
}

pub fn metrics() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(Metrics::new)
}

/// 连接活跃守卫：构造 +1、drop -1（panic 展开路径同样归位）
pub struct ActiveGuard;

impl ActiveGuard {
    pub fn enter() -> Self {
        metrics().conn_active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        metrics().conn_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 渲染 Prometheus 文本格式（`uptime_secs`/`version` 由调用方注入与
/// `/health` 同源）。字段顺序稳定，便于面板/告警规则 diff。
pub fn render(uptime_secs: u64) -> String {
    let m = metrics();
    let v = env!("CARGO_PKG_VERSION");
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    format!(
        concat!(
            "# HELP hydra_up Node process is up.\n",
            "# TYPE hydra_up gauge\n",
            "hydra_up 1\n",
            "# HELP hydra_uptime_seconds Process uptime in seconds.\n",
            "# TYPE hydra_uptime_seconds gauge\n",
            "hydra_uptime_seconds {uptime}\n",
            "# HELP hydra_build_info Build metadata.\n",
            "# TYPE hydra_build_info gauge\n",
            "hydra_build_info{{version=\"{ver}\"}} 1\n",
            "# HELP hydra_connections_total TCP connections accepted.\n",
            "# TYPE hydra_connections_total counter\n",
            "hydra_connections_total {conn_total}\n",
            "# HELP hydra_connections_active Connections currently being served.\n",
            "# TYPE hydra_connections_active gauge\n",
            "hydra_connections_active {conn_active}\n",
            "# HELP hydra_connections_rejected_total Connections refused (per-IP limit or capacity).\n",
            "# TYPE hydra_connections_rejected_total counter\n",
            "hydra_connections_rejected_total {conn_rejected}\n",
            "# HELP hydra_target_connect_ok_total Target connections established.\n",
            "# TYPE hydra_target_connect_ok_total counter\n",
            "hydra_target_connect_ok_total {target_ok}\n",
            "# HELP hydra_target_connect_fail_total Target connection failures (DNS/SSRF/timeout).\n",
            "# TYPE hydra_target_connect_fail_total counter\n",
            "hydra_target_connect_fail_total {target_fail}\n",
            "# HELP hydra_udp_relay_connections_total UDP relay connections entered.\n",
            "# TYPE hydra_udp_relay_connections_total counter\n",
            "hydra_udp_relay_connections_total {udp_total}\n",
        ),
        uptime = uptime_secs,
        ver = v,
        conn_total = g(&m.conn_total),
        conn_active = g(&m.conn_active),
        conn_rejected = g(&m.conn_rejected),
        target_ok = g(&m.target_ok),
        target_fail = g(&m.target_fail),
        udp_total = g(&m.udp_relay_total),
    )
}

/// `/metrics` HTTP 响应（与 health 同款 close 连接语义）
pub fn metrics_response(method: &str, uptime_secs: u64) -> String {
    if !method.eq_ignore_ascii_case("GET") {
        return super::health::simple_response(
            405,
            "Method Not Allowed",
            "text/plain",
            "method not allowed\n",
        );
    }
    super::health::simple_response(200, "OK", "text/plain; version=0.0.4", &render(uptime_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_all_families() {
        let body = render(7);
        for family in [
            "hydra_up 1",
            "hydra_uptime_seconds 7",
            "hydra_connections_total",
            "hydra_connections_active",
            "hydra_connections_rejected_total",
            "hydra_target_connect_ok_total",
            "hydra_target_connect_fail_total",
            "hydra_udp_relay_connections_total",
            &format!("version=\"{}\"", env!("CARGO_PKG_VERSION")),
        ] {
            assert!(body.contains(family), "缺字段: {family}");
        }
        // TYPE 行与样本行成对（9 个指标族）
        assert_eq!(body.matches("# TYPE ").count(), 9);
    }

    #[test]
    fn counters_reflect_and_guard_balances() {
        let m = metrics();
        let before = m.conn_total.load(Ordering::Relaxed);
        m.conn_total.fetch_add(3, Ordering::Relaxed);
        assert_eq!(
            m.conn_total.load(Ordering::Relaxed),
            before + 3,
            "进程级单例计数应可见"
        );
        let before_active = m.conn_active.load(Ordering::Relaxed);
        {
            let _g1 = ActiveGuard::enter();
            let _g2 = ActiveGuard::enter();
            assert_eq!(m.conn_active.load(Ordering::Relaxed), before_active + 2);
        }
        assert_eq!(m.conn_active.load(Ordering::Relaxed), before_active);
    }

    #[test]
    fn metrics_response_get_only() {
        assert!(metrics_response("GET", 1).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(metrics_response("POST", 1).starts_with("HTTP/1.1 405"));
        let resp = metrics_response("GET", 1);
        assert!(resp.contains("Content-Type: text/plain; version=0.0.4\r\n"));
    }
}
