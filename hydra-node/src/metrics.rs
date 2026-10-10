//! 进程级指标（Prometheus 文本格式，挂 `/metrics`，随健康端点开关）。
//!
//! - 无第三方依赖：手写文本渲染（OpenMetrics 基本型：`# HELP/# TYPE` + 样本行）；
//! - 计数面（全部原子，热路径 `fetch_add` 零锁）：
//!   - `hydra_connections_total`：TCP accept 成功数
//!   - `hydra_connections_active`：当前在服务连接数（任务进出守卫）
//!   - `hydra_connections_rejected_{per_ip,capacity,tls,auth}_total`：拒入分解
//!   - `hydra_target_connect_ok_total` / `hydra_target_connect_fail_total`：
//!     目标建连成败（含 DNS/SSRF/超时；TCP+UDP 两路径共用）
//!   - `hydra_udp_relay_connections_total`：UDP 中继连接进入数
//!   - `hydra_udp_sessions_active`：UDP 活跃会话 gauge（会话进出守卫）
//!   - `hydra_udp_datagrams_{fwd,drop}_total`：UDP 数据报转发/丢弃
//!   - `hydra_bytes_{in,out}_total`：TCP 转发字节（pump 汇入）
//!   - `hydra_handshake_{tls,noise,dns,target}_seconds`：四段建连延迟直方图
//!     （固定对数桶，`+Inf` 收尾；观测点：TLS/Noise 客户端侧暂无、节点侧齐全）
//! - 热路径统计一律连接内累加、关闭时汇入（原子竞争压到每连接几次）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// 固定对数桶（秒）：10ms → 32s，11 桶 + Inf
const HISTOGRAM_BUCKETS_SECS: [f64; 11] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// 直方图（固定桶 + Inf；无 quantile —— Prometheus histogram 语义）
#[derive(Default)]
pub struct Histogram {
    buckets: [AtomicU64; 11],
    count: AtomicU64,
    sum_ms: AtomicU64, // 毫秒整数累计（避免浮点原子）
}

impl Histogram {
    fn new() -> Self {
        Self::default()
    }

    /// 记录一次观测（秒，f64）
    pub fn observe(&self, secs: f64) {
        for (i, b) in HISTOGRAM_BUCKETS_SECS.iter().enumerate() {
            if secs <= *b {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms
            .fetch_add((secs * 1000.0) as u64, Ordering::Relaxed);
    }

    /// 直方图渲染（`name` 无后缀；自动生成 bucket/sum/count 三行组）
    fn render(&self, name: &str, help: &str) -> String {
        let m = metrics();
        let _ = m;
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} histogram\n");
        let mut cumulative = 0u64;
        for (i, b) in HISTOGRAM_BUCKETS_SECS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "{name}_bucket{{le=\"{b}\"}} {cumulative}\n"
            ));
        }
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        out.push_str(&format!(
            "{name}_sum {}\n{name}_count {count}\n",
            self.sum_ms.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        out
    }
}

/// 拒入原因分解（conn_rejected 的细分；总数恒等于四者之和）
#[derive(Default)]
pub struct Rejected {
    pub per_ip: AtomicU64,
    pub capacity: AtomicU64,
    pub tls: AtomicU64,
    pub auth: AtomicU64,
}

/// 进程级指标单例（热路径无锁自增）
pub struct Metrics {
    pub conn_total: AtomicU64,
    pub conn_active: AtomicU64,
    pub conn_rejected: AtomicU64,
    pub target_ok: AtomicU64,
    pub target_fail: AtomicU64,
    pub udp_relay_total: AtomicU64,
    // ── Metrics v2（内核优化 #4）──
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub rejected: Rejected,
    pub udp_sessions_active: AtomicU64,
    pub udp_datagrams_fwd: AtomicU64,
    pub udp_datagrams_drop: AtomicU64,
    pub hs_tls: Histogram,
    pub hs_noise: Histogram,
    pub hs_dns: Histogram,
    pub hs_target: Histogram,
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
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            rejected: Rejected::default(),
            udp_sessions_active: AtomicU64::new(0),
            udp_datagrams_fwd: AtomicU64::new(0),
            udp_datagrams_drop: AtomicU64::new(0),
            hs_tls: Histogram::new(),
            hs_noise: Histogram::new(),
            hs_dns: Histogram::new(),
            hs_target: Histogram::new(),
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

/// UDP 活跃会话守卫（会话任务生命周期内持有）
pub struct UdpSessionGuard;

impl UdpSessionGuard {
    pub fn enter() -> Self {
        metrics()
            .udp_sessions_active
            .fetch_add(1, Ordering::Relaxed);
        UdpSessionGuard
    }
}

impl Drop for UdpSessionGuard {
    fn drop(&mut self) {
        metrics()
            .udp_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// 渲染 Prometheus 文本格式（`uptime_secs`/`version` 由调用方注入与
/// `/health` 同源）。字段顺序稳定，便于面板/告警规则 diff。
pub fn render(uptime_secs: u64) -> String {
    let m = metrics();
    let v = env!("CARGO_PKG_VERSION");
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let mut out = format!(
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
            "# HELP hydra_connections_rejected_total Connections refused (any reason).\n",
            "# TYPE hydra_connections_rejected_total counter\n",
            "hydra_connections_rejected_total {conn_rejected}\n",
            "# HELP hydra_connections_rejected_reason_total Refusals by reason.\n",
            "# TYPE hydra_connections_rejected_reason_total counter\n",
            "hydra_connections_rejected_reason_total{{reason=\"per_ip\"}} {rej_per_ip}\n",
            "hydra_connections_rejected_reason_total{{reason=\"capacity\"}} {rej_cap}\n",
            "hydra_connections_rejected_reason_total{{reason=\"tls\"}} {rej_tls}\n",
            "hydra_connections_rejected_reason_total{{reason=\"auth\"}} {rej_auth}\n",
            "# HELP hydra_target_connect_ok_total Target connections established.\n",
            "# TYPE hydra_target_connect_ok_total counter\n",
            "hydra_target_connect_ok_total {target_ok}\n",
            "# HELP hydra_target_connect_fail_total Target connection failures (DNS/SSRF/timeout).\n",
            "# TYPE hydra_target_connect_fail_total counter\n",
            "hydra_target_connect_fail_total {target_fail}\n",
            "# HELP hydra_udp_relay_connections_total UDP relay connections entered.\n",
            "# TYPE hydra_udp_relay_connections_total counter\n",
            "hydra_udp_relay_connections_total {udp_total}\n",
            "# HELP hydra_udp_sessions_active Active UDP relay sessions.\n",
            "# TYPE hydra_udp_sessions_active gauge\n",
            "hydra_udp_sessions_active {udp_sessions}\n",
            "# HELP hydra_udp_datagrams_total UDP datagrams forwarded/dropped.\n",
            "# TYPE hydra_udp_datagrams_total counter\n",
            "hydra_udp_datagrams_total{{result=\"fwd\"}} {udp_fwd}\n",
            "hydra_udp_datagrams_total{{result=\"drop\"}} {udp_drop}\n",
            "# HELP hydra_bytes_total Relayed bytes (client<->target, both directions aggregated per side).\n",
            "# TYPE hydra_bytes_total counter\n",
            "hydra_bytes_total{{dir=\"in\"}} {bytes_in}\n",
            "hydra_bytes_total{{dir=\"out\"}} {bytes_out}\n",
        ),
        uptime = uptime_secs,
        ver = v,
        conn_total = g(&m.conn_total),
        conn_active = g(&m.conn_active),
        conn_rejected = g(&m.conn_rejected),
        rej_per_ip = g(&m.rejected.per_ip),
        rej_cap = g(&m.rejected.capacity),
        rej_tls = g(&m.rejected.tls),
        rej_auth = g(&m.rejected.auth),
        target_ok = g(&m.target_ok),
        target_fail = g(&m.target_fail),
        udp_total = g(&m.udp_relay_total),
        udp_sessions = g(&m.udp_sessions_active),
        udp_fwd = g(&m.udp_datagrams_fwd),
        udp_drop = g(&m.udp_datagrams_drop),
        bytes_in = g(&m.bytes_in),
        bytes_out = g(&m.bytes_out),
    );
    out.push_str(&m.hs_tls.render(
        "hydra_handshake_tls_seconds",
        "TLS handshake duration.",
    ));
    out.push_str(&m.hs_noise.render(
        "hydra_handshake_noise_seconds",
        "Noise-PSK handshake duration.",
    ));
    out.push_str(&m.hs_dns.render(
        "hydra_handshake_dns_seconds",
        "Target DNS resolution duration.",
    ));
    out.push_str(&m.hs_target.render(
        "hydra_handshake_target_seconds",
        "Target TCP connect duration.",
    ));
    out
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
            "hydra_bytes_total{dir=\"in\"}",
            "hydra_bytes_total{dir=\"out\"}",
            "hydra_udp_sessions_active",
            "hydra_udp_datagrams_total{result=\"fwd\"}",
            "hydra_udp_datagrams_total{result=\"drop\"}",
            "hydra_connections_rejected_reason_total{reason=\"per_ip\"}",
            "hydra_connections_rejected_reason_total{reason=\"tls\"}",
            "hydra_handshake_tls_seconds_bucket",
            "hydra_handshake_dns_seconds_bucket",
            "hydra_handshake_target_seconds_bucket{le=\"+Inf\"}",
            &format!("version=\"{}\"", env!("CARGO_PKG_VERSION")),
        ] {
            assert!(body.contains(family), "缺字段: {family}");
        }
        // TYPE 行 = 13 常规族 + 4 直方图
        assert_eq!(body.matches("# TYPE ").count(), 17);
    }

    #[test]
    fn histogram_buckets_ordered_and_counted() {
        let h = Histogram::new();
        h.observe(0.005); // ≤0.01 → 第 0 桶
        h.observe(0.3); // ≤0.5 → 第 4 桶
        h.observe(100.0); // >30 → 仅 Inf
        assert_eq!(h.count.load(Ordering::Relaxed), 3);
        assert_eq!(h.buckets[0].load(Ordering::Relaxed), 1);
        // sum：0.005+0.3+100 = 100.305s → ms 累计
        assert_eq!(h.sum_ms.load(Ordering::Relaxed), 100_305);
        let rendered = h.render("t", "test");
        assert!(rendered.contains("t_bucket{le=\"0.01\"} 1"));
        assert!(rendered.contains("t_bucket{le=\"+Inf\"} 3"));
        assert!(rendered.contains("t_count 3"));
    }

    #[test]
    fn counters_reflect_and_guards_balance() {
        let m = metrics();
        let before = m.conn_total.load(Ordering::Relaxed);
        m.conn_total.fetch_add(3, Ordering::Relaxed);
        assert_eq!(m.conn_total.load(Ordering::Relaxed), before + 3);
        let before_active = m.udp_sessions_active.load(Ordering::Relaxed);
        {
            let _g = UdpSessionGuard::enter();
            assert_eq!(
                m.udp_sessions_active.load(Ordering::Relaxed),
                before_active + 1
            );
        }
        assert_eq!(m.udp_sessions_active.load(Ordering::Relaxed), before_active);
    }

    #[test]
    fn metrics_response_get_only() {
        assert!(metrics_response("GET", 1).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(metrics_response("POST", 1).starts_with("HTTP/1.1 405"));
        assert!(metrics_response("GET", 1)
            .contains("Content-Type: text/plain; version=0.0.4\r\n"));
    }
}
