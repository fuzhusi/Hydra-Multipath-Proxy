//! 总览页仪表盘的速率采样历史与当日流量累计（UI 无关纯逻辑，UI 与单测共用）。

use hydra_client::TrafficStats;
use std::collections::VecDeque;

// ── UI 重设计第三批：总览页仪表盘速率历史序列 ──
/// 速率采样历史 + 当日流量累计（UI 无关纯逻辑，UI 与单测共用）。
/// - `samples`：最近 [`SpeedHistory::CAPACITY`] 个 (上行 B/s, 下行 B/s) 采样点
///   （采样周期 500ms → 曲线窗口 = 60s）；
/// - `daily_up/daily_down`：当日累计流量（由相邻采样的累计字节数差分得到；
///   跨自然日自动清零；代理重启导致累计值回退时按新起点重新累计，不产生负数）。
///
/// 序列本身不落盘：应用退出即清零，「今日」语义 = 本次运行期间（同自然日内）。
pub(crate) struct SpeedHistory {
    pub(crate) samples: VecDeque<(f64, f64)>,
    /// 上次采样的累计发送字节数（差分基准；None = 尚无基准）
    pub(crate) last_sent: Option<u64>,
    /// 上次采样的累计接收字节数
    pub(crate) last_recv: Option<u64>,
    pub(crate) daily_up: u64,
    pub(crate) daily_down: u64,
    /// 当日标记（本地日期）；日期变化时清空当日累计
    pub(crate) day: chrono::NaiveDate,
}

impl SpeedHistory {
    /// 曲线保留的最大采样点数（v3 方案 P1：最近 120 点）
    pub(crate) const CAPACITY: usize = 120;

    pub(crate) fn now_day() -> chrono::NaiveDate {
        chrono::Local::now().date_naive()
    }

    pub(crate) fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            last_sent: None,
            last_recv: None,
            daily_up: 0,
            daily_down: 0,
            day: Self::now_day(),
        }
    }

    /// 推入一次采样（每 500ms 由后台采样线程调用）：
    /// 维护 120 点滑动窗口 + 当日流量差分累计 + 跨日清零。
    pub(crate) fn push_sample(&mut self, stats: &TrafficStats) {
        // 跨自然日：清空当日累计（「今日」语义）
        let today = Self::now_day();
        if today != self.day {
            self.day = today;
            self.daily_up = 0;
            self.daily_down = 0;
        }
        // 当日流量差分：累计值回退（代理重启换了 TrafficMonitor）→ 以新值为新基准，不累计
        match self.last_sent {
            Some(prev) if stats.bytes_sent >= prev => self.daily_up += stats.bytes_sent - prev,
            _ => {}
        }
        match self.last_recv {
            Some(prev) if stats.bytes_received >= prev => {
                self.daily_down += stats.bytes_received - prev
            }
            _ => {}
        }
        self.last_sent = Some(stats.bytes_sent);
        self.last_recv = Some(stats.bytes_received);

        self.samples.push_back((stats.upload_speed, stats.download_speed));
        while self.samples.len() > Self::CAPACITY {
            self.samples.pop_front();
        }
    }

    /// 仅清空曲线序列（启停代理时调用）；当日累计保留（同一天内重启不清零）
    pub(crate) fn reset_samples(&mut self) {
        self.samples.clear();
        self.last_sent = None;
        self.last_recv = None;
    }

    /// 当前采样点数（≤ CAPACITY）
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.samples.len()
    }

    /// 上行序列（B/s，按时间先后）
    pub(crate) fn up_series(&self) -> Vec<f64> {
        self.samples.iter().map(|(up, _)| *up).collect()
    }

    /// 下行序列（B/s，按时间先后）
    pub(crate) fn down_series(&self) -> Vec<f64> {
        self.samples.iter().map(|(_, down)| *down).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── UI 重设计第三批：仪表盘速率历史序列 / 统计纯函数 ──

    /// 构造采样用 TrafficStats（其余字段填零即可）
    fn sample_stats(sent: u64, recv: u64, up: f64, down: f64) -> TrafficStats {
        TrafficStats {
            bytes_sent: sent,
            bytes_received: recv,
            upload_speed: up,
            download_speed: down,
            active_connections: 0,
            total_connections: 0,
            uptime_secs: 0,
        }
    }

    #[test]
    fn speed_history_caps_at_120_and_keeps_latest() {
        let mut h = SpeedHistory::new();
        for i in 0..300u64 {
            h.push_sample(&sample_stats(i * 10, i * 20, i as f64, (i * 2) as f64));
        }
        assert_eq!(h.len(), SpeedHistory::CAPACITY);
        assert_eq!(h.len(), 120);
        // 最新点在队尾：上行 = 299，下行 = 598
        assert_eq!(h.up_series().last(), Some(&299.0));
        assert_eq!(h.down_series().last(), Some(&598.0));
        // 最旧点 = 第 180 个采样（300-120）
        assert_eq!(h.up_series().first(), Some(&180.0));
    }

    #[test]
    fn speed_history_daily_accumulates_deltas() {
        let mut h = SpeedHistory::new();
        // 首个采样只立基准不累计
        h.push_sample(&sample_stats(100, 200, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (0, 0));
        h.push_sample(&sample_stats(350, 900, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (250, 700));
        h.push_sample(&sample_stats(400, 1000, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (300, 800));
    }

    #[test]
    fn speed_history_monitor_restart_does_not_go_negative() {
        let mut h = SpeedHistory::new();
        h.push_sample(&sample_stats(10_000, 20_000, 0.0, 0.0));
        // 代理重启：新 TrafficMonitor 累计值回退 → 不累计负数，仅更新基准
        h.push_sample(&sample_stats(50, 80, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (0, 0));
        h.push_sample(&sample_stats(150, 280, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (100, 200));
    }

    #[test]
    fn speed_history_reset_samples_keeps_daily_totals() {
        let mut h = SpeedHistory::new();
        h.push_sample(&sample_stats(100, 200, 1.0, 2.0));
        h.push_sample(&sample_stats(300, 600, 1.0, 2.0));
        assert_eq!((h.daily_up, h.daily_down), (200, 400));
        h.reset_samples();
        assert_eq!(h.len(), 0);
        assert!(h.up_series().is_empty());
        // 当日累计保留（同一天内启停代理不清零）
        assert_eq!((h.daily_up, h.daily_down), (200, 400));
        // 重置后基准也清空：下一采样重新立基准（不把重启前的累计续上）
        h.push_sample(&sample_stats(1000, 2000, 0.0, 0.0));
        assert_eq!((h.daily_up, h.daily_down), (200, 400));
    }
}
