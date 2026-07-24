use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// 流量统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    /// 上传字节数
    pub bytes_sent: u64,
    /// 下载字节数
    pub bytes_received: u64,
    /// 当前上传速度 (bytes/sec)
    pub upload_speed: f64,
    /// 当前下载速度 (bytes/sec)
    pub download_speed: f64,
    /// 活跃连接数
    pub active_connections: u64,
    /// 总连接数
    pub total_connections: u64,
    /// 运行时间 (秒)
    pub uptime_secs: u64,
}

/// 流量统计器
pub struct TrafficMonitor {
    /// 上传字节数
    bytes_sent: AtomicU64,
    /// 下载字节数
    bytes_received: AtomicU64,
    /// 活跃连接数
    active_connections: AtomicU64,
    /// 总连接数
    total_connections: AtomicU64,
    /// 启动时间
    start_time: Instant,
    /// 速度计算历史
    speed_history: Arc<RwLock<SpeedHistory>>,
}

/// 速度计算历史记录
struct SpeedHistory {
    /// 最近的上传字节数记录 (timestamp, bytes)
    sent_samples: Vec<(Instant, u64)>,
    /// 最近的下载字节数记录 (timestamp, bytes)
    recv_samples: Vec<(Instant, u64)>,
    /// 最后一次的速度值
    last_upload_speed: f64,
    last_download_speed: f64,
}

impl SpeedHistory {
    fn new() -> Self {
        Self {
            sent_samples: Vec::new(),
            recv_samples: Vec::new(),
            last_upload_speed: 0.0,
            last_download_speed: 0.0,
        }
    }

    /// 添加上传样本
    fn add_sent_sample(&mut self, bytes: u64) {
        let now = Instant::now();
        self.sent_samples.push((now, bytes));
        // 保留最近 5 秒的样本
        let cutoff = now - std::time::Duration::from_secs(5);
        self.sent_samples.retain(|(t, _)| *t > cutoff);
    }

    /// 添加下载样本
    fn add_recv_sample(&mut self, bytes: u64) {
        let now = Instant::now();
        self.recv_samples.push((now, bytes));
        // 保留最近 5 秒的样本
        let cutoff = now - std::time::Duration::from_secs(5);
        self.recv_samples.retain(|(t, _)| *t > cutoff);
    }

    /// 计算上传速度
    fn calculate_upload_speed(&mut self) -> f64 {
        if self.sent_samples.len() < 2 {
            return self.last_upload_speed;
        }

        let first = self.sent_samples.first().unwrap();
        let last = self.sent_samples.last().unwrap();
        let duration = last.0.duration_since(first.0).as_secs_f64();

        if duration <= 0.0 {
            return self.last_upload_speed;
        }

        let total_bytes: u64 = self.sent_samples.iter().skip(1).map(|(_, b)| *b).sum();
        let speed = total_bytes as f64 / duration;
        self.last_upload_speed = speed;
        speed
    }

    /// 计算下载速度
    fn calculate_download_speed(&mut self) -> f64 {
        if self.recv_samples.len() < 2 {
            return self.last_download_speed;
        }

        let first = self.recv_samples.first().unwrap();
        let last = self.recv_samples.last().unwrap();
        let duration = last.0.duration_since(first.0).as_secs_f64();

        if duration <= 0.0 {
            return self.last_download_speed;
        }

        let total_bytes: u64 = self.recv_samples.iter().skip(1).map(|(_, b)| *b).sum();
        let speed = total_bytes as f64 / duration;
        self.last_download_speed = speed;
        speed
    }
}

impl TrafficMonitor {
    /// 创建新的流量统计器
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            start_time: Instant::now(),
            speed_history: Arc::new(RwLock::new(SpeedHistory::new())),
        }
    }

    /// 记录上传数据
    pub async fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        let mut history = self.speed_history.write().await;
        history.add_sent_sample(bytes);
    }

    /// 记录下载数据
    pub async fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        let mut history = self.speed_history.write().await;
        history.add_recv_sample(bytes);
    }

    /// 增加活跃连接数
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 减少活跃连接数
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 获取当前统计信息
    pub async fn get_stats(&self) -> TrafficStats {
        let mut history = self.speed_history.write().await;
        let upload_speed = history.calculate_upload_speed();
        let download_speed = history.calculate_download_speed();

        TrafficStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            upload_speed,
            download_speed,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// 重置统计
    pub fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.active_connections.store(0, Ordering::Relaxed);
        self.total_connections.store(0, Ordering::Relaxed);
    }
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 格式化字节数为人类可读格式
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let bytes = bytes as f64;
    if bytes < KB {
        format!("{:.0} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes / KB)
    } else if bytes < GB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes < TB {
        format!("{:.2} GB", bytes / GB)
    } else {
        format!("{:.2} TB", bytes / TB)
    }
}

/// 格式化速度为人类可读格式
pub fn format_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes_per_sec < KB {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < MB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else if bytes_per_sec < GB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    }
}

/// 格式化运行时间
pub fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{}天 {:02}:{:02}:{:02}", days, hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(0.0), "0 B/s");
        assert_eq!(format_speed(1024.0), "1.00 KB/s");
        assert_eq!(format_speed(1024.0 * 1024.0), "1.00 MB/s");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "00:00:00");
        assert_eq!(format_duration(61), "00:01:01");
        assert_eq!(format_duration(3661), "01:01:01");
        assert_eq!(format_duration(86401), "1天 00:00:01");
    }
}
