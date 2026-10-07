use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    /// 速度计算历史（std Mutex：仅 get_stats 快照路径加锁，每 500ms 一次；
    /// 热路径 record_sent/received_sync 只做原子累加，不再触碰此锁——R-28）。
    ///
    /// 样本语义（R-28 修复）：记录「时刻 + 累计字节计数快照」，速度 = 窗口两端
    /// 计数差 / 时间差。原先每个 64KB 数据块都加锁 push 一次增量样本，高吞吐下
    /// Mutex 在 relay 热路径上形成强竞争；采样移入 get_stats 后热路径零锁。
    /// 此数据仅服务 GUI 速度显示；speedtest 吞吐差分读取的 node_traffic 条目
    /// 本就是纯原子（NodeTrafficEntry），不受本次改动影响。
    speed_history: Mutex<SpeedHistory>,
    /// 按节点流量计数（socket 地址 → 条目；节点路径中继在包装流时创建，直连路径无条目）
    node_traffic: Mutex<HashMap<SocketAddr, Arc<NodeTrafficEntry>>>,
}

/// 速度计算历史记录（R-28：样本 = (时刻, 累计字节计数快照)，仅在 get_stats 加锁写入）
struct SpeedHistory {
    /// 最近的上传累计计数快照 (timestamp, bytes_sent_total)
    sent_samples: Vec<(Instant, u64)>,
    /// 最近的下载累计计数快照 (timestamp, bytes_received_total)
    recv_samples: Vec<(Instant, u64)>,
    /// 最后一次的速度值（样本不足/时间差为零时保持上值，避免显示抖动归零）
    last_upload_speed: f64,
    last_download_speed: f64,
}

/// 窗口速度计算：push 当前累计计数快照，取 5s 窗口两端 (计数差/时间差)。
/// 计数被 reset() 清零（新快照小于旧快照）时丢弃历史样本重新起算。
fn window_speed(samples: &mut Vec<(Instant, u64)>, total: u64, last: f64) -> f64 {
    let now = Instant::now();
    let cutoff = now - std::time::Duration::from_secs(5);
    samples.retain(|(t, _)| *t > cutoff);
    if samples.last().is_some_and(|(_, t)| *t > total) {
        samples.clear(); // 计数回退 = reset 过，旧窗口作废
    }
    samples.push((now, total));
    if samples.len() < 2 {
        return last;
    }
    let first = samples.first().expect("len >= 2");
    let newest = samples.last().expect("len >= 2");
    let duration = newest.0.duration_since(first.0).as_secs_f64();
    if duration <= 0.0 {
        return last;
    }
    newest.1.saturating_sub(first.1) as f64 / duration
}

/// 单节点流量计数条目：上行 = 客户端→节点，下行 = 节点→客户端。
/// 全原子计数，供中继包装流在 poll 上下文内无锁累加、测速按窗口差分读取。
#[derive(Debug, Default)]
pub struct NodeTrafficEntry {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl NodeTrafficEntry {
    /// 累加上行字节（客户端→节点）
    pub fn add_sent(&self, bytes: u64) {
        if bytes > 0 {
            self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// 累加下行字节（节点→客户端）
    pub fn add_received(&self, bytes: u64) {
        if bytes > 0 {
            self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// 累计上行字节
    pub fn sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// 累计下行字节
    pub fn received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// 方向性字节计数器：决定一次累加计入全局 TrafficMonitor 与（可选的）节点条目的哪个方向。
/// up=true 计入上行（客户端→节点/直连目标），up=false 计入下行。
#[derive(Clone, Default)]
pub struct ByteCounter {
    monitor: Option<Arc<TrafficMonitor>>,
    node: Option<Arc<NodeTrafficEntry>>,
    up: bool,
}

impl ByteCounter {
    /// 上行方向计数器（客户端→远端）
    pub fn up(monitor: Option<Arc<TrafficMonitor>>, node: Option<Arc<NodeTrafficEntry>>) -> Self {
        Self {
            monitor,
            node,
            up: true,
        }
    }

    /// 下行方向计数器（远端→客户端）
    pub fn down(monitor: Option<Arc<TrafficMonitor>>, node: Option<Arc<NodeTrafficEntry>>) -> Self {
        Self {
            monitor,
            node,
            up: false,
        }
    }

    /// 累加 n 字节到对应方向；monitor 为 None 时仅（若有）节点条目计数
    pub fn record(&self, n: u64) {
        if n == 0 {
            return;
        }
        if let Some(m) = &self.monitor {
            if self.up {
                m.record_sent_sync(n);
            } else {
                m.record_received_sync(n);
            }
        }
        if let Some(node) = &self.node {
            if self.up {
                node.add_sent(n);
            } else {
                node.add_received(n);
            }
        }
    }
}

/// 计数流包装：在转发字节的同时累加到全局 TrafficMonitor 与（可选）单节点条目。
///
/// 方向语义（由 [`ByteCounter`] 携带）：
/// - 上行包装（up=true）：对 `poll_write` 的字节数计数（客户端→节点方向）；
/// - 下行包装（up=false）：对 `poll_read` 的字节数计数（节点→客户端方向）。
///
/// 泛型 AsyncRead/AsyncWrite 实现即可覆盖 TCP/TLS 节点流与直连 TCP
/// （QUIC 路径固有的错误码通道已随 QUIC 移除；TCP 链路的认证/目标错误
/// 均在建流阶段由 connect_target 显式报错，转发期无应用错误码）。
pub struct CountingStream<T> {
    inner: T,
    counter: ByteCounter,
}

impl<T> CountingStream<T> {
    /// 包装 inner，按 counter 的方向语义计数
    pub fn new(inner: T, counter: ByteCounter) -> Self {
        Self { inner, counter }
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - filled_before) as u64;
            if n > 0 && !self.counter.up {
                self.counter.record(n);
            }
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            if *n > 0 && self.counter.up {
                self.counter.record(*n as u64);
            }
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
            speed_history: Mutex::new(SpeedHistory {
                sent_samples: Vec::new(),
                recv_samples: Vec::new(),
                last_upload_speed: 0.0,
                last_download_speed: 0.0,
            }),
            node_traffic: Mutex::new(HashMap::new()),
        }
    }

    /// 记录上传数据
    pub async fn record_sent(&self, bytes: u64) {
        self.record_sent_sync(bytes);
    }

    /// 记录下载数据
    pub async fn record_received(&self, bytes: u64) {
        self.record_received_sync(bytes);
    }

    /// 同步记录上传数据（热路径 R-28：仅原子累加，不加任何锁；
    /// 速度样本由 get_stats 快照路径按窗口差分推算）
    pub fn record_sent_sync(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 同步记录下载数据（热路径 R-28：仅原子累加，不加任何锁）
    pub fn record_received_sync(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 取（或创建）指定节点的流量计数条目。条目按地址复用，
    /// 测速窗口差分依赖同一 Arc 内的原子计数单调累加。
    pub fn node_entry(&self, addr: SocketAddr) -> Arc<NodeTrafficEntry> {
        let mut map = self
            .node_traffic
            .lock()
            .expect("node_traffic mutex poisoned");
        map.entry(addr).or_default().clone()
    }

    /// 全部节点流量快照：(地址, 上行字节, 下行字节)，供 GUI/测速读取
    pub fn node_traffic_snapshot(&self) -> Vec<(SocketAddr, u64, u64)> {
        let map = self
            .node_traffic
            .lock()
            .expect("node_traffic mutex poisoned");
        map.iter()
            .map(|(addr, e)| (*addr, e.sent(), e.received()))
            .collect()
    }

    /// 增加活跃连接数
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 减少活跃连接数（09-P2-8：饱和递减——reset() 与并发关闭竞态时
    /// wrapping `fetch_sub` 会回绕为 u64::MAX）
    pub fn connection_closed(&self) {
        let mut cur = self.active_connections.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return;
            }
            match self.active_connections.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(v) => cur = v,
            }
        }
    }

    /// 获取当前统计信息（R-28：唯一的 speed_history 加锁点，由 GUI 采样线程每
    /// 500ms 调用一次；速度由 5s 窗口两端累计计数差分推算）
    pub async fn get_stats(&self) -> TrafficStats {
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        let mut history = self
            .speed_history
            .lock()
            .expect("speed_history mutex poisoned");
        let last_up = history.last_upload_speed;
        let last_down = history.last_download_speed;
        let upload_speed = window_speed(&mut history.sent_samples, bytes_sent, last_up);
        let download_speed = window_speed(&mut history.recv_samples, bytes_received, last_down);
        history.last_upload_speed = upload_speed;
        history.last_download_speed = download_speed;

        TrafficStats {
            bytes_sent,
            bytes_received,
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    /// CountingStream：上行包装对 poll_write 计数（全局 sent + 节点 sent），
    /// 下行包装对 poll_read 计数（全局 received + 节点 received），字节数逐字节一致。
    #[tokio::test]
    async fn test_counting_stream_up_down() {
        let monitor = Arc::new(TrafficMonitor::new());
        let entry = monitor.node_entry("127.0.0.1:10000".parse().unwrap());

        let (client, node) = tokio::io::duplex(64);
        let mut up = CountingStream::new(
            client,
            ByteCounter::up(Some(monitor.clone()), Some(entry.clone())),
        );
        let mut down = CountingStream::new(
            node,
            ByteCounter::down(Some(monitor.clone()), Some(entry.clone())),
        );

        const PAYLOAD: usize = 300; // 超过 duplex 缓冲 64B，强制多轮 poll 读写
        let payload: Vec<u8> = (0..PAYLOAD).map(|i| i as u8).collect();
        let expect = payload.clone();

        let writer = tokio::spawn(async move {
            up.write_all(&payload).await.expect("write_all");
            up.shutdown().await.expect("shutdown");
        });
        let mut got = Vec::new();
        down.read_to_end(&mut got).await.expect("read_to_end");
        writer.await.unwrap();

        assert_eq!(got, expect, "payload must pass through byte-identical");
        assert_eq!(entry.sent(), PAYLOAD as u64, "node up counter");
        assert_eq!(entry.received(), PAYLOAD as u64, "node down counter");
        let stats = monitor.get_stats().await;
        assert_eq!(stats.bytes_sent, PAYLOAD as u64, "monitor sent");
        assert_eq!(stats.bytes_received, PAYLOAD as u64, "monitor received");
    }

    /// 节点条目与全局 monitor 是独立计数面：仅节点计数器（monitor=None）不影响全局，
    /// 仅全局计数器（node=None）不影响任何节点条目——直连路径（无节点归属）即此形态。
    #[tokio::test]
    async fn test_byte_counter_attribution_direct_vs_node() {
        let monitor = Arc::new(TrafficMonitor::new());
        let node_entry = monitor.node_entry("127.0.0.1:10001".parse().unwrap());
        let other_entry = monitor.node_entry("127.0.0.1:10002".parse().unwrap());

        // 直连形态：全局计数，不归属任何节点
        ByteCounter::up(Some(monitor.clone()), None).record(100);
        ByteCounter::down(Some(monitor.clone()), None).record(50);
        // 节点形态：全局 + 指定节点条目同时累加
        ByteCounter::up(Some(monitor.clone()), Some(node_entry.clone())).record(30);
        ByteCounter::down(Some(monitor.clone()), Some(node_entry.clone())).record(20);

        let stats = monitor.get_stats().await;
        assert_eq!(stats.bytes_sent, 130);
        assert_eq!(stats.bytes_received, 70);
        assert_eq!(node_entry.sent(), 30);
        assert_eq!(node_entry.received(), 20);
        assert_eq!(other_entry.sent(), 0, "untouched node must stay zero");
        assert_eq!(other_entry.received(), 0);
        assert_eq!(
            monitor.node_traffic_snapshot().len(),
            2,
            "snapshot must cover both created entries"
        );
    }

    /// 零字节记录必须被忽略（不产生虚假样本）
    #[tokio::test]
    async fn test_zero_byte_record_ignored() {
        let monitor = Arc::new(TrafficMonitor::new());
        let entry = monitor.node_entry("127.0.0.1:10003".parse().unwrap());
        monitor.record_sent_sync(0);
        monitor.record_received_sync(0);
        entry.add_sent(0);
        entry.add_received(0);
        let stats = monitor.get_stats().await;
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(entry.sent(), 0);
    }

    /// reset() 后计数回退：window_speed 必须丢弃旧窗口重新起算，速度不出现负数
    #[test]
    fn test_window_speed_discards_after_reset() {
        let mut samples: Vec<(Instant, u64)> = Vec::new();
        let s1 = window_speed(&mut samples, 0, 0.0);
        assert_eq!(s1, 0.0, "首个样本无窗口，保持 last");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let s2 = window_speed(&mut samples, 1000, 0.0);
        assert!(s2 > 0.0, "第二个样本应有正速度（20ms 内 1000B）");
        // 模拟 reset：计数回退到 0 → 旧窗口作废；样本不足 2 个时按设计保持
        // 上次速度（GUI 下一帧 500ms 后即有新窗口，不显示负数/跳变）
        let s3 = window_speed(&mut samples, 0, s2);
        assert_eq!(s3, s2, "reset 后窗口作废，样本不足时保持上值");
        assert_eq!(samples.len(), 1, "reset 后只保留新样本");
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
