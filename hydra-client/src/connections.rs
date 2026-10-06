//! 活跃连接注册表（GUI「连接」页数据源）。
//!
//! 与 [`crate::traffic::TrafficMonitor`] 同范式：中继热路径只做原子累加，
//! 快照读取（GUI 每 500ms 一次）时才加锁遍历条目表。注册表由进程级静态
//! 单例持有（[`connections_registry`]），proxy.rs 中继起点/终点/字节回调处
//! 以最小钩子接入，GUI 直接读全局单例。
//!
//! 保密性与日志脱敏（Exec2）一致：入库的 `target` 为 [`hydra_protocol::mask_target`]
//! 脱敏后的短哈希视图，明文目标不进注册表。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 条目上限：超出时优先淘汰最旧的已完成条目（不足则淘汰最旧条目）。
pub const MAX_ENTRIES: usize = 1024;
/// 已完成条目保留时长：供 UI「最近关闭」区展示，超时后清理。
pub const RETAIN_AFTER_CLOSE: Duration = Duration::from_secs(60);

/// 单条连接的只读快照（GUI 表格行）。
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// 连接 ID（注册表内单调递增）
    pub id: u64,
    /// 目标地址（已按 mask_target 脱敏，仅显示用）
    pub target: String,
    /// 出口节点地址；直连（CN 分流）路径为 0.0.0.0:0（UI 显示「直连」）
    pub node: SocketAddr,
    /// 建立时刻
    pub started_at: Instant,
    /// 累计上行字节（客户端 → 目标）
    pub bytes_up: u64,
    /// 累计下行字节（目标 → 客户端）
    pub bytes_down: u64,
    /// 是否仍然活跃（finish 后为 false）
    pub active: bool,
    /// 关闭时刻（活跃中为 None）
    pub closed_at: Option<Instant>,
}

/// 单条连接的可变条目：字节计数为纯原子（中继任务内无锁累加），
/// 生命周期状态由注册表的 Mutex 表统一管理。
#[derive(Debug)]
pub struct ConnEntry {
    id: u64,
    target: String,
    node: SocketAddr,
    started_at: Instant,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    active: AtomicBool,
    closed_at: Mutex<Option<Instant>>,
}

impl ConnEntry {
    /// 累加上行字节（客户端 → 目标）
    pub fn add_up(&self, n: u64) {
        if n > 0 {
            self.bytes_up.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// 累加下行字节（目标 → 客户端）
    pub fn add_down(&self, n: u64) {
        if n > 0 {
            self.bytes_down.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// 按 (上行增量, 下行增量) 一次性累加
    pub fn add_bytes(&self, up: u64, down: u64) {
        self.add_up(up);
        self.add_down(down);
    }

    /// 连接 ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// 标记连接结束（幂等：重复 finish 只记首次关闭时刻）
    pub fn finish(&self) {
        if self.active.swap(false, Ordering::Relaxed) {
            let mut closed = self.closed_at.lock().unwrap_or_else(|p| p.into_inner());
            if closed.is_none() {
                *closed = Some(Instant::now());
            }
        }
    }

    /// 是否仍活跃
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// 生成只读快照
    pub fn snapshot(&self) -> ConnInfo {
        ConnInfo {
            id: self.id,
            target: self.target.clone(),
            node: self.node,
            started_at: self.started_at,
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            active: self.active(),
            closed_at: self.closed_at.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        }
    }
}

/// 活跃连接注册表（线程安全；快照路径加锁，热路径纯原子）。
pub struct ConnectionRegistry {
    /// 条目表（插入序 = 注册序 = id 序，淘汰时天然「最旧优先」）
    entries: Mutex<Vec<Arc<ConnEntry>>>,
    next_id: AtomicU64,
    /// 条目上限（测试用小容量注入；生产为 [`MAX_ENTRIES`]）
    max_entries: usize,
}

impl ConnectionRegistry {
    /// 创建生产容量（1024）的注册表
    pub fn new() -> Self {
        Self::with_limit(MAX_ENTRIES)
    }

    /// 创建指定容量上限的注册表（供测试注入小容量验证淘汰逻辑）
    pub fn with_limit(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            max_entries,
        }
    }

    /// 注册一条新连接，返回计数条目句柄（中继任务持有并原子累加字节）
    pub fn register(&self, target: String, node: SocketAddr) -> Arc<ConnEntry> {
        let entry = Arc::new(ConnEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            target,
            node,
            started_at: Instant::now(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            active: AtomicBool::new(true),
            closed_at: Mutex::new(None),
        });
        let mut list = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        list.push(entry.clone());
        self.prune_locked(&mut list);
        entry
    }

    /// 按连接 ID 累加字节（等价于持有 ConnEntry 句柄时的 add_bytes；
    /// 供不持有句柄的调用方按 ID 更新，找不到已清理的 ID 时静默忽略）
    pub fn update_bytes(&self, id: u64, up: u64, down: u64) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|e| e.id == id)
        {
            entry.add_bytes(up, down);
        }
    }

    /// 按连接 ID 标记结束（幂等；ID 已被清理时静默忽略）
    pub fn finish(&self, id: u64) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|e| e.id == id)
        {
            entry.finish();
        }
    }

    /// 全部条目快照（保留注册顺序；GUI 按活跃/时间自行排序）。
    /// 顺带清理超过保留时长的已完成条目。
    pub fn snapshot(&self) -> Vec<ConnInfo> {
        let mut list = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        self.prune_locked(&mut list);
        list.iter().map(|e| e.snapshot()).collect()
    }

    /// 清空注册表（GUI 重新启动代理时调用，避免展示上一轮会话的陈旧条目）
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// 淘汰策略（调用方已持锁）：
    /// 1. 清理关闭超过 [`RETAIN_AFTER_CLOSE`] 的已完成条目；
    /// 2. 仍超上限时，优先移除最旧的已完成条目，不足再移除最旧条目。
    fn prune_locked(&self, list: &mut Vec<Arc<ConnEntry>>) {
        let now = Instant::now();
        list.retain(|e| match e.snapshot().closed_at {
            Some(closed) => now.duration_since(closed) < RETAIN_AFTER_CLOSE,
            None => true,
        });
        while list.len() > self.max_entries {
            // 已完成条目优先淘汰；都活跃时移除最旧（表本身按注册序排列）
            let victim = list
                .iter()
                .position(|e| !e.active())
                .unwrap_or(0);
            list.remove(victim);
        }
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 进程级全局注册表单例（与 proxy.rs 的 target_unreach_counts 同范式）。
/// proxy 中继与 GUI 连接页共用同一实例。
pub fn connections_registry() -> &'static ConnectionRegistry {
    static REGISTRY: std::sync::OnceLock<ConnectionRegistry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(ConnectionRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn node(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    /// 注册 → 快照出现该条目，字段一致
    #[test]
    fn test_register_snapshot() {
        let reg = ConnectionRegistry::new();
        let e = reg.register("a1b2c3d4:443".to_string(), node(10001));
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        let info = &snap[0];
        assert_eq!(info.id, e.id());
        assert_eq!(info.target, "a1b2c3d4:443");
        assert_eq!(info.node, node(10001));
        assert!(info.active);
        assert!(info.closed_at.is_none());
        assert_eq!((info.bytes_up, info.bytes_down), (0, 0));
    }

    /// 字节累计：add_bytes 原子累加，update_bytes(id, ..) 按 ID 更新一致
    #[test]
    fn test_update_bytes_accumulates() {
        let reg = ConnectionRegistry::new();
        let e = reg.register("t.example:80".to_string(), node(10002));
        e.add_bytes(100, 200);
        e.add_bytes(50, 25);
        assert_eq!((e.snapshot().bytes_up, e.snapshot().bytes_down), (150, 225));
        // 按 ID 路径（不持句柄）
        reg.update_bytes(e.id(), 10, 20);
        let info = reg.snapshot().remove(0);
        assert_eq!((info.bytes_up, info.bytes_down), (160, 245));
        // 未知 ID 静默忽略，不 panic
        reg.update_bytes(9999, 1, 1);
        // 零字节不计
        e.add_bytes(0, 0);
        assert_eq!(reg.snapshot()[0].bytes_up, 160);
    }

    /// finish：转 inactive、记录关闭时刻；重复 finish 幂等
    #[test]
    fn test_finish_marks_inactive() {
        let reg = ConnectionRegistry::new();
        let e = reg.register("t.example:443".to_string(), node(10003));
        assert!(reg.snapshot()[0].active);
        reg.finish(e.id());
        let info = &reg.snapshot()[0];
        assert!(!info.active, "finish 后必须转 inactive");
        assert!(info.closed_at.is_some(), "finish 后必须记录关闭时刻");
        // 句柄路径 + 重复 finish：幂等
        e.finish();
        e.finish();
        let info = &reg.snapshot()[0];
        assert!(!info.active);
        // finish 后条目仍保留（供「最近关闭」展示）
        assert_eq!(reg.snapshot().len(), 1);
    }

    /// 上限淘汰：超容量时优先淘汰最旧已完成条目，活跃条目尽量保留
    #[test]
    fn test_eviction_cap() {
        let reg = ConnectionRegistry::with_limit(3);
        let a = reg.register("a:1".to_string(), node(1));
        let b = reg.register("b:2".to_string(), node(2));
        let _c = reg.register("c:3".to_string(), node(3));
        // a 完成后注册第 4 条：应淘汰最旧的已完成 a，保留 b/c/新条目
        a.finish();
        let _d = reg.register("d:4".to_string(), node(4));
        let ids: Vec<u64> = reg.snapshot().iter().map(|i| i.id).collect();
        assert_eq!(ids.len(), 3, "超上限必须淘汰");
        assert!(!ids.contains(&a.id()), "最旧已完成条目应被淘汰");
        assert!(ids.contains(&b.id()), "未完成的较早条目应保留");
        assert!(ids.contains(&_c.id()), "较新条目应保留");
        // 全部活跃时继续注册：淘汰最旧条目
        let _ = ids;
        let _e = reg.register("e:5".to_string(), node(5));
        let ids2: Vec<u64> = reg.snapshot().iter().map(|i| i.id).collect();
        assert_eq!(ids2.len(), 3);
        assert!(!ids2.contains(&ids[0]), "全活跃时应淘汰最旧条目");
        assert!(ids2.contains(&b.id()));
    }

    /// 全局单例：多次调用返回同一实例
    #[test]
    fn test_global_singleton() {
        let ptr = connections_registry() as *const ConnectionRegistry;
        let ptr2 = connections_registry() as *const ConnectionRegistry;
        assert_eq!(ptr, ptr2);
    }
}
