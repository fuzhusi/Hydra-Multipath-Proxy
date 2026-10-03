//! 每源固定窗口限速器（吸收 P1-2，C1 规格：固定窗口实现即可但要有界）。
//!
//! 设计要点：
//! - **只对垃圾记账**：正常流量（解包成功）从不进入本表——`blocked()` 只做一次哈希查找，
//!   不插入条目；正常路径零分配零记账。只有解包失败的包才通过 `note_garbage()` 计入。
//! - **有界**：HashMap 按源 IP 记录，容量上限 `capacity`；插入时先淘汰过期窗口，
//!   仍满则整表清空（最坏 O(capacity)，攻击场景下 ≤ 每接收 capacity 个包触发一次，代价可忽略）。
//! - **固定窗口**：`window_ms` 对齐取整为窗口号 `now_ms / window_ms`，窗口切换自动重置计数。
//! - **预算语义**：每源每窗口最多 `budget` 次解包尝试；超出后该源在本窗口内剩余包
//!   **不尝试解包直接丢弃**（把每源每窗口的混淆层 CPU 封顶在 budget × 3 次 keystream 运算）。
//!   下一窗口自动恢复预算（给时钟错配/密钥错配的对端持续重试的机会）。

use std::collections::HashMap;
use std::net::IpAddr;

/// 默认表容量（源 IP 数上限）。4096 × ~50B ≈ 数百 KB 内存上界。
pub const DEFAULT_CAPACITY: usize = 4096;
/// 默认窗口时长（毫秒）
pub const DEFAULT_WINDOW_MS: u64 = 1000;
/// 默认每源每窗口垃圾解包预算
pub const DEFAULT_BUDGET: u32 = 2048;

#[derive(Debug, Clone, Copy)]
struct Window {
    /// 固定窗口号（now_ms / window_ms）
    id: u64,
    /// 本窗口内已记账的垃圾包数
    seen: u32,
}

/// 有界每源固定窗口限速器。线程安全由调用方（`ObfsCrypto` 的 Mutex）保证。
#[derive(Debug)]
pub struct SourceLimiter {
    map: HashMap<IpAddr, Window>,
    capacity: usize,
    window_ms: u64,
    budget: u32,
}

impl SourceLimiter {
    pub fn new(capacity: usize, window_ms: u64, budget: u32) -> Self {
        Self {
            map: HashMap::new(),
            capacity: capacity.max(1),
            window_ms: window_ms.max(1),
            budget,
        }
    }

    /// 该源在本窗口内是否已超预算（超预算 → 不解包直接丢）。
    /// 只查找不插入：正常流量永远不产生表条目。
    pub fn blocked(&mut self, src: IpAddr, now_ms: u64) -> bool {
        let wid = now_ms / self.window_ms;
        match self.map.get_mut(&src) {
            // 同一窗口：按计数判断
            Some(w) if w.id == wid => w.seen >= self.budget,
            // 过期条目：窗口翻转，重置计数（不算垃圾，只是恢复预算）
            Some(w) => {
                w.id = wid;
                w.seen = 0;
                false
            }
            None => false,
        }
    }

    /// 记一次解包失败。达到预算后 `blocked()` 开始返回 true。
    pub fn note_garbage(&mut self, src: IpAddr, now_ms: u64) {
        let wid = now_ms / self.window_ms;
        if self.map.len() >= self.capacity && !self.map.contains_key(&src) {
            // 有界淘汰：先清过期窗口；仍满（全部活跃 = 伪造源泛洪）则拒绝新源插入。
            // 不整表清空——那会重置攻击者已消耗的预算，使其可以轮换源无限维持攻击。
            self.map.retain(|_, w| w.id == wid);
            if self.map.len() >= self.capacity {
                return;
            }
        }
        let w = self.map.entry(src).or_insert(Window { id: wid, seen: 0 });
        if w.id != wid {
            w.id = wid;
            w.seen = 0;
        }
        w.seen += 1;
    }

    /// 当前表内源数量（测试/观测用）
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8) -> IpAddr {
        std::net::IpAddr::from([127, 0, 0, a])
    }

    #[test]
    fn budget_gates_per_source_per_window() {
        let mut l = SourceLimiter::new(64, 1000, 2);
        assert!(!l.blocked(ip(1), 0));
        l.note_garbage(ip(1), 0);
        assert!(!l.blocked(ip(1), 0));
        l.note_garbage(ip(1), 0);
        // 预算 2 耗尽 → 本窗口内拦截
        assert!(l.blocked(ip(1), 0));
        assert!(l.blocked(ip(1), 999));
        // 其他源不受影响
        assert!(!l.blocked(ip(2), 0));
    }

    #[test]
    fn window_rollover_resets_budget() {
        let mut l = SourceLimiter::new(64, 1000, 1);
        l.note_garbage(ip(1), 0);
        assert!(l.blocked(ip(1), 500));
        // 新窗口：预算恢复
        assert!(!l.blocked(ip(1), 1000));
        assert!(!l.blocked(ip(1), 12345));
    }

    #[test]
    fn table_is_bounded_and_evicts() {
        let mut l = SourceLimiter::new(4, 1000, 1000);
        // 同窗口灌入远超容量的伪造源
        for i in 0..100u8 {
            l.note_garbage(ip(i), 0);
        }
        assert!(l.len() <= 4, "表必须有界，实际 {}", l.len());
        // 窗口翻转后过期条目可被淘汰，新源可入表
        for i in 0..10u8 {
            l.note_garbage(ip(i), 2000);
        }
        assert!(l.len() <= 4);
        assert!(l.len() > 0);
    }

    #[test]
    fn normal_traffic_never_inserts_entries() {
        let mut l = SourceLimiter::new(64, 1000, 2);
        for _ in 0..10_000 {
            assert!(!l.blocked(ip(7), 0));
        }
        assert!(l.is_empty(), "正常流量不得在限速表中留下条目");
    }
}
