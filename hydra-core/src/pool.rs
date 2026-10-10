//! 节点温连接池（pre-warm）：零协议变更消除每请求握手延迟。
//!
//! # 问题背景
//! v3 协议一条 TCP/TLS 连接只服务一个目标（地址帧 → 2B 应答 → 裸转发 → 关闭），
//! 浏览器式短请求每条都付一次 TCP + TLS 1.3 + Noise-PSK 握手（约一个 RTT +
//! 握手计算，实测 300–500ms）。真·单连接多目标需要帧化改协议（v4，破坏裸转发
//! 透明性），本池用**预热**拿到几乎全部延迟收益：握手提前在上一请求的转发期间
//! 后台完成，请求到达时取用现成温连接直发目标帧。
//!
//! # 语义
//! - 每节点空闲温连接上限 [`IDLE_CAP_PER_NODE`]，存活 [`IDLE_TTL`]（checkout
//!   时惰性淘汰过期项，drop 即关闭）；
//! - 温连接**交接即消费**：`request_target` 已发地址帧，失败/成功都不回池；
//! - 上层在每次成功 open 后调用 `replenish`（proxy 侧封装）保持池水位——
//!   握手与当前请求的转发完全重叠；
//! - 池是**尽力而为优化**：checkout 后请求失败一律弃连回退全新握手，不参与
//!   节点评分，任何路径都不会因池而改变原有错误语义。
//!
//! 节点侧零改动（旧/新节点、单/多节点部署均兼容）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::tcp_transport::TcpNodeStream;

/// 每节点空闲温连接基础上限（内核优化 #7 弹性化：实际 cap =
/// clamp(BASE, 近期并发峰值 EWMA, MAX)——突发期自动抬升水位，静默期衰减回落）
pub const IDLE_CAP_BASE: usize = 2;
/// 弹性上限（突发命中需要；节点余量充足 per-IP 256/全局 1000，8/节点可忽略）
pub const IDLE_CAP_MAX: usize = 8;
/// 兼容别名（replenish 等调用点沿用）
pub const IDLE_CAP_PER_NODE: usize = IDLE_CAP_BASE;
/// 温连接空闲寿命：checkout 时惰性淘汰（节点侧连接空闲看门狗 300s，60s 内
/// 复用不会撞上）
pub const IDLE_TTL: Duration = Duration::from_secs(60);

struct Entry<S> {
    stream: S,
    warmed_at: Instant,
}

/// 温连接池。线程安全（std Mutex，锁内无 await）。
/// 泛型参数仅为可测试性（默认 [`TcpNodeStream`]，测试注入 Duplex 流）。
pub struct ChannelPool<S = TcpNodeStream> {
    inner: Mutex<HashMap<SocketAddr, Vec<Entry<S>>>>,
    /// 每节点近期并发需求（checkout 未命中次数的 60s 滑窗 EWMA）——
    /// 弹性 cap 驱动（内核优化 #7）
    peak: Mutex<HashMap<SocketAddr, f64>>,
}

impl<S> ChannelPool<S> {
    /// `new()` 手工构造而非 `derive(Default)`：`Default` 对泛型会附带
    /// `S: Default` 约束，而池语义不需要 S 可默认构造。
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            peak: Mutex::new(HashMap::new()),
        }
    }

    /// 节点当前弹性 cap：clamp(BASE, peak EWMA, MAX)。
    /// peak 在 checkout 未命中时 +1（EWMA 抬升），checkin 命中时缓慢衰减。
    fn cap_for(&self, node: SocketAddr) -> usize {
        let peak = self
            .peak
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&node)
            .copied()
            .unwrap_or(0.0);
        (IDLE_CAP_BASE as f64)
            .max(peak.ceil())
            .min(IDLE_CAP_MAX as f64) as usize
    }

    /// 记录一次 checkout 未命中（需求信号）：EWMA 抬升
    fn note_miss(&self, node: SocketAddr) {
        let mut m = self.peak.lock().unwrap_or_else(|p| p.into_inner());
        let cur = m.get(&node).copied().unwrap_or(0.0);
        // EWMA α=0.5：突发快速抬升
        m.insert(node, cur * 0.5 + (cur + 1.0) * 0.5);
    }

    /// 记录一次成功交付：缓慢衰减（静默期 cap 回落至 BASE）
    fn note_hit(&self, node: SocketAddr) {
        let mut m = self.peak.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(cur) = m.get_mut(&node) {
            *cur = (*cur - IDLE_CAP_BASE as f64).max(0.0) * 0.95 + IDLE_CAP_BASE as f64;
            if *cur <= IDLE_CAP_BASE as f64 + 0.1 {
                m.remove(&node);
            }
        }
    }

    /// 取出一根温连接：头部弹出，途中淘汰过期项（drop 即关闭）。
    /// 池空/该节点无温连接 → None（调用方回退全新握手；未命中记录进
    /// 峰值 EWMA，弹性 cap 随需求抬升）。
    pub fn checkout(&self, node: SocketAddr) -> Option<S> {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(mut slot) = m.remove(&node) else {
            drop(m);
            self.note_miss(node);
            return None;
        };
        let now = Instant::now();
        while let Some(e) = slot.first() {
            if now.duration_since(e.warmed_at) < IDLE_TTL {
                break;
            }
            let _ = slot.remove(0); // 过期：drop 关闭
        }
        let out = if slot.is_empty() {
            None
        } else {
            Some(slot.remove(0).stream)
        };
        if !slot.is_empty() {
            m.insert(node, slot);
        }
        drop(m);
        self.note_hit(node);
        out
    }

    /// 归还温连接；达弹性上限即丢弃关闭（超出部分直接 drop）。
    pub fn checkin(&self, node: SocketAddr, stream: S) {
        let cap = self.cap_for(node);
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let slot = m.entry(node).or_default();
        if slot.len() >= cap {
            return; // stream drop = 关闭
        }
        slot.push(Entry {
            stream,
            warmed_at: Instant::now(),
        });
    }

    /// 该节点当前空闲温连接数（补充决策：仅低于上限时回填）。
    pub fn idle_len(&self, node: SocketAddr) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&node)
            .map_or(0, |s| s.len())
    }

    /// 周期清扫：淘汰全部过期条目（返回清除数）。配 ProxyServer reaper
    /// 周期调用——checkout 惰性淘汰之外的第二道防线（永不 checkout 的
    /// 节点条目不再无限期驻留 fd）。
    pub fn evict_expired(&self) -> usize {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = std::time::Instant::now();
        let mut removed = 0usize;
        m.retain(|_, slot| {
            let before = slot.len();
            slot.retain(|e| now.duration_since(e.warmed_at) < IDLE_TTL);
            removed += before - slot.len();
            !slot.is_empty()
        });
        removed
    }

    /// 全池空闲连接总数（测试/可观测性）。
    pub fn total_idle(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(Vec::len)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn node(a: u8) -> SocketAddr {
        format!("127.0.0.1:{a}").parse().unwrap()
    }

    fn chan() -> DuplexStream {
        let (_a, b) = tokio::io::duplex(64);
        b
    }

    #[test]
    fn checkout_空池返回none() {
        let p = ChannelPool::<DuplexStream>::new();
        assert!(p.checkout(node(1)).is_none());
        assert_eq!(p.total_idle(), 0);
    }

    #[test]
    fn 存取往返_各节点互不串池() {
        let p = ChannelPool::<DuplexStream>::new();
        p.checkin(node(1), chan());
        p.checkin(node(1), chan());
        p.checkin(node(2), chan());
        assert_eq!(p.idle_len(node(1)), 2);
        assert_eq!(p.idle_len(node(2)), 1);
        let got = p.checkout(node(1));
        assert!(got.is_some(), "节点1 应可取到温连接");
        assert_eq!(p.idle_len(node(1)), 1);
        // 取空后再取 → None，且空槽位被清理
        let _ = p.checkout(node(1));
        assert!(p.checkout(node(1)).is_none());
        assert_eq!(p.idle_len(node(1)), 0);
        assert_eq!(p.idle_len(node(2)), 1, "节点2 不受影响");
    }

    #[test]
    fn 容量上限_超出即丢弃() {
        let p = ChannelPool::<DuplexStream>::new();
        for _ in 0..5 {
            p.checkin(node(9), chan());
        }
        assert_eq!(p.idle_len(node(9)), IDLE_CAP_PER_NODE);
        assert_eq!(p.total_idle(), IDLE_CAP_PER_NODE);
    }

    #[test]
    fn 过期温连接_checkout时淘汰() {
        let p = ChannelPool::<DuplexStream>::new();
        p.checkin(node(3), chan());
        // 手动把唯一条目改成过期（测试直接操作内部条目）
        {
            let mut m = p.inner.lock().unwrap();
            let slot = m.get_mut(&node(3)).unwrap();
            slot[0].warmed_at = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        assert!(p.checkout(node(3)).is_none(), "过期条目应被淘汰而非交付");
        assert_eq!(p.idle_len(node(3)), 0, "淘汰后空槽位清理");
    }

    #[test]
    fn 弹性cap_未命中抬升_命中衰减_上限封顶() {
        let p = ChannelPool::<DuplexStream>::new();
        let n = node(11);
        // 连续未命中 → peak 抬升 → cap 增大（封顶 MAX）
        for _ in 0..20 {
            assert!(p.checkout(n).is_none()); // 每次未命中 note_miss
        }
        let cap = p.cap_for(n);
        assert!(cap > IDLE_CAP_BASE, "未命中后 cap 应抬升（实际 {cap}）");
        assert!(cap <= IDLE_CAP_MAX);
        // 大量命中 → peak 衰减回落至 BASE 附近
        for _ in 0..50 {
            p.checkin(n, chan());
            let _ = p.checkout(n); // hit → note_hit 衰减
        }
        let cap_after = p.cap_for(n);
        assert!(cap_after <= cap, "命中衰减后 cap 应回落（{cap} → {cap_after}）");
    }

    #[test]
    fn 弹性cap_checkin_按弹性水位收容() {
        let p = ChannelPool::<DuplexStream>::new();
        let n = node(12);
        // 未命中抬升 cap 后，checkin 应能收容超过 BASE 的条目
        for _ in 0..10 {
            assert!(p.checkout(n).is_none());
        }
        let cap = p.cap_for(n);
        for _ in 0..cap {
            p.checkin(n, chan());
        }
        assert_eq!(p.idle_len(n), cap);
        // 超出弹性 cap 的丢弃
        p.checkin(n, chan());
        assert_eq!(p.idle_len(n), cap);
    }

    #[test]
    fn 周期清扫_只清过期_保活新鲜() {
        let p = ChannelPool::<DuplexStream>::new();
        p.checkin(node(7), chan()); // 将过期
        p.checkin(node(7), chan()); // 新鲜
        {
            let mut m = p.inner.lock().unwrap();
            let slot = m.get_mut(&node(7)).unwrap();
            slot[0].warmed_at = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        assert_eq!(p.evict_expired(), 1);
        assert_eq!(p.idle_len(node(7)), 1);
        assert_eq!(p.evict_expired(), 0);
        assert_eq!(p.idle_len(node(7)), 1);
        let _ = p.checkout(node(7));
        assert_eq!(p.evict_expired(), 0);
    }

    #[test]
    fn 过期淘汰后交付未过期条目() {
        let p = ChannelPool::<DuplexStream>::new();
        p.checkin(node(4), chan()); // 头部（将过期）
        p.checkin(node(4), chan()); // 尾部（新鲜）
        {
            let mut m = p.inner.lock().unwrap();
            let slot = m.get_mut(&node(4)).unwrap();
            slot[0].warmed_at = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        // 头部过期被淘汰，交付的是尾部新鲜条目（交付即消费，池清空）
        assert!(p.checkout(node(4)).is_some());
        assert_eq!(p.idle_len(node(4)), 0);
        assert!(p.checkout(node(4)).is_none());
    }
}
