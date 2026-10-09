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

/// 每节点空闲温连接上限（浏览器对同一节点并发通常 ≤2；上限 2 平衡命中率和
/// 节点侧闲置连接驻留）
pub const IDLE_CAP_PER_NODE: usize = 2;
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
}

impl<S> ChannelPool<S> {
    /// `new()` 手工构造而非 `derive(Default)`：`Default` 对泛型会附带
    /// `S: Default` 约束，而池语义不需要 S 可默认构造。
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// 取出一根温连接：头部弹出，途中淘汰过期项（drop 即关闭）。
    /// 池空/该节点无温连接 → None（调用方回退全新握手）。
    pub fn checkout(&self, node: SocketAddr) -> Option<S> {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut slot = m.remove(&node)?;
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
        out
    }

    /// 归还温连接；达上限即丢弃关闭（超出部分直接 drop）。
    pub fn checkin(&self, node: SocketAddr, stream: S) {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let slot = m.entry(node).or_default();
        if slot.len() >= IDLE_CAP_PER_NODE {
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
