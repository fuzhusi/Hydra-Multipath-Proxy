//! 批次 A5：高频事件采样器。
//!
//! 数据面热路径上个别失败/丢弃事件在故障场景会退化为每包一条（回包注入
//! 失败、上行队列满丢弃等），洪峰时日志本身就是性能问题。采样器以纯原子
//! 计数放行每 N 条中的第 1 条（N=50000，调用点静态注释标注采样因子），
//! 零锁、零分配；未放行的事件仅计一次 fetch_add。

use std::sync::atomic::{AtomicUsize, Ordering};

/// 采样器（静态 `static SAMPLER: Sampler = Sampler::new();` 使用）
pub struct Sampler {
    n: AtomicUsize,
}

impl Sampler {
    pub const fn new() -> Self {
        Self {
            n: AtomicUsize::new(0),
        }
    }

    /// 每 `every` 条放行第 1 条（`every == 0` 视为不采样——全放行且不计数；
    /// 调用点传静态常量，语义由本约定固定）。
    #[inline]
    pub fn should_log(&self, every: usize) -> bool {
        every == 0 || self.n.fetch_add(1, Ordering::Relaxed).is_multiple_of(every)
    }

    /// 累计事件数（观测用）
    pub fn total(&self) -> usize {
        self.n.load(Ordering::Relaxed)
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每 50000 条放行 1 条：首条放行，其后 49999 条拦截，第 50001 条再放行
    #[test]
    fn test_sampler_every_n() {
        const N: usize = 50_000;
        let s = Sampler::new();
        assert!(s.should_log(N), "首条应放行");
        for _ in 1..N {
            assert!(!s.should_log(N), "窗口内不应放行");
        }
        assert!(s.should_log(N), "下一个整除点应放行");
        // 计数包含两次放行自身（先计数后判定）
        assert_eq!(s.total(), N + 1);
    }

    /// 采样因子 0 = 不采样（全放行）
    #[test]
    fn test_sampler_zero_factor_passes_all() {
        let s = Sampler::new();
        for _ in 0..10 {
            assert!(s.should_log(0));
        }
        assert_eq!(s.total(), 0, "因子 0 不消耗计数");
    }
}
