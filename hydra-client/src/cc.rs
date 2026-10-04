//! Brutal 式固定速率拥塞控制（Hysteria2 思路）。
//!
//! ## 背景与动机
//!
//! 高丢包跨境链路上，默认 CUBIC 每次拥塞事件（丢包）都会乘性降窗（指数级退让），
//! 吞吐随丢包率坍缩（Mathis 公式：吞吐 ≈ MSS/(RTT·√p)）。Hysteria2 的 Brutal 拥塞控制
//! 用"发送端按配置带宽恒速发包、不因丢包退让"换高丢包链路下的确定性吞吐。
//!
//! ## 算法（固定速率 + ACK 反馈补齐）
//!
//! - 目标速率 `bandwidth`（来自 env `HYDRA_BRUTAL_MBPS`）。
//! - 窗口锚定在 BDP = `bandwidth × sRTT`：quinn 的 pacer 依 window/RTT 派生发包节奏，
//!   窗口 = BDP 即稳态发包速率 ≈ 配置带宽。
//! - ACK 批次结束时以 ≥1×sRTT 的观测窗估计实际送达率：
//!   - 送达率 ≥ 目标：窗口 = BDP（健康反馈下的再校准，非退让）；
//!   - 送达率 < 目标（丢包吞掉部分带宽）：窗口按缺口比例放大补齐，
//!     系数上限 [`MAX_WINDOW_FACTOR`]（2.0×BDP），防雪崩放大。
//! - **[`Controller::on_congestion_event`] 是空操作（仅计数）**：丢包永不直接降窗——
//!   这是 Brutal 与 CUBIC 的本质区别，也是单测的硬断言。
//!
//! ## 使用约束（务必两端理解一致）
//!
//! 1. **两端都设才有效**：拥塞控制只约束发送端。客户端设了只提升"客户端→节点"方向；
//!    "节点→客户端"方向（下载主方向）必须由节点侧也启用 Brutal 才不退让
//!    （节点侧接线不在本文件权限内，见项目改进计划报告 WS-B/总控）。
//! 2. **接收窗口须 ≥ 带宽×RTT**：对端流接收窗口（`HYDRA_STREAM_WINDOW`，默认 8MB）
//!    小于 BDP 时瓶颈在流控而非拥塞控制，Brutal 无效。经验公式：
//!    `HYDRA_STREAM_WINDOW(MB) ≥ 带宽(Mbps) × RTT(s) / 8`（如 100Mbps×200ms → ≥2.5MB）。
//! 3. **滥用风险如实声明**：固定速率在共享瓶颈上对 CUBIC 流不友好（Brutal 的已知代价），
//!    带宽应配置为不超过实际链路容量（Hysteria2 同样要求）。
//!
//! 未设置 `HYDRA_BRUTAL_MBPS` 时 [`BrutalConfig::from_env`] 返回 None，
//! transport.rs 不动 factory → quinn 默认 CUBIC，行为零改动。

use quinn_proto::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::time::{Duration, Instant};

/// Brutal 带宽配置 env（Mbps，支持小数，如 "30"、"12.5"）
pub const HYDRA_BRUTAL_MBPS_ENV: &str = "HYDRA_BRUTAL_MBPS";

/// 1 Mbps = 125_000 bytes/s
const BYTES_PER_SEC_PER_MBPS: f64 = 1_000_000.0 / 8.0;

/// 无 ACK 反馈前的默认 RTT（初始窗口锚点）
const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(100);
/// 速率估计的最小观测窗（短于它的 ACK 批次噪声过大）
const MIN_RATE_INTERVAL: Duration = Duration::from_millis(25);
/// 最小窗口（MTU 数）——防极小带宽配置下窗口塌到发不出整包
const MIN_WINDOW_MTUS: u64 = 4;
/// 丢包补偿系数上限：窗口最高放大到 MAX_WINDOW_FACTOR × BDP
const MAX_WINDOW_FACTOR: f64 = 2.0;
/// 允许配置的最小/最大带宽（Mbps），越界视为非法配置 → 回退 CUBIC
const MIN_BANDWIDTH_MBPS: f64 = 0.1;
const MAX_BANDWIDTH_MBPS: f64 = 100_000.0;

/// Brutal 拥塞控制配置（= 目标带宽），实现 [`ControllerFactory`] 供 quinn 按需构造控制器。
///
/// quinn 0.10 在连接建立与路径迁移时经 factory 重建控制器，故配置需 Clone 且为共享入口。
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    bandwidth_bytes_per_sec: u64,
}

impl BrutalConfig {
    /// 由目标带宽（字节/秒）构造
    pub fn new(bandwidth_bytes_per_sec: u64) -> Self {
        Self {
            bandwidth_bytes_per_sec: bandwidth_bytes_per_sec.max(1),
        }
    }

    /// 目标带宽（字节/秒）
    pub fn bandwidth_bytes_per_sec(&self) -> u64 {
        self.bandwidth_bytes_per_sec
    }

    /// 读取进程 env [`HYDRA_BRUTAL_MBPS_ENV`]。未设置/非法 → None（用默认 CUBIC，零改动）。
    pub fn from_env() -> Option<Self> {
        Self::from_env_lookup(|name| std::env::var(name).ok())
    }

    /// 可注入 env 的解析核心（单测不触碰进程全局 env）。
    ///
    /// 解析规则：trim 后按 f64 解析，须在 [0.1, 100_000] Mbps 内；空串/非法/越界 → None。
    pub fn from_env_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let raw = lookup(HYDRA_BRUTAL_MBPS_ENV)?;
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let mbps: f64 = raw.parse().ok()?;
        if !mbps.is_finite() || !(MIN_BANDWIDTH_MBPS..=MAX_BANDWIDTH_MBPS).contains(&mbps) {
            return None;
        }
        Some(Self::new((mbps * BYTES_PER_SEC_PER_MBPS) as u64))
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(&self, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.clone(), now, current_mtu))
    }
}

/// Brutal 式控制器状态机。
///
/// 窗口唯一变更入口是 [`Brutal::update_window`]（ACK 批次驱动的速率再校准）；
/// 拥塞事件（丢包/ECN）**永不**直接改窗——固定速率语义的核心。
#[derive(Debug, Clone)]
pub struct Brutal {
    config: BrutalConfig,
    max_datagram_size: u64,
    /// 对端路径 RTT 估计（取自 quinn 传入的 `RttEstimator::get()`，即 sRTT）
    srtt: Option<Duration>,
    /// 当前允许的在途字节数（`Controller::window()` 直接返回）
    window: u64,
    /// 上个观测窗内累计被 ACK 确认的字节数
    acked_bytes: u64,
    /// 上个速率观测窗起点
    last_window_update: Instant,
    /// 诊断计数：拥塞事件次数 / 丢失字节数（Brutal 不据此动作）
    congestion_events: u64,
    lost_bytes: u64,
}

impl Brutal {
    pub fn new(config: BrutalConfig, now: Instant, current_mtu: u16) -> Self {
        let mut c = Self {
            config,
            max_datagram_size: u64::from(current_mtu),
            srtt: None,
            window: 0,
            acked_bytes: 0,
            last_window_update: now,
            congestion_events: 0,
            lost_bytes: 0,
        };
        c.window = c.compute_initial_window();
        c
    }

    /// 初始窗口 = 默认 RTT（100ms）下的 BDP，下限 4×MTU。
    /// 首批 ACK 带回真实 sRTT 后，窗口按 [`Brutal::update_window`] 校准。
    fn compute_initial_window(&self) -> u64 {
        let bdp = self.bdp_with(DEFAULT_INITIAL_RTT);
        bdp.max(self.min_window())
    }

    fn bdp(&self) -> u64 {
        self.bdp_with(self.rtt_or_default())
    }

    fn bdp_with(&self, rtt: Duration) -> u64 {
        (self.config.bandwidth_bytes_per_sec as f64 * rtt.as_secs_f64()) as u64
    }

    fn rtt_or_default(&self) -> Duration {
        self.srtt.unwrap_or(DEFAULT_INITIAL_RTT)
    }

    fn min_window(&self) -> u64 {
        self.max_datagram_size * MIN_WINDOW_MTUS
    }

    fn max_window(&self) -> u64 {
        // 下限兜底 min_window：极小带宽×大 MTU 时 2×BDP 可能小于 4×MTU，
        // 而 clamp 要求 min ≤ max，否则 panic
        ((self.bdp() as f64 * MAX_WINDOW_FACTOR) as u64).max(self.min_window())
    }

    /// `Controller::on_ack` 的适配核心（RttEstimator 无公开构造器，单测直接驱动本方法）。
    fn observe_ack(&mut self, bytes: u64, rtt: Duration) {
        self.srtt = Some(rtt);
        self.acked_bytes += bytes;
    }

    /// ACK 批次结束时的窗口再校准（窗口唯一变更入口）。
    ///
    /// - 观测窗 < max(sRTT, [`MIN_RATE_INTERVAL`])：样本不足，跳过；
    /// - 无确认字节 / 应用限速（`app_limited`）：缺口不是丢包造成的，
    ///   仅保证窗口不低于 BDP（只增不减）；
    /// - 送达率 < 目标：按缺口比例放大补齐（封顶 [`MAX_WINDOW_FACTOR`]×BDP）；
    /// - 送达率 ≥ 目标：窗口 = BDP（健康反馈下的再校准，下限始终 ≥ min_window）。
    fn update_window(&mut self, now: Instant, app_limited: bool) {
        let elapsed = now
            .checked_duration_since(self.last_window_update)
            .unwrap_or_default();
        let min_interval = self.rtt_or_default().max(MIN_RATE_INTERVAL);
        if elapsed < min_interval {
            return;
        }
        let acked = std::mem::take(&mut self.acked_bytes);
        self.last_window_update = now;

        let bdp = self.bdp().clamp(self.min_window(), self.max_window());
        if acked == 0 || app_limited {
            self.window = self.window.max(bdp);
            return;
        }

        let actual = acked as f64 / elapsed.as_secs_f64();
        let target = self.config.bandwidth_bytes_per_sec as f64;
        let factor = if actual < target {
            (target / actual).min(MAX_WINDOW_FACTOR)
        } else {
            1.0
        };
        self.window = ((bdp as f64 * factor) as u64).clamp(self.min_window(), self.max_window());
    }
}

impl Controller for Brutal {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {
        // 固定速率语义：不跟踪发送字节，速率由 window=BDP 经 quinn pacer 体现
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.observe_ack(bytes, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.update_window(now, app_limited);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Brutal 核心：丢包/ECN 不降窗、不退让。仅保留诊断计数。
        self.congestion_events += 1;
        self.lost_bytes += lost_bytes;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.compute_initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// 把 Brutal 拥塞控制应用到 TransportConfig。
///
/// 仅当 `HYDRA_BRUTAL_MBPS` 已设置时由 transport.rs 调用；未设置走 quinn 默认 CUBIC。
pub fn apply_brutal_congestion_control(
    transport_config: &mut quinn::TransportConfig,
    config: BrutalConfig,
) {
    tracing::info!(
        "Brutal congestion control enabled: target bandwidth = {} Mbps ({} bytes/s). \
         注意：两端都设才对双向有效；对端接收窗口(HYDRA_STREAM_WINDOW)需 ≥ 带宽×RTT",
        config.bandwidth_bytes_per_sec as f64 * 8.0 / 1_000_000.0,
        config.bandwidth_bytes_per_sec
    );
    transport_config.congestion_controller_factory(config);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个测试独立的时间基线（Instant 只能取自时钟，内部相对推进）
    fn t0() -> Instant {
        Instant::now()
    }

    fn config_mbps(mbps: f64) -> BrutalConfig {
        BrutalConfig::new((mbps * BYTES_PER_SEC_PER_MBPS) as u64)
    }

    // ===================== env 解析 =====================

    fn env_of<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            map.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn brutal_env_unset_returns_none() {
        // 未设置 → None → transport 不动 factory → quinn 默认 CUBIC（回归保障）
        assert!(BrutalConfig::from_env_lookup(|_| None).is_none());
    }

    #[test]
    fn brutal_env_parses_decimal_mbps() {
        let c = BrutalConfig::from_env_lookup(env_of(&[(HYDRA_BRUTAL_MBPS_ENV, "12.5")])).unwrap();
        assert_eq!(c.bandwidth_bytes_per_sec(), 1_562_500); // 12.5 Mbps = 1.5625 MB/s
    }

    #[test]
    fn brutal_env_invalid_values_fall_back_to_cubic() {
        // （"1e2" 是合法 f64 科学计数 = 100Mbps，按可接受处理）
        for bad in [
            "abc", "", "   ", "-5", "0", "0.05", "8.5.1", "Infinity", "NaN", "100001",
        ] {
            let r = BrutalConfig::from_env_lookup(env_of(&[(HYDRA_BRUTAL_MBPS_ENV, bad)]));
            assert!(r.is_none(), "env={bad:?} 应视为非法并回退 CUBIC");
        }
    }

    // ===================== 固定速率窗口行为 =====================

    #[test]
    fn initial_window_is_bdp_at_default_rtt() {
        let c = Brutal::new(config_mbps(50.0), t0(), 1200);
        // 50 Mbps = 6_250_000 B/s × 100ms = 625_000 B
        assert_eq!(c.window(), 625_000);
        assert_eq!(c.initial_window(), 625_000);
    }

    #[test]
    fn tiny_bandwidth_floors_at_four_mtu() {
        // 0.1 Mbps × 100ms = 1250 B < 4×1200 → 窗口塌到发不出整包，须抬到下限
        let c = Brutal::new(config_mbps(0.1), t0(), 1200);
        assert_eq!(c.window(), 4 * 1200);
    }

    #[test]
    fn window_grows_with_acks_when_rtt_exceeds_default() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(10.0), now, 1200);
        assert_eq!(c.window(), 125_000); // 10 Mbps × 100ms

        // 真实 sRTT = 200ms → BDP = 1_250_000×0.2 = 250_000 B > 初始窗口
        c.observe_ack(1_000_000, Duration::from_millis(200));
        // 观测窗 250ms ≥ sRTT；送达 1MB/0.25s = 4MB/s ≥ 目标 1.25MB/s → 窗口校准到 BDP
        c.on_end_acks(now + Duration::from_millis(250), 0, false, None);
        assert_eq!(c.window(), 250_000);
    }

    #[test]
    fn window_ratchets_up_to_bdp_even_when_app_limited() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(10.0), now, 1200);
        c.observe_ack(1, Duration::from_millis(200));
        // app_limited：缺口是应用没数据，不是丢包 → 只抬到 BDP，不估速率
        c.on_end_acks(now + Duration::from_millis(250), 0, true, None);
        assert_eq!(c.window(), 250_000);
    }

    #[test]
    fn loss_shortfall_inflates_window_up_to_two_times_bdp() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(10.0), now, 1200); // 目标 1_250_000 B/s
        c.observe_ack(625_000, Duration::from_millis(100));
        // 送达 625_000B / 1.0s = 625_000 B/s = 0.5×目标 → 系数 2.0 → 窗口 = 2×BDP(100ms)=250_000
        c.on_end_acks(now + Duration::from_secs(1), 0, false, None);
        assert_eq!(c.window(), 250_000);

        // 继续丢包到缺口更大：送达率 0.1×目标 → 系数本应 10，封顶 2.0
        c.observe_ack(125_000, Duration::from_millis(100));
        c.on_end_acks(now + Duration::from_secs(2), 0, false, None);
        assert_eq!(c.window(), 250_000, "补偿系数封顶 2×BDP，不得无限放大");
    }

    #[test]
    fn short_observation_window_skips_recalibration() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(10.0), now, 1200);
        c.observe_ack(1_000_000, Duration::from_millis(200));
        // 观测窗 50ms < max(sRTT=200ms) → 跳过，窗口保持初始值
        c.on_end_acks(now + Duration::from_millis(50), 0, false, None);
        assert_eq!(c.window(), 125_000);
    }

    // ===================== 不退让（Brutal 本质）=====================

    #[test]
    fn congestion_events_never_shrink_window() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(50.0), now, 1200); // 目标 6_250_000 B/s，初始 625_000
                                                               // 先经丢包缺口把窗口推到补偿上限：送达率 0.1×目标 → 窗口 = 2×BDP = 1_250_000
        c.observe_ack(625_000, Duration::from_millis(100));
        c.on_end_acks(now + Duration::from_secs(1), 0, false, None);
        assert_eq!(c.window(), 1_250_000);
        let before = c.window();

        // 模拟持续高丢包：普通拥塞事件、持久拥塞、大块丢失，窗口必须逐字节不变
        for i in 0..100 {
            c.on_congestion_event(now + Duration::from_millis(i), now, i % 2 == 0, 100_000);
        }
        assert_eq!(c.window(), before, "丢包不得降窗（CUBIC 会乘性减半）");
        assert_eq!(c.congestion_events, 100);
        assert_eq!(c.lost_bytes, 100 * 100_000);

        // 拥塞事件后再来健康 ACK 批次：窗口按送达率校准回 BDP（不叠加任何退让罚金）
        c.observe_ack(6_250_000, Duration::from_millis(100));
        c.on_end_acks(now + Duration::from_secs(2), 0, false, None);
        assert_eq!(
            c.window(),
            625_000,
            "送达率恢复=目标 → 窗口=BDP(50Mbps×100ms)"
        );
    }

    // ===================== 工厂 / 克隆 / MTU =====================

    #[test]
    fn factory_builds_controller_with_expected_initial_window() {
        let now = t0();
        let built = config_mbps(50.0).build(now, 1200);
        assert_eq!(built.window(), 625_000);
        assert_eq!(built.initial_window(), 625_000);
    }

    #[test]
    fn clone_box_preserves_window_state() {
        // quinn 0.10 在路径迁移时经 clone_box 重建控制器，状态不能丢
        let now = t0();
        let mut c = Brutal::new(config_mbps(10.0), now, 1200);
        c.observe_ack(1_000_000, Duration::from_millis(200));
        c.on_end_acks(now + Duration::from_millis(250), 0, false, None);
        let cloned = c.clone_box();
        assert_eq!(cloned.window(), c.window());
        assert_eq!(cloned.initial_window(), c.initial_window());
    }

    #[test]
    fn mtu_update_raises_min_window_floor() {
        let now = t0();
        let mut c = Brutal::new(config_mbps(0.1), now, 1200);
        assert_eq!(c.window(), 4 * 1200);
        c.on_mtu_update(9000);
        c.observe_ack(0, Duration::from_millis(100));
        c.on_end_acks(now + Duration::from_millis(200), 0, true, None);
        // BDP 1250 < 新下限 4×9000 → app_limited 分支 clamp 到 36000
        assert_eq!(c.window(), 4 * 9000);
    }

    #[test]
    fn into_any_downcasts_back_to_brutal() {
        let c: Box<dyn Controller> = Box::new(Brutal::new(config_mbps(10.0), t0(), 1200));
        let any = c.into_any();
        assert!(any.downcast::<Brutal>().is_ok());
    }
}
