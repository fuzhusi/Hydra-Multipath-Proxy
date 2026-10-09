//! 探测基础设施：进程级共享 tokio runtime + 测速目标解析（env 可覆盖）。

/// 进程级探测 runtime（审查 R-34）：健康检查（每 30s）与单节点手动测试共用，
/// 不再每次在后台线程里冷启动/销毁一个多线程 tokio runtime（num_cpus 个
/// worker 线程 + epoll 实例 + 线程创建毛刺）。多线程可从任意线程 block_on。
pub(crate) fn probe_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("创建探测 tokio 运行时失败")
    })
}

/// 单节点测速探测目标默认值（问题 3）。
///
/// 此前用 `192.0.0.1:9`（TEST-NET-3 文档段 discard 端口）：该网段不路由，多数
/// 防火墙对不可路由地址静默丢包 → 节点侧建连挂满超时 → 节点明明健康却报
/// "测速超时"。改为 `1.1.1.1:443`（Cloudflare，TCP 443 全球快速可连，节点侧
/// 建连 ~1ms 级）：节点回 TargetUnreachable（0x01 应答）仍代表"认证通过、
/// 节点健康"（目标侧失败不影响节点判定），成功/握手失败/连接超时三分逻辑不变。
pub(crate) const PROBE_TARGET_DEFAULT: &str = "1.1.1.1:443";

/// 探测目标 env 覆盖键（特殊网络环境下可指向自选可达地址）
pub(crate) const PROBE_TARGET_ENV: &str = "HYDRA_PROBE_TARGET";

/// 探测目标解析（纯函数便于单测）：env 值非空（去首尾空白）则覆盖，否则用默认值。
pub(crate) fn probe_target_from(env_value: Option<&str>) -> String {
    match env_value {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => PROBE_TARGET_DEFAULT.to_string(),
    }
}

/// 当前生效的探测目标（读 env 覆盖；只读不写，无 R-24 数据竞争面）
pub(crate) fn probe_target() -> String {
    probe_target_from(std::env::var(PROBE_TARGET_ENV).ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 问题 3：测速探测目标常量与 env 覆盖 ──

    #[test]
    fn probe_target_defaults_to_cloudflare_443() {
        // 默认目标必须是 1.1.1.1:443（修复 192.0.0.1:9 静默丢包导致的测速误判）
        assert_eq!(probe_target_from(None), "1.1.1.1:443");
        assert_eq!(probe_target_from(Some("")), "1.1.1.1:443");
        assert_eq!(probe_target_from(Some("   ")), "1.1.1.1:443");
        assert_eq!(PROBE_TARGET_DEFAULT, "1.1.1.1:443");
        assert_eq!(PROBE_TARGET_ENV, "HYDRA_PROBE_TARGET");
    }

    #[test]
    fn probe_target_env_override() {
        // env 覆盖生效（去首尾空白）；纯函数无进程 env 副作用，可并行
        assert_eq!(probe_target_from(Some("10.0.0.1:8080")), "10.0.0.1:8080");
        assert_eq!(probe_target_from(Some("  1.2.3.4:443  ")), "1.2.3.4:443");
    }
}
