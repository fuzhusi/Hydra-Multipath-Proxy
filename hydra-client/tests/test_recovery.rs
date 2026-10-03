//! A2：Offline 节点自动恢复探测集成测试。
//! 杀节点 → Offline → 同端口重启节点 → 探测周期+超时+余量内恢复 Online → 端到端流量恢复。
//!
//! 注意：同一测试二进制内的多个 #[tokio::test] 并行运行且共享进程环境变量，
//! 因此 HYDRA_PROBE_INTERVAL_SECS 的取值/回退断言与主流程合并在单个测试内串行执行。

mod common;

use std::time::Duration;

use hydra_protocol::{NodeStatus, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn node_status(nodes: &[hydra_protocol::NodeInfo], addr: std::net::SocketAddr) -> NodeStatus {
    nodes
        .iter()
        .find(|n| n.address == addr)
        .map(|n| n.status.clone())
        .expect("node not found in scheduler")
}

/// 杀节点 → Offline → 重启节点 → 恢复 Online ≤ 探测周期 + 超时 + 2s，且端到端流量恢复
#[tokio::test]
async fn test_offline_node_auto_recovery() -> Result<()> {
    // 探测间隔 env 解析：默认 30s / 非法回退 / 0 clamp 到 1（与主流程串行，避免并行 env 竞争）
    std::env::remove_var("HYDRA_PROBE_INTERVAL_SECS");
    assert_eq!(
        hydra_client::probe_interval_from_env(),
        Duration::from_secs(30),
        "default probe interval must be 30s"
    );
    std::env::set_var("HYDRA_PROBE_INTERVAL_SECS", "not-a-number");
    assert_eq!(
        hydra_client::probe_interval_from_env(),
        Duration::from_secs(30),
        "invalid value must fall back to default"
    );
    std::env::set_var("HYDRA_PROBE_INTERVAL_SECS", "0");
    assert_eq!(
        hydra_client::probe_interval_from_env(),
        Duration::from_secs(1),
        "0 must clamp to 1s"
    );

    // 短探测周期（1s）用于主流程
    std::env::set_var("HYDRA_PROBE_INTERVAL_SECS", "1");

    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let (proxy_addr, proxy) =
        common::spawn_proxy_with_handle(vec![(node.addr, node.cert.clone())]).await;
    let scheduler = proxy.scheduler();
    let target = format!("127.0.0.1:{}", echo_port);

    // 1. 初始 Online，请求正常
    assert!(matches!(
        node_status(&scheduler.get_all_nodes().await, node.addr),
        NodeStatus::Online
    ));
    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    s.write_all(b"before-kill").await?;
    let mut buf = [0u8; 11];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"before-kill");

    // 2. 杀节点：关闭 QUIC endpoint，等待端口释放（server 任务退出）
    node.endpoint.close(0u32.into(), b"test shutdown");
    // 释放测试持有的 endpoint 克隆——与 server 任务内的 endpoint 一同释放 UDP socket
    drop(node.endpoint);
    assert!(
        common::wait_udp_port_free(node.addr.port(), Duration::from_secs(5)).await,
        "node port not released after close"
    );

    // 连接失败路径将把节点标记 Offline；触发一次失败请求确保状态落入 Offline
    let (_s, _code) = common::socks5_connect_lenient(proxy_addr, &target).await?;
    // 等待故障切换路径完成 mark_node_offline
    let mut marked_offline = false;
    for _ in 0..50 {
        if matches!(
            node_status(&scheduler.get_all_nodes().await, node.addr),
            NodeStatus::Offline
        ) {
            marked_offline = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(marked_offline, "node was not marked Offline after kill");

    // 探测器在节点死亡期间持续失败：等待至少一个探测周期，确认未被误恢复
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        matches!(
            node_status(&scheduler.get_all_nodes().await, node.addr),
            NodeStatus::Offline
        ),
        "dead node must stay Offline"
    );

    // 3. 同端口、同证书重启节点
    let restarted = common::spawn_node_with_opts(node.addr, node.opts.clone()).await;
    assert_eq!(
        restarted.addr, node.addr,
        "restarted node must reuse the port"
    );
    assert_eq!(
        restarted.cert, node.cert,
        "restarted node must reuse the cert"
    );

    // 4. 轮询等待恢复 Online：deadline = 探测周期(1s) + 探测超时(5s) + 2s 余量（放宽到 10s 防 CI 抖动）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut recovered = false;
    while tokio::time::Instant::now() < deadline {
        if matches!(
            node_status(&scheduler.get_all_nodes().await, node.addr),
            NodeStatus::Online
        ) {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recovered,
        "node did not recover Online within probe deadline"
    );

    // 5. 端到端：流量经重启后的节点恢复正常
    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    s.write_all(b"after-recovery").await?;
    let mut buf = [0u8; 14];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"after-recovery");

    std::env::remove_var("HYDRA_PROBE_INTERVAL_SECS");
    Ok(())
}
