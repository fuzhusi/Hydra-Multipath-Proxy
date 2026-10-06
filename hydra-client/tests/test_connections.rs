//! 连接注册表 E2E：SOCKS5 连接经代理中继 → 注册表快照出现该连接、
//! 字节一致；关闭后转 inactive（「最近关闭」语义）。

mod common;

use std::time::Duration;

use hydra_client::connections::connections_registry;
use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 容忍窗口：与流量 E2E 同余量（防偶发重连/分块边界差异）
fn counted_within(actual: u64, expect: u64) -> bool {
    actual >= expect && actual <= expect + 2048
}

/// 起 proxy + 节点 + echo，建一条 SOCKS5 连接传数据：
/// 1. 传输中快照出现该连接（active，节点归属正确）；
/// 2. 字节累计与实际传输一致（±余量）；
/// 3. 关闭后条目转 inactive 且保留（最近关闭）。
#[tokio::test]
async fn test_connection_registry_tracks_socks_relay() -> Result<()> {
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let (proxy_addr, _proxy, _monitor) =
        common::spawn_proxy_with_monitor(vec![(node.addr, node.cert.clone())]).await;
    let target = format!("127.0.0.1:{}", echo_port);

    // 注册表是进程级单例：清空后本测试从零开始（并行用例互不依赖计数基线）
    connections_registry().clear();

    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();

    // 回显一半后采样：此时中继仍在进行，快照应出现 active 连接
    let (first, second) = payload.split_at(payload.len() / 2);
    s.write_all(first).await?;
    let mut got_first = vec![0u8; first.len()];
    s.read_exact(&mut got_first).await?;
    assert_eq!(got_first, first, "echo first half must round-trip");

    // 传数据期间快照：恰好 1 条连接（speedtest 探测不走中继，不注册）
    let snap = connections_registry().snapshot();
    assert_eq!(snap.len(), 1, "only the SOCKS relay must be registered");
    let info = &snap[0];
    assert!(info.active, "in-flight relay must be active");
    assert_eq!(info.node, node.addr, "relay must be attributed to the node");
    // 目标入库即脱敏（mask_target 短哈希），明文目标不落注册表
    assert!(
        !info.target.contains(&format!("127.0.0.1:{}", echo_port)),
        "registry target must be masked"
    );

    // 传完剩余数据并关闭
    s.write_all(second).await?;
    let mut got_second = vec![0u8; second.len()];
    s.read_exact(&mut got_second).await?;
    assert_eq!(got_second, second, "echo second half must round-trip");
    drop(s);

    // 等中继任务收敛（ACTIVE_RELAYS 归零），连接转 inactive
    let mut done = false;
    for _ in 0..50 {
        if hydra_client::active_relay_count() == 0 {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "relay must converge after client drop");

    let snap = connections_registry().snapshot();
    assert_eq!(snap.len(), 1, "closed entry must be retained for UI");
    let info = &snap[0];
    assert!(!info.active, "entry must flip to inactive after close");
    assert!(info.closed_at.is_some(), "close time must be recorded");
    // 字节一致（上下行各 = payload 往返一次）
    assert!(
        counted_within(info.bytes_up, payload.len() as u64),
        "up {} must match payload {}",
        info.bytes_up,
        payload.len()
    );
    assert!(
        counted_within(info.bytes_down, payload.len() as u64),
        "down {} must match payload {}",
        info.bytes_down,
        payload.len()
    );
    // 时长字段自洽：关闭时刻不早于开始时刻
    assert!(info.closed_at.unwrap() >= info.started_at);
    Ok(())
}
