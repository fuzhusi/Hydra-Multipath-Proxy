mod common;

use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 故障切换：节点1 服务正常 → 关闭节点1 → 新请求自动切换到节点2 并成功
#[tokio::test]
async fn test_failover() -> Result<()> {
    // 节点1 评分更高（spawn_proxy 按顺序递减），首个请求走节点1
    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;

    let target = format!("127.0.0.1:{}", echo_port);

    // 1. 节点1 在线：请求成功
    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    s.write_all(b"before-failover").await?;
    let mut buf = [0u8; 15];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"before-failover");

    // 2. 杀死节点1（关闭其 QUIC endpoint：拒绝新连接并断开存量连接）
    node1.endpoint.close(0u32.into(), b"test shutdown");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // 3. 新请求应标记节点1 故障并自动切换到节点2
    let mut s = common::socks5_connect(proxy_addr, &target).await?;
    s.write_all(b"after-failover!").await?;
    let mut buf = [0u8; 15];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"after-failover!");

    Ok(())
}
