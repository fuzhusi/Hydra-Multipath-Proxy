//! A4 + A6：客户端转发收敛集成测试。
//! - A4 半关闭语义：客户端关写侧仍能收完响应
//! - A4 中继活动计数器归零（孤儿任务不再存在）
//! - A6 HTTP 明文代理二进制转发逐字节保真（1MB body）

mod common;

use std::time::Duration;

use hydra_client::active_relay_count;
use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 等待活动中继计数回落到目标值（中继任务收敛需要一点时间）。
/// 计数器是进程级全局量，同二进制的多个 #[tokio::test] 并行运行会互相计入，
/// 因此断言用"回到本测试开始时的基线值"而非硬编码 0。
async fn wait_relays_at(timeout: Duration, target: usize) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if active_relay_count() <= target {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    active_relay_count()
}

/// A4 半关闭：SOCKS5 客户端关写侧（shutdown write）后，仍能完整收到响应直到 EOF
#[tokio::test]
async fn test_half_close_client_can_still_receive_full_response() -> Result<()> {
    let baseline = active_relay_count();
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;
    s.write_all(b"half-close-payload").await?;
    // 关闭写侧（TCP half-close）：FIN 沿 客户端→节点→目标 传递
    s.shutdown().await?;

    // 写侧已关，但仍必须收完回显响应并读到干净 EOF
    let mut received = Vec::new();
    s.read_to_end(&mut received).await?;
    assert_eq!(received, b"half-close-payload");

    // 中继完全收敛，无孤儿任务
    assert!(
        wait_relays_at(Duration::from_secs(5), baseline).await <= baseline,
        "active relay count must return to baseline"
    );

    Ok(())
}

/// A4 计数器：多次连接建立/结束后，活动中继计数归零
#[tokio::test]
async fn test_active_relay_counter_returns_to_zero() -> Result<()> {
    let baseline = active_relay_count();
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    for i in 0..3 {
        let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;
        s.write_all(format!("round-{:02}", i).as_bytes()).await?;
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await?;
        assert_eq!(&buf, format!("round-{:02}", i).as_bytes());
    }

    assert!(
        wait_relays_at(Duration::from_secs(5), baseline).await <= baseline,
        "active relay count must return to baseline after connections close"
    );

    Ok(())
}

/// A6：POST 1MB 二进制 body 经 HTTP 明文代理到回显服务器，逐字节相等。
/// 头部与首段二进制 body 同批发送——旧实现的 from_utf8_lossy 累积会把
/// 非 UTF-8 body 字节替换为 U+FFFD 造成损坏，本测试防回归。
#[tokio::test]
async fn test_http_binary_body_byte_exact() -> Result<()> {
    let baseline = active_relay_count();
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    // 1MB 二进制 body：覆盖全部 256 个字节值（含大量非法 UTF-8 序列）
    let body: Vec<u8> = (0..1024 * 1024usize).map(|i| (i % 256) as u8).collect();

    let head = format!(
        "POST http://127.0.0.1:{}/echo HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        echo_port, echo_port, body.len()
    );
    let mut first_write = head.clone().into_bytes();
    // 头部与首段二进制同批：复现"body 与头部同读"的损坏路径
    first_write.extend_from_slice(&body[..8192]);

    let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
    s.write_all(&first_write).await?;
    s.write_all(&body[8192..]).await?;
    // 关写侧：请求发送完毕，等待完整回显
    s.shutdown().await?;

    // 回显服务器逐字节回显整个请求：客户端应收回到 head + body 的完整副本
    let mut received = Vec::new();
    s.read_to_end(&mut received).await?;

    let mut expected = head.into_bytes();
    expected.extend_from_slice(&body);
    assert_eq!(
        received.len(),
        expected.len(),
        "echoed length mismatch — binary body likely corrupted (lossy UTF-8)"
    );
    assert_eq!(received, expected, "echoed bytes must be identical");

    // 中继收敛
    assert!(
        wait_relays_at(Duration::from_secs(5), baseline).await <= baseline,
        "active relay count must return to baseline"
    );

    Ok(())
}
