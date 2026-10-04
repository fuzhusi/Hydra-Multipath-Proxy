//! V3.4 强制门集成测试（施工方案 §2 验收 6 之 ①②）。
//! ① HYDRA_CHANNELS=4 经 4 流通道传 256MB 数据校验和逐字节相等
//! ② 传输中 reset 1 条数据流：通道接管不中断（replay 窗口补发 + 节点按 seq 去重）

mod common;

use hydra_client::aggregate_stream::{force_channels, last_channel_info, test_reset_data_stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

/// 两个集成测试共用进程级静态测试钩子（FORCE / LAST_CHANNEL：kill 注入与
/// last_channel_info 观测指向"最近构建的通道"），并发执行会互相串扰
///（kill 可能注入到另一测试的通道）。本二进制内强制串行。
static SERIAL: AsyncMutex<()> = AsyncMutex::const_new(());

/// 模式字节：byte(i) = (i % 251) as u8。校验和 = 字节和（u64）。
/// 每 251 字节一组，组和 = 0+1+..+250 = 31375。
fn expected_sum(n: u64) -> u64 {
    let (full, rem) = (n / 251, n % 251);
    full * 31_375 + rem * (rem - 1) / 2
}

fn fill_pattern(buf: &mut [u8], start_idx: u64) {
    for (j, b) in buf.iter_mut().enumerate() {
        *b = ((start_idx + j as u64) % 251) as u8;
    }
}

/// ① 256MB 经 4 流通道，回显校验和逐字节相等，且确认确实走了通道路径
///
/// V3.4 v2（上行 ACK/NACK 重传协议）修复已知缺陷：节点对上行按 seq 累计 ACK，
/// 客户端对 300ms 未确认帧按序重发、finish 半关闭前排空确认（全部 ACK 或 5s
/// 超时显式失败），单帧丢失不再不可恢复。原 #[ignore] 已解除（强制门①）。
#[tokio::test(flavor = "multi_thread")]
async fn test_channel_256mb_checksum() {
    let _serial = SERIAL.lock().await;
    let _ = std::env::set_var("RUST_LOG", "debug");
    let _ = tracing_subscriber::fmt::try_init();
    force_channels(Some(4));
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    let target = format!("127.0.0.1:{}", echo_port);
    let mut s = common::socks5_connect(proxy_addr, &target)
        .await
        .expect("socks5 connect");

    // 通道建流发生在 socks5 握手期间：必须确认走了通道路径且 ≥2 流
    let (_, streams) = last_channel_info().expect("must have taken the channel path");
    assert!(streams >= 2, "expected ≥2 channel streams, got {}", streams);

    const TOTAL: u64 = 256 * 1024 * 1024;
    const CHUNK: usize = 256 * 1024;
    let (mut rd, mut wr) = tokio::io::split(s);

    // 写任务：全量 256MB 模式；读任务：边收边累计校验和
    let writer = tokio::spawn(async move {
        let mut sent: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        while sent < TOTAL {
            let n = CHUNK.min((TOTAL - sent) as usize);
            fill_pattern(&mut buf[..n], sent);
            wr.write_all(&buf[..n]).await.expect("writer");
            sent += n as u64;
        }
        wr.shutdown().await.expect("writer shutdown");
        sent
    });
    let reader = tokio::spawn(async move {
        let mut received: u64 = 0;
        let mut sum: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        while received < TOTAL {
            let n = rd.read(&mut buf).await.expect("reader");
            if n == 0 {
                panic!("echo EOF at {} / {}", received, TOTAL);
            }
            sum += buf[..n].iter().map(|&b| b as u64).sum::<u64>();
            received += n as u64;
        }
        (received, sum)
    });

    let sent = writer.await.unwrap();
    let (received, sum) = reader.await.unwrap();
    assert_eq!(sent, TOTAL);
    assert_eq!(received, TOTAL);
    assert_eq!(sum, expected_sum(TOTAL), "256MB channel transfer corrupted");
}

/// ② 传输中 reset 第一条数据流：通道接管（重发+节点去重），数据不损坏不中断
#[tokio::test(flavor = "multi_thread")]
async fn test_channel_stream_kill_takeover() {
    let _serial = SERIAL.lock().await;
    let _ = std::env::set_var("RUST_LOG", "debug");
    let _ = tracing_subscriber::fmt::try_init();
    force_channels(Some(4));
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    let target = format!("127.0.0.1:{}", echo_port);
    let mut s = common::socks5_connect(proxy_addr, &target)
        .await
        .expect("socks5 connect");
    let (_, streams) = last_channel_info().expect("must have taken the channel path");
    assert!(
        streams >= 3,
        "need ≥3 streams so killing one still leaves capacity"
    );

    const TOTAL: u64 = 64 * 1024 * 1024;
    const CHUNK: usize = 256 * 1024;
    let (mut rd, mut wr) = tokio::io::split(s);

    // 200ms 后杀第一条数据流（强制门②的杀流注入）
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        test_reset_data_stream(0);
    });

    let writer = tokio::spawn(async move {
        let mut sent: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        while sent < TOTAL {
            let n = CHUNK.min((TOTAL - sent) as usize);
            fill_pattern(&mut buf[..n], sent);
            wr.write_all(&buf[..n])
                .await
                .expect("writer (takeover failed?)");
            sent += n as u64;
        }
        wr.shutdown().await.expect("writer shutdown");
        sent
    });
    let reader = tokio::spawn(async move {
        let mut received: u64 = 0;
        let mut sum: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        while received < TOTAL {
            let n = rd.read(&mut buf).await.expect("reader");
            if n == 0 {
                panic!("echo EOF at {} / {}", received, TOTAL);
            }
            sum += buf[..n].iter().map(|&b| b as u64).sum::<u64>();
            received += n as u64;
        }
        (received, sum)
    });

    let sent = writer.await.unwrap();
    let (received, sum) = reader.await.unwrap();
    assert_eq!(sent, TOTAL);
    assert_eq!(received, TOTAL);
    assert_eq!(sum, expected_sum(TOTAL), "data corrupted after stream kill");
}
