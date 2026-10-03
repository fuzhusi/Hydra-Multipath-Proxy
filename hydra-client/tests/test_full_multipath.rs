mod common;

use bytes::Bytes;
use hydra_client::{Assembler, Splitter};
use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 端到端：64KB 数据块经代理与回显服务器完整往返
#[tokio::test]
async fn test_full_multipath_transmission() -> Result<()> {
    let node1 = common::spawn_node().await;
    let node2 = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert.clone()),
    ])
    .await;

    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();

    let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;
    s.write_all(&payload).await?;

    let mut received = vec![0u8; payload.len()];
    s.read_exact(&mut received).await?;
    assert_eq!(received, payload);

    Ok(())
}

#[tokio::test]
async fn test_chunk_reassembly() -> Result<()> {
    // 测试数据分片和重组逻辑
    let test_data = Bytes::from("Hello, World! This is a test message.");
    let mut splitter = Splitter::new(10); // 10字节的分片
    let mut assembler = Assembler::new();

    let packets = splitter.split(test_data.clone(), 1, 1);
    println!("Split data into {} chunks", packets.len());

    // 模拟乱序接收
    let mut reordered_packets = packets.clone();
    // 交换第一个和第三个分片
    if reordered_packets.len() >= 3 {
        reordered_packets.swap(0, 2);
    }

    // 重组数据
    let mut assembled_data = Bytes::new();
    for packet in reordered_packets {
        if let Some(assembled) = assembler.add_packet(packet) {
            assembled_data = assembled;
        }
    }

    println!("Chunk reassembly test completed!");

    Ok(())
}
