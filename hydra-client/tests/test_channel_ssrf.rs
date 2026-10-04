//! V3.4 强制门之 ⑤：channel 模式的目标地址必须经节点侧 SSRF 过滤。
//! 独立测试二进制：本文件不设 HYDRA_ALLOW_PRIVATE_TARGETS（common 的 spawn 帮手会设 1，
//! 因此这里手工起节点），默认拒绝策略下 channel 目标 169.254.169.254（云元数据）必须被拒。

mod common;

use hydra_client::aggregate_stream::{channel_attempted, force_channels};
use hydra_node::{HydraServer, NodeOptions};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 与 common::spawn_node 相同，但不设置 HYDRA_ALLOW_PRIVATE_TARGETS（保持默认拒绝）
async fn spawn_node_default_deny() -> (SocketAddr, Vec<u8>) {
    std::env::remove_var("HYDRA_ALLOW_PRIVATE_TARGETS");
    let dir = std::env::temp_dir().join(format!(
        "hydra-ch-ssrf-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = NodeOptions {
        max_connections: 50,
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        ..NodeOptions::default()
    };
    let server = HydraServer::new(
        "127.0.0.1:0".parse().unwrap(),
        common::test_auth_key(),
        opts,
    )
    .await
    .unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    let cert = server.cert_der().to_vec();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    (addr, cert)
}

/// 裸 SOCKS5 握手（不断言成功），返回回复状态码 reply[1]
async fn socks5_connect_status(proxy_addr: SocketAddr, target: &str) -> std::io::Result<u8> {
    let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "bad greeting",
        ));
    }
    let (host, port_str) = target.rsplit_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    Ok(reply[1])
}

#[tokio::test(flavor = "multi_thread")]
async fn test_channel_target_ssrf_denied() {
    force_channels(Some(4));
    let (node_addr, cert) = spawn_node_default_deny().await;
    let proxy_addr = common::spawn_proxy(vec![(node_addr, cert)]).await;

    // 云元数据地址：channel 模式的目标必须被节点 SSRF 过滤拒绝（0x11）
    let status = socks5_connect_status(proxy_addr, "169.254.169.254:80")
        .await
        .expect("proxy should reply, not hang");
    assert_ne!(
        status, 0x00,
        "metadata target must be denied by SSRF filter"
    );

    // 确认请求确实先走了通道路径（SSRF 拒绝发生在 build_channel 之前，
    // last_channel_info 观测不到，用独立尝试标记取证）
    assert!(channel_attempted(), "channel path must have been attempted");
}
