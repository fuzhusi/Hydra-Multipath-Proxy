mod common;

use hydra_protocol::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 端到端：SOCKS5 代理 → 认证 → 节点 → 回显服务器，数据原样返回
#[tokio::test]
async fn test_client_connection() -> Result<()> {
    let node = common::spawn_node().await;
    let echo_port = common::spawn_echo_server().await;
    let proxy_addr = common::spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;

    s.write_all(b"Hello, Hydra!").await?;
    let mut buf = [0u8; 13];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"Hello, Hydra!");

    Ok(())
}
