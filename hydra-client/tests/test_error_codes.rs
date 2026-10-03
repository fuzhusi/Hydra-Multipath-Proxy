//! A3：节点错误显式传播集成测试。
//! - 已认证流：目标连接失败 → 客户端读到 `ReadError::Reset(0x11)`（不再是干净 EOF 冒充成功）
//! - 未认证流：零字节静默关闭（防探测语义不回归，读到 EOF 而非 Reset）
//! - 经代理的 SOCKS5 层：目标不可达应答失败码而非挂死/冒充成功，且节点不被误判 Offline

mod common;

use std::time::Duration;

use hydra_client::NODE_ERR_TARGET_CONNECT;
use hydra_protocol::{AuthToken, Result, CLIENT_ID};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 与 transport.rs 相同的 pinning 客户端配置（测试本地构造，不改 transport.rs）
fn client_config(node_cert_der: Vec<u8>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(&rustls::Certificate(node_cert_der))
        .expect("invalid node cert");
    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.resumption = rustls::client::Resumption::disabled();
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    config.transport_config(std::sync::Arc::new(transport));
    config
}

/// 建立到节点的已认证 QUIC 连接（pinned 证书 + SNI）
async fn connect_node(
    ep: &quinn::Endpoint,
    node_addr: std::net::SocketAddr,
    cert: Vec<u8>,
) -> quinn::Connection {
    let cfg = client_config(cert);
    let connecting = ep
        .connect_with(cfg, node_addr, hydra_client::DEFAULT_SNI)
        .expect("connect failed");
    tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("connect timeout")
        .expect("connect error")
}

/// 请求帧：64B token + 2B 大端长度前缀 + 目标地址
fn request_frame(auth_key: &[u8], target: &str) -> Vec<u8> {
    let token = AuthToken::generate(auth_key, CLIENT_ID);
    let mut frame = token.to_vec();
    let addr = target.as_bytes();
    frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(addr);
    frame
}

/// 已认证流 + 目标端口拒绝连接 → 客户端读到 ReadError::Reset(0x11) 与 STOP_SENDING(0x11)
#[tokio::test]
async fn test_target_connect_failure_resets_with_0x11() -> Result<()> {
    let node = common::spawn_node().await;
    let auth_key = common::test_auth_key();

    // 制造一个必然拒绝连接的端口：绑定后立即释放
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    let conn = connect_node(&ep, node.addr, node.cert.clone()).await;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(&request_frame(
        &auth_key,
        &format!("127.0.0.1:{}", closed_port),
    ))
    .await?;

    // 节点连接目标失败 → RESET_STREAM(0x11)：read 返回 Reset 错误而非 0x00 应答/EOF
    let mut buf = [0u8; 2];
    let err = tokio::time::timeout(Duration::from_secs(20), recv.read(&mut buf))
        .await
        .expect("read timed out waiting for reset")
        .expect_err("expected Reset error, got Ok — EOF masquerading regression?");
    match err {
        quinn::ReadError::Reset(code) => {
            assert_eq!(
                u64::from(code),
                NODE_ERR_TARGET_CONNECT,
                "expected 0x11 target-connect error code"
            );
        }
        other => panic!("expected ReadError::Reset(0x11), got: {}", other),
    }

    // 客户端发送侧应收到 STOP_SENDING(0x11)
    let code = tokio::time::timeout(Duration::from_secs(10), send.stopped())
        .await
        .expect("timed out waiting for STOP_SENDING")
        .expect("stream unexpectedly finished instead of stopped");
    assert_eq!(
        u64::from(code),
        NODE_ERR_TARGET_CONNECT,
        "STOP_SENDING must carry 0x11"
    );

    Ok(())
}

/// 未认证流（垃圾 token）→ 零字节静默关闭：读到干净 EOF，绝无 Reset（防探测前提不破坏）
#[tokio::test]
async fn test_unauthenticated_stream_stays_silent() -> Result<()> {
    let node = common::spawn_node().await;

    let ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    let conn = connect_node(&ep, node.addr, node.cert.clone()).await;
    let (mut send, mut recv) = conn.open_bi().await?;

    // 64 字节垃圾 token（认证必失败）；后续字节同样静默（写入结果不关心）
    send.write_all(&[0xABu8; 64]).await?;
    let _ = send
        .write_all(&[
            0x00, 0x09, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1',
        ])
        .await;

    // 节点必须静默关流：EOF（0 字节），无任何数据、无错误码
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(10), recv.read(&mut buf))
        .await
        .expect("read timed out");
    match read {
        Ok(Some(0)) | Ok(None) => {} // 干净 EOF / 流已结束
        Ok(Some(n)) => panic!("unauthenticated stream returned {} data bytes", n),
        Err(e) => panic!(
            "unauthenticated stream must close silently (EOF), got: {}",
            e
        ),
    }

    Ok(())
}

/// SOCKS5 层经代理连接被拒绝端口：应答失败码（不挂死、不冒充成功），且节点不被误判 Offline
#[tokio::test]
async fn test_socks5_reports_failure_for_unreachable_target() -> Result<()> {
    let node = common::spawn_node().await;
    let (proxy_addr, proxy) =
        common::spawn_proxy_with_handle(vec![(node.addr, node.cert.clone())]).await;
    let scheduler = proxy.scheduler();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let (_s, reply_code) =
        common::socks5_connect_lenient(proxy_addr, &format!("127.0.0.1:{}", closed_port)).await?;
    assert_ne!(reply_code, 0x00, "unreachable target must not succeed");

    // 0x11 是目标侧问题：节点存活，不应被标记 Offline
    let status = scheduler
        .get_all_nodes()
        .await
        .into_iter()
        .find(|n| n.address == node.addr)
        .unwrap()
        .status;
    assert!(
        matches!(status, hydra_protocol::NodeStatus::Online),
        "node must stay Online after target-side failure (0x11), got {:?}",
        status
    );

    // 节点仍然可用：连接正常目标成功
    let echo_port = common::spawn_echo_server().await;
    let mut s = common::socks5_connect(proxy_addr, &format!("127.0.0.1:{}", echo_port)).await?;
    s.write_all(b"still-alive").await?;
    let mut buf = [0u8; 11];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"still-alive");

    Ok(())
}

/// 静默校验：测试密钥与协议 token 长度一致（防止测试本身失真）
#[test]
fn test_auth_key_shape() {
    let key = hydra_client::auth_key_from_hex(common::TEST_KEY_HEX).unwrap();
    assert!(key.len() >= 16);
    assert_eq!(AuthToken::TOKEN_LEN, 64);
}
