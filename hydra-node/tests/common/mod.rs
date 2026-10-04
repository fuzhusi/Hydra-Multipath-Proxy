//! SSRF 过滤集成测试共用脚手架（仅 tests/ 内使用；与 hydra-client/tests/common 无关）
#![allow(dead_code)]

use hydra_node::{HydraServer, NodeOptions};
use quinn::{ClientConfig, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 测试用预共享密钥（任意 32 字节级熵即可，节点侧只做 HMAC 校验）
pub fn test_auth_key() -> Vec<u8> {
    b"ssrf-test-auth-key-0123456789ab".to_vec()
}

pub struct TestNode {
    pub addr: SocketAddr,
    /// 节点自签证书 DER（客户端 pinning 用）
    pub cert: Vec<u8>,
}

/// 启动一个监听随机端口的节点服务器（证书写入按进程/序号隔离的临时目录）
pub async fn spawn_node() -> TestNode {
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("hydra-ssrf-test-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = NodeOptions {
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        ..NodeOptions::default()
    };
    let server = HydraServer::new("127.0.0.1:0".parse().unwrap(), test_auth_key(), opts)
        .await
        .unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    let cert = server.cert_der().to_vec();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    // 等待 QUIC endpoint 就绪
    tokio::time::sleep(Duration::from_millis(150)).await;
    TestNode { addr, cert }
}

/// 客户端 endpoint：把节点自签证书加入信任根（等价 hydra-client 的 pinning 路径），ALPN h3
pub fn client_endpoint(node_cert_der: Vec<u8>) -> Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(&rustls::Certificate(node_cert_der))
        .expect("无效的节点证书");

    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // 节点侧 ALPN 固定 h3，客户端必须一致
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(quinn::TransportConfig::default()));
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    endpoint
}

/// 已认证地打开一条流并发送目标地址；返回 (send, recv)。
/// send 交由调用方持有（提前 drop 会触发 quinn 隐式 reset(0)，可能丢弃节点未读数据）。
pub async fn open_authed_stream(
    endpoint: &Endpoint,
    node_addr: SocketAddr,
    auth_key: &[u8],
    target: &str,
) -> (quinn::SendStream, quinn::RecvStream) {
    let conn = endpoint
        .connect(node_addr, "hydra.node")
        .unwrap()
        .await
        .expect("QUIC connect");
    let (mut send, recv) = conn.open_bi().await.expect("open_bi");

    let token = hydra_protocol::AuthToken::generate(auth_key, hydra_protocol::CLIENT_ID);
    assert_eq!(token.len(), 64);
    send.write_all(&token).await.expect("write token");

    let addr = target.as_bytes();
    assert!(!addr.is_empty() && addr.len() <= 256, "非法测试目标长度");
    send.write_all(&(addr.len() as u16).to_be_bytes())
        .await
        .expect("write addr len");
    send.write_all(addr).await.expect("write addr");
    (send, recv)
}

/// 启动 TCP 回显服务器，返回端口
pub async fn spawn_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}
