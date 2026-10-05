//! SSRF 过滤集成测试共用脚手架（仅 tests/ 内使用；与 hydra-client/tests/common 无关）
//! TCP 转型（Wave 3）后：客户端走 TCP/TLS + Noise-PSK 握手新协议。
#![allow(dead_code)]

use hydra_node::{HydraServer, NodeOptions};
use hydra_protocol::handshake;
use hydra_protocol::tcp_frame::write_target;
use std::net::SocketAddr;
use std::sync::Arc;

static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 测试用预共享密钥（任意 32 字节级熵即可，节点侧只做 Noise-PSK 校验）
pub fn test_auth_key() -> Vec<u8> {
    b"ssrf-test-auth-key-0123456789abc".to_vec()
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
    let addr = server.tcp_listen_addr.unwrap();
    let cert = server.cert_der().to_vec();
    // 接受循环已在 spawn_tcp_listener 内部后台运行；server 句柄保持存活即可
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    TestNode { addr, cert }
}

/// 经 TCP+TLS 连接节点，完成 Noise-PSK 握手并写地址帧（与节点侧新协议对称）。
/// 返回 TLS 流：调用方直接读 2B 应答码做断言（可区分 OK / TARGET_FAIL / DNS_FAIL）。
pub async fn connect_and_request(
    node_addr: SocketAddr,
    node_cert_der: &[u8],
    auth_key: &[u8],
    target: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    // 证书 pinning：节点自签证书加入本地信任根，标准 webpki 校验
    // （rustls 0.23 / Wave 3：pki-types + 显式 ring provider，语义不变）
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(node_cert_der.to_vec()))
        .expect("无效的节点证书");
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 协议版本配置失败")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // 不做 ALPN（同节点侧）；禁会话恢复
    crypto.alpn_protocols = Vec::new();
    crypto.resumption = rustls::client::Resumption::disabled();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto));
    let server_name = rustls::pki_types::ServerName::try_from("hydra.node".to_owned()).unwrap();

    let tcp = tokio::net::TcpStream::connect(node_addr)
        .await
        .expect("TCP connect to node");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake with node");

    // TLS exporter 通道绑定材料（两端同 label/context 即同值）
    let mut exporter = [0u8; handshake::EXPORTER_LEN];
    tls.get_ref()
        .1
        .export_keying_material(&mut exporter, handshake::EXPORTER_LABEL, Some(b""))
        .expect("TLS exporter 不可用");

    // Noise-PSK 握手：client_side 自己写 [0x03][msg1]
    let cert_fp = handshake::cert_fingerprint(node_cert_der);
    let (mut rd, mut wr) = tokio::io::split(tls);
    handshake::client_side(&mut wr, &mut rd, auth_key, &cert_fp, &exporter)
        .await
        .expect("Noise handshake with node");

    // 地址帧；读写两半合回流
    write_target(&mut wr, target).await.expect("write target");
    rd.unsplit(wr)
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
