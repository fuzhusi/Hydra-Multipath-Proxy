//! 反代静态页回退集成测试（抗主动探测增强）。
//!
//! 场景：起节点（`fallback_page` 开/关两份 NodeOptions），用「TLS 建立后发
//! 任意非信令字节」的探测客户端（证书 pinning 原始 TLS，与 tests/common 的
//! connect_and_request 同构，但不走版本字节/Noise 握手）断言：
//! - 开关开启：收到完整 HTTP/1.1 200 静态页（Content-Length 与 body 一致）
//! - 开关关闭：零字节静默 EOF（默认语义零变化）

#![allow(dead_code)]

use common::{test_auth_key, TestNode};
use hydra_node::{HydraServer, NodeOptions};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

/// 启动指定 fallback_page 开关节点
async fn spawn_node_with(fallback_page: bool) -> TestNode {
    // 回环 echo 目标需要放行私有目标（与 test_signal 基线一致；AuthMode/
    // SSRF 过滤在节点构造时读一次 env）
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "hydra-fallback-test-{}-{}",
        std::process::id(),
        seq
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = NodeOptions {
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        fallback_page,
        ..NodeOptions::default()
    };
    let server = HydraServer::new("127.0.0.1:0".parse().unwrap(), test_auth_key(), opts)
        .await
        .unwrap();
    let addr = server.tcp_listen_addr.unwrap();
    let cert = server.cert_der().to_vec();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    TestNode { addr, cert }
}

static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 探测客户端：完成真 TLS 握手（证书 pinning）后，发送任意非信令字节。
/// 返回 TLS 流（调用方直接读节点回包）。
async fn probe_connect(
    node_addr: SocketAddr,
    node_cert_der: &[u8],
    payload: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    // 证书 pinning：节点自签证书加入本地信任根（与 tests/common 同构）
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            node_cert_der.to_vec(),
        ))
        .expect("无效的节点证书");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 协议版本配置失败")
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = Vec::new();
    crypto.resumption = rustls::client::Resumption::disabled();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto));
    let server_name = rustls::pki_types::ServerName::try_from("hydra.node".to_owned()).unwrap();

    let tcp = tokio::net::TcpStream::connect(node_addr)
        .await
        .expect("TCP connect to node");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake with node");
    // 发送非信令数据（非 0x03 版本字节；也不构成合法 HTTP 请求）
    tls.write_all(payload).await.expect("写探测字节");
    tls.flush().await.unwrap();
    // 写半保持打开（模拟探测者等待响应），由调用方读回包
    tls
}

/// 读取节点回包直至连接关闭；返回全部字节。
/// 注意：节点侧 drop TLS 流不发 close_notify，rustls 客户端会以
/// UnexpectedEof 报错——此处把该错误视为 EOF（已收字节仍有效）。
async fn read_to_close(mut tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(
            Duration::from_secs(10),
            AsyncReadExt::read(&mut tls, &mut chunk),
        )
        .await
        .expect("读响应超时")
        {
            Ok(0) | Err(_) => break, // Ok(0)=close_notify EOF；Err=无 close_notify 的截断
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

/// 开关开启：版本字节非 0x03 → 收到完整 HTTP 200 静态页
#[tokio::test]
async fn 开关开启_版本字节错误回整页() {
    let node = spawn_node_with(true).await;
    let tls = probe_connect(node.addr, &node.cert, b"\x01garbage-not-http").await;
    let resp = read_to_close(tls).await;
    let text = String::from_utf8(resp.clone()).unwrap();
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "应回 200: {text:.80}"
    );
    assert!(text.contains("Content-Type: text/html; charset=utf-8\r\n"));
    assert!(text.contains("Connection: close\r\n"));
    let len_line = text
        .lines()
        .find(|l| l.starts_with("Content-Length:"))
        .expect("Content-Length 头");
    let declared: usize = len_line
        .strip_prefix("Content-Length: ")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let body = text.split_once("\r\n\r\n").unwrap().1;
    assert_eq!(declared, body.len(), "Content-Length 与 body 一致");
    assert_eq!(body, hydra_node::FALLBACK_HTML, "body 完整等于内置页面");
}

/// 开关开启：任意非信令字节（单字节 0x07，不构成 HTTP 请求）也照常回整页
/// （标准反代：任何非代理流量都得到同一页面）
#[tokio::test]
async fn 开关开启_任意非信令字节也回整页() {
    let node = spawn_node_with(true).await;
    let tls = probe_connect(node.addr, &node.cert, b"\x07").await;
    let resp = read_to_close(tls).await;
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

/// 开关关闭（默认）：同样探测 → 零字节静默关闭（行为零变化）
#[tokio::test]
async fn 开关关闭_静默无数据() {
    let node = spawn_node_with(false).await;
    let tls = probe_connect(node.addr, &node.cert, b"\x01garbage-not-http").await;
    let resp = read_to_close(tls).await;
    assert!(
        resp.is_empty(),
        "默认应零字节静默关流，实际收到 {} 字节",
        resp.len()
    );
}

/// 正常代理客户端不受影响：开关开启时标准认证路径仍成功建目标转发
#[tokio::test]
async fn 开关开启_正常客户端不受影响() {
    let node = spawn_node_with(true).await;
    let port = common::spawn_echo_server().await;
    let mut stream = common::connect_and_request(
        node.addr,
        &node.cert,
        &test_auth_key(),
        &format!("127.0.0.1:{port}"),
    )
    .await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 先读 2B 应答码（REPLY_OK = 0x0000；connect_and_request 不代读）
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x00, 0x00], "应答码应为 OK");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf, b"ping",
        "正常代理路径应照常工作（实际收到 {buf:02x?}）"
    );
}
