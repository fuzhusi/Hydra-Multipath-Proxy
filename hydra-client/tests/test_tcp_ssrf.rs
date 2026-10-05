//! Team-T 强制门④：SSRF 目标过滤对 TCP/TLS 路径同样生效
//!
//! 独立测试二进制：本进程**不**设置 HYDRA_ALLOW_PRIVATE_TARGETS
//! （节点默认拒绝私有目标；127.0.0.1 回显目标必须被静默拒绝）。
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};

use hydra_client::tcp_transport::connect_target;
use hydra_node::{HydraServer, NodeOptions};

const SNI: &str = "hydra.node";

fn test_auth_key() -> Vec<u8> {
    // 与 tests 基线同一测试密钥（hex 解码后 32 字节）
    hydra_client::auth_key_from_hex(
        "3031323334353637383961626364656630313233343536373839616263646566",
    )
    .unwrap()
}

/// 强制门④：未放宽 SSRF 时，TCP 路径对 127.0.0.1 目标必须静默拒绝（不建连、不回显）
#[tokio::test]
async fn tcp_ssrf_blocks_loopback_target() {
    // 确保节点侧 SSRF 过滤处于默认拒绝状态（与本二进制的其他测试无并发）
    std::env::remove_var("HYDRA_ALLOW_PRIVATE_TARGETS");

    static SEQ: AtomicU32 = AtomicU32::new(0);
    let s = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("hydra-tcp-ssrf-{}-{}", std::process::id(), s));
    std::fs::create_dir_all(&dir).unwrap();

    // 回显服务器确实在监听——拒绝只能来自 SSRF 过滤，而非目标不存在
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let opts = NodeOptions {
        max_connections: 16,
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        ..NodeOptions::default()
    };
    let server = HydraServer::new("127.0.0.1:0".parse().unwrap(), test_auth_key(), opts)
        .await
        .unwrap();
    let tcp_addr = server.tcp_listen_addr.expect("TCP 监听应已绑定");
    let cert = server.cert_der().to_vec();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let trust = hydra_client::tcp_transport::TlsTrust::pinned(vec![cert.clone()]);
    let result = connect_target(
        tcp_addr,
        SNI,
        &trust,
        &test_auth_key(),
        &format!("127.0.0.1:{}", echo_port),
    )
    .await;
    assert!(
        result.is_err(),
        "强制门④：SSRF 过滤必须对 TCP 路径生效（127.0.0.1 目标被拒绝）"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        !err.contains("0x11"),
        "静默拒绝语义：不得回显可区分错误码，实际: {}",
        err
    );
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
