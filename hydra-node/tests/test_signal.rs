//! P2P 信令集成测试（NAT 穿透方案 §3.2）：loopback 双客户端全链路。
//!
//! 场景：起节点（p2p_signal=true），两个客户端分别用
//! `hydra_client::tcp_transport::connect_target` 连到保留目标
//! `@hydra-p2p/alice` / `@hydra-p2p/bob`（复用认证路径：版本字节 + Noise-PSK +
//! 地址帧 + 2B 应答），随后经信令完成 register → invite → incoming →
//! accept → accepted 全链路（JSON 行读写）。
//!
//! 客户端打洞编排（nat.rs）下一轮实现；本文件只验证节点侧信令路由。

use hydra_client::tcp_transport::{connect_target, TlsTrust};
use hydra_node::signal::{SignalDownMessage, SignalMessage};
use hydra_node::NodeOptions;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::io::ReadHalf;

static SEQ: AtomicU32 = AtomicU32::new(0);

/// 启动开启信令模式的节点，返回 (地址, 证书 DER)
async fn spawn_signal_node() -> (SocketAddr, Vec<u8>) {
    // 信令会话不触达 SSRF 过滤，但与既有测试基线保持一致（允许私有目标）
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("hydra-signal-test-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = NodeOptions {
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        p2p_signal: true,
        ..NodeOptions::default()
    };
    let server = hydra_node::HydraServer::new("127.0.0.1:0".parse().unwrap(), test_auth_key(), opts)
        .await
        .unwrap();
    (server.tcp_listen_addr.unwrap(), server.cert_der().to_vec())
}

fn test_auth_key() -> Vec<u8> {
    // 必须恰好 32 字节（Noise-PSK 校验）
    b"signal-test-auth-key-0123456789a".to_vec()
}

/// 经客户端认证路径连到 `@hydra-p2p/<peer_id>`，返回（读半, 写半）
async fn connect_signal(
    node: SocketAddr,
    cert: &[u8],
    peer_id: &str,
) -> (
    BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>,
    hydra_client::tcp_transport::TcpWriteHalf,
) {
    let trust = TlsTrust::pinned(vec![cert.to_vec()]);
    let stream = connect_target(node, "", &trust, &test_auth_key(), &format!("@hydra-p2p/{peer_id}"))
        .await
        .expect("信令连接（认证路径）应成功");
    let (rd, wr) = tokio::io::split(stream);
    (BufReader::new(rd), wr)
}

/// 写一条上行消息（JSON 行）
async fn send(wr: &mut hydra_client::tcp_transport::TcpWriteHalf, msg: &SignalMessage) {
    let line = serde_json::to_string(msg).unwrap();
    wr.write_all(line.as_bytes()).await.unwrap();
    wr.write_all(b"\n").await.unwrap();
    wr.flush().await.unwrap();
}

/// 读一条下行消息（JSON 行）
async fn recv(rd: &mut BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>) -> SignalDownMessage {
    let mut line = String::new();
    let r = tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut line)).await;
    let n = r.expect("读下行超时").expect("读下行失败");
    assert!(n > 0, "连接被节点关闭");
    serde_json::from_str(&line).expect("下行 JSON 解析")
}

/// 发送 invite；节点回 error(peer_offline) = 目标尚未注册 → 退避重试。
/// 无 error（下行静默 = 已转发给目标）即返回——两条连接的 register 处理
/// 无全局时序保证，重试消除测试竞态。
async fn invite_until_online(
    alice_wr: &mut hydra_client::tcp_transport::TcpWriteHalf,
    alice_rd: &mut BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>,
    target: &str,
    cand: Vec<String>,
) {
    for _ in 0..20 {
        send(
            alice_wr,
            &SignalMessage::Invite {
                peer_id: target.to_string(),
                cand: cand.clone(),
            },
        )
        .await;
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_millis(500), alice_rd.read_line(&mut line)).await
        {
            // 无下行（节点已转发给目标）：invite 完成
            Err(_) | Ok(Ok(0)) => return,
            Ok(Err(e)) => panic!("读下行失败: {e}"),
            Ok(Ok(_)) => {
                let msg: SignalDownMessage = serde_json::from_str(&line).expect("下行 JSON");
                match msg {
                    // 目标尚未注册：稍后重试
                    SignalDownMessage::Error { code, .. } if code == "peer_offline" => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    other => panic!("invite 后收到意外下行: {other:?}"),
                }
            }
        }
    }
    panic!("目标始终不在线: {target}");
}

#[tokio::test]
async fn 信令全链路_register_invite_incoming_accept_accepted() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .with_test_writer()
        .try_init();
    let (addr, cert) = spawn_signal_node().await;

    // 双客户端连接（各自一条信令会话）
    let (mut alice_rd, mut alice_wr) = connect_signal(addr, &cert, "a1a1a1a1a1a1a1a1").await;
    let (mut bob_rd, mut bob_wr) = connect_signal(addr, &cert, "b2b2b2b2b2b2b2b2").await;

    // register（心跳/注册；alice 的 peer_id 故意填错 → 应收错误并断开验证放后面单独测）
    send(
        &mut alice_wr,
        &SignalMessage::Register {
            peer_id: "a1a1a1a1a1a1a1a1".into(),
            mapped: "127.0.0.1:40001".into(),
        },
    )
    .await;
    send(
        &mut bob_wr,
        &SignalMessage::Register {
            peer_id: "b2b2b2b2b2b2b2b2".into(),
            mapped: "127.0.0.1:40002".into(),
        },
    )
    .await;

    // invite：alice → bob（带 offline 重试，消除双连接注册时序竞态）；
    // bob 应收到 incoming{from:alice, cand}
    invite_until_online(
        &mut alice_wr,
        &mut alice_rd,
        "b2b2b2b2b2b2b2b2",
        vec!["127.0.0.1:40001".into()],
    )
    .await;
    let incoming = recv(&mut bob_rd).await;
    match incoming {
        SignalDownMessage::Incoming { from, cand } => {
            assert_eq!(from, "a1a1a1a1a1a1a1a1");
            assert_eq!(cand, vec!["127.0.0.1:40001".to_string()]);
        }
        other => panic!("应收到 incoming，实际 {other:?}"),
    }

    // accept：bob → alice；alice 应收到 accepted{from:bob}
    send(
        &mut bob_wr,
        &SignalMessage::Accept {
            to: "a1a1a1a1a1a1a1a1".into(),
            cand: vec!["127.0.0.1:40002".into()],
        },
    )
    .await;
    let accepted = recv(&mut alice_rd).await;
    match accepted {
        SignalDownMessage::Accepted { from, cand } => {
            assert_eq!(from, "b2b2b2b2b2b2b2b2");
            assert_eq!(cand, vec!["127.0.0.1:40002".to_string()]);
        }
        other => panic!("应收到 accepted，实际 {other:?}"),
    }
}

#[tokio::test]
async fn invite_目标不在线回error() {
    let (addr, cert) = spawn_signal_node().await;
    let (mut rd, mut wr) = connect_signal(addr, &cert, "cccccccccccccccc").await;
    send(
        &mut wr,
        &SignalMessage::Register {
            peer_id: "cccccccccccccccc".into(),
            mapped: "127.0.0.1:40003".into(),
        },
    )
    .await;
    send(
        &mut wr,
        &SignalMessage::Invite {
            peer_id: "dddddddddddddddd".into(),
            cand: vec![],
        },
    )
    .await;
    match recv(&mut rd).await {
        SignalDownMessage::Error { code, peer } => {
            assert_eq!(code, "peer_offline");
            assert_eq!(peer.as_deref(), Some("dddddddddddddddd"));
        }
        other => panic!("应收到 error，实际 {other:?}"),
    }
}

#[tokio::test]
async fn register_peer_id与地址帧不一致被拒绝() {
    let (addr, cert) = spawn_signal_node().await;
    let (mut rd, mut wr) = connect_signal(addr, &cert, "eeeeeeeeeeeeeeee").await;
    // 消息体 peer_id ≠ 地址帧身份 → 错误消息且会话断开
    send(
        &mut wr,
        &SignalMessage::Register {
            peer_id: "ffffffffffffffff".into(),
            mapped: "127.0.0.1:40004".into(),
        },
    )
    .await;
    match recv(&mut rd).await {
        SignalDownMessage::Error { code, .. } => assert_eq!(code, "peer_id_mismatch"),
        other => panic!("应收到 error，实际 {other:?}"),
    }
    // 会话已断开：再读应得到 EOF（TLS abrupt 关闭以 UnexpectedEof 呈现）
    let mut line = String::new();
    match rd.read_line(&mut line).await {
        Ok(0) => {}
        Ok(_) => panic!("peer_id 不匹配后会话应被断开"),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("读 EOF 意外错误: {e}"),
    }
}

#[tokio::test]
async fn 非法json_断开会话() {
    let (addr, cert) = spawn_signal_node().await;
    let (mut rd, mut wr) = connect_signal(addr, &cert, "0123456789abcdef").await;
    wr.write_all(b"this is not json\n").await.unwrap();
    wr.flush().await.unwrap();
    // 节点应直接断开（无下行消息）：读到 EOF。TLS 对端 abrupt 关闭时
    // tokio-rustls 以 UnexpectedEof 报错（而非 Ok(0)），两种形态都视为已断开
    let mut line = String::new();
    let r = tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut line)).await;
    match r {
        Err(_) => panic!("等待断开超时"),
        Ok(Ok(0)) => {} // 干净 EOF
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {} // TLS 无 close_notify EOF
        Ok(Err(e)) => panic!("读下行意外错误: {e}"),
        Ok(Ok(n)) => panic!("应断开，实际收到 {n} 字节: {line}"),
    }
}

#[tokio::test]
async fn 信令目标peer_id非法_静默关流() {
    let (addr, cert) = spawn_signal_node().await;
    // peer_id 含非 hex 字符 → 节点不发 2B 应答直接静默关流（防探测语义不变），
    // 客户端认证路径在读应答处收到 EOF → connect_target 报「节点静默关闭」
    let trust = TlsTrust::pinned(vec![cert.clone()]);
    let r = connect_target(addr, "", &trust, &test_auth_key(), "@hydra-p2p/not-hex!!").await;
    let err = r.expect_err("非法 peer_id 应静默关流导致认证路径报错");
    assert!(
        err.to_string().contains("静默关闭"),
        "应为静默关闭错误: {err}"
    );
}
