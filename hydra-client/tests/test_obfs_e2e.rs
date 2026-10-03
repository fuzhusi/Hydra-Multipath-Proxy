//! WS-C C2 E2E：obfs 模式全链路（node + client + 回显服务器）。
//!
//! 本文件为独立测试进程：进程内统一设置 HYDRA_MODE=obfs / HYDRA_OBFS_KEY，
//! 客户端侧（ProxyServer → Transport::create_shared_endpoint）经 env 走 obfs socket，
//! 节点侧经 spawn_node_in_mode(Obfs) 显式传入。masquerade 回归由既有测试
//! （不设置这些 env 的独立进程）保证，零改动。

mod common;

use std::sync::Once;
use std::time::Duration;

use common::{socks5_connect, spawn_echo_server, spawn_node_in_mode, spawn_proxy, TEST_KEY_HEX};
use hydra_obfs::TransportMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static ENV: Once = Once::new();

/// 进程内一次性设置 obfs 双模式 env（两端密码一致；模式 = obfs）
fn init_obfs_env() {
    ENV.call_once(|| {
        std::env::set_var(hydra_obfs::HYDRA_MODE_ENV, "obfs");
        std::env::set_var(hydra_obfs::HYDRA_OBFS_KEY_ENV, "e2e-obfs-passphrase-v3.1");
    });
}

fn test_auth_key() -> Vec<u8> {
    hydra_client::auth_key_from_hex(TEST_KEY_HEX).unwrap()
}

/// 确定性伪随机填充（避免测试对随机 crate 的依赖顺序敏感）
fn fill_pseudo_random(buf: &mut [u8], seed: u64) {
    let mut x = seed | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
}

/// obfs 全链路：SOCKS5 → 代理 → obfs 节点 → 回显服务器，
/// 小报文 + 2MB 随机大块逐字节校验（大块强制多 QUIC 报文/多混淆变换往返）。
#[tokio::test]
async fn obfs_full_chain_echo_roundtrip() {
    init_obfs_env();
    let _ = test_auth_key();

    let node = spawn_node_in_mode("127.0.0.1:0".parse().unwrap(), TransportMode::Obfs).await;
    let echo_port = spawn_echo_server().await;
    let proxy = spawn_proxy(vec![(node.addr, node.cert.clone())]).await;

    let mut stream = socks5_connect(proxy, &format!("127.0.0.1:{}", echo_port))
        .await
        .expect("obfs 链路 SOCKS5 连接必须成功");

    // 小报文
    let msg = b"hydra obfs v3.1 full-chain hello";
    stream.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, msg, "小报文回显必须逐字节一致");

    // 2MB 随机大块
    let mut big = vec![0u8; 2 * 1024 * 1024];
    fill_pseudo_random(&mut big, 0x4859_4452);
    stream.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big, "2MB 大块回显必须逐字节一致（混淆层无损）");

    // 二次往返：确认链路可复用
    stream.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, msg);
}

/// 节点侧垃圾包零回应 + 丢弃不伤链路：
/// 向 obfs 节点直发 50 个垃圾 UDP 包（明文 QUIC / 随机字节），节点必须零回应
/// （500ms 无可读数据）；随后代理链路照常工作（垃圾静默丢弃不破坏正常服务）。
#[tokio::test]
async fn obfs_node_silently_drops_garbage_and_stays_healthy() {
    init_obfs_env();
    let node = spawn_node_in_mode("127.0.0.1:0".parse().unwrap(), TransportMode::Obfs).await;

    // 垃圾包：明文 QUIC 形状 + 随机字节 + 过短包
    let junk_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    junk_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut junk = vec![0u8; 1200];
    junk[0] = 0xC3; // 明文 QUIC 长包头形状
    junk[1..5].copy_from_slice(&1u32.to_be_bytes());
    for (i, b) in junk[5..].iter_mut().enumerate() {
        *b = (i * 31 % 251) as u8;
    }
    for _ in 0..25 {
        junk_sock.send_to(&junk, node.addr).unwrap();
        junk_sock.send_to(&[0x12, 0x34, 0x56], node.addr).unwrap();
        junk_sock.send_to(&junk[..600], node.addr).unwrap();
    }
    // 零回应断言：500ms 内不得收到任何数据
    let mut buf = [0u8; 2048];
    match junk_sock.recv_from(&mut buf) {
        Ok((n, from)) => panic!("obfs 节点对垃圾包必须零回应，却收到 {n}B from {from}"),
        // Windows 把读超时映射为 TimedOut，Unix 为 WouldBlock——两者都等于"零回应"
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "意外的 socket 错误: {e}"
        ),
    }

    // 链路健康：垃圾包之后代理照常可用
    let echo_port = spawn_echo_server().await;
    let proxy = spawn_proxy(vec![(node.addr, node.cert.clone())]).await;
    let mut stream = socks5_connect(proxy, &format!("127.0.0.1:{}", echo_port))
        .await
        .expect("垃圾包之后链路必须仍然可用");
    let msg = b"after-garbage-still-alive";
    stream.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(got, msg);
}

/// 两端 mode 不匹配 = 静默丢包：masquerade 客户端连 obfs 节点，
/// 客户端明文 QUIC Initial 被节点混淆层当作垃圾静默丢弃 → 连接超时失败，
/// 且失败是"无信号"的（不会收到任何节点侧回应/错误包）。
#[tokio::test]
async fn obfs_mode_mismatch_is_a_silent_black_hole() {
    init_obfs_env();
    let node = spawn_node_in_mode("127.0.0.1:0".parse().unwrap(), TransportMode::Obfs).await;

    // 显式 masquerade 客户端（不经 env）
    let (endpoint, _) = hydra_client::Transport::create_shared_endpoint_in_mode(
        vec![node.cert.clone()],
        hydra_client::DEFAULT_SNI,
        TransportMode::Masquerade,
    )
    .unwrap();
    let transport = hydra_client::Transport::from_endpoint(endpoint, hydra_client::DEFAULT_SNI);
    let result = transport.connect(node.addr).await;
    assert!(result.is_err(), "mode 不匹配时连接必须失败");
    // 5s 客户端超时路径（Transport::connect 的 tokio timeout），错误类型不敏感——
    // 关键是不存在"侥幸建立"（建立即意味着明文 QUIC 穿透了混淆层）
}
