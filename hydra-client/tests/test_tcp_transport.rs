//! TCP 转型（Wave 1）验收门：TCP/TLS（TLS 1.3 + Noise-PSK）路径 E2E。
//!
//! ① 大流量三档（64KB / 1MB 直连 connect_target；10MB 经 SOCKS5 代理路径验证接线）；
//! ② 错误 PSK → connect_target 必须报错，且错误信息不含可区分错误码（节点静默关流语义）；
//! ③ 半关闭：写端 shutdown 后读端读到完整回显再读到 EOF；
//! ④ SOCKS5 E2E：默认（不设 HYDRA_TRANSPORT）走 TCP，回显逐字节一致；
//! ⑤ transport_from_env 默认返回 Tcp。

mod common;

use common::{lcg_payload, socks5_connect, spawn_echo_server, spawn_node, spawn_proxy, Lcg};
use hydra_client::tcp_transport::{connect_target, transport_from_env, TransportChoice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SNI: &str = "hydra.node";

fn auth_key() -> Vec<u8> {
    hydra_client::auth_key_from_hex(common::TEST_KEY_HEX).unwrap()
}

/// 直连 connect_target → 回显服务器：并发写读 + 写端半关闭，回显逐字节相等。
///
/// 注意必须**边写边读**：若先写全量再读，payload 超过 TCP 接收缓冲后
/// （本机缓冲通常 <1MB），节点回写阻塞 → 节点停止读客户端 → 客户端写阻塞，
/// 构成测试自身的死锁（与协议无关；真实代理场景两端天然并发）。
async fn direct_echo_roundtrip(total: usize, seed: u64) {
    let node = spawn_node().await;
    let echo_port = spawn_echo_server().await;
    let target = format!("127.0.0.1:{}", echo_port);

    let trust = hydra_client::tcp_transport::TlsTrust::pinned(vec![node.cert.clone()]);
    let stream = connect_target(node.addr, SNI, &trust, &auth_key(), &target)
        .await
        .expect("connect_target should succeed against live node");
    let (mut rd, mut wr) = tokio::io::split(stream);

    // 写任务：分块写全量后 shutdown（半关闭）
    let writer = tokio::spawn(async move {
        let mut gen = Lcg::new(seed);
        let mut wbuf = vec![0u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(wbuf.len());
            gen.fill(&mut wbuf[..n]);
            wr.write_all(&wbuf[..n]).await.expect("write payload");
            sent += n;
        }
        wr.shutdown().await.expect("half-close write side");
    });

    // 读任务：流式逐字节比对，直到 EOF
    let mut verify = Lcg::new(seed);
    let mut rbuf = vec![0u8; 64 * 1024];
    let mut got = 0usize;
    loop {
        let n = rd.read(&mut rbuf).await.expect("read echo");
        if n == 0 {
            break;
        }
        for (i, b) in rbuf[..n].iter().enumerate() {
            assert_eq!(
                *b,
                verify.next_byte(),
                "byte mismatch at offset {}",
                got + i
            );
        }
        got += n;
    }
    writer.await.expect("writer task");
    assert_eq!(
        got, total,
        "echo must return exactly the sent payload length"
    );
}

/// ①a：64KB 直连回显逐字节一致
#[tokio::test]
async fn wave1_e2e_64kb_direct_echo() {
    direct_echo_roundtrip(64 * 1024, 0xA1).await;
}

/// ①b：1MB 直连回显逐字节一致
#[tokio::test]
async fn wave1_e2e_1mb_direct_echo() {
    direct_echo_roundtrip(1024 * 1024, 0xB2).await;
}

/// ①c：10MB 经 SOCKS5 代理路径（默认 TCP），验证代理接线与大数据量完整性
#[tokio::test]
async fn wave1_e2e_10mb_socks5_proxy_echo() {
    let node = spawn_node().await;
    let echo_port = spawn_echo_server().await;
    let proxy = spawn_proxy(vec![(node.addr, node.cert.clone())]).await;
    let mut s = socks5_connect(proxy, &format!("127.0.0.1:{}", echo_port))
        .await
        .expect("SOCKS5 connect via proxy");

    const TOTAL: usize = 10 * 1024 * 1024;
    let payload = lcg_payload(0xC3, TOTAL);

    // 写全量后关写侧（半关闭），再读全量
    let up = tokio::spawn(async move {
        s.write_all(&payload).await.expect("write payload");
        s.shutdown().await.expect("half-close write side");
        s
    });
    let mut s = up.await.expect("writer task");
    let mut got = Vec::with_capacity(TOTAL);
    s.read_to_end(&mut got).await.expect("read echo");
    assert_eq!(got.len(), TOTAL, "echo length must match");
    assert_eq!(
        got,
        lcg_payload(0xC3, TOTAL),
        "10MB echo must be byte-identical"
    );
}

/// ②：错误 PSK → connect_target 必须报错；节点侧为静默关流（无错误码回传），
/// 错误信息不得携带可区分的应用错误码
#[tokio::test]
async fn wave1_wrong_psk_fails_without_distinguishable_code() {
    let node = spawn_node().await;
    let echo_port = spawn_echo_server().await;
    let target = format!("127.0.0.1:{}", echo_port);

    let wrong_key = {
        let mut k = auth_key();
        k[0] ^= 0xFF;
        k
    };
    let trust = hydra_client::tcp_transport::TlsTrust::pinned(vec![node.cert.clone()]);
    let result = connect_target(node.addr, SNI, &trust, &wrong_key, &target).await;
    let err = result.expect_err("wrong PSK must fail");
    let msg = err.to_string();
    assert!(
        !msg.contains("0x11") && !msg.contains("0x12") && !msg.contains("0x13"),
        "静默关流语义：错误信息不得携带可区分错误码，got: {}",
        msg
    );
}

/// ③：半关闭——connect_target 后写一段数据并 shutdown 写端，
/// 读端应读到完整回显（字节数 == 发送字节数）后读到 EOF（0）
#[tokio::test]
async fn wave1_half_close_echo_then_eof() {
    let node = spawn_node().await;
    let echo_port = spawn_echo_server().await;
    let target = format!("127.0.0.1:{}", echo_port);

    let trust = hydra_client::tcp_transport::TlsTrust::pinned(vec![node.cert.clone()]);
    let stream = connect_target(node.addr, SNI, &trust, &auth_key(), &target)
        .await
        .expect("connect_target should succeed");
    let (mut rd, mut wr) = tokio::io::split(stream);

    // 写任务：写一段数据后 shutdown 写端（半关闭）
    let payload = lcg_payload(0xD4, 128 * 1024);
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&payload).await.expect("write payload");
        wr.shutdown().await.expect("shutdown write half");
    });

    // 读端：先读到与发送等量的回显，随后读到干净 EOF
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.expect("read to EOF");
    writer.await.expect("writer task");
    assert_eq!(got, expected, "echo must be byte-identical");
    // read_to_end 已在 EOF（0）处停止：再读一次确认流已干净关闭
    let mut extra = [0u8; 1];
    let n = rd.read(&mut extra).await.expect("post-EOF read");
    assert_eq!(n, 0, "stream must stay cleanly closed after EOF");
}

/// ④：SOCKS5 E2E——默认（不设 HYDRA_TRANSPORT）即走 TCP，回显逐字节一致
#[tokio::test]
async fn wave1_socks5_default_transport_is_tcp() {
    // 确保未设 HYDRA_TRANSPORT（默认路径）
    std::env::remove_var("HYDRA_TRANSPORT");

    let node = spawn_node().await;
    let echo_port = spawn_echo_server().await;
    let proxy = spawn_proxy(vec![(node.addr, node.cert.clone())]).await;
    let mut s = socks5_connect(proxy, &format!("127.0.0.1:{}", echo_port))
        .await
        .expect("SOCKS5 connect via proxy (default tcp)");

    let payload = lcg_payload(0xE5, 256 * 1024);
    let expected = payload.clone();
    let up = tokio::spawn(async move {
        s.write_all(&payload).await.expect("write payload");
        s.shutdown().await.expect("half-close write side");
        s
    });
    let mut s = up.await.expect("writer task");
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.expect("read echo");
    assert_eq!(got, expected, "SOCKS5 E2E echo must be byte-identical");
}

/// ⑤：transport_from_env 默认返回 Tcp（未设 HYDRA_TRANSPORT）
#[test]
fn wave1_transport_from_env_defaults_to_tcp() {
    std::env::remove_var("HYDRA_TRANSPORT");
    assert_eq!(transport_from_env(), TransportChoice::Tcp);
}
