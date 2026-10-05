//! SSRF 目标过滤集成测试（遗留 P1-3）：默认拒绝模式下，已认证连接指向
//! 私有/保留地址（云元数据 169.254.169.254、回环）被拒，TCP 新协议下收到
//! 2B 应答码 0x00 0x01（REPLY_TARGET_FAIL）。
//!
//! 注意：本测试二进制依赖环境变量 `HYDRA_ALLOW_PRIVATE_TARGETS` 未设置
//! （默认拒绝）。若外部 shell 显式设置了该变量，测试会失败——属人为配置。
use std::time::Duration;

mod common;

use hydra_protocol::tcp_frame::{REPLY_LEN, REPLY_TARGET_FAIL};
use tokio::io::AsyncReadExt;

/// 验证目标被拒时客户端读到 2B 应答码 [0x00, 0x01]（REPLY_TARGET_FAIL，
/// 而非成功前导或静默关流）
async fn expect_target_fail(mut tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>, target_desc: &str) {
    let mut buf = [0u8; REPLY_LEN];
    let outcome = tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut buf)).await;
    match outcome {
        Ok(Ok(_)) if buf == [0x00, REPLY_TARGET_FAIL] => {} // 期望路径
        Ok(Ok(n)) => panic!(
            "{}: 目标应被拒绝，却收到 {} 字节应答 {:?}",
            target_desc,
            n,
            &buf[..n]
        ),
        Err(_) => panic!("{}: 等待应答码超时", target_desc),
        Ok(Err(e)) => panic!("{}: 读应答失败 {:?}（期望 0x00 0x01）", target_desc, e),
    }
}

/// 规格要求用例：默认下连云元数据端点 169.254.169.254:80 被拒（应答码 0x01）
#[tokio::test]
async fn default_denies_metadata_link_local_target() {
    let node = common::spawn_node().await;
    let tls = common::connect_and_request(
        node.addr,
        &node.cert,
        &common::test_auth_key(),
        "169.254.169.254:80",
    )
    .await;
    expect_target_fail(tls, "169.254.169.254:80").await;
}

/// 回环目标即使真实监听（回显服务器在跑）也必须被拒——
/// 过滤缺失时节点会连上回显服务器并回 [0x00,0x00]，本测试即红（可区分的回归信号）
#[tokio::test]
async fn default_denies_loopback_target_even_when_listening() {
    let echo_port = common::spawn_echo_server().await;
    let node = common::spawn_node().await;
    let tls = common::connect_and_request(
        node.addr,
        &node.cert,
        &common::test_auth_key(),
        &format!("127.0.0.1:{}", echo_port),
    )
    .await;
    expect_target_fail(tls, "127.0.0.1（回显服务器监听中）").await;
}

/// IPv4 映射字面量（::ffff:169.254.169.254）不得绕过过滤
#[tokio::test]
async fn default_denies_ipv4_mapped_link_local_target() {
    let node = common::spawn_node().await;
    let tls = common::connect_and_request(
        node.addr,
        &node.cert,
        &common::test_auth_key(),
        "[::ffff:169.254.169.254]:80",
    )
    .await;
    expect_target_fail(tls, "[::ffff:169.254.169.254]:80").await;
}
