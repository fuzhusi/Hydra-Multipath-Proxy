//! SSRF 目标过滤集成测试（遗留 P1-3）：默认拒绝模式下，已认证流指向
//! 私有/保留地址（云元数据 169.254.169.254、回环）被拒，走既有 0x11 错误路径。
//!
//! 注意：本测试二进制依赖环境变量 `HYDRA_ALLOW_PRIVATE_TARGETS` 未设置
//! （默认拒绝）。若外部 shell 显式设置了该变量，测试会失败——属人为配置。
use std::time::Duration;

mod common;

use hydra_node::ERR_TARGET_CONNECT;
use quinn::VarInt;

/// 验证目标被拒时客户端读到 ReadError::Reset(0x11)（而非成功前导或静默 FIN）
async fn expect_reset_0x11(mut recv: quinn::RecvStream, target_desc: &str) {
    let mut buf = [0u8; 2];
    let outcome = tokio::time::timeout(Duration::from_secs(10), recv.read(&mut buf)).await;
    match outcome {
        Ok(Err(quinn::ReadError::Reset(code))) => {
            assert_eq!(
                code,
                VarInt::from_u32(ERR_TARGET_CONNECT),
                "{}: 期望 0x11，实际 {:#x}",
                target_desc,
                u64::from(code)
            );
        }
        Ok(Ok(Some(n))) => panic!(
            "{}: 目标应被拒绝，却收到 {} 字节数据（成功前导?）: {:?}",
            target_desc,
            n,
            &buf[..n]
        ),
        Ok(Ok(n)) => panic!(
            "{}: 目标应被拒绝，却得到流正常结束 {:?}（静默 FIN 而非显式错误码）",
            target_desc, n
        ),
        Ok(Err(e)) => panic!("{}: 收到其他错误 {:?}（期望 Reset(0x11)）", target_desc, e),
        Err(_) => panic!("{}: 等待 Reset(0x11) 超时", target_desc),
    }
}

/// 规格要求用例：默认下连云元数据端点 169.254.169.254:80 被拒（0x11）
#[tokio::test]
async fn default_denies_metadata_link_local_target() {
    let node = common::spawn_node().await;
    let endpoint = common::client_endpoint(node.cert.clone());
    let (send, recv) = common::open_authed_stream(
        &endpoint,
        node.addr,
        &common::test_auth_key(),
        "169.254.169.254:80",
    )
    .await;
    // send 保持存活至读出结果（提前 drop 可能触发隐式 reset 干扰节点读数）
    let _ = &send;
    expect_reset_0x11(recv, "169.254.169.254:80").await;
}

/// 回环目标即使真实监听（回显服务器在跑）也必须被拒——
/// 过滤缺失时节点会连上回显服务器并回 [0x00,0x00]，本测试即红（可区分的回归信号）
#[tokio::test]
async fn default_denies_loopback_target_even_when_listening() {
    let echo_port = common::spawn_echo_server().await;
    let node = common::spawn_node().await;
    let endpoint = common::client_endpoint(node.cert.clone());
    let (send, recv) = common::open_authed_stream(
        &endpoint,
        node.addr,
        &common::test_auth_key(),
        &format!("127.0.0.1:{}", echo_port),
    )
    .await;
    let _ = &send;
    expect_reset_0x11(recv, "127.0.0.1（回显服务器监听中）").await;
}

/// IPv4 映射字面量（::ffff:169.254.169.254）不得绕过过滤
#[tokio::test]
async fn default_denies_ipv4_mapped_link_local_target() {
    let node = common::spawn_node().await;
    let endpoint = common::client_endpoint(node.cert.clone());
    let (send, recv) = common::open_authed_stream(
        &endpoint,
        node.addr,
        &common::test_auth_key(),
        "[::ffff:169.254.169.254]:80",
    )
    .await;
    let _ = &send;
    expect_reset_0x11(recv, "[::ffff:169.254.169.254]:80").await;
}
