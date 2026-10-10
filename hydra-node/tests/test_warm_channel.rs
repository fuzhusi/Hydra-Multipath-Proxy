//! 温连接（pre-warm）等待窗口回归测试（评审方案 1）。
//!
//! 守护的耦合：节点侧"已认证连接等待目标地址帧"的超时从 AUTH_TIMEOUT(10s)
//! 改为连接空闲看门狗 idle（默认 300s）——客户端温连接池（60s TTL）依赖该
//! 窗口。本测试用**注入的短 idle** 把窗口夹在可测范围：
//! - ① idle=14s：闲置 11.5s（> 旧 10s 窗口）后发目标帧 → 应成功
//!   （若回退为 AUTH_TIMEOUT 语义，此用例失败——耦合被守护）；
//! - ② idle=2s：闲置 3s → 应拿不到成功应答（窗口边界负例；评审 P1：
//!   断言落在"读应答失败"并带超时兜底，不假设失败发生在写入侧）。

mod common;

use common::{connect_and_handshake, spawn_echo_server, spawn_node_with_idle, test_auth_key};
use hydra_protocol::tcp_frame::{read_reply, write_target};
use std::time::Duration;

#[tokio::test]
async fn 温连接_闲置超过旧auth窗口_仍可交付目标() {
    // 回环目标默认被 SSRF 拒绝：本测试放开（与其他 e2e 同款；OnceLock 进程内生效）
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let node = spawn_node_with_idle(Some(Duration::from_secs(14))).await;
    let echo_port = spawn_echo_server().await;
    let key = test_auth_key();

    // 温连接：握手完成，故意不发目标帧
    let (rd, mut wr) = connect_and_handshake(node.addr, &node.cert, &key).await;
    tokio::time::sleep(Duration::from_millis(11_500)).await;

    // 闲置后交付目标：应拿到成功应答并完成回显
    write_target(&mut wr, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("写目标帧");
    let mut stream = rd.unsplit(wr);
    tokio::time::timeout(Duration::from_secs(5), read_reply(&mut stream))
        .await
        .expect("应在 5s 内读到应答")
        .expect("应答应为成功（闲置 11.5s > 旧 10s 窗口后仍可建目标）");

    // 回显验证：隧道真实可用
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = b"warm-channel-echo";
    stream.write_all(payload).await.expect("写回显");
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("读回显");
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn 温连接_超过节点等待窗口_拿不到成功应答() {
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let node = spawn_node_with_idle(Some(Duration::from_secs(2))).await;
    let echo_port = spawn_echo_server().await;
    let key = test_auth_key();

    let (mut rd, mut wr) = connect_and_handshake(node.addr, &node.cert, &key).await;
    tokio::time::sleep(Duration::from_millis(3_000)).await; // > 2s 窗口

    // 评审 P1：写入可能进 OS 缓冲"成功"，失败体现在读应答（EOF/错误）——
    // 断言落在读侧并带超时兜底（防挂起）
    let r = write_target(&mut wr, &format!("127.0.0.1:{echo_port}")).await;
    if r.is_ok() {
        let reply = tokio::time::timeout(Duration::from_secs(5), read_reply(&mut rd)).await;
        let failed = match reply {
            Err(_) => true,    // 超时 = 未在窗口内拿到应答
            Ok(Err(_)) => true, // 连接关闭/读取错误/失败应答码
            Ok(Ok(())) => false, // 拿到成功应答 = 违反窗口语义
        };
        assert!(failed, "超过节点等待窗口后不应拿到成功应答");
    }
    // 写入直接失败也算通过（连接已被节点关闭）
}
