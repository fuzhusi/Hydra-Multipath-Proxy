//! 允许开关（`HYDRA_ALLOW_PRIVATE_TARGETS=1`）下的行为验证：
//! 回环目标恢复可连——这是既有测试基线（127.0.0.1 回显服务器）所依赖的模式。
//! 独立测试二进制：env 为进程级全局，与其他默认拒绝用例隔离，避免并行互扰。
use std::time::Duration;

mod common;

#[tokio::test]
async fn allow_switch_restores_loopback_echo() {
    // 节点侧每次处理流时读取 env，任意流开始前设置即生效
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");

    tokio::time::timeout(Duration::from_secs(15), async {
        let echo_port = common::spawn_echo_server().await;
        let node = common::spawn_node().await;
        let endpoint = common::client_endpoint(node.cert.clone());
        let (mut send, mut recv) = common::open_authed_stream(
            &endpoint,
            node.addr,
            &common::test_auth_key(),
            &format!("127.0.0.1:{}", echo_port),
        )
        .await;

        // 成功前导 [0x00, 0x00]
        let mut hdr = [0u8; 2];
        recv.read_exact(&mut hdr).await.expect("读成功前导");
        assert_eq!(hdr, [0x00, 0x00], "回环目标在允许模式下应连接成功");

        // 回环打通：发数据经节点转发到回显服务器并原样返回
        send.write_all(b"ping").await.expect("write payload");
        send.finish().await.expect("finish");

        let echoed = recv.read_to_end(64 * 1024).await.expect("读回显数据");
        assert_eq!(&echoed, b"ping");
    })
    .await
    .expect("允许模式回环回显超时");
}
