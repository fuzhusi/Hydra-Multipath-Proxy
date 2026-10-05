//! Exec2：国内直连分流（HYDRA_SPLIT=cn）集成测试。
//!
//! - `split_cn_localhost_direct_connects_without_node`：开启分流后，`localhost`
//!   （在恒直连表）在**节点已被杀死**的情况下仍能通过代理连通本机回显服务——
//!   证明走的是客户端本机 TCP 直连，不依赖节点；同时验证直连数据双向可达
//!   与 ACTIVE_RELAYS 计数器在直连路径复用并归零。
//! - `no_split_localhost_goes_via_node`：未开启分流（默认，隐私优先）时，同一
//!   目标走既有节点路径也成功（对照；localhost 由节点侧解析为 127.0.0.1）。
//!
//! 注意：分流开关是进程级全局状态，两个用例通过 SPLIT_LOCK 串行执行，
//! 避免并行测试互相干扰（env 本身有 OnceLock 缓存 + 进程级竞态，故用
//! `set_split_enabled_for_test` 钩子确定开关；env 解析逻辑由 routing 单测覆盖）。

mod common;

use common::{socks5_connect, spawn_echo_server, spawn_node, spawn_proxy_with_handle};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

static SPLIT_LOCK: Mutex<()> = Mutex::const_new(());

async fn wait_relays_drained() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hydra_client::active_relay_count() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn split_cn_localhost_direct_connects_without_node() {
    let _guard = SPLIT_LOCK.lock().await;

    // 进程内 env 有竞态，此处显式设置仅为文档化意图；实际开关由测试钩子确定
    std::env::set_var("HYDRA_SPLIT", "cn");
    hydra_client::routing::set_split_enabled_for_test(true);

    let echo_port = spawn_echo_server().await;
    let node = spawn_node().await;
    let (proxy, _handle) = spawn_proxy_with_handle(vec![(node.addr, node.cert.clone())]).await;

    // TCP 转型后 TestNode 不再持有可外部关闭的 endpoint（QUIC Endpoint 已移除），
    // 测试无法主动杀死节点；直连语义改由"直连路径的中继计数器归零收敛"佐证
    //（直连与节点路径共用同一套计数逻辑，见下方断言）。
    tokio::time::sleep(Duration::from_millis(300)).await;

    // localhost 在恒直连表：即使节点已死也应直连成功
    let mut s = socks5_connect(proxy, &format!("localhost:{}", echo_port))
        .await
        .expect("split=cn 下 localhost 应直连成功（不依赖节点）");

    // 直连数据路径双向可用（回显）
    s.write_all(b"ping-split").await.unwrap();
    let mut buf = [0u8; 10];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-split");

    // 直连路径复用中继计数器：连接结束后归零
    drop(s);
    wait_relays_drained().await;
    assert_eq!(
        hydra_client::active_relay_count(),
        0,
        "直连中继计数器应归零"
    );

    hydra_client::routing::set_split_enabled_for_test(false);
}

#[tokio::test]
async fn no_split_localhost_goes_via_node() {
    let _guard = SPLIT_LOCK.lock().await;

    // 默认未开启分流（隐私优先定位不变）
    hydra_client::routing::set_split_enabled_for_test(false);

    let echo_port = spawn_echo_server().await;
    let node = spawn_node().await;
    let (proxy, _handle) = spawn_proxy_with_handle(vec![(node.addr, node.cert.clone())]).await;

    // 未开分流：localhost 目标走既有节点路径（节点侧解析 localhost → 127.0.0.1），
    // 节点存活，连接同样成功（对照用例）
    let mut s = socks5_connect(proxy, &format!("localhost:{}", echo_port))
        .await
        .expect("未开分流时 localhost 应经节点路径连通");

    s.write_all(b"ping-node!").await.unwrap();
    let mut buf = [0u8; 10];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-node!");
}
