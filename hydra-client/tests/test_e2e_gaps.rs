//! R-42 测试缺口专项（05 报告 R-42）：补 TCP 转型后零覆盖的端到端路径。
//!
//! 覆盖（本轮承诺四项）：
//! 1. **真证书 PEM 路径 E2E**：rcgen 生成 PEM 证书/私钥落盘 → 节点以 PEM 文件启动
//!    （cert.rs parse_pem_pair 加载路径）→ 客户端 pin 叶证书 DER 建链回显
//!    （完整链路：PEM 加载 → TLS pinning → Noise-PSK → SOCKS5 → 回显）。
//!    CA 模式（TlsTrust::public_ca）依赖公共 CA 根对真实域名的校验，自签
//!    rcgen 证书不受公共根信任，本地不可自动化——按设计用 pinned(leaf der)
//!    验证 PEM 加载与链路（任务书指定方案）。
//! 2. **分享链接端到端**：生成完整分享链接（v=3，含 k/cc）→ from_share_url
//!    解析 → 用链接自带的凭据（auth_key + cert DER）建代理 → 回显成功。
//! 3. **多节点故障切换 E2E over TCP**：两节点，节点 1 运行在独立 tokio runtime
//!    上（shutdown 该 runtime = kill 节点：listener 随任务取消而关闭），
//!    kill 后客户端应自动切换到节点 2 完成回显。
//! 4. **HYDRA_IDLE_TIMEOUT_SECS 短值空闲回收**：空闲连接被节点静默关闭、
//!    持续活跃的连接不受影响（注意：节点侧 env 值 clamp 下限 30s，本测试
//!    实测耗时 ~35s，为最短可自动化集成形态）。

mod common;

use common::{
    socks5_connect, spawn_echo_server, spawn_node, spawn_node_with_idle_timeout,
    spawn_proxy_with_handle, TEST_KEY_HEX,
};
use hydra_client::{ProxyServer, ShareLink};
use hydra_node::NodeOptions;
use hydra_protocol::{NodeInfo, NodeStatus};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_auth_key() -> Vec<u8> {
    hydra_client::auth_key_from_hex(TEST_KEY_HEX).unwrap()
}

/// 通过代理向回显服务器做一次 write→read 往返断言
async fn echo_roundtrip(s: &mut tokio::net::TcpStream, payload: &[u8]) {
    s.write_all(payload).await.expect("写代理流");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("读回显超时")
        .expect("读回显失败");
    assert_eq!(buf, payload, "回显字节必须一致");
}

/// 手工起代理并等待绑定就绪（② 自定义 PSK 用；注意必须用 tokio sleep 让出执行，
/// current-thread 测试 runtime 下 std::thread::sleep 会饿死 proxy.start 任务）
async fn wait_bind(proxy: &std::sync::Arc<ProxyServer>) -> std::net::SocketAddr {
    for _ in 0..50 {
        if let Some(a) = proxy.bound_addr() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy failed to bind");
}

/// ① 真证书 PEM 路径 E2E：节点挂 PEM 文件（rcgen 生成）+ 客户端 pinned(leaf der)。
#[tokio::test]
async fn pem真证书节点_客户端pinned叶证书_建链回显() {
    // rcgen 0.13 生成自签证书并序列化为 PEM（ACME 部署形态的等价本地替身）
    let ck = rcgen::generate_simple_self_signed(vec!["hydra.node".into(), "localhost".into()])
        .expect("rcgen 生成证书");
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    // 落盘为 PEM 文件对（节点 cert.rs 检测 -----BEGIN 走 parse_pem_pair 加载路径）
    let dir = std::env::temp_dir().join(format!(
        "hydra-pem-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_file = dir.join("cert.pem");
    let key_file = dir.join("key.pem");
    std::fs::write(&cert_file, &cert_pem).unwrap();
    std::fs::write(&key_file, &key_pem).unwrap();

    // 节点以 PEM 文件启动（真证书加载路径）
    let opts = NodeOptions {
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
        ..NodeOptions::default()
    };
    let node = hydra_node::HydraServer::new("127.0.0.1:0".parse().unwrap(), test_auth_key(), opts)
        .await
        .expect("节点以 PEM 证书启动应成功");
    let addr = node.tcp_listen_addr.expect("TCP 监听应已绑定");
    let leaf_der = node.cert_der().to_vec();

    // PEM 加载 sanity：cert_der() 应与 PEM 内叶证书一致（rcgen der() 同源）
    assert_eq!(
        leaf_der,
        ck.cert.der().as_ref(),
        "节点加载的 DER 应为 PEM 叶证书"
    );

    // 客户端 pinned(leaf der) 建链：完整代理 → 回显
    let echo_port = spawn_echo_server().await;
    let proxy = std::sync::Arc::new(
        ProxyServer::new("127.0.0.1:0".parse().unwrap())
            .with_nodes(vec![addr])
            .with_auth_key(test_auth_key())
            .with_node_certs(vec![leaf_der]),
    );
    let p = proxy.clone();
    tokio::spawn(async move {
        let _ = p.start().await;
    });
    let mut s = socks5_connect(wait_bind(&proxy).await, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("PEM 节点链路 SOCKS5 建链应成功");
    echo_roundtrip(&mut s, b"pem-e2e-hello").await;
}

/// ② 分享链接端到端：生成 → 解析 → 用链接凭据建链回显。
#[tokio::test]
async fn 分享链接_生成解析_凭据建链回显() {
    let node = spawn_node().await;

    // 生成完整分享（v2：k=auth_key，cc=cert DER）
    let info = NodeInfo {
        address: node.addr,
        bandwidth: 100.0,
        latency: 10.0,
        loss_rate: 0.01,
        load: 0.5,
        status: NodeStatus::Online,
    };
    let link = ShareLink::new(&info)
        .with_auth_key_bytes(&test_auth_key())
        .with_cert_der(&node.cert);
    let url = link.to_share_url();
    assert!(url.starts_with("hydra://"), "分享链接 scheme: {url}");

    // 解析（另一端拿到链接文本）
    let parsed = ShareLink::from_share_url(url.trim()).expect("分享链接应可解析");
    assert!(parsed.is_full_share(), "完整分享应同时携带密钥与证书");
    let key = parsed
        .auth_key_bytes()
        .expect("k 解码")
        .expect("完整分享必带 k");
    let cert = parsed
        .cert_der_bytes()
        .expect("cc 解码")
        .expect("完整分享必带 cc");
    assert_eq!(key, test_auth_key(), "链接密钥应与节点 PSK 一致");
    assert_eq!(cert, node.cert, "链接证书应与节点证书一致");
    assert!(parsed.transport_is_tcp(), "TCP 转型后链接应为 tcp 传输");

    // 用链接自带的凭据（而非测试常量）建代理 → 回显
    let echo_port = spawn_echo_server().await;
    let proxy = std::sync::Arc::new(
        ProxyServer::new("127.0.0.1:0".parse().unwrap())
            .with_nodes(vec![node.addr])
            .with_auth_key(key)
            .with_node_certs(vec![cert]),
    );
    let p = proxy.clone();
    tokio::spawn(async move {
        let _ = p.start().await;
    });
    let mut s = socks5_connect(wait_bind(&proxy).await, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("用分享链接凭据建链应成功");
    echo_roundtrip(&mut s, b"share-link-e2e").await;
}

/// ③ 多节点故障切换 E2E over TCP：节点 1 kill → 自动切节点 2 回显成功。
#[tokio::test]
async fn 双节点_第一节点kill_自动切第二节点回显() {
    // 节点 1 跑在独立 runtime 上：shutdown 该 runtime 即"kill"节点
    // （listener 由节点接受循环任务持有，任务随 runtime 关闭被取消，端口释放）。
    // runtime 的创建与 block_on 必须在独立 OS 线程——测试自身就在 tokio runtime
    // 里，从 runtime 上下文内再 block_on 另一个 runtime 会 panic。
    let node1 = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("节点 1 独立 runtime");
        let node = rt.block_on(async { spawn_node().await });
        (node, rt)
    })
    .join()
    .expect("节点 1 启动线程");
    let (node1, rt1) = node1;
    let node2 = spawn_node().await;
    let echo_port = spawn_echo_server().await;

    // 两节点代理（第一节点评分优先）
    let (proxy_addr, _proxy) = spawn_proxy_with_handle(vec![
        (node1.addr, node1.cert.clone()),
        (node2.addr, node2.cert),
    ])
    .await;

    // kill 前：链路可用（由节点 1 服务——评分优先，即便偶由节点 2 服务也不影响后续断言）
    let mut s = socks5_connect(proxy_addr, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("kill 前建链应成功");
    echo_roundtrip(&mut s, b"before-kill").await;

    // kill 节点 1：关闭其 runtime，listener 关闭、端口不可达
    rt1.shutdown_background();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tokio::net::TcpStream::connect(node1.addr).await.is_err(),
        "节点 1 端口应已不可达（kill 生效）"
    );

    // kill 后：新连接应自动故障切换到节点 2 并回显成功
    let mut s = socks5_connect(proxy_addr, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("kill 后应切换到节点 2 建链成功");
    echo_roundtrip(&mut s, b"after-kill-failover").await;
}

/// ④ 短 idle 超时：空闲连接被回收、活跃连接存活（节点 clamp 下限 30s，~35s）。
/// 07-P2-4：idle 超时改为 NodeOptions.idle_timeout 显式注入，不再写进程级
/// env（HYDRA_IDLE_TIMEOUT_SECS 的 set/remove 与并行测试线程构成数据竞争，
/// 且会被并行用例的 spawn_node 读到造成跨用例干扰）。
#[tokio::test(flavor = "multi_thread")]
async fn 空闲超时短值_空闲连接被回收_活跃连接存活() {
    let node = spawn_node_with_idle_timeout(Duration::from_secs(30)).await;
    let echo_port = spawn_echo_server().await;
    let (proxy_addr, _proxy) = spawn_proxy_with_handle(vec![(node.addr, node.cert)]).await;

    // 连接 A：建立后保持空闲（不写数据）
    let mut idle_conn = socks5_connect(proxy_addr, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("空闲连接建链");
    // 连接 B：建立后每 2s 持续活跃（保活往返）
    let mut active_conn = socks5_connect(proxy_addr, &format!("127.0.0.1:{echo_port}"))
        .await
        .expect("活跃连接建链");

    // 后台任务等连接 A 被节点 idle 回收（读到 EOF）
    let idle_task = tokio::spawn(async move {
        let mut buf = [0u8; 16];
        // 节点静默关闭：SOCKS5 客户端侧读到 EOF（或连接错误）
        match idle_conn.read(&mut buf).await {
            Ok(0) => true,  // EOF = 被回收
            Ok(_) => false, // 意外数据
            Err(_) => true, // 连接被强制关闭同样算回收
        }
    });

    // 主循环：保活 B（每 2s 一次往返），同时等 A 的 EOF（节点 30s idle）
    let start = Instant::now();
    let idle_result = loop {
        // B 保活往返（活跃连接不因 idle 被杀的证据）
        echo_roundtrip(&mut active_conn, b"keepalive").await;
        // A 是否已被回收（最长等 45s = 30s idle + 建链/调度余量）
        if idle_task.is_finished() {
            break idle_task.await.unwrap_or(false);
        }
        if start.elapsed() > Duration::from_secs(45) {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(2000)).await;
    };

    assert!(idle_result, "空闲连接应在 idle 超时后被节点回收（EOF）");
    assert!(
        start.elapsed() >= Duration::from_secs(25),
        "回收应发生在 idle 超时（≥25s）之后而非提前误杀，实际 {:?}",
        start.elapsed()
    );
    // B 在 A 被回收后仍然可用（活跃连接存活）
    echo_roundtrip(&mut active_conn, b"still-alive").await;
}
