#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use hydra_client::ProxyServer;
use hydra_node::{HydraServer, NodeOptions};

/// 测试用预共享密钥（hex 解码后 32 字节）
pub const TEST_KEY_HEX: &str = "3031323334353637383961626364656630313233343536373839616263646566";

static SEQ: AtomicU32 = AtomicU32::new(0);

pub fn test_auth_key() -> Vec<u8> {
    hydra_client::auth_key_from_hex(TEST_KEY_HEX).unwrap()
}

pub struct TestNode {
    pub addr: SocketAddr,
    pub cert: Vec<u8>,
    /// 保存 endpoint 以便测试中主动关闭节点（模拟故障）
    pub endpoint: quinn::Endpoint,
    /// 节点配置（证书目录等），供同端口重启（A2 恢复探测测试）
    pub opts: NodeOptions,
}

/// 启动一个监听随机端口的节点服务器（带认证；证书持久化到独立临时目录）
pub async fn spawn_node() -> TestNode {
    spawn_node_on("127.0.0.1:0".parse().unwrap()).await
}

/// 在指定地址启动节点服务器（指定 127.0.0.1:0 则随机端口）
pub async fn spawn_node_on(addr: SocketAddr) -> TestNode {
    // 测试全部使用 127.0.0.1 回显与回环目标：放宽节点侧 SSRF 过滤
    // （生产默认拒绝私有目标；见 hydra-node/src/handler.rs 与 docs/guides/部署指南.md）
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("hydra-test-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir).unwrap();

    let opts = NodeOptions {
        max_connections: 100,
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        ..NodeOptions::default()
    };
    spawn_node_with_opts(addr, opts).await
}

/// C2：在指定传输模式下启动节点（mode 显式传入，不依赖进程 env；
/// obfs 模式的混淆密码仍经 HYDRA_OBFS_KEY env——由 E2E 在进程内统一设置）
pub async fn spawn_node_in_mode(addr: SocketAddr, mode: hydra_obfs::TransportMode) -> TestNode {
    // 同 spawn_node_on：测试回环目标需放宽节点侧 SSRF 过滤
    std::env::set_var("HYDRA_ALLOW_PRIVATE_TARGETS", "1");
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("hydra-obfs-test-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir).unwrap();

    let opts = NodeOptions {
        max_connections: 100,
        cert_file: dir.join("cert.der"),
        key_file: dir.join("key.der"),
        mode,
        ..NodeOptions::default()
    };
    spawn_node_with_opts(addr, opts).await
}

/// 用既有配置（证书目录）启动节点服务器——重启后证书不变，客户端 pinning 仍有效
pub async fn spawn_node_with_opts(addr: SocketAddr, opts: NodeOptions) -> TestNode {
    let server = HydraServer::new(addr, test_auth_key(), opts.clone())
        .await
        .unwrap();
    let bound = server.endpoint.local_addr().unwrap();
    let cert = server.cert_der().to_vec();
    let endpoint = server.endpoint.clone();
    tokio::spawn(async move {
        let _ = server.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    TestNode {
        addr: bound,
        cert,
        endpoint,
        opts,
    }
}

/// 启动一个 TCP 回显服务器，返回端口
pub async fn spawn_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// 启动完整代理（SOCKS5/HTTP）。nodes 为 (节点地址, 节点证书) 列表，
/// 按顺序递减初始评分，保证第一个节点被优先选中。
pub async fn spawn_proxy(nodes: Vec<(SocketAddr, Vec<u8>)>) -> SocketAddr {
    spawn_proxy_with_handle(nodes).await.0
}

/// 同 spawn_proxy，但一并返回 ProxyServer 句柄（供测试读取调度器状态，如 A2 恢复验证）
pub async fn spawn_proxy_with_handle(
    nodes: Vec<(SocketAddr, Vec<u8>)>,
) -> (SocketAddr, std::sync::Arc<ProxyServer>) {
    let node_addrs: Vec<SocketAddr> = nodes.iter().map(|(a, _)| *a).collect();
    let certs: Vec<Vec<u8>> = nodes.iter().map(|(_, c)| c.clone()).collect();

    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap())
        .with_nodes(node_addrs)
        .with_auth_key(test_auth_key())
        .with_node_certs(certs);
    let proxy = std::sync::Arc::new(proxy);
    let p = proxy.clone();
    tokio::spawn(async move {
        let _ = p.start().await;
    });
    for _ in 0..50 {
        if let Some(addr) = proxy.bound_addr() {
            return (addr, proxy);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy failed to bind");
}

/// 同 spawn_proxy_with_handle，但注入共享 TrafficMonitor 并一并返回其句柄
/// （流量统计 E2E：断言中继字节数与全局/按节点计数一致）
pub async fn spawn_proxy_with_monitor(
    nodes: Vec<(SocketAddr, Vec<u8>)>,
) -> (
    SocketAddr,
    std::sync::Arc<ProxyServer>,
    std::sync::Arc<hydra_client::TrafficMonitor>,
) {
    let node_addrs: Vec<SocketAddr> = nodes.iter().map(|(a, _)| *a).collect();
    let certs: Vec<Vec<u8>> = nodes.iter().map(|(_, c)| c.clone()).collect();
    let monitor = std::sync::Arc::new(hydra_client::TrafficMonitor::new());

    let proxy = ProxyServer::new("127.0.0.1:0".parse().unwrap())
        .with_nodes(node_addrs)
        .with_auth_key(test_auth_key())
        .with_node_certs(certs)
        .with_traffic_monitor(monitor.clone());
    let proxy = std::sync::Arc::new(proxy);
    let p = proxy.clone();
    tokio::spawn(async move {
        let _ = p.start().await;
    });
    for _ in 0..50 {
        if let Some(addr) = proxy.bound_addr() {
            return (addr, proxy, monitor);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy failed to bind");
}

/// 等待 UDP 端口释放（节点 endpoint 关闭后 server 任务退出需短暂时间）
pub async fn wait_udp_port_free(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// 通过代理发起 SOCKS5 CONNECT（域名类型交给节点解析），返回已就绪的 TCP 流
pub async fn socks5_connect(
    proxy_addr: SocketAddr,
    target: &str,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;

    // greeting: 无认证
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00], "greeting reply mismatch");

    // CONNECT 请求（ATYP=域名，由节点侧解析 DNS）
    let (host, port_str) = target.rsplit_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 connect failed: status={}", reply[1]);
    Ok(s)
}

/// SOCKS5 CONNECT 的宽松版本：不断言成功，返回应答码（供故障路径测试）
pub async fn socks5_connect_lenient(
    proxy_addr: SocketAddr,
    target: &str,
) -> std::io::Result<(tokio::net::TcpStream, u8)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00], "greeting reply mismatch");

    let (host, port_str) = target.rsplit_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    Ok((s, reply[1]))
}
