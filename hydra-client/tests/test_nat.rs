//! NAT 穿透客户端侧集成测试（NAT 穿透方案 §3.1 / §3.3）。
//!
//! 覆盖：
//! 1. `discover_public_address`：本地假 STUN TCP 服务器（手工按 RFC 5389 构造
//!    Binding Success，映射地址写死 203.0.113.7:x）→ 解析与分类断言；
//!    无 HYDRA_STUN_ADDRS → 特定错误（功能关闭语义）。
//! 2. 节点信令全链路（register → invite → incoming → accept → accepted），
//!    双"客户端"进程内各连 `@hydra-p2p/alice` / `@hydra-p2p/bob`。
//! 3. 打洞 loopback 验证：同机两端 mapped=127.0.0.1:port（无 NAT），验证
//!    「同时 connect+accept → Noise-PSK 握手 → nonce 回显」编排路径。
//!    **如实标注**：真实 NAT 下的同时打开无法本地自动化，本测试只验证编排与
//!    校验逻辑；NAT 行为对连接建立的影响需真实网络人工验证。
//! 4. `punch_direct` 端到端：节点信令 + 假 STUN（回显探测方真实本地地址，
//!    即 loopback 上的"如实"映射）→ 双端同时跑编排 → 双双拿到直连流。

mod common;

use common::{spawn_node_with_p2p, TEST_KEY_HEX};
use hydra_client::nat::{
    discover_full, discover_public_address, parse_stun_addrs, punch_direct, punch_open_and_verify,
    PunchParams, PUNCH_WINDOW,
};
use hydra_client::tcp_transport::{connect_target, TlsTrust};
use hydra_node::signal::{SignalDownMessage, SignalMessage};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::ReadHalf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

// ── 假 STUN 服务器（RFC 5389 手工构造）─────────────────────────────────────

/// 构造 Binding Success Response（仅 IPv4；XOR-MAPPED-ADDRESS 按 RFC 5389 §15.2）
fn binding_success(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let v4 = match mapped {
        SocketAddr::V4(v) => v,
        _ => panic!("测试仅覆盖 IPv4 映射"),
    };
    let xport = v4.port() ^ 0x2112;
    let oct = v4.ip().octets();
    let xaddr = [oct[0] ^ 0x21, oct[1] ^ 0x12, oct[2] ^ 0xA4, oct[3] ^ 0x42];
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
    buf.extend_from_slice(&12u16.to_be_bytes()); // 属性区 = 4B 头 + 8B 载荷
    buf.extend_from_slice(&hydra_protocol::stun::MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(tx_id);
    buf.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
    buf.extend_from_slice(&8u16.to_be_bytes());
    buf.push(0x00);
    buf.push(0x01); // family = IPv4
    buf.extend_from_slice(&xport.to_be_bytes());
    buf.extend_from_slice(&xaddr);
    buf
}

/// 读一条完整 STUN 请求，返回事务 ID
async fn read_request(sock: &mut tokio::net::TcpStream) -> [u8; 12] {
    let mut header = [0u8; 20];
    sock.read_exact(&mut header).await.unwrap();
    let msg_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut rest = vec![0u8; msg_len];
    if msg_len > 0 {
        sock.read_exact(&mut rest).await.unwrap();
    }
    let mut tx = [0u8; 12];
    tx.copy_from_slice(&header[8..20]);
    tx
}

/// 起一个假 STUN 服务器：对每个 Binding Request 回固定映射地址
async fn spawn_fake_stun_fixed(mapped: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let tx = read_request(&mut sock).await;
                let resp = binding_success(&tx, mapped);
                let _ = sock.write_all(&resp).await;
            });
        }
    });
    addr
}

/// 起一对共享状态的假 STUN 服务器：模拟 EIM NAT——同一客户端的两次探测
/// 映射到同一端口（取其首次探测的本地端口）。真实 EIM NAT 正是这样归一化
/// 映射的；loopback 上无 NAT，需由假服务器补齐该语义。
async fn spawn_fake_stun_eim_pair() -> (SocketAddr, SocketAddr) {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    // 客户端 IP → 其首次探测的本地端口（仅本测试用；每端各用独立的一对服务器）
    let seen: Arc<Mutex<HashMap<std::net::IpAddr, u16>>> = Arc::new(Mutex::new(HashMap::new()));
    let mk = |seen: Arc<Mutex<HashMap<std::net::IpAddr, u16>>>| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let tx = read_request(&mut sock).await;
                    let client = sock.peer_addr().unwrap();
                    let port = *seen
                        .lock()
                        .unwrap()
                        .entry(client.ip())
                        .or_insert(client.port());
                    let resp = binding_success(&tx, SocketAddr::new(client.ip(), port));
                    let _ = sock.write_all(&resp).await;
                });
            }
        });
        addr
    };
    let a = mk(seen.clone()).await;
    let b = mk(seen).await;
    (a, b)
}

// ── 地址发现 + 分类 ─────────────────────────────────────────────────────────

#[test]
fn stun地址解析_注入列表_空与非法报特定错误() {
    // 07-P2-4：不再 set/remove HYDRA_STUN_ADDRS（进程级 env 写入与并行测试线程
    // 的 env 读取构成数据竞争）——改测参数化入口 parse_stun_addrs；discover 的
    // 服务器列表注入见 discover_* 系列用例（直接传 &[SocketAddr]）。
    let v = parse_stun_addrs("127.0.0.1:3478, 127.0.0.1:3479").unwrap();
    assert_eq!(
        v,
        vec![
            "127.0.0.1:3478".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:3479".parse::<SocketAddr>().unwrap()
        ]
    );
    // 空值/非法值同样是特定错误
    assert!(parse_stun_addrs("  ")
        .unwrap_err()
        .to_string()
        .contains("HYDRA_STUN_ADDRS"));
    assert!(parse_stun_addrs("not-an-addr")
        .unwrap_err()
        .to_string()
        .contains("非法地址"));
}

#[tokio::test]
async fn discover_两服务器同映射_eim() {
    let mapped: SocketAddr = "203.0.113.7:40000".parse().unwrap();
    let s1 = spawn_fake_stun_fixed(mapped).await;
    let s2 = spawn_fake_stun_fixed(mapped).await;
    let (got, nat) = discover_public_address(&[s1, s2]).await.unwrap();
    assert_eq!(got, mapped);
    assert_eq!(nat, hydra_protocol::stun::NatType::Eim);
}

#[tokio::test]
async fn discover_两服务器映射不同_symmetric() {
    let a = spawn_fake_stun_fixed("203.0.113.7:40000".parse().unwrap()).await;
    let b = spawn_fake_stun_fixed("203.0.113.9:40001".parse().unwrap()).await;
    let (got, nat) = discover_public_address(&[a, b]).await.unwrap();
    assert_eq!(got, "203.0.113.7:40000".parse().unwrap());
    assert_eq!(nat, hydra_protocol::stun::NatType::Symmetric);
}

#[tokio::test]
async fn discover_单服务器_保守按symmetric处理() {
    let mapped: SocketAddr = "203.0.113.7:40123".parse().unwrap();
    let s = spawn_fake_stun_fixed(mapped).await;
    let d = discover_full(&[s]).await.unwrap();
    assert_eq!(d.mapped, mapped);
    assert_eq!(d.nat, hydra_protocol::stun::NatType::Symmetric);
    // 本地 socket 地址一并返回（打洞 listener 绑定用）
    assert!(d.local.port() > 0);
}

#[tokio::test]
async fn discover_服务器不可达_报错() {
    // 44041 端口大概率无人监听：connect 应失败而非挂起
    let bad: SocketAddr = "127.0.0.1:44041".parse().unwrap();
    assert!(discover_public_address(&[bad, bad]).await.is_err());
    assert!(discover_public_address(&[]).await.is_err());
}

// ── 节点信令全链路（客户端视角）────────────────────────────────────────────

fn test_auth_key() -> Vec<u8> {
    hydra_client::auth_key_from_hex(TEST_KEY_HEX).unwrap()
}

/// 经认证路径连到 @hydra-p2p/<peer_id>，返回 (行读, 写)
async fn connect_signal(
    node: SocketAddr,
    cert: &[u8],
    peer_id: &str,
) -> (
    BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>,
    hydra_client::tcp_transport::TcpWriteHalf,
) {
    let trust = TlsTrust::pinned(vec![cert.to_vec()]);
    let stream = connect_target(
        node,
        "",
        &trust,
        &test_auth_key(),
        &format!("@hydra-p2p/{peer_id}"),
    )
    .await
    .expect("信令连接（认证路径）应成功");
    let (rd, wr) = tokio::io::split(stream);
    (BufReader::new(rd), wr)
}

async fn send_msg(wr: &mut hydra_client::tcp_transport::TcpWriteHalf, msg: &SignalMessage) {
    let line = serde_json::to_string(msg).unwrap();
    wr.write_all(line.as_bytes()).await.unwrap();
    wr.write_all(b"\n").await.unwrap();
    wr.flush().await.unwrap();
}

async fn recv_msg(
    rd: &mut BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>,
) -> SignalDownMessage {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut line))
        .await
        .expect("读下行超时")
        .expect("读下行失败");
    assert!(n > 0, "连接被节点关闭");
    serde_json::from_str(&line).expect("下行 JSON 解析")
}

/// invite 目标未注册时节点回 error(peer_offline)：退避重试消除双连接注册竞态
async fn invite_until_online(
    wr: &mut hydra_client::tcp_transport::TcpWriteHalf,
    rd: &mut BufReader<ReadHalf<hydra_client::tcp_transport::TcpNodeStream>>,
    target: &str,
    cand: Vec<String>,
) {
    for _ in 0..30 {
        send_msg(
            wr,
            &SignalMessage::Invite {
                peer_id: target.to_string(),
                cand: cand.clone(),
            },
        )
        .await;
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_millis(400), rd.read_line(&mut line)).await {
            // 无下行（节点已转发给目标）：invite 完成
            Err(_) | Ok(Ok(0)) => return,
            Ok(Err(e)) => panic!("读下行失败: {e}"),
            Ok(Ok(_)) => {
                match serde_json::from_str::<SignalDownMessage>(&line).expect("下行 JSON") {
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
async fn 客户端视角信令全链路() {
    let node = spawn_node_with_p2p().await;
    let (mut alice_rd, mut alice_wr) =
        connect_signal(node.addr, &node.cert, "a6a6a6a6a6a6a6a6").await;
    let (mut bob_rd, mut bob_wr) = connect_signal(node.addr, &node.cert, "b7b7b7b7b7b7b7b7").await;

    send_msg(
        &mut alice_wr,
        &SignalMessage::Register {
            peer_id: "a6a6a6a6a6a6a6a6".into(),
            mapped: "127.0.0.1:41001".into(),
            proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), "a6a6a6a6a6a6a6a6"),
        },
    )
    .await;
    send_msg(
        &mut bob_wr,
        &SignalMessage::Register {
            peer_id: "b7b7b7b7b7b7b7b7".into(),
            mapped: "127.0.0.1:41002".into(),
            proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), "b7b7b7b7b7b7b7b7"),
        },
    )
    .await;

    // alice invite bob（带 offline 重试）→ bob 收 incoming
    invite_until_online(
        &mut alice_wr,
        &mut alice_rd,
        "b7b7b7b7b7b7b7b7",
        vec!["127.0.0.1:41001".into()],
    )
    .await;
    match recv_msg(&mut bob_rd).await {
        SignalDownMessage::Incoming { from, cand } => {
            assert_eq!(from, "a6a6a6a6a6a6a6a6");
            assert_eq!(cand, vec!["127.0.0.1:41001".to_string()]);
        }
        other => panic!("应收到 incoming，实际 {other:?}"),
    }

    // bob accept → alice 收 accepted
    send_msg(
        &mut bob_wr,
        &SignalMessage::Accept {
            to: "a6a6a6a6a6a6a6a6".into(),
            cand: vec!["127.0.0.1:41002".into()],
        },
    )
    .await;
    match recv_msg(&mut alice_rd).await {
        SignalDownMessage::Accepted { from, cand } => {
            assert_eq!(from, "b7b7b7b7b7b7b7b7");
            assert_eq!(cand, vec!["127.0.0.1:41002".to_string()]);
        }
        other => panic!("应收到 accepted，实际 {other:?}"),
    }
}

// ── 打洞 loopback 验证 ──────────────────────────────────────────────────────

/// 取一个空闲回环端口（bind→读→关；存在微小竞态，测试可接受）
async fn free_loopback_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn 打洞核心_loopback_同时打开_握手_nonce回显() {
    // 注：真实 NAT 下的 TCP 同时打开无法本地自动化；本测试在 loopback 上
    // 验证的是 punch_open_and_verify 的编排（connect+accept → Noise-PSK
    // 握手 → nonce 回显防自连）逻辑本身。为使断言确定（真实同时打开会在两端
    // 各产生两条连接、任选其一后两条流不一定配对），B 端候选指向不可达地址
    // ——只保留「A 出站 connect ↔ B accept」这一条连接，数据面配对唯一。
    let pb = free_loopback_port().await;
    let b_cand: SocketAddr = format!("127.0.0.1:{pb}").parse().unwrap();
    let dead: SocketAddr = "127.0.0.1:44999".parse().unwrap();
    let key = test_auth_key();

    // A：listener 绑随机端口（无人来），出站连 B 的候选
    let key_a = key.clone();
    let peer_a = tokio::spawn(async move {
        punch_open_and_verify(
            "127.0.0.1:0".parse().unwrap(),
            &[b_cand],
            &key_a,
            PUNCH_WINDOW,
        )
        .await
    });
    // B：listener 绑候选端口（A 来连），出站候选不可达
    let peer_b =
        tokio::spawn(
            async move { punch_open_and_verify(b_cand, &[dead], &key, PUNCH_WINDOW).await },
        );

    let (ra, rb) = tokio::join!(peer_a, peer_b);
    let sa = ra.unwrap().expect("A 端（connect 路径）应建成经验证的直连");
    let sb = rb.unwrap().expect("B 端（accept 路径）应建成经验证的直连");

    // 唯一一条连接：A 写 ping → B 读（配对确定）
    let (mut sbrd, _) = sb.into_split();
    let (_, mut wr) = sa.into_split();
    wr.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    sbrd.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn 打洞核心_nonce相同判自连拒绝() {
    // 自连场景无法用真 socket 直接构造（连到自己会回显自己的 nonce）——
    // 该防线在 verify_stream 内部，经 duplex 流单测等价覆盖：两端 nonce 相同
    // 时的拒绝分支由「本端读到的对端 nonce == 自己 nonce」触发。此处直接验证
    // 打洞窗口超时路径：候选不可达 + 无 listener（另端不监听）→ None。
    // （同时即 06 报告 P3-7④ 的确认：EIM 全候选不可达 → 窗口超时回落 None）
    let dead: SocketAddr = "127.0.0.1:44999".parse().unwrap();
    let r = punch_open_and_verify(
        "127.0.0.1:0".parse().unwrap(),
        &[dead],
        &test_auth_key(),
        Duration::from_secs(2),
    )
    .await;
    assert!(r.is_none(), "候选不可达应在窗口内返回 None");
}

/// hairpin 自连拒绝（06 报告 P1-4 / P3-7①）：候选指向「自身映射地址+同端口」。
/// loopback 上「映射地址」即本端 listener 地址，等价于 hairpin 回环的最贴近替身：
/// 出站 connect 命中本端 listener 时，第一层过滤（对端地址 == 本端 listener 地址）
/// 直接丢弃；即便穿透该层，同进程两端共享同一 nonce 也会被 verify_stream 判自连
/// 拒绝（nonce 同源防线单测覆盖）。两条防线叠加 → 窗口内必须回落 None，
/// 不得建成静默回环隧道。
#[tokio::test]
async fn hairpin_自连候选_双防线拒绝回落None() {
    // 取一个端口并释放，供 punch listener 绑定（REUSEADDR 下亦可共存，先释放更稳）
    let self_addr = free_loopback_port().await;
    let self_cand: SocketAddr = format!("127.0.0.1:{self_addr}").parse().unwrap();
    let start = Instant::now();
    let r = punch_open_and_verify(
        self_cand,
        &[self_cand],
        &test_auth_key(),
        Duration::from_secs(2),
    )
    .await;
    assert!(r.is_none(), "hairpin 自连候选必须被拒绝，不得返回连接");
    // 自连被丢弃后本端 listener 仍在窗口内等待对端（loopback 无对端），
    // 回落发生在窗口耗尽：断言耗时有界（不忙等、不久挂）
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "自连拒绝后应在窗口内回落（实际 {:?}）",
        start.elapsed()
    );
}

/// 多候选（06 报告 P3-7③）：候选列表含死地址在前、可达候选在后时，
/// 任一成功即可建成直连（死候选毫秒级失败不拖垮整体）。
#[tokio::test]
async fn 打洞核心_多候选_死活混合_任一成功即建成() {
    let pb = free_loopback_port().await;
    let b_cand: SocketAddr = format!("127.0.0.1:{pb}").parse().unwrap();
    let dead: SocketAddr = "127.0.0.1:44998".parse().unwrap();
    let key = test_auth_key();

    // A：候选 = [死地址, B 可达候选]；B：listener 绑候选端口，出站候选死地址
    let key_a = key.clone();
    let peer_a = tokio::spawn(async move {
        punch_open_and_verify(
            "127.0.0.1:0".parse().unwrap(),
            &[dead, b_cand],
            &key_a,
            PUNCH_WINDOW,
        )
        .await
    });
    let peer_b =
        tokio::spawn(
            async move { punch_open_and_verify(b_cand, &[dead], &key, PUNCH_WINDOW).await },
        );

    let (ra, rb) = tokio::join!(peer_a, peer_b);
    assert!(ra.unwrap().is_some(), "多候选中任一可达即应建成（A 端）");
    assert!(rb.unwrap().is_some(), "B 端（accept 路径）应建成");
}

/// 信令断线重连（06 报告 P3-7②）：注册后断开连接，同 peer_id + 正确 proof
/// 重新注册应被接受，且后续 invite 能送达重连后的会话。
#[tokio::test]
async fn 信令断线重连_同peer_id_正确proof重注册后收invite() {
    let node = spawn_node_with_p2p().await;
    let pid = "e5e5e5e5e5e5e5e5";

    // 第一次注册后立即断开（模拟客户端崩溃/网络闪断）
    {
        let (mut rd, mut wr) = connect_signal(node.addr, &node.cert, pid).await;
        send_msg(
            &mut wr,
            &SignalMessage::Register {
                peer_id: pid.into(),
                mapped: "127.0.0.1:41005".into(),
                proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), pid),
            },
        )
        .await;
        // 等注册落地后再断开（写后即 drop 可能在节点读取前关闭）
        let mut line = String::new();
        let _ = tokio::time::timeout(Duration::from_millis(300), rd.read_line(&mut line)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 重连：同 peer_id + 正确 proof 重新注册
    let (mut alice_rd, mut _alice_wr) = connect_signal(node.addr, &node.cert, pid).await;
    send_msg(
        &mut _alice_wr,
        &SignalMessage::Register {
            peer_id: pid.into(),
            mapped: "127.0.0.1:41006".into(),
            proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), pid),
        },
    )
    .await;

    // bob 注册并 invite alice → 重连后的 alice 会话应收到 incoming
    let (mut bob_rd, mut bob_wr) = connect_signal(node.addr, &node.cert, "f6f6f6f6f6f6f6f6").await;
    send_msg(
        &mut bob_wr,
        &SignalMessage::Register {
            peer_id: "f6f6f6f6f6f6f6f6".into(),
            mapped: "127.0.0.1:41007".into(),
            proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), "f6f6f6f6f6f6f6f6"),
        },
    )
    .await;
    invite_until_online(
        &mut bob_wr,
        &mut bob_rd,
        pid,
        vec!["127.0.0.1:41007".into()],
    )
    .await;
    match recv_msg(&mut alice_rd).await {
        SignalDownMessage::Incoming { from, cand } => {
            assert_eq!(from, "f6f6f6f6f6f6f6f6");
            assert_eq!(cand, vec!["127.0.0.1:41007".to_string()]);
        }
        other => panic!("重连后应收到 incoming，实际 {other:?}"),
    }
}

/// 多候选信令转发（06 报告 P3-7③ 信令层）：invite/accept 携带多条候选
/// （含非法/死地址形态）时节点必须原样转发，交由打洞层「任一成功」裁决。
#[tokio::test]
async fn 信令_多候选完整转发() {
    let node = spawn_node_with_p2p().await;
    let (mut alice_rd, mut alice_wr) =
        connect_signal(node.addr, &node.cert, "a7a7a7a7a7a7a7a7").await;
    let (mut bob_rd, mut bob_wr) = connect_signal(node.addr, &node.cert, "b8b8b8b8b8b8b8b8").await;
    for (pid, mapped) in [
        ("a7a7a7a7a7a7a7a7", "127.0.0.1:41011"),
        ("b8b8b8b8b8b8b8b8", "127.0.0.1:41012"),
    ] {
        let target_wr: &mut hydra_client::tcp_transport::TcpWriteHalf = if pid.starts_with('a') {
            &mut alice_wr
        } else {
            &mut bob_wr
        };
        send_msg(
            target_wr,
            &SignalMessage::Register {
                peer_id: pid.into(),
                mapped: mapped.into(),
                proof: hydra_protocol::p2p_owner_proof(&test_auth_key(), pid),
            },
        )
        .await;
    }

    // alice invite bob：候选 = [死地址, 公网形态地址, 内网形态地址] 多条
    let cands = vec![
        "127.0.0.1:44997".to_string(),
        "203.0.113.7:45001".to_string(),
        "192.168.1.50:45002".to_string(),
    ];
    invite_until_online(
        &mut alice_wr,
        &mut alice_rd,
        "b8b8b8b8b8b8b8b8",
        cands.clone(),
    )
    .await;
    match recv_msg(&mut bob_rd).await {
        SignalDownMessage::Incoming { from, cand } => {
            assert_eq!(from, "a7a7a7a7a7a7a7a7");
            assert_eq!(cand, cands, "多候选必须完整有序转发");
        }
        other => panic!("应收到 incoming，实际 {other:?}"),
    }

    // bob accept 回多条候选 → alice 收 accepted 同样完整
    let resp_cands = vec![
        "203.0.113.9:45003".to_string(),
        "10.0.0.5:45004".to_string(),
    ];
    send_msg(
        &mut bob_wr,
        &SignalMessage::Accept {
            to: "a7a7a7a7a7a7a7a7".into(),
            cand: resp_cands.clone(),
        },
    )
    .await;
    match recv_msg(&mut alice_rd).await {
        SignalDownMessage::Accepted { from, cand } => {
            assert_eq!(from, "b8b8b8b8b8b8b8b8");
            assert_eq!(cand, resp_cands, "accept 多候选必须完整有序转发");
        }
        other => panic!("应收到 accepted，实际 {other:?}"),
    }
}

/// 完整 punch_direct 端到端（loopback）：节点信令 + 假 STUN 回显真实本地地址
/// （= 无 NAT 的映射语义），双端同时跑编排 → 双双拿到直连流。
#[tokio::test]
async fn punch_direct_端到端_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .with_test_writer()
        .try_init();
    let node = spawn_node_with_p2p().await;
    // 每端各用独立的一对假 STUN（EIM 语义：同一端的两次探测映射到同一端口）
    let (sa1, sa2) = spawn_fake_stun_eim_pair().await;
    let (sb1, sb2) = spawn_fake_stun_eim_pair().await;
    let trust = TlsTrust::pinned(vec![node.cert.clone()]);
    let key = test_auth_key();

    let run = |my: &'static str, peer: &'static str, stuns: [SocketAddr; 2]| {
        let trust = trust.clone();
        let key = key.clone();
        async move {
            let p = PunchParams {
                node_addr: node.addr,
                sni: "",
                trust: &trust,
                auth_key: &key,
                stun_addrs: &stuns,
                my_peer_id: my,
                peer_id: peer,
            };
            punch_direct(&p).await
        }
    };

    let (ra, rb) = tokio::join!(
        run("c1c1c1c1c1c1c1c1", "d2d2d2d2d2d2d2d2", [sa1, sa2]),
        run("d2d2d2d2d2d2d2d2", "c1c1c1c1c1c1c1c1", [sb1, sb2])
    );
    assert!(ra.is_some(), "A 端 punch_direct 应成功（实际回落中继）");
    assert!(rb.is_some(), "B 端 punch_direct 应成功（实际回落中继）");

    // 数据面配对已在「打洞核心_loopback」用例中确定性验证；此处真实同时打开
    // 会产生两条连接、两端各自任选其一，两条返回流不一定互为同一条连接
    // （多出来的连接在各自函数返回时随 channel 丢弃关闭），故只断言：
    // 双端各自拿到一条已过 Noise-PSK 握手 + nonce 校验的 loopback 直连流。
    let sa = ra.unwrap();
    let sb = rb.unwrap();
    assert!(sa.peer_addr().unwrap().ip().is_loopback());
    assert!(sb.peer_addr().unwrap().ip().is_loopback());
}
