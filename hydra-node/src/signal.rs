//! P2P 信令会话（NAT 穿透方案 §3.2）：注册表状态机（纯逻辑，可单测）+
//! 异步路由（JSON 行协议，跨连接转发 invite/accept）。
//!
//! 复用既有认证：只有通过 Noise-PSK 握手的连接才能进入信令模式（tcp_server
//! 按 `@hydra-p2p/<peer_id>` 保留前缀分流）。信令内容仅 peer_id 与候选地址。
//!
//! 线缆格式：一行一条 JSON（'\n' 分隔）：
//! - 客户端→节点：`{"op":"register","peer_id":..,"mapped":"ip:port"}` /
//!   `{"op":"invite","peer_id":<目标>,"cand":[..]}` /
//!   `{"op":"accept","to":<A_id>,"cand":[..]}`
//! - 节点→客户端：`{"op":"incoming","from":<A_id>,"cand":[..]}` /
//!   `{"op":"accepted","from":<B_id>,"cand":[..]}` / `{"op":"error","code":..}`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// 注册表容量上限（防滥用；方案 §3.2：注册表 ≤1024）
pub const MAX_PEERS: usize = 1024;
/// 信令会话读超时（客户端靠 register 心跳续期；无数据达此时长即断开）
pub const SIGNAL_READ_TIMEOUT: Duration = Duration::from_secs(90);
/// 单行 JSON 长度上限（超长断开，防资源耗尽）
const MAX_LINE_LEN: usize = 4096;
/// 每 peer 下行队列深度（跨连接投递用；满即丢弃并警告——信令量极小，满=对端卡死）
const DOWNLINK_CAP: usize = 32;
/// 每连接信令速率（条/秒，令牌桶回填速率）与桶容量（突发上限）。
/// 心跳 60s 一条 + 打洞期数条，10/s 余量充足；超限 = 慢滴滥用，断开。
pub const SIGNAL_RATE: u32 = 10;
pub const SIGNAL_BURST: u32 = 20;

// ── 消息定义（serde，tag = "op"）────────────────────────────────────────────

/// 客户端 → 节点 消息（未知 op 反序列化即拒绝 → 断开）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op")]
pub enum SignalMessage {
    /// 注册/心跳续期（60s 周期；peer_id 与地址帧中的会话身份一致才被接受）。
    /// `proof` = peer_id 属主证明（hydra_protocol::auth::p2p_owner_proof，
    /// PSK 派生，双方天然可验）：同 peer_id 二次注册必须携带相同 proof，
    /// 否则按"重注册顶替"攻击拒绝。
    #[serde(rename = "register")]
    Register {
        peer_id: String,
        mapped: String,
        proof: String,
    },
    /// A 请求连 B：节点转发为 incoming 给 B
    #[serde(rename = "invite")]
    Invite { peer_id: String, cand: Vec<String> },
    /// B 应答 A：节点转发为 accepted 给 A
    #[serde(rename = "accept")]
    Accept { to: String, cand: Vec<String> },
}

/// 节点 → 客户端 消息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op")]
pub enum SignalDownMessage {
    /// 收到对端连接请求（from = 发起方 inviter peer_id）
    #[serde(rename = "incoming")]
    Incoming { from: String, cand: Vec<String> },
    /// 对端接受了本端的邀请（from = 应答方 peer_id）
    #[serde(rename = "accepted")]
    Accepted { from: String, cand: Vec<String> },
    /// 错误（目标离线等）
    #[serde(rename = "error")]
    Error { code: String, peer: Option<String> },
}

// ── 注册表（纯逻辑状态机）──────────────────────────────────────────────────

/// 单条注册项：映射地址 + 最后活跃时刻 + 该连接的下行投递端 + 属主证明
pub struct PeerEntry {
    pub mapped: SocketAddr,
    pub last_active: Instant,
    pub downlink: mpsc::Sender<Vec<u8>>,
    /// peer_id 属主证明（注册时校验通过后记录；二次注册必须一致）
    pub owner_proof: String,
}

/// 信令注册表：peer_id → 会话项（外层 Arc，内层 Mutex；同步方法不做 IO）
pub struct SignalRegistry {
    peers: std::sync::Mutex<HashMap<String, PeerEntry>>,
}

impl SignalRegistry {
    pub fn new() -> Self {
        Self {
            peers: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 注册/刷新（upsert）。重复注册同一 peer_id = 心跳/地址更新（覆盖旧连接的
    /// 下行端——旧连接写端随之作废，由其读循环自行退出）；**属主证明不一致的
    /// 二次注册被拒绝**（防重注册顶替：冒用者与真实属主的 proof 必不同——
    /// 真实 proof 由 PSK HMAC 派生，PSK 之外的持有者无法伪造）。表满返回 Err。
    pub fn register(
        &self,
        peer_id: &str,
        mapped: SocketAddr,
        owner_proof: &str,
        now: Instant,
        downlink: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), String> {
        let mut peers = self.peers.lock().unwrap();
        if let Some(existing) = peers.get(peer_id) {
            if existing.owner_proof != owner_proof {
                return Err("owner_proof_mismatch（peer_id 属主证明不一致，疑似顶替）".to_string());
            }
        } else if peers.len() >= MAX_PEERS {
            return Err(format!("注册表已满（上限 {MAX_PEERS}）"));
        }
        peers.insert(
            peer_id.to_string(),
            PeerEntry {
                mapped,
                last_active: now,
                downlink,
                owner_proof: owner_proof.to_string(),
            },
        );
        Ok(())
    }

    /// 移除注册（仅当当前条目仍归属本连接的下行端时才删——防止新连接的
    /// 重新注册被旧连接的清理误删）
    pub fn remove_if_downlink(&self, peer_id: &str, downlink: &mpsc::Sender<Vec<u8>>) {
        let mut peers = self.peers.lock().unwrap();
        if peers
            .get(peer_id)
            .map(|e| e.downlink.same_channel(downlink))
            .unwrap_or(false)
        {
            peers.remove(peer_id);
        }
    }

    /// 刷新最后活跃时刻（心跳）
    pub fn touch(&self, peer_id: &str, now: Instant) {
        if let Some(e) = self.peers.lock().unwrap().get_mut(peer_id) {
            e.last_active = now;
        }
    }

    /// 摘除超时条目（返回摘除的 peer_id 列表，供日志）
    pub fn sweep(&self, now: Instant, ttl: Duration) -> Vec<String> {
        let mut peers = self.peers.lock().unwrap();
        let expired: Vec<String> = peers
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_active) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            peers.remove(k);
        }
        expired
    }

    /// 查询（投递 invite/accept 时用）
    pub fn get(&self, peer_id: &str) -> Option<(SocketAddr, mpsc::Sender<Vec<u8>>)> {
        let peers = self.peers.lock().unwrap();
        peers
            .get(peer_id)
            .map(|e| (e.mapped, e.downlink.clone()))
    }

    /// 当前注册数（测试/监控用）
    pub fn len(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SignalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── 异步路由（每信令连接一个任务）──────────────────────────────────────────

/// 服务一条信令会话：循环读 JSON 行 → 处理 → 跨连接投递下行消息。
///
/// - `my_peer_id`：地址帧 `@hydra-p2p/<peer_id>` 解析出的本连接身份；
///   register 消息的 peer_id 必须与其一致（身份由地址帧一次性确定，防混淆）。
/// - `auth_key`：节点 PSK——register 的属主 proof 由它 HMAC 派生，节点独立复算
///   校验（评审-专家团队：信令 peer_id 属主；伪造 proof 无法通过）。
/// - 跨连接投递：本连接的下行端 mpsc 与写任务（[`downlink_writer`]）相连，
///   其他连接处理 invite/accept 时经 registry 取 sender 投递。
/// - 读超时 90s 覆盖空闲（客户端 register 心跳续期）；单行 >4096B 断开。
pub async fn serve_signal_stream<R, W>(
    registry: Arc<SignalRegistry>,
    my_peer_id: String,
    auth_key: Vec<u8>,
    mut rd: R,
    wr: W,
) where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // 下行队列 + 写任务：把其他连接投递来的序列化 JSON 行写回本连接
    let (tx, rx) = mpsc::channel::<Vec<u8>>(DOWNLINK_CAP);
    let writer = tokio::spawn(downlink_writer(wr, rx, my_peer_id.clone()));

    let mut line_buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    // 每连接消息速率限制（安全分报告 P3-2 慢滴防护）：令牌桶——桶容量
    // SIGNAL_BURST，每秒回填 SIGNAL_RATE 个。超过即断开（信令量极小：
    // 心跳 60s 一条 + 打洞握手期几条，正常流量远低于此）。
    let mut tokens: u32 = SIGNAL_BURST;
    let mut last_refill = Instant::now();
    loop {
        // 逐字节读行（信令量极小；天然解决「行中间跨包」与长度上限）
        // 读超时 = 空闲看门狗：90s 无任何数据（含心跳）即断开
        let n = match tokio::time::timeout(SIGNAL_READ_TIMEOUT, rd.read(&mut byte)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("信令会话 {my_peer_id} 读错误: {e}");
                break;
            }
            Err(_) => {
                debug!("信令会话 {my_peer_id} 读超时（{}s），断开", SIGNAL_READ_TIMEOUT.as_secs());
                break;
            }
        };
        if n == 0 {
            debug!("信令会话 {my_peer_id} 客户端关闭");
            break;
        }
        if byte[0] == b'\n' {
            // 速率限制（按完整行计）：回填后无令牌 → 慢滴/滥用，断开
            let elapsed = last_refill.elapsed().as_secs_f64();
            last_refill = Instant::now();
            tokens = refill_tokens(tokens, elapsed);
            if tokens == 0 {
                warn!("信令会话 {my_peer_id} 消息速率超限（>{SIGNAL_RATE}/s），断开");
                break;
            }
            tokens -= 1;
            // 一行完整：处理（消息处理顺带 sweep 超时条目，免定时任务）
            let line = std::mem::take(&mut line_buf);
            let expired = registry.sweep(Instant::now(), SIGNAL_READ_TIMEOUT);
            if !expired.is_empty() {
                info!("信令注册表摘除超时条目: {} 个", expired.len());
            }
            if handle_line(&registry, &my_peer_id, &auth_key, &line, &tx).await.is_err() {
                break; // 协议错误（JSON 失败/未知 op/行超长）→ 断开
            }
            continue;
        }
        line_buf.push(byte[0]);
        if line_buf.len() > MAX_LINE_LEN {
            warn!("信令会话 {my_peer_id} 单行超 {}B，断开", MAX_LINE_LEN);
            break;
        }
    }

    // 结束：先从注册表摘除本连接条目（释放 registry 持有的下行端），再关闭本端，
    // 等写任务把积压消息（如错误回执）写完再关流——直接 abort 会丢掉已入队
    // 未写出的下行消息；若 peer 已被新连接顶替（channel 仍开放），限时兜底退出
    registry.remove_if_downlink(&my_peer_id, &tx);
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
}

/// 处理一行 JSON。返回 Err = 协议错误（断开会话）。
async fn handle_line(
    registry: &SignalRegistry,
    my_peer_id: &str,
    auth_key: &[u8],
    line: &[u8],
    my_downlink: &mpsc::Sender<Vec<u8>>,
) -> Result<(), ()> {
    if line.is_empty() {
        return Ok(()); // 空行忽略（容忍客户端多敲换行）
    }
    let msg: SignalMessage = serde_json::from_slice(line).map_err(|e| {
        debug!("信令 JSON 解析失败: {e}");
    })?;
    let now = Instant::now();
    match msg {
        SignalMessage::Register { peer_id, mapped, proof } => {
            if peer_id != my_peer_id {
                // 身份由地址帧决定：消息体 peer_id 不一致 = 协议错误
                send_error(my_downlink, "peer_id_mismatch", Some(&peer_id)).await;
                return Err(());
            }
            // 属主证明（评审-专家团队-安全与协议）：节点用 PSK 独立复算校验，
            // 伪造/空缺 proof 直接拒绝——防止已认证连接冒用他人 peer_id 抢注。
            if !hydra_protocol::verify_p2p_owner_proof(auth_key, my_peer_id, &proof) {
                warn!("信令注册属主证明校验失败（{}），拒绝", mask_peer_id(my_peer_id));
                send_error(my_downlink, "owner_proof_invalid", Some(my_peer_id)).await;
                return Err(());
            }
            let mapped_addr: SocketAddr = mapped.parse().map_err(|_| ())?;
            if let Err(e) = registry.register(my_peer_id, mapped_addr, &proof, now, my_downlink.clone())
            {
                send_error(my_downlink, &e, None).await;
                return Err(());
            }
            debug!("信令注册: {} @ {mapped_addr}", mask_peer_id(my_peer_id));
        }
        SignalMessage::Invite { peer_id, cand } => {
            registry.touch(my_peer_id, now);
            let down = {
                let (_, down) = match registry.get(&peer_id) {
                    Some(x) => x,
                    None => {
                        debug!("invite 目标 {peer_id} 不在线");
                        send_error(my_downlink, "peer_offline", Some(&peer_id)).await;
                        return Ok(());
                    }
                };
                down
            };
            let out = SignalDownMessage::Incoming {
                from: my_peer_id.to_string(),
                cand,
            };
            if forward(&down, &out).await.is_err() {
                // 目标下行队列满/写端关闭：视作离线
                send_error(my_downlink, "peer_offline", Some(&peer_id)).await;
            }
        }
        SignalMessage::Accept { to, cand } => {
            registry.touch(my_peer_id, now);
            let down = match registry.get(&to) {
                Some((_, d)) => d,
                None => {
                    send_error(my_downlink, "peer_offline", Some(&to)).await;
                    return Ok(());
                }
            };
            let out = SignalDownMessage::Accepted {
                from: my_peer_id.to_string(),
                cand,
            };
            if forward(&down, &out).await.is_err() {
                send_error(my_downlink, "peer_offline", Some(&to)).await;
            }
        }
    }
    Ok(())
}

/// peer_id 日志脱敏：仅保留尾 4 字符（与 mask_target 同纪律）
fn mask_peer_id(id: &str) -> String {
    if id.len() > 4 {
        format!("…{}", &id[id.len() - 4..])
    } else {
        id.to_string()
    }
}

/// 令牌桶回填（纯函数）：按流逝秒数回填 `SIGNAL_RATE`，封顶 `SIGNAL_BURST`。
/// 单测覆盖：满桶不溢出、长时间流逝仍封顶、逐秒消耗后回填。
fn refill_tokens(tokens: u32, elapsed_secs: f64) -> u32 {
    ((tokens as f64 + elapsed_secs * SIGNAL_RATE as f64) as u32).min(SIGNAL_BURST)
}

/// 序列化下行消息为 JSON 行并投递（追加 '\n'）
async fn forward(down: &mpsc::Sender<Vec<u8>>, msg: &SignalDownMessage) -> Result<(), ()> {
    let mut line = serde_json::to_vec(msg).map_err(|_| ())?;
    line.push(b'\n');
    down.send(line).await.map_err(|_| ())
}

/// 回错误消息给本连接
async fn send_error(down: &mpsc::Sender<Vec<u8>>, code: &str, peer: Option<&str>) {
    let _ = forward(
        down,
        &SignalDownMessage::Error {
            code: code.to_string(),
            peer: peer.map(|s| s.to_string()),
        },
    )
    .await;
}

/// 下行写任务：持续把队列里的 JSON 行写回本连接（队列关闭/写失败即退出）
async fn downlink_writer<W: AsyncWrite + Unpin + Send + 'static>(
    mut wr: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    peer_id: String,
) {
    while let Some(line) = rx.recv().await {
        if wr.write_all(&line).await.is_err() {
            debug!("信令会话 {peer_id} 下行写失败，写任务退出");
            break;
        }
        let _ = wr.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 PSK（Noise-PSK 恰 32 字节）
    fn test_key() -> Vec<u8> {
        vec![7u8; 32]
    }

    #[test]
    fn 令牌桶_回填封顶_与逐秒消耗() {
        // 满桶 + 长时间流逝：封顶不溢出
        assert_eq!(refill_tokens(SIGNAL_BURST, 3600.0), SIGNAL_BURST);
        // 满桶 + 极短流逝：仍封顶
        assert_eq!(refill_tokens(SIGNAL_BURST, 0.1), SIGNAL_BURST);
        // 消耗到 0 后 1 秒：回填 SIGNAL_RATE
        assert_eq!(refill_tokens(0, 1.0), SIGNAL_RATE);
        // 半秒：回填一半（向下取整）
        assert_eq!(refill_tokens(0, 0.5), SIGNAL_RATE / 2);
    }

    fn helper(v: &serde_json::Value) -> String {
        v.to_string()
    }

    #[test]
    fn 消息序列化往返() {
        // 上行
        let up = SignalMessage::Register {
            peer_id: "abcd1234".into(),
            mapped: "203.0.113.7:40000".into(),
            proof: hydra_protocol::p2p_owner_proof(&test_key(), "abcd1234"),
        };
        let line = helper(&serde_json::to_value(&up).unwrap());
        assert!(line.contains("\"op\":\"register\""), "含 op 字段: {line}");
        assert_eq!(serde_json::from_str::<SignalMessage>(&line).unwrap(), up);

        let invite = SignalMessage::Invite {
            peer_id: "b".into(),
            cand: vec!["1.2.3.4:5".into()],
        };
        let line = serde_json::to_string(&invite).unwrap();
        assert_eq!(serde_json::from_str::<SignalMessage>(&line).unwrap(), invite);

        let accept = SignalMessage::Accept {
            to: "a".into(),
            cand: vec![],
        };
        let line = serde_json::to_string(&accept).unwrap();
        assert_eq!(serde_json::from_str::<SignalMessage>(&line).unwrap(), accept);

        // 下行
        let incoming = SignalDownMessage::Incoming {
            from: "alice".into(),
            cand: vec!["203.0.113.1:1".into()],
        };
        let line = serde_json::to_string(&incoming).unwrap();
        assert!(line.contains("\"op\":\"incoming\""));
        assert_eq!(
            serde_json::from_str::<SignalDownMessage>(&line).unwrap(),
            incoming
        );
    }

    #[test]
    fn 未知op拒绝() {
        let err = serde_json::from_str::<SignalMessage>(r#"{"op":"hack","peer_id":"x"}"#);
        assert!(err.is_err(), "未知 op 应被拒绝");
        // 缺字段同样拒绝
        assert!(serde_json::from_str::<SignalMessage>(r#"{"op":"register"}"#).is_err());
    }

    #[test]
    fn registry_注册_上限_重复_摘除() {
        let reg = SignalRegistry::new();
        let now = Instant::now();
        let (tx, _rx) = mpsc::channel(8);
        let proof = hydra_protocol::p2p_owner_proof(&test_key(), "a");

        // 正常注册 + touch（touch 到近期时刻：距 sweep 检查点仅 50s < ttl）
        reg.register("a", "1.1.1.1:1".parse().unwrap(), &proof, now, tx.clone()).unwrap();
        assert_eq!(reg.len(), 1);
        reg.touch("a", now + Duration::from_secs(150));
        assert_eq!(reg.get("a").unwrap().0, "1.1.1.1:1".parse().unwrap());

        // 重复注册（upsert）：同 proof 心跳/地址更新，不占新额度，覆盖旧值
        reg.register("a", "2.2.2.2:2".parse().unwrap(), &proof, now + Duration::from_secs(150), tx.clone()).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get("a").unwrap().0, "2.2.2.2:2".parse().unwrap());

        // 冒用顶替（Wave1-7 核心）：同 peer_id、不同 proof 的二次注册必须被拒，
        // 且原注册不被顶替
        let forged = hydra_protocol::p2p_owner_proof(&[9u8; 32], "a");
        assert!(reg.register("a", "6.6.6.6:6".parse().unwrap(), &forged, now, tx.clone()).is_err());
        assert_eq!(reg.get("a").unwrap().0, "2.2.2.2:2".parse().unwrap());

        // 上限：注册到 MAX_PEERS 后拒绝新 peer
        for i in 1..MAX_PEERS {
            reg.register(&format!("p{i}"), "3.3.3.3:3".parse().unwrap(), &hydra_protocol::p2p_owner_proof(&test_key(), &format!("p{i}")), now, tx.clone())
                .unwrap();
        }
        assert_eq!(reg.len(), MAX_PEERS);
        assert!(reg.register("overflow", "3.3.3.3:3".parse().unwrap(), "p", now, tx.clone()).is_err());

        // 超时摘除：a 的 last_active 在 ttl 内（刚 touch），p1 已超时
        let later = now + Duration::from_secs(200);
        let expired = reg.sweep(later, Duration::from_secs(120));
        assert!(expired.contains(&"p1".to_string()));
        assert!(!expired.contains(&"a".to_string()), "刚 touch 的不应被摘除");
        assert!(reg.get("p1").is_none());
        assert!(reg.get("a").is_some());
    }

    /// 冒用顶替端到端（Wave1-7）：同一 peer_id 的两条"连接"，
    /// 伪造 proof 的注册被拒（owner_proof_invalid → 会话断开），真实 proof 注册不受影响。
    #[tokio::test]
    async fn 冒用顶替_伪造proof注册被拒() {
        use tokio::io::AsyncBufReadExt;

        let reg = Arc::new(SignalRegistry::new());
        let key = test_key();

        let (client, server) = tokio::io::duplex(4096);
        let (s_rd, s_wr) = tokio::io::split(server);
        tokio::spawn(serve_signal_stream(
            reg.clone(),
            "aaaa".to_string(),
            key.clone(),
            s_rd,
            s_wr,
        ));
        let (c_rd, mut c_wr) = tokio::io::split(client);

        // 正确 proof：注册成功
        let ok = SignalMessage::Register {
            peer_id: "aaaa".into(),
            mapped: "1.1.1.1:1".into(),
            proof: hydra_protocol::p2p_owner_proof(&key, "aaaa"),
        };
        c_wr.write_all(serde_json::to_string(&ok).unwrap().as_bytes()).await.unwrap();
        c_wr.write_all(b"\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(reg.len(), 1, "正确 proof 应注册成功");

        // 同进程内模拟"另一条连接"冒用同 peer_id + 伪造 proof：被 registry 顶层
        // owner_proof_mismatch 拒绝（节点 HMAC 校验已在 serve 路径覆盖）
        let (tx_forged, _rx_forged) = mpsc::channel(8);
        let forged = hydra_protocol::p2p_owner_proof(&[9u8; 32], "aaaa");
        assert!(reg
            .register("aaaa", "6.6.6.6:6".parse().unwrap(), &forged, Instant::now(), tx_forged)
            .is_err(), "伪造 proof 的顶替注册必须被拒");

        // 错误 proof 走 serve 路径：节点直接断开会话（handle_line Err）
        let (client2, server2) = tokio::io::duplex(4096);
        let (s_rd2, s_wr2) = tokio::io::split(server2);
        tokio::spawn(serve_signal_stream(
            reg.clone(),
            "bbbb".to_string(),
            key.clone(),
            s_rd2,
            s_wr2,
        ));
        let (d_rd, mut d_wr) = tokio::io::split(client2);
        let mut d_rd = tokio::io::BufReader::new(d_rd);
        let bad = SignalMessage::Register {
            peer_id: "bbbb".into(),
            mapped: "1.1.1.1:2".into(),
            proof: hydra_protocol::p2p_owner_proof(&[1u8; 32], "bbbb"),
        };
        d_wr.write_all(serde_json::to_string(&bad).unwrap().as_bytes()).await.unwrap();
        d_wr.write_all(b"\n").await.unwrap();
        // 节点应回 error(owner_proof_invalid) 后断开
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), d_rd.read_line(&mut line))
            .await
            .expect("等 error 回执超时")
            .expect("读失败");
        assert!(n > 0, "应收到错误回执");
        let msg: SignalDownMessage = serde_json::from_str(&line).unwrap();
        match msg {
            SignalDownMessage::Error { code, .. } => {
                assert_eq!(code, "owner_proof_invalid");
            }
            other => panic!("应收到 error(owner_proof_invalid)，实际 {other:?}"),
        }
        // 会话被断开：注册表无 bbbb
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(reg.get("bbbb").is_none(), "伪造 proof 的会话不得留下注册");
        // 原属主注册不受顶替影响
        assert!(reg.get("aaaa").is_some());

        let _ = c_rd; // 读端未用
    }

    #[test]
    fn registry_remove_仅删本连接条目() {
        let reg = SignalRegistry::new();
        let now = Instant::now();
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        let proof = hydra_protocol::p2p_owner_proof(&test_key(), "a");
        reg.register("a", "1.1.1.1:1".parse().unwrap(), &proof, now, tx1.clone()).unwrap();
        // 新连接重新注册（同 proof 合法顶替 = 地址/下行端更新）
        reg.register("a", "1.1.1.1:1".parse().unwrap(), &proof, now, tx2.clone()).unwrap();
        // 旧连接退出：其下行端已不匹配，不应误删新连接的注册
        reg.remove_if_downlink("a", &tx1);
        assert!(reg.get("a").is_some());
        // 新连接退出：匹配，删除
        reg.remove_if_downlink("a", &tx2);
        assert!(reg.get("a").is_none());
    }

    /// 直接驱动 serve_signal_stream 的进程内双客户端路由测试（duplex 流）：
    /// A register+invite → B 读端应收到 incoming{from:A}
    #[tokio::test]
    async fn serve_双连接路由() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let reg = Arc::new(SignalRegistry::new());

        // 辅助：一条 duplex = 一条「连接」。服务半给 serve_signal_stream，
        // 客户端半拆成 (写半, 按行读) 供测试驱动。
        fn mk(
            reg: Arc<SignalRegistry>,
            peer: &str,
        ) -> (
            impl tokio::io::AsyncWrite + Unpin,
            BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        ) {
            let (client, server) = tokio::io::duplex(4096);
            let (s_rd, s_wr) = tokio::io::split(server);
            tokio::spawn(serve_signal_stream(
                reg,
                peer.to_string(),
                vec![7u8; 32],
                s_rd,
                s_wr,
            ));
            let (c_rd, c_wr) = tokio::io::split(client);
            (c_wr, BufReader::new(c_rd))
        }

        // B 先连接并注册（保证 invite 时目标在线）
        let (mut b_wr, mut b_rd) = mk(reg.clone(), "bbbb");
        let reg_b = SignalMessage::Register {
            peer_id: "bbbb".into(),
            mapped: "1.1.1.1:2".into(),
            proof: hydra_protocol::p2p_owner_proof(&[7u8; 32], "bbbb"),
        };
        b_wr.write_all(serde_json::to_string(&reg_b).unwrap().as_bytes()).await.unwrap();
        b_wr.write_all(b"\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(reg.get("bbbb").is_some(), "bbbb 应已注册");

        // A 注册 + invite B
        let (mut a_wr, a_rd) = mk(reg.clone(), "aaaa");
        let reg_a = SignalMessage::Register {
            peer_id: "aaaa".into(),
            mapped: "1.1.1.1:1".into(),
            proof: hydra_protocol::p2p_owner_proof(&[7u8; 32], "aaaa"),
        };
        a_wr.write_all(serde_json::to_string(&reg_a).unwrap().as_bytes()).await.unwrap();
        a_wr.write_all(b"\n").await.unwrap();
        let inv = SignalMessage::Invite {
            peer_id: "bbbb".into(),
            cand: vec!["1.1.1.1:2".into()],
        };
        a_wr.write_all(serde_json::to_string(&inv).unwrap().as_bytes()).await.unwrap();
        a_wr.write_all(b"\n").await.unwrap();

        // B 应收到 incoming
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), b_rd.read_line(&mut line))
            .await
            .expect("等 incoming 超时")
            .expect("读失败");
        assert!(n > 0);
        let msg: SignalDownMessage = serde_json::from_str(&line).unwrap();
        match msg {
            SignalDownMessage::Incoming { from, cand } => {
                assert_eq!(from, "aaaa");
                assert_eq!(cand, vec!["1.1.1.1:2".to_string()]);
            }
            other => panic!("应收到 incoming，实际 {other:?}"),
        }
        let _ = a_rd; // A 的读端未用（无下行）
    }
}
