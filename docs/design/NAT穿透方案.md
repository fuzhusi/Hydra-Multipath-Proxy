# NAT 穿透方案（TCP 时代 v1）

- 日期：2026-10-05 ｜ 状态：**已实施完成（同日；STUN 事务 ID 已修正为 RFC 5389 标准 12B/20B 头以对接公网服务器）**
- 背景：QUIC 时代的 `nat_traversal.rs`（UDP 打洞）与 STUN 模块已随 TCP 转型删除。现行架构 = 客户端主动外连公网节点（出站 TCP），日常使用无需穿透。本方案补齐「节点/对端无公网 IP」与「P2P 直连省中继带宽」两个场景，全部基于 TCP（UDP 不可用的网络约束不变）。

---

## 1. 目标与非目标

**目标**
1. **公网地址发现**：客户端/节点经 TCP STUN（RFC 5389 Binding）获知自己在 NAT 后的公网映射地址
2. **NAT 行为分类**（RFC 4787 简化版）：判定映射行为 EIM（端点无关映射，可打洞）/ SDM·ADM（对称型，打洞成功率低）
3. **P2P TCP 打洞**：两个 NAT 后的对等端经节点信令协调，尝试 **TCP 同时打开**（simultaneous open，RFC 5128 §2.4）建立直连
4. **中继兜底**：打洞失败自动回落经节点转发（现有能力，零新增风险）

**非目标（如实声明）**
- 不做 UPnP/PCP/PMP 端口映射（家庭路由器支持率高但企业/移动网关不支持，且安全面大——列为远期可选项）
- 不做 UDP 打洞（网络约束：UDP 回程 QoS 丢包，本项目明确放弃 UDP）
- 不保证穿透成功：SDM/ADM NAT 下回落中继（如实给用户报「NAT 类型」）

## 2. 架构与角色

```
[A: 客户端/NAT后]     [N: 公网节点(信令+中继)]     [B: 客户端/NAT后]
   │ 1. STUN 探测: 得知映射地址 map(A)          │
   │ 2. 经现有加密链路向 N 注册 peer_id ↔ map(A) │
   │ 3. A 请求连 B ──信令──▶ N ──信令──▶ B       │
   │ 4. A、B 同时向对方 map 地址发起 TCP connect（同时打开）
   │ 5. 成功 → Noise-PSK 握手 → 直连；失败 → 走 N 中继（现状路径）
```

- **协调者**：公网 hydra-node 兼任（不新增组件）。节点开启 `HYDRA_P2P_SIGNAL=1` 后，认证通过的连接可进入**信令模式**
- **peer_id**：客户端自选随机 16 字节 hex（每次会话可换），仅作信令路由键；安全性由既有 Noise-PSK 认证保证——**未认证连接无法注册/收发信令**（防探测与滥用语义不变）

## 3. 协议设计

### 3.1 STUN 探测（hydra-protocol::stun）
- RFC 5389 消息编解码（TCP）：Binding Request/Response、MAGIC_COOKIE、16B 事务 ID、XOR-MAPPED-ADDRESS（含 0x0020 属性与旧式 MAPPED-ADDRESS 兼容读取）、FINGERPRINT 可选校验
- 每次探测：本地随机端口 → STUN 服务器 TCP 19302/443，读 XOR-MAPPED-ADDRESS
- **分类法**（简化 RFC 4787，TCP 同时打开只需映射行为）：
  - 同一本地 socket 对两个不同 STUN 服务器探测：映射地址相同 → **EIM**（打洞可行）；不同 → **SDM/ADM**（回落中继）
  - 输出 `NatType { Eim, Symmetric, Unknown }` + 公网映射地址
  - **已知局限（如实声明）**：EIM 判定只比较映射地址，不含 NAT 的**过滤行为**（RFC 4787 EIF）——address/port-dependent filtering 的网关即使 EIM 也会丢弃对端发往 mapped 端口的 SYN，打洞成功率受此限制，失败一律回落中继

### 3.2 信令模式（节点侧，tcp_server 扩展）
- 地址帧目标为保留字 `@hydra-p2p/<peer_id>`（仅当 `HYDRA_P2P_SIGNAL=1` 且目标以该前缀开头）：不建目标连接，进入信令会话
- 信令帧（JSON 行，便于调试，量极小）：
  - `{"op":"register","peer_id":...,"mapped":"ip:port"}` → 注册/刷新（60s 心跳续期，超时摘除）
  - `{"op":"invite","peer_id":<目标>,"cand":["ip:port",...]}` → A 请求连 B；节点转发为 `{"op":"incoming","from":<A_id>,"cand":[...]}` 给 B
  - `{"op":"accept","to":<A_id>,"cand":[...]}` → B 应答，节点转发为 `{"op":"accepted","from":<B_id>,"cand":[...]}`
- 状态机：`HashMap<peer_id, (mapped, 最后活跃)>` + 待达邀请表；离线/超时回错误 op；上限（注册表 ≤1024、单连接 1 会话）防滥用
- 隐私：信令内容仅候选地址与 peer_id，日志脱敏规则不变

### 3.3 打洞流程（客户端）
1. STUN 探测得 map(A)、NAT 类型；EIM 才进入打洞，否则直接走中继
2. 经节点信令 invite/accept 交换双方候选（映射地址，可多条）
3. **同时打开**：双方各自 `TcpStream::connect` 对方候选 + 同时在本端监听候选端口 accept（自连过滤）；任一连接建成 → 3s 内完成 Noise-PSK 握手（PSK 双方已知）+ 目标帧回显校验 → 即 P2P 隧道
4. 10s 窗口未成功 → 关闭尝试，回落节点中继（现状代码，零改动）
5. 打洞结果写入日志与 GUI 状态（direct/relay）

## 4. 模块落点

| 模块 | 内容 |
|---|---|
| `hydra-protocol/src/stun.rs`（新） | STUN 编解码 + 分类逻辑 + 单测（构造报文往返、XOR 正确性） |
| `hydra-node/src/tcp_server.rs` | 地址帧保留前缀 `@hydra-p2p/` → 信令会话（新 `signal.rs` 状态机 + 单测） |
| `hydra-client/src/nat.rs`（新） | STUN 探测/分类、打洞编排、中继回落；CLI 入口 `--p2p <peer_id> --peer <对方id>`（实验性） |
| 测试 | 编解码单测；节点信令路由集成测试（loopback 双客户端注册/转发）；打洞在 loopback 上验证「同时打开→握手」路径（真实 NAT 无法本地自动化，如实标注） |

## 5. 安全与资源

- 信令**复用现有认证**：Noise-PSK 握手不过 → 不可能注册/收发（未认证静默关流语义不变）
- 节点侧资源上限：注册表 1024 条、信令会话 60s 无心跳摘除、单帧 ≤4KB、JSON 解析失败即断开
- 打洞连接与中继连接同安全级（Noise-PSK + exporter 绑定），P2P 直连不降低加密强度
- 默认**全关**：`HYDRA_P2P_SIGNAL` 未设 = 节点零改动；客户端 p2p 为显式实验功能

## 6. 实施顺序

1. `hydra-protocol::stun` 编解码 + 单测
2. 节点信令模式（signal.rs + tcp_server 接线）+ 集成测试
3. 客户端 nat.rs（探测/分类/打洞/回落）+ loopback 打洞集成测试
4. CLI 入口 + README + 全量回归

## 7. 实施记录（2026-10-05，已交付）

- **交付物**：`hydra-protocol/src/stun.rs`（RFC 5389 标准线格式：12B 事务 ID/20B 头，8 单测含硬编码 XOR 已知值与 FINGERPRINT CRC32 校验）；`hydra-node/src/signal.rs`（SignalRegistry 状态机 + JSON 行信令路由，5 单测）；节点 `@hydra-p2p/` 信令模式（`HYDRA_P2P_SIGNAL=1` 开启，默认关）；`hydra-client/src/nat.rs`（探测/分类/打洞编排/中继回落）；CLI `--p2p/--peer/--node` 实验入口。
- **实现中的关键修正/决定**：① STUN 事务 ID 按公网服务器互操作要求定为 RFC 标准 12B（初版 16B 已纠正）；② 信令身份由地址帧 peer_id 决定，register 冒用他人 id 即断开；③ 打洞并发验证（每条候选连接独立握手任务，防两端互等死锁）；④ 自连判定用 nonce 回显比对（比地址过滤可靠）；⑤ 双端对称启动（双向同时 invite 也能收敛）。
- **测试**：全 workspace **153 通过 / 0 失败**（新增：STUN 8、信令节点侧 5+5、客户端 NAT 9；含 loopback 全链路打洞端到端）。
- **如实标注**：真实 NAT 环境的穿透成功率无法本地自动化验证——EIM NAT 的同时打开在业界有成熟先例，Symmetric 一律回落中继；上线前需在真实双 NAT 环境人工验证一次。
