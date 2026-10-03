# Phase A 代码复审报告（2026-10-04）

- **复审对象**: Phase A 安全加固后的全部代码（commit b3bbc3f + d8e4a39，26 文件改动）
- **方式**: 两个独立评审组并行（客户端+协议正确性 / 节点+测试+GUI），交叉验证
- **基线**: 17/17 测试全绿，E2E（SOCKS5/HTTP/大文件/自定义端口）已验证
- **总体结论**: **无 P0**。协议 v2 两侧字节序列严格一致；认证闭环成立（未认证者无法让节点处理任何数据）；发现 3 个 P1 已当场修复，其余 P2 部分修复、部分列入路线图。

## 已当场修复（commit 本次）

| # | 严重度 | 问题 | 位置 | 修复 |
|---|---|---|---|---|
| 1 | P1 | **服务端 keepalive 使未认证连接永不空闲超时**，攻击者可开满 max_connections（默认1000）个零字节连接永久占用 Semaphore 配额 → 完全 DoS | `hydra-node/src/handler.rs` | 连接级**认证宽限看门狗**：10 秒内无任何流完成认证则强制断开连接 |
| 2 | P1 | **时钟偏移导致认证全灭且被误判为节点故障**：token 对未来时间戳零容忍，跨机部署时钟差 ≥1s 即全部被拒 | `hydra-protocol/src/auth.rs:81` | 时间窗允许 ±5s 容差（`CLOCK_SKEW_TOLERANCE`），`saturating_sub` 防下溢 |
| 3 | P1 | **超时不对称误判节点故障**：客户端应答超时 5s < 节点目标连接超时 60s，慢目标会把健康节点标 Offline 且节点侧连接泄漏挂 60s | `proxy.rs:201`、`handler.rs:127` | 节点目标连接超时 60s→15s，客户端应答超时 5s→20s（20 > 15，不对称消除） |
| 4 | P1 | **连接池写锁跨网络 await**：`get_stream` 持锁执行 open_bi+token 写入，所有并发取流被全局串行化 | `hydra-client/src/pool.rs` | 重构为"锁内只 pop/push 连接，open_bi 在锁外"，单次持锁为纯内存操作 |
| 5 | P2 | **证书半存在时静默重新生成**，客户端 pin 的指纹失效且无告警 | `hydra-node/src/cert.rs` | 只剩其一即报错拒绝启动；提示补齐或成对删除 |
| 6 | P2 | `HYDRA_MAX_CONNECTIONS=0` 使节点静默拒绝一切连接 | `hydra-node/src/server.rs` | `max(1)` 兜底 |
| 7 | P2 | **pre-auth 日志洪水**：未认证流每次 accept/失败都打 info/warn，扫描者可刷爆日志盘 | `hydra-node/src/handler.rs` | pre-auth 路径日志降为 `debug!` |
| 8 | P2 | 客户端无 SNI 配置项：节点改证书 SAN 后 webpki 名字校验必失败且无从调整 | `hydra-client/src/main.rs` | 新增 `HYDRA_SNI` 环境变量覆盖（须与节点证书 SAN 匹配） |
| 9 | P2 | SOCKS5 域名有效长度仅 251 字节（RFC 允许 255） | `proxy.rs:494` | 请求缓冲区 256→320 字节 |
| 10 | P2 | HTTP 明文代理 IPv6 字面量 `[::1]:8080` 被 `splitn(2,':')` 错误拆分 | `proxy.rs:343` | 先尝试整体 `parse::<SocketAddr>()` 再回退冒号切分 |
| 11 | P2 | `test_quic.rs` 证书写到源码树目录反复覆盖 | `hydra-node/tests/test_quic.rs` | 证书写入按进程隔离的临时目录 |

## 遗留项（评估后列入路线图，不在本次修）

| # | 严重度 | 问题 | 处置 |
|---|---|---|---|
| A | P2 | nonce 无重放防护（30s 窗口内 token 可重放）。实际利用需先攻破 TLS pinning 或持有 PSK，单租户自用风险低 | Phase B：节点侧 nonce 有界去重表 |
| B | P2 | AuthRateLimiter 死代码（零调用），易误以为有防护 | Phase B：随认证补强接线或删除 |
| C | P2 | Offline 节点无主动恢复探测（现靠候选尾部被动重试），speedtest 删除后评分恒为静态初始值 | Phase B：测速重写（结果写回调度器） |
| D | P2 | 双向转发 `select!` 单向完成后另一方向任务成孤儿（依赖对端关闭收敛；节点侧已用 `join!` 更正确） | Phase B：协议错误显式传播时一并处理 |
| E | P2 | GUI "测试"按钮阻塞 UI 线程最长 5s；test_node_connection 丢弃证书错误根因 | Phase B（GUI 项） |
| F | P2 | **Windows 系统代理未实现**（GUI 只有 gsettings/kde，静默无效） | Phase B 首项（Windows 平台核心功能） |
| G | P2 | cert/key 无权限控制（Unix 默认 0644）+ 默认相对路径依赖 cwd | Phase B |
| H | P2 | config.rs 的 NodeConfig 已无消费者（死代码） | Phase B 配置系统真实化时处理 |

## 正面确认

- 协议一致性：64B token、2 字节大端长度前缀（上限 256 两侧一致）、应答码 0x00/0x01/0x02 语义严格匹配
- 认证闭环：所有失败路径（超时/短读/坏 token/坏地址）静默关流，未认证者最多消耗 1 个 permit（现受 10s 宽限约束）+ QUIC 握手 CPU
- panic/溢出审计：新代码无可触发的 panic 或整型溢出；SOCKS5 各失败路径均有错误回复，无吞错不发码

## 测试盲区（建议 Phase B 补齐）

1. 认证失败路径：错误 PSK 下客户端收到的应是流被静默关闭（无错误码）
2. 证书 pinning 失败：客户端持错误证书应连接失败（防止回归 SkipVerification 而测试不红）
3. Semaphore 上限：第 N+1 个连接应被延迟而非处理
4. 0x01/0x02 错误码路径（目标不可达 / 节点 DNS 失败）下 SOCKS 客户端收到的回复码
5. 并发场景：多请求同时打到坏/慢节点的竞争；HTTP 代理路径与 IPv6 目标完全未测
