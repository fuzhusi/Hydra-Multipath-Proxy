# 近期新增代码专项审查报告（UDP 中继 / 连接注册表 / TUN v6 / 指纹 / Android 绑定）

- 日期：2026-10-06 ｜ 方法：只读精读（专项：逻辑漏洞与 bug）
- 结论：**无 P0/P1**；P2×2、P3×8。大面逻辑经核查正确（清单见文末）。

## P2

1. **[P2] hydra-node/src/udp_relay.rs uplink_data（约 L400-413）：已存在会话的每个上行数据报都重复做节点侧 DNS 解析，且 5s 超时阻塞整条连接上行**
   机理：每帧先 `resolve_udp_target(target).await`（域名走 lookup_host，5s 超时），之后才查会话表。域名目标 + 上行串行读循环 → 每包一次 DNS（对上游 resolver 放大）；一次解析超时停摆该连接全部 64 会话上行。
   修复：先查表取 existing_target，命中且等于帧内 target 则直接投递；仅新建/换目标时 resolve。

2. **[P2] hydra-node/src/udp_relay.rs SSRF 镜像判定（约 L225-244）：IPv6 组播 ff00::/8 未拦截**
   机理：IPv4 拦了组播，v6 分支缺 `ff00::/8`——已认证客户端可向本地组播（ff02::1 SSDP 等）发包。
   修复：v6 分支补组播段判定（顺带补 2001:db8::/32 文档段，低优先）。

## P3

3. udp_frame.rs decode 不校验 datagram ≤ MAX_DATAGRAM_LEN——超限帧致节点 socket.send EMSGSIZE → 会话被拆（应只丢该报）。修复：Data 分支加长度校验。
4. session_task 回收与在途上行投递竞态：close 后同 session 仍可能发下行数据帧；且脱离空闲管理。修复：取句柄的临界区内先 touch()。
5. 换目标分支 remove 后的 is_full 检查死代码（低优先，误导性防御）。
6. 测试用 set_var 并发风险（仅测试域，低优先）。
7. hydra-core send_to 在 encode 失败时已消耗 session_id 且映射残留（长生命周期通道 sid 加速耗尽）。修复：先 encode 再登记。
8. tun.rs v6 TCP 带扩展头被误判非 TCP → SYN 回不可达而非代理。修复：带扩展头的 SYN 静默丢弃（不回不可达）。
9. ensure_v6_dst 忽略 addrs.push 失败，池与接口地址表可失同步。修复：push 失败不入池并告警。
10. ICMPv4 代答不豁免广播/组播目的与未指定源（DHCP/mDNS 场景，RFC 1122 §3.2.2）。修复：此类返回 None。
11. session_task `biased` select 优先下行，持续上行可饥饿下行回包。修复：去 biased。

## 已核查无问题（大面）
- 帧编解码字节序/严格解码/粘包；客户端 sid checked_add、close 反查；换目标不双 socket 不串线；锁纪律（MutexGuard 不跨 await）与下行写串行化；SSRF v4 全段 + 内嵌 v4（mapped/::/96/NAT64）+ DNS 解析后复查无 TOCTOU；connections.rs 原子计数/finish 幂等/淘汰策略/锁序；proxy 钩子 17 行全覆盖无遗漏；指纹缓存键 XOR 双射、env trim 大小写、feature 降级；tun.rs ICMP 校验和（v4 无伪首部/v6 伪首部）、非首片不代答、入站 ICMPv6 静默、RST ack=seq+1；ensure_v6_dst 淘汰终止性；hydra-android 引擎启停/心跳/占位证书语义。
