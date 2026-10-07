# TUN 模式方案（透明代理 v1）

- 日期：2026-10-05 ｜ 状态：**已实施完成（同日，v1）**。实施偏差如实记录：①依赖定为 tun2 4.0（async feature）+ smoltcp 0.11；②smoltcp 无通配监听，TUN 只拦截端口列表（默认 80/443/8080/8443，`HYDRA_TUN_PORTS` 可调）——方案未预见的硬限制；③测试 **160 通过 / 0 失败**（新增 compute_routes 路由豁免、smoltcp 双 Interface 回环端到端、流上限 RST），真实 Wintun 设备路径需管理员人工验证（指引见部署指南）
- 背景：当前客户端仅提供 SOCKS5/HTTP 本地代理，应用需手动配置代理。TUN 模式创建虚拟网卡接管系统流量，实现**免配置全局代理**（对标 Clash/mihomo 的 TUN Mode）。约束不变：仅 TCP 隧道（UDP 回程丢包网络，项目无 UDP 转发能力）。

---

## 1. 目标与非目标

**目标（v1）**
1. 客户端创建 TUN 虚拟网卡（Windows: Wintun；Linux: /dev/net/tun），自动配置地址与路由
2. 用户态 TCP/IP 栈（smoltcp）终结 TUN 上的 TCP 流，每条流**原样经现有代理链路**转发（复用 open_target/故障切换/分流/流量统计，零语义分叉）
3. **防环路**：代理自身到节点的连接必须豁免——节点 IP 走物理网卡路由（路由表排除项）
4. CLI 开关 `--tun`（env `HYDRA_TUN=1`），默认关闭，行为与现状完全一致

**非目标（v1 如实声明）**
- **不做 UDP 转发**：代理链路无 UDP 能力；TUN 上的 UDP 包（含 QUIC/HTTP3）直接丢弃并回 ICMP Port Unreachable（引导应用回落 TCP）
- **不做 DNS 劫持/fake-IP**：v1 依赖「系统 DNS 服务器路由豁免」——DNS 明文走物理网卡直出（与不装 TUN 时一致，隐私无回退）；UDP DNS 自然被豁免路径覆盖。DNS 经代理加密是 v2 方向（需先实现 UDP-over-proxy 或 TCP DNS 劫持）
- 不做按规则分流（CN 直连在 TUN v1 中退化为「全部经节点」；splitter 的域名分流依赖域名信息，TUN 拿不到——v2 结合 fake-IP 恢复）
- 不做自动管理员提权：TUN 需要管理员/root 运行，启动时无权限则明确报错

## 2. 架构

```
应用流量 → 系统路由(0.0.0.0/1 + 128.0.0.0/1 → TUN) → [Wintun/TUN 设备]
    → smoltcp 用户态栈（终结 TCP：SYN/SYN-ACK/数据/关闭全在栈内仿真）
    → 每条新建流： hydra_client::open 通道（既有故障切换/评分/统计）
    → 节点 → 目标
代理自身流量 → 节点 IP 豁免路由 → 物理网卡 → 节点（不进 TUN，无环路）
```

- **路由策略**（v1 简化，不用 policy routing）：添加 `0.0.0.0/1` 与 `128.0.0.0/1` 两条低 metric 路由指向 TUN（比默认路由更精确即生效），豁免清单各加一条更精确路由回物理网关：①各节点 IP/32；②系统 DNS 服务器 /32；③TUN 自身网段。退出/崩溃时清理（注册 Windows SetConsoleCtrlHandler + drop guard；崩溃残留由下次启动时清理同接口旧路由兜底）
- **TCP 栈**：smoltcp 0.11（Interface + SocketSet，每流一个 TcpSocket）；TUN 设备 crate 用 `tun2`（tun-rs 维护版，Windows 走 Wintun 驱动，需 `wintun.dll` 与系统同架构放在 exe 目录或 PATH；Linux 走 /dev/net/tun）
- **MTU**：TUN MTU 65535 上限对 smoltcp 无意义且浪费内存，取 **1500**；mss 优化交给栈
- **缓冲与背压**：TUN 读 → smoltcp 注入；栈出站字节 → 直写代理通道（tokio copy），天然背压；并发流上限 512（超限对新流回 RST，防资源耗尽）

## 3. 模块落点

| 模块 | 内容 |
|---|---|
| `hydra-client/src/tun.rs`（新） | 设备创建/路由配置（win/linux cfg 分支）、smoltcp 栈驱动循环、流编排（调既有内部接口开目标通道）、豁免路由表、drop guard 清理 |
| `hydra-client/src/proxy.rs` | 暴露内部 `open_tun_channel(target) -> NodeLink`（open_target 复用，pub(crate) → pub(in crate) 收窄可见性即可） |
| `hydra-client/src/main.rs` | `--tun` 参数 / `HYDRA_TUN=1`：在 SOCKS 监听之外叠加启动 TUN（可并存） |
| `Cargo.toml` | hydra-client 增 optional 依赖 `tun2`、`smoltcp`，feature `"tun"`（默认开启；关掉可编出无 TUN 的最小客户端） |
| 测试 | 可自动化：路由豁免清单计算、目标通道编排（loopback 假 TUN 不做——smoltcp 栈回环测试构造 IP/TCP 报文注入验证 smoltcp 集成正确性）；真实 Wintun 全链路需管理员，**人工验证指引写入部署指南** |

## 4. 平台矩阵与依赖（如实声明）

| 平台 | TUN 设备 | 依赖 | 状态 |
|---|---|---|---|
| Windows 10+ | Wintun 驱动（`wintun.dll` 需随包分发，管理员运行） | tun2 | v1 目标 |
| Linux | /dev/net/tun（TUNSETIFF），root 或 CAP_NET_ADMIN | tun2 | v1 目标（代码路径同源） |
| macOS | utun | tun2 | 未验证，代码同源，问题如实记录 |
| Android | 需 VpnService 集成 | — | 不在本期（已有安卓方案文档另行规划） |

## 5. 安全与稳定性

- TUN 只增本地攻击面为「无」（本机 root 才能碰设备）；代理链路加密强度不变
- 崩溃安全：路由残留是最坏情形（断网）——启动时按接口名幂等清理 + 文档提供 `route delete` 手工恢复命令
- 与系统代理互斥提示：Windows 系统代理设置开着时 TUN 流量会二次进代理循环，启动 TUN 时检测并告警（v1 不自动关闭）

## 6. 验收标准

1. `cargo build --features tun` 全平台编译通过（本机 Windows 验证）；`cargo test --workspace` 全绿
2. 路由豁免逻辑单测：给定节点列表/DNS，生成的路由命令清单正确且含全部豁免项
3. 人工验证指引（部署指南新增节）：管理员运行 → `curl --interface` 或浏览器验证出口 IP = 节点 IP；断开 TUN 后网络自动恢复
4. 如实标注：UDP 丢弃、无 DNS 劫持、无域名分流为 v1 边界

## 7. 实施顺序

1. 依赖接入 + `tun.rs` 骨架（设备/路由/栈循环）+ 豁免清单单测
2. 流编排接 proxy 通道 + CLI 接线
3. smoltcp 回环集成测试 + 全量回归
4. README/部署指南更新 + 人工验证指引

---

## 交付补记（2026-10，v2 方向落地）

本文"非目标"中的两项已随 UDP-over-proxy 三层交付后接线实现（默认开启）：

- **UDP 转发**：公网目标 UDP（QUIC/HTTP3/DNS/P2P）经节点 UDP 中继加密隧道
  转发；`HYDRA_TUN_UDP=0` 可恢复本文的 ICMP 代答回落行为。实现：tun.rs
  UDP 统一分发 + keyed 会话（`UdpChannel::send_to_ext`）+ 中继任务（断线重连
  + 流表回包构造 v4/v6）。
- **DNS 经代理加密**：公网系统 DNS 不再豁免出物理网卡，查询随 UDP 隧道经
  节点解析；`HYDRA_TUN_DNS_DIRECT=1` 恢复直连。未采用 fake-IP——真实 IP +
  全接管路由天然免劫持匹配。

仍为边界：无域名分流；TCP 仍按 `HYDRA_TUN_PORTS` 端口列表拦截（smoltcp 无
通配监听，任意端口动态监听为后续方向）。
