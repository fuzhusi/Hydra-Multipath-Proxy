# Hydra Multipath Proxy

[![CI](https://github.com/fuzhusi/Hydra-Multipath-Proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/fuzhusi/Hydra-Multipath-Proxy/actions/workflows/ci.yml)

基于 Rust 的多节点安全代理：本地 SOCKS5/HTTP 代理 → **TCP/TLS + Noise-PSK 握手** → 自建节点集群 → 互联网。

> **关于 "Multipath" 命名**：指**连接级多节点加权分发与故障自愈**——每条连接走单一节点，多节点按评分分流新连接、故障自动切换。QUIC 时代的字节级多路径聚合（V3.4）已随 UDP 路径移除，如实声明避免名实脱钩。

> **交付状态：v1.0 可交付产品**（2026-10）。三档如实划分：
> - **已交付**：TCP/TLS + Noise-PSK 隧道、自签 pinning 与 ACME 真证书双路线、多节点加权分发与故障自愈、测速动态调度、**温连接池**（预热复用，每请求省一次节点握手）、TUN 透明代理完整版（IPv6 双栈 + **UDP-over-proxy 接管** + **DNS 经隧道** + **TCP 任意端口动态接流**）、**节点侧 v4-only 降噪**（DNS AAAA 本地过滤 + 目标建连 v4 优先）、NAT 穿透 v1（TCP STUN 分类 + 同时打开打洞 + 中继兜底；真实 NAT 组合环境需人工实网验证）、反代静态页回退、ClientHello 指纹模仿（最大近似方案，见 docs/design/ClientHello指纹模仿方案与实施.md）、UI 重设计 v3 全部批次（含连接页）+ **GUI 模块化拆分**（21 文件）、GUI 全功能（托盘/分享/订阅/连接页/配置持久化/CA 信任模式/**托盘菜单禁用态**）、**节点 /metrics（Prometheus）**、CI 与 Release 安装包、**Android M1 本地代理 + M2 全局 VPN**（VpnService 全接管 + TCP 任意端口 + DNS 经隧道）+ **M2.1 VPN 保护**（kill switch 断线阻断自动重连 / 开机自启 / 分应用代理白黑名单）。
> - **v0.2.4 增量**（2026-10-10）：**内核优化 13 项**——节点 DNS 共享缓存（正向 60s/负 10s/1024 LRU）、Happy Eyeballs 目标并行建连（首两候选 250ms 错峰竞速）、冷连接握手捎带（5→4 RTT）、弹性温池（cap 按 peak EWMA clamp 2..8）、温连接 stale 8s 短超时、Metrics v2（17 指标族 + 四段握手直方图）、UDP 中继分层缓冲 + 单调钟、节点侧 TCP Fast Open + keepalive + TCP_USER_TIMEOUT、评分归一化；**UI v4.1 三主题**（Dark/Light/Abyss 运行时切换）+ 首页重排；**CLI 分享链接直传**（`hydra://` 给 CLI 即全配好）；P2P 打洞同时打开握手角色修复（按地址序分配）。
> - **v0.2.5 / 0.2.6 增量 + Unreleased**（2026-10-11）：**Android UI v1.1**——品牌四主题（跟随系统 Material You 动态取色/深色/浅色/深海 Abyss）+ 连接主页大按钮（112dp 圆钮 + 四态状态环）+ 双模语义（本地代理/全局 VPN 同钮分流）+ MainActivity 模块化拆分 + TalkBack 可达性；**真机端到端验证**（模拟器 + 真实 VPS：tun0 全局接管实测流量、深链导入、四主题渲染）；**Android 正式签名链**（keystore Secrets 注入 CI，缺失回退 debug 签名）+ R8 修复 + 真机 P0 修复（深链导入配置覆盖清空等）；桌面速率图 10 秒定格滚动 + Catmull-Rom 平滑 + 托盘退出强退兜底 + 关于对话框；**系统代理残留治理**（启动自愈 + 修复式保存 + WM_ENDSESSION 关机恢复——根治"关闭代理后浏览器断网"）。
> - **规划中**：eframe/egui 升级 0.27→0.33+（根治 webbrowser 漏洞告警与 unmaintained 依赖群，当前已评估豁免）、多节点并行下载 GUI 前端（CLI 已交付）、rekey Tier2（并入 v4 帧化协议——snow 0.9.6 具备 rekey API 但现协议 Noise 仅认证、数据面为 TLS 1.3，对现协议无效果）。

> **项目性质**：个人自用工具，AI 辅助开发。经多轮独立代码审查（[docs/review/](docs/review/)），本 README 与代码逐项核对——未列出的能力即为未实现，不做夸大宣传。
>
> **TCP 转型（2026-10）**：部署网络存在 UDP 回程 QoS 丢包（tcpdump 实证），项目从 QUIC/UDP 全面转向 **TCP 443 + TLS**（方案与裁决见 [docs/design/TCP转型与加密选型方案.md](docs/design/TCP转型与加密选型方案.md)）。QUIC/UDP 路径与 obfs 模块已删除（git 历史可考）。

---

## 核心特性

### 传输与加密
- **TCP/TLS 隧道**（tokio-rustls，TLS 1.3）：无 ALPN（流量形态 = 普通 HTTPS 访问）、禁会话恢复（阻断跨连接关联）
- **信任双路线**：自签证书 pinning（`HYDRA_TRUST=pin`，默认）与 **ACME 真证书**（节点直挂 PEM fullchain，客户端 `HYDRA_TRUST=ca` 信任公共 CA，可选叶证书 SHA-256 硬 pin 防 CA 误签发）——证书轮换不再破坏固定
- **Noise-PSK 应用层握手**（snow，`Noise_NNpsk2_25519_ChaChaPoly_SHA256`）：前向安全、无时钟窗依赖、抗重放；confirm 以**服务器叶证书 SHA-256 指纹 + TLS exporter** 双通道绑定（指纹取 TLS 协商出的对端证书，多节点/证书轮换零额外配置）
- **私有帧协议**：握手后 `[u16 BE 地址长度][目标地址]` + `[2B 应答码]`——线缆格式私有，通用 DPI 规则零命中
- **认证失败静默关流**：版本字节非法 / 握手失败 / 认证失败一律零字节关闭，主动探测无法识别节点身份
- **DNS 隐私**：客户端不解析目标域名，域名只经加密通道交节点解析，明文域名永不离开本机

### 可靠性与性能
- **节点故障切换 + 自愈**：传输失败自动标记 Offline、切换下一节点（最多 3 候选）；后台探测器周期**完整握手探测**（TCP + TLS + Noise-PSK，认证面故障可在探测复现），Offline 节点恢复自动重新上线、Online 节点连续失败自动降级 Degraded——死节点不再"恒被选中靠每连接失败兜底"
- **连接级多节点加权分发**：多节点按评分承接新连接，杀节点不中断
- **测速动态调度**：主动探测 RTT + 被动吞吐差分（按节点字节计数）+ 故障衰减，实测写回节点评分
- **温连接池（pre-warm）**：节点握手在上一请求转发期间后台完成（**弹性 cap**：按峰值负载 EWMA 在 2..8 间自适应、60s TTL + 周期清扫），请求到达复用现成通道直发目标帧——浏览器式短请求**每请求省一次 TCP+TLS+Noise 握手（300–500ms → ~0）**；复用陈旧温连接走 **8s 短超时**快速失败重建（`HYDRA_WARM_TIMEOUT_SECS` 可调），零协议变更，温连接失败自动回退全新握手（纯优化层，不碰评分/故障切换语义）
- **冷连接握手捎带**：目标地址帧并入握手尾包发送，冷连接建达目标 **5→4 RTT**（线缆兼容，老客户端无感知）
- **Happy Eyeballs 目标建连**（节点侧）：目标多候选（双栈域名常见）首两个 **250ms 错峰并行竞速**先到先用，黑洞候选不再吃满串行预算（失败尾延迟 20s → ~2-3s）；剩余候选串行接力（15s 总预算语义不变）
- **节点 DNS 共享缓存**：多客户端并发解析共享进程级缓存（正向 60s/负缓存 10s/1024 LRU/并发 64 闸），并发解析不再放大上游 DNS 压力；`HYDRA_DNS_CACHE=0` 关闭
- **目标流存活防护**：节点侧目标连接启用 keepalive + `TCP_USER_TIMEOUT`（Linux，90s）——死目标 ~90s 回收，不再等 300s idle 兜底；节点监听侧可选 **TCP Fast Open**（Linux 门控，sysctl `tcp_fastopen≥2`）
- **v4-only 节点降噪**（节点侧）：无 IPv6 出口的节点对 DNS AAAA 查询直接合成 NODATA 应答（客户端回落 A，v6 目标从源头消失）+ 目标建连 v4 优先逐候选回落——消除 v4-only VPS 的 ENETUNREACH 错误噪音（实测单节点单日 1.5 万条 → 0）
- **多节点并行下载器**（`hydra-fetch` CLI）：HTTP Range 分块按节点评分加权分散到多节点并行拉取 + 断点续传（状态文件 ETag/Last-Modified 强校验）+ 单流回落 + 可选 SHA-256 校验；worker 持久隧道复用（keep-alive），经加密隧道端到端 TLS
- **连接最长寿命**（V3.3 Tier1，可选）：`HYDRA_MAX_CONN_AGE_SECS` 超龄强制关闭（默认关，推荐 24h）——会话寿命/资源边界的防御纵深；数据面 TLS 流量密钥 rustls 本已按套件约束自动刷新，此项关闭"单连接挂一周"类极端暴露窗
- **拥塞与转发调优**：节点侧一键启用内核 **BBR + fq**（[deploy/99-hydra-bbr.conf](deploy/99-hydra-bbr.conf)）；转发空闲看门狗（`HYDRA_IDLE_TIMEOUT_SECS`）防连接额度耗尽
- **半关闭语义**：一侧 EOF 时显式 shutdown 对侧写端（浏览器提前关写侧不挂起响应）
- **优雅停机**：节点监听 SIGTERM/SIGINT，退出前完成资源清理

### 安全与隐私
- **SSRF 目标过滤**：节点拒绝 loopback/链路本地/RFC1918/ULA 目标（含 IPv4-mapped/NAT64 内嵌绕过），云元数据地址不可达
- **资源上限**：最大并发连接数（Semaphore 强制）、认证阶段超时静默关流
- **日志脱敏**：访问目标一律 SHA-256 短哈希，明文仅 `RUST_LOG=debug` 可见
- **密钥文件化**：节点支持 `HYDRA_AUTH_KEY_FILE`（Unix 0600 校验），替代 env 泄漏面

### TUN 透明代理（已交付，`tun` feature 默认开启）
- 全流量接管：应用**无需配置代理**。`0.0.0.0/1 + 128.0.0.0/1 → TUN` → smoltcp 用户态栈 → 既有节点链路（故障切换/流量统计语义零分叉）
- **防环路**：节点 IP / 系统 DNS / TUN 网段自动豁免路由（/32 回物理网关），物理网关自动探测；退出/崩溃由 drop guard + 下次启动幂等清理恢复（P3-7：/1 接管路由优先摘除，防 5s 停机宽限不足残留）
- **IPv6 双栈**：`ipv6_enabled` 默认开启——IPv6 TCP 经用户态栈正向代理（动态 AnyIP：smoltcp 0.11 的 any-ip 仅 IPv4，入站 v6 目的地址临时挂为接口 /128 有界轮转池）；v6 非 TCP 包回 ICMPv6 不可达供应用回落 IPv4；节点 IPv6 豁免照旧（`HYDRA_TUN_IPV6=0` 可关闭，关闭时 v6 全部快速失败代答）
- **UDP-over-proxy 接管（已交付，默认开）**：公网目标 UDP（QUIC/HTTP3/DNS/P2P）经节点 UDP 中继**加密隧道**转发，回包按流表精确反解注入 TUN；v4/v6 双栈；中继断线自动重连（按当前最优节点）；`HYDRA_TUN_UDP=0` 恢复 v1 行为（公网 UDP 代答 **ICMPv4 port unreachable** type 3/code 3 引导回落 TCP）
- **DNS 经隧道（已交付，默认开）**：UDP 接管生效时公网系统 DNS 查询随隧道经节点解析（加密、无明文泄漏——TUN 方案 v2 方向落地）；`HYDRA_TUN_DNS_DIRECT=1` 恢复 v1 直连；用户显式指定的 `HYDRA_TUN_DNS` 恒豁免（内网 resolver 场景）
- **已知边界（如实）**：无域名分流（`HYDRA_SPLIT=cn` 仅 SOCKS 路径生效）；TCP 端口已全量接流（R1 动态监听：首连 SYN 驱动补挂 listener，上限 256 端口，`HYDRA_TUN_PORTS` 为固定基础列表）；Windows 真机 v6 接管需 netsh + 管理员，未做真机验证（见人工验证清单）
- **私网直连**：RFC1918 + CGNAT（IPv4）与 ULA fc00::/7（IPv6）默认豁免回物理网关（09-P2-1）——路由器/NAS 等内网设备访问不进代理（节点本就 SSRF 拒绝私网目标）；物理网关未知时私网 TCP 丢弃并告警
- 设计与实现记录：[docs/design/TUN模式方案.md](docs/design/TUN模式方案.md)
- **人工验证清单（无法本地自动化，需管理员真机执行）**：
  1. Wintun 全链路：管理员运行 `--tun`，浏览器访问 HTTPS 站点经节点出口；退出后 `route print` 无 0.0.0.0/1、128.0.0.0/1 残留
  2. IPv6 接管：双栈真机 + `HYDRA_TUN_IF=<适配器名>`，`netsh interface ipv6 show route` 出现 ::/1、8000::/1；`curl -6 https://api64.ipify.org` 经节点出口
  3. UDP 经隧道（09 交付）：TUN 下 `nslookup google.com 8.8.8.8` 与 QUIC/HTTP3 站点（如 youtube）应正常工作（经节点出口，节点侧日志可见 UDP 中继连接）；`HYDRA_TUN_UDP=0` 时 QUIC 应用应秒级回落 TCP
  4. 强杀清理：TUN 运行中直接关终端（CTRL_CLOSE_EVENT）后确认 /1 接管路由不残留

### NAT 穿透
- TCP STUN（RFC 5389）公网地址发现 + NAT 映射行为分类（EIM/对称型）
- 节点信令（`HYDRA_P2P_SIGNAL=1`）协调下的 **TCP 同时打开打洞**，失败自动回落节点中继
- CLI：`hydra-client --p2p <我的id> --peer <对方id> --node <节点>`；方案与实现记录见 [docs/design/NAT穿透方案.md](docs/design/NAT穿透方案.md)

### 便捷性
- **桌面 GUI**（egui，中文）：六页导航（状态总览/节点/订阅/**连接**/日志/设置）、状态卡实时速率、**连接页**（活跃连接实时表格：目标脱敏/节点归属/上下行计数/最近关闭）、**系统托盘**（关窗到托盘、托盘菜单启停/退出/禁用态）、配置持久化 + 首启向导、Windows 系统代理一键设置（注册表+WinINet，崩溃自动恢复）、真证书 CA 信任模式（设置页可配 + 可选叶证书硬 pin）、**三主题运行时切换**（Dark / Light / Abyss，零锁取色；Abyss 双 accent）+ 首页重排（Hero 状态条/三数据卡/快捷操作/速率图表重构）、破坏性操作全部确认对话框、日志分级过滤 + 导出（容量 1000）
- **分享体系**：`hydra://` 链接可携带完整凭据（认证密钥**强制恰好 32 字节**，生成/导入双层校验），**二维码生成 + 图片识别导入 + 粘贴/文件导入**；**CLI 直传**：`hydra-client "hydra://..."` 自动配置密钥/证书（与 GUI/Android 一致，不再需要手动 env）；带"完整链接=持有节点"安全提示
- **订阅**：自有格式（多行/逐行 base64/整体 base64），URL 或本地文件，自动合并节点
- **国内直连分流**（`HYDRA_SPLIT=cn`）：内置 CN 域名后缀表 + 用户扩展文件，默认关闭（隐私优先）

### Android（已交付：M1 本地代理 + M2 全局 VPN + M2.1 VPN 保护 + UI v1.1）
- **全局 VPN**（VpnService）：全流量接管（含 DNS），首次启动系统授权；`establish` TUN → fd 交付 Rust 用户态栈（与桌面 TUN 同栈：任意端口动态接流 + UDP 中继 + DNS 经隧道）；出站连接 protect 防回环
- **本地端口模式**：前台服务持进程内 SOCKS5 引擎（EncryptedSharedPreferences 加密存储，Keystore 主密钥；厂商 ROM Keystore 损坏自动降级并留痕）
- **UI v1.1（v0.2.5，评审 R1-R13 落实）**：品牌四主题（跟随系统 Material You 动态取色，默认 / 深色 / 浅色 / 深海 Abyss）+ 连接主页**大按钮形态**（112dp 圆钮 + 四态状态环：断开灰/连接中旋转/已连接绿/错误红 + 28sp 状态字）+ **双模语义**（本地代理与全局 VPN 同一按钮按模式分流）+ TalkBack 可达性（动态 contentDescription/状态直播/动画随系统）+ MainActivity 模块化拆分（52KB 单文件 → Theme/Home/Nodes/Settings/ShareImporter 独立模块）
- **真机端到端验证**（v0.2.6，模拟器 + 真实 VPS）：tun0 UP 全局接管实测隧道流量、深链导入反馈动线、四主题渲染、TalkBack 语义；P0 修复（深链导入后点连接不再覆盖清空配置、相机权限改按需、配置 commit 落盘）
- **M2.1 VPN 保护**：
  - **kill switch（默认开）**：隧道中断时保持接管路由**黑洞阻断出站流量**（防真实 IP 泄漏）+ 指数退避自动重连；用户显式停止才恢复直连。已知边界：重连切换存在毫秒级直连窗口；分应用白名单模式下阻断范围为白名单应用（见已知限制）
  - **开机自启**（默认关）+ 系统 Always-on 深链引导（OS 级"始终开启 + 屏蔽无 VPN 网络"，最可靠路径）
  - **分应用代理**：白名单（仅所选应用走 VPN）/ 黑名单（所选应用直连），应用选择器多选
- **导入与运维**：`hydra://` 链接 / 扫二维码（相机权限按需请求）/ 粘贴导入；逐节点连通性测试；事件日志时间线；启动逐阶段诊断（①-④）+ 20s 看门狗
- **分发与签名**：Release 工作流自动产出 APK——CI 配有 keystore Secrets 时为**正式签名 release 包（R8 优化）**，缺失时自动生成临时 debug 签名兜底；本地构建 `android/gradlew assembleDebug`。注意：**签名不同不能覆盖安装**（换包需先卸载）
- 真机回归清单见 CHANGELOG

### 节点运维
- **健康检查 + Metrics v2（Prometheus，17 指标族）**：`HYDRA_HEALTH_ADDR` 开启独立 HTTP 端点（默认拒绝非回环绑定，确需暴露设 `HYDRA_HEALTH_PUBLIC=1` 自担风险）——`GET /health` 运行状态 JSON；`GET /metrics` Prometheus 文本格式，Grafana 直接抓取：
  - **连接面**：`hydra_connections_total`（受理）/ `active`（活跃）/ `rejected_total` + `rejected_reason_total`（拒入**四因分解**：per_ip / capacity / tls / auth）
  - **目标面**：`target_connect_ok/fail_total`；**字节面**：`bytes_total`（client↔target 双向分侧）
  - **UDP 中继面**：`udp_relay_connections_total` / `udp_sessions_active` / `udp_datagrams_total`（转发/丢弃）
  - **握手延迟直方图**：`hs_tls` / `hs_noise` / `hs_dns` / `hs_target`（四段各桶 P50/P90 可算）
  - **进程面**：`hydra_up` / `uptime_seconds` / `build_info`
- **BBR 一键启用**：`deploy/99-hydra-bbr.conf`；TFO 需 `net.ipv4.tcp_fastopen ≥ 2`（sysctl）
- systemd unit / Docker / install.sh 见 [deploy/](deploy/)

---

## 架构总览

```
┌───────────────────────── 客户端设备 ─────────────────────────┐
│  浏览器 / 应用程序                                            │
│    │ ① SOCKS5/HTTP 127.0.0.1:1080（显式代理）                 │
│    │ ② TUN 虚拟网卡全局接管（无需配置应用，含 UDP/DNS）        │
│    ▼                                                         │
│  hydra-client（CLI）/ hydra-client-gui（GUI）/ Android 引擎    │
│   · 多节点评分调度（测速 RTT + 被动吞吐 + 故障衰减）           │
│   · 温连接池（弹性 2..8，请求前预热，省 300-500ms 握手）       │
│   · 故障自愈（Offline 探测恢复 / Degraded 降级）              │
│   · 分享/订阅/分流 · 连接页实时统计 · 三主题                   │
└─────────────────────────────┬───────────────────────────────┘
                              │ TCP 443：TLS 1.3（Chrome 近似指纹，
                              │ 无 ALPN）+ Noise-PSK 握手 + 私有地址帧
                              │ （域名明文不出本机，节点侧解析）
                              ▼
┌───────────────────────── 节点（VPS）─────────────────────────┐
│  hydra-node                                                  │
│   · TLS 终结 + Noise-PSK 认证（失败静默关流/反代静态页回退）   │
│   · SSRF 私网过滤 · 并发/单 IP 上限 · 慢速认证超时             │
│   · DNS 共享缓存（1024 LRU）+ AAAA 本地过滤（v4-only 降噪）    │
│   · Happy Eyeballs 并行建连 · keepalive + USER_TIMEOUT        │
│   · UDP 中继（TUN 的 UDP/QUIC/DNS 经此加密转发）              │
│   · /health + /metrics（Prometheus 17 指标族）                │
└─────────────────────────────┬───────────────────────────────┘
                              ▼
                          互联网目标
```

**四个二进制**：

| 二进制 | 角色 | 一句话用法 |
|---|---|---|
| `hydra-node` | 节点（VPS） | `hydra-node 0.0.0.0:443`（env 配密钥/证书） |
| `hydra-client` | CLI 客户端 | `hydra-client "hydra://..."` 或 `--listen 127.0.0.1:1080 节点:443`；`--tun` 全局接管 |
| `hydra-client-gui` | 桌面 GUI | 双击即用，六页导航 + 托盘 |
| `hydra-fetch` | 多节点并行下载器 | `hydra-fetch <URL> 节点1:443 节点2:443`（或 `HYDRA_NODES`） |

---

## 快速开始

### Windows 安装包（推荐普通用户）

到 [Releases](https://github.com/fuzhusi/Hydra-Multipath-Proxy/releases) 下载（v0.2.4 起三产物）：

| 产物 | 适用 | 内容 |
|---|---|---|
| `Hydra-Setup-v0.2.4-x64.exe` | Windows 普通用户 | 安装器：程序 + 官方签名 wintun.dll + 快捷方式 + 卸载器 |
| `hydra-windows-x64.zip` | Windows 便携党 | 解压即用（GUI/CLI/hydra-fetch + wintun.dll + README） |
| `hydra-linux-x64.tar.gz` | Linux x64 | GUI/CLI/hydra-fetch 三二进制（GUI 需 GTK 运行库） |

- **双击安装**：自动复制程序与官方签名 `wintun.dll` 到 Program Files，创建开始菜单/桌面快捷方式，自带卸载器
- **TUN 模式开箱即用**：安装版 GUI 快捷方式默认请求管理员权限（UAC），无需手动处理 wintun.dll
- 配置保存在 `%APPDATA%\hydra`，卸载重装不丢失

### 0. 最快路径（GUI，两分钟）

1. 节点侧起一个 `hydra-node`（见第 3 步）
2. 客户端装 GUI，首启向导：粘贴认证密钥 → 选节点证书 → 填节点地址 → 启动
3. 之后节点页"分享"出 `hydra://` 链接/二维码，其他设备扫码或粘贴即用（CLI 也认：`hydra-client "hydra://..."`）

### 1. 编译（便携方式 / 从源码）

```bash
cargo build --release
```

### 2. 生成认证密钥（客户端与节点必须一致）

```bash
openssl rand -hex 32
# 输出示例: a1b2c3d4...（64 个 hex 字符，解码后恰好 32 字节）
```

### 3. 启动节点（VPS 上，放行 TCP 443）

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."
./target/release/hydra-node 0.0.0.0:443
```

首次启动自动生成自签证书并持久化（默认 `hydra-node-cert.der` / `hydra-node-key.der`），日志打印证书 SHA-256 指纹。**把 `hydra-node-cert.der` 复制到客户端设备。**

生产部署一键化（systemd + BBR 内核调优 + 防火墙指引）：`sudo ./deploy/install.sh`。

### 4. 真证书部署（可选，推荐长期使用）

节点侧把 ACME 证书直接挂给 Hydra（支持 PEM fullchain，自动识别）：

```bash
export HYDRA_CERT_FILE=/etc/letsencrypt/live/your.domain/fullchain.cer
export HYDRA_KEY_FILE=/etc/letsencrypt/live/your.domain/private.key
export HYDRA_SNI=your.domain    # 证书 SAN 对应的域名
```

客户端侧改用公共 CA 信任（无需分发证书文件）：

```bash
export HYDRA_TRUST=ca
export HYDRA_SNI=your.domain
export HYDRA_CERT_SHA256=<叶证书指纹，64 hex，可选加固>
```

真证书部署建议同时开启**反代静态页回退**（见下节）。

### 反代静态页（抗主动探测，可选）

默认情况下，非代理流量访问 443（TLS 建立后版本字节/握手/认证失败）节点会
**零字节静默关流**——「有真 TLS 却永不出字节」本身可被主动探测统计为弱指纹。
开启后（Trojan 经典手法），这些路径改回一份内置的自包含静态网页（伪装成普通
个人博客落地页，无本项目字样、无外部资源），即标准反向代理行为：

```bash
export HYDRA_FALLBACK_PAGE=1   # 默认 0 关闭（保守升级）
# toml 等价字段: fallback_page = true
```

**取舍（两种策略各有指纹，无免费午餐）**：

- 静默关流：不泄露应用层数据，但「总被无数据关闭」是指纹；
- 回退静态页：对单个探测者像真网站，但「每次都同一页面」也可被批量探测统计
  （字节级一致，无真实站点的路由/内容多样性）。

**建议**：真证书部署（`HYDRA_TRUST=ca` + 真域名）建议开启——TLS 层已与真实
站点难以区分，回退页补齐应用层相似度，收益大于固定页面指纹的代价；自签证书
无域名的隐蔽部署建议保持默认关闭。回退路径仍受认证阶段超时与连接额度保护。

### 5. 启动客户端

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."                    # 与节点一致
export HYDRA_NODE_CERT=/path/to/hydra-node-cert.der    # 节点证书文件（pin 模式）
./target/release/hydra-client --listen 127.0.0.1:1080 1.2.3.4:443 [更多节点...]
```

### 6. 配置浏览器并验证

- SOCKS5 代理：`127.0.0.1:1080`（SOCKS v5），或 HTTP 代理同端口；或使用 GUI 的"Windows 系统代理"一键开关

```bash
curl -x socks5h://127.0.0.1:1080 https://www.google.com
```

### 7. TUN 透明代理（可选，需管理员/root）

```bash
# Windows：管理员运行；wintun.dll（与 exe 同架构）放 exe 目录或 PATH
# Linux：root 或 CAP_NET_ADMIN（/dev/net/tun）
./hydra-client --tun 1.2.3.4:443    # 或 HYDRA_TUN=1
```

### GUI 客户端（推荐）

```bash
./target/release/hydra-client-gui
```

首启引导：①粘贴认证密钥 ②选择节点证书 ③添加节点 ④启动代理。配置持久化后双击即用。节点列表点"分享"生成**二维码**，其他设备"从图片导入"扫码即用。

### GUI 页面导览（六页）

| 页面 | 能做什么 |
|---|---|
| 状态总览 | 启动/停止 + Hero 状态条（运行态/节点归属）、三数据卡（构造级等宽）、**10 秒定格滚动速率图**（Catmull-Rom 平滑、Y 轴固定网格、悬停显示格式化上/下行网速）、快捷操作 |
| 节点 | 节点卡片（健康**三通道**：颜色 + 字形 + 文字，色盲可辨）、逐节点延迟测试、增删改（确认对话框）、分享二维码、分组管理 |
| 订阅 | 订阅 URL / 本地文件导入、多行逐行/整体 base64 兼容、自动合并节点、级联删除确认（显示将删节点数） |
| 连接 | 活跃连接**实时表格**：目标（SHA-256 脱敏）/ 节点归属 / 上下行字节计数 / 最近关闭时间 |
| 日志 | 级别枚举着色与过滤（info/warn/error）、容量 1000、导出文件；启动自愈等关键事件在此留痕 |
| 设置 | 系统代理开关、TUN、三主题（Dark/Light/Abyss 运行时切换）、信任模式（pin / CA + 叶证书硬 pin）、分流、关窗行为、关于（版本/许可，读取构建版本号） |

### Android 安装（侧载）

1. Release 页下载 `hydra-android-<版本>.apk`（CI 自动产出：配了 keystore Secrets 时为**正式签名 + R8 优化**的 release 包；缺失时回退临时 debug 签名。**签名不同不能覆盖安装**——换签名包需先卸载旧版）
2. 允许"安装未知来源应用"（各厂商入口不同，安装时系统会引导）
3. 打开 App 导入节点：粘贴 `hydra://` 链接 / 扫二维码 / 手动填写
4. **大按钮连接**：本地代理模式直接启停；全局 VPN 模式首次需授权 VpnService。主题默认跟随系统（Material You 动态取色），可切深色/浅色/深海

---

## 配置参考

### 环境变量总表

**通用**

| 变量 | 说明 |
|---|---|
| `HYDRA_AUTH_KEY` | 预共享密钥（hex，解码后**恰好 32 字节**），**必填**；即 Noise-PSK 的 PSK |
| `HYDRA_AUTH_KEY_FILE` | 节点：密钥文件路径（替代 env，Unix 0600 校验） |
| `HYDRA_AUTH_MODE` | 握手版本：`auto`（默认）/ `v2`（legacy）/ `v3`；TCP 路径固定 v3 |
| `HYDRA_LOG_LEVEL` | 日志级别（默认 `info`；`RUST_LOG` 存在时优先） |
| `HYDRA_LISTEN` | 监听地址（节点默认 `0.0.0.0:8080`，推荐 `0.0.0.0:443`；客户端默认 `127.0.0.1:1080`；CLI 参数优先） |

**节点**

| 变量 | 说明 |
|---|---|
| `HYDRA_CERT_FILE` / `HYDRA_KEY_FILE` | 证书/私钥路径（默认 `hydra-node-cert.der` / `hydra-node-key.der`；支持 PEM fullchain 自动识别） |
| `HYDRA_CERT_DOMAINS` | 自签证书 SAN（默认 `hydra.node,localhost`） |
| `HYDRA_MAX_CONNECTIONS` | 最大并发连接数（默认 1000，Semaphore 强制） |
| `HYDRA_HEALTH_ADDR` | 健康检查 + 指标端点（如 `127.0.0.1:8081`；`GET /health` 状态 JSON，`GET /metrics` Prometheus 文本；未设=关闭） |
| `HYDRA_HEALTH_PUBLIC` | `1` 放行健康端点非回环绑定（默认拒绝——端点无认证，公网暴露自担风险） |
| `HYDRA_IDLE_TIMEOUT_SECS` | 转发空闲看门狗（默认 300s，双向无数据即断开；**也是已认证连接等待目标地址帧的时限**——客户端温连接池依赖该窗口） |
| `HYDRA_DNS_FILTER_AAAA` | `1` 强制开启 DNS AAAA 本地过滤 / `0` 关闭；默认自动（节点无 IPv6 出口路由时开启，v4-only VPS 降噪） |
| `HYDRA_DNS_CACHE` | `0` 关闭节点 DNS 共享缓存（回落逐连接解析，并发闸保留）；默认开（正向 60s/负 10s/1024 LRU） |
| `HYDRA_MAX_CONN_AGE_SECS` | 连接最长寿命（V3.3 Tier1，默认 0=关；clamp 60..604800）：超龄强制关闭（客户端按传输故障处理/UDP 通道自动重连）——会话寿命上限的防御纵深（rustls 已自动刷新 TLS 流量密钥）；运营推荐 86400（24h）。**客户端 TUN 的 UDP 通道轮换读同一变量** |
| `HYDRA_NODE_CONFIG` | toml 配置路径（自动探测 `./node.toml` → `/etc/hydra/node.toml`） |
| `HYDRA_ALLOW_PRIVATE_TARGETS` | `1` 放行私有目标（默认拒绝，仅测试/本地开发） |
| `HYDRA_P2P_SIGNAL` | `1` 开启 P2P 信令模式（NAT 穿透） |
| `HYDRA_FALLBACK_PAGE` | `1` 开启反代静态页回退（TLS 后认证失败回复内置网页而非静默关流；默认 `0` 关闭；取舍见[反代静态页](#反代静态页抗主动探测)） |

**客户端**

| 变量 | 说明 |
|---|---|
| `HYDRA_NODE_CERT` / `HYDRA_NODE_CERTS` | 节点证书文件（单/逗号分隔多个，**顺序与节点参数一一对应**；pin 模式） |
| `HYDRA_TRUST` | 信任模式：`pin`（默认，自签固定）\| `ca`（真证书/公共 CA） |
| `HYDRA_CERT_SHA256` | ca 模式可选：叶证书 SHA-256 硬 pin（64 hex，防 CA 误签发） |
| `HYDRA_SNI` | SNI 域名（默认 `hydra.node`；真证书部署填证书 SAN 域名） |
| `HYDRA_PROBE_INTERVAL_SECS` | 节点探测周期（Offline 恢复 + Online 活性探测，默认 30s） |
| `HYDRA_WARM_TIMEOUT_SECS` | 温连接复用陈旧连接的响应短超时（默认 8s，clamp 2..20）——过期握手快速失败重建，不拖满节点 15s 目标拨号预算 |
| `HYDRA_SPLIT` | `cn` 启用国内域名直连分流（默认关闭） |
| `HYDRA_DIRECT_DOMAIN_FILE` | 自定义直连域名列表（一行一域名） |
| `HYDRA_SPEEDTEST` | `0` 关闭测速评分（Online 节点活性探测与 Offline 恢复探测保留） |
| `HYDRA_STUN_ADDRS` | STUN 服务器（逗号分隔 ip:port 或域名；未设=NAT 穿透关闭） |
| `HYDRA_TUN` | `1` 启用 TUN 透明代理（需管理员） |
| `HYDRA_TUN_IF` / `HYDRA_TUN_ADDR` / `HYDRA_TUN_GW` / `HYDRA_TUN_DNS` | TUN 网卡名/地址/网关/DNS（`HYDRA_TUN_DNS` 支持 v4/v6 混合列表） |
| `HYDRA_TUN_PORTS` | TUN 固定基础 TCP 端口列表（默认 `80,443,8080,8443`）；**其余端口由 R1 动态监听自动接流**（首连 SYN 驱动补挂，上限 256 端口） |
| `HYDRA_TUN_EXCLUDE` / `HYDRA_TUN_IPV6` | 额外路由豁免 / IPv6 接管开关 |
| `HYDRA_TUN_UDP` | UDP-over-proxy 接管开关（默认开；`0` 恢复 v1 快速回落 TCP） |
| `HYDRA_TUN_DNS_DIRECT` | `1` = 系统 DNS 直连物理网卡（v1 行为）；默认经隧道加密 |
| `HYDRA_PER_IP_CONNECTIONS` | **节点**单源 IP 并发连接上限（默认 256，0=关闭；防单主机钉满连接额度） |
| `HYDRA_TRANSPORT` | legacy 兼容：`quic` 值告警回落 tcp（QUIC 已移除）；缺省即 TCP |

优先级统一为：**命令行参数 > 环境变量 > 配置文件 > 默认值**。GUI 场景下配置文件 > 环境变量。

### 节点 toml 配置示例

```toml
# node.toml（字段与环境变量同名小写，全部可选）
listen_addr = "0.0.0.0:443"
auth_key_file = "/etc/hydra/auth.key"   # 推荐：密钥文件化，替代 env
max_connections = 1000
cert_file = "/etc/hydra/cert.der"
key_file = "/etc/hydra/key.der"
health_addr = "127.0.0.1:8081"
```

---

## 协议规格（客户端 ↔ 节点，单条 TCP/TLS 流）

```
TCP 建连 → TLS 1.3（证书 pinning 或 CA + SNI 校验；无 ALPN；禁会话恢复）
→ [0x03][Noise-PSK 握手]   msg1(48B) → msg2(48B) → confirm_c(32B) → confirm_s(32B)
    confirm = HKDF-SHA256(handshake_hash, salt = 叶证书 SHA-256 ‖ TLS exporter, info = 方向)
→ [地址帧]  [target_len u16 大端][target]（≤1024B，域名/IPv4/IPv6:port）
→ [应答 2B] 0x00 成功 / 0x01 目标连接失败（含 SSRF 拒绝）/ 0x02 节点侧 DNS 失败
→ 双向裸转发（半关闭：一侧 EOF → 显式 shutdown 对侧写端）
```

- 握手前的任何异常（版本字节非 0x03、握手失败、超时）＝**零字节静默关闭**，无应答码回显（防主动探测）
- 目标失败属认证后的应用层错误：回 2B 应答码后关闭，客户端**不误触发节点故障切换**
- 通道绑定：confirm 绑定 **TLS 协商出的对端叶证书指纹**（pin/CA 两模式均已被 TLS 认证）+ TLS exporter（跨连接转发/重放即失效）
- **地址帧捎带**（v0.2.4 优化）：客户端可把目标地址帧并入握手尾包（msg3）一次发出——冷连接省 1 RTT；节点兼容无捎带的旧式两段发送（老客户端无感知）

---

## 项目结构

```
Hydra-Multipath-Proxy/
├── hydra-protocol/     # 协议：Noise-PSK 握手（含地址帧捎带）、TCP/UDP 帧编解码、认证 token、日志脱敏
├── hydra-node/         # 节点：TCP/TLS 服务、握手认证、SSRF 过滤、DNS 共享缓存、UDP 中继、Metrics v2、Happy Eyeballs、信号停机、toml 配置
├── hydra-client/       # 客户端：SOCKS5/HTTP、TCP 传输、温连接池（弹性 cap）、故障切换、测速调度、分流、TUN（用户态栈）、NAT/STUN、订阅
├── hydra-fetch/        # 多节点并行下载器 CLI：Range 分块 + 评分加权 + 断点续传 + 单流回落
├── hydra-core/         # 跨平台核心库：代理/调度/测速/传输/池/订阅/分流（桌面与 Android 共用）
├── hydra-client-gui/   # GUI：模块化拆分（src 共 27 个 .rs；六页导航/托盘/分享/订阅/三主题/公共组件库）
├── hydra-android/      # Android FFI 库（uniffi）：HydraEngine、start_vpn/stop_vpn（VPN 数据面）、protect 钩子、分享解析
├── android/            # Android Gradle 工程（Kotlin/Compose：全局 VPN 服务 + 本地引擎 + 三页 UI + cargo-ndk 脚本）
├── config/             # 节点 toml 样例
├── deploy/             # systemd unit / Docker / install.sh / env.example / 99-hydra-bbr.conf（BBR+fq）
├── scripts/            # 本地构建辅助（build-ui.ps1 一键出本地 GUI 测试包；Android Rust 交叉编译脚本）
└── docs/               # review（00-09 共 10 份审查报告）/ design（内核优化 13 项/UI v4/TUN/NAT/指纹等方案）/ improvement / assessment / guides
```

## 测试与质量

```bash
cargo test --workspace
```

**366 通过 / 0 失败**（30 个测试套件，2026-10-11 实测；rustls 0.23 + ring 0.17 单版本收敛，clippy `--all-targets -D warnings` 零告警；CI 为 Windows + Ubuntu 双矩阵 + cargo-audit/cargo-deny 安全扫描，badge 见顶部）。

**Linux 构建系统依赖**（tray-icon/egui 的 GTK 后端需要，CI 已内置）：

```bash
sudo apt-get install -y libxkbcommon-dev libwayland-dev libx11-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
```

TCP 转型验收门（[tests/test_tcp_transport.rs](hydra-client/tests/test_tcp_transport.rs)）：
- 64KB / 1MB / 10MB 三档 E2E 回显逐字节相等（10MB 走 SOCKS5 代理全链路）
- 错误 PSK → 静默关流，无可区分应用错误码
- 半关闭：写端 shutdown 后读端收到完整回显 + 干净 EOF
- 默认传输 = TCP；多节点测速动态调度路由切换

覆盖还包括：握手双栈互通/篡改拒绝/真重放拒绝；SSRF 拒绝；分流直连；日志脱敏；二维码往返；流量统计与按节点计数；恢复探测；STUN 编解码与 NAT 分类；节点信令路由与 loopback 同时打开打洞端到端（含**同时打开握手角色按地址序对偶**回归）；**温命中 e2e**（idle=30s 注入后 11.5s 交付仍命中 / idle=2s 负例）；TUN 路由计算与用户态栈回环。

## 故障排查（FAQ）

| 症状 | 原因与处理 |
|---|---|
| `未设置 HYDRA_AUTH_KEY 环境变量` | 密钥没配到当前进程。**分享链接用户**：v0.2.4 起 CLI/GUI/Android 直传 `hydra://` 链接即自动配置（GUI 首启向导粘贴链接即可）；**手动 env 用户**：`export HYDRA_AUTH_KEY=<64 hex>` 后再启动 |
| GUI 双击打不开 | 大概率**单实例冲突**：已有实例在后台（托盘里找），会弹提示框；仍无反应则删 `%APPDATA%\hydra\config.json` 重试并用 `RUST_LOG=debug` 收集日志 |
| 托盘右键退出无响应 | v0.2.4 已修复（退出即时收敛）；旧版本请用任务管理器结束进程后升级 |
| 停止代理一直转圈后报失败 | Android 端 v0.2.4 已修复（FdTransport 停机重写）；请更新 APK |
| 关闭代理后浏览器断网 | v0.2.6+ 已根治：**重新打开一次 Hydra 即自动清除残留系统代理**（日志页可见"启动自愈"留痕），此后正常启停不再复现；应急可在 Windows 设置→网络→代理 手动关闭 |
| 能连上但所有网站打不开 | ①节点侧看日志有无 `Blocked SSRF target`（不该出现，除非目标是内网）②客户端证书与节点指纹不匹配（重新分发 `hydra-node-cert.der`）③节点防火墙没放行 443 |
| TUN 模式报权限错误 | Windows 需**管理员**运行且 wintun.dll 与 exe 同架构同目录；Linux 需 root 或 CAP_NET_ADMIN |
| TUN 下 QUIC/视频网站慢 | v0.2.4 默认 UDP 经隧道；若节点 UDP 中继质量差可 `HYDRA_TUN_UDP=0` 回落（QUIC 应用自动降 TCP） |
| v4-only VPS 大量 ENETUNREACH 日志 | v0.2.4 已内置 AAAA 本地过滤自动开启；确认 `HYDRA_DNS_FILTER_AAAA` 未被设为 `0` |
| 浏览器走代理但 IP 没变 | 确认用的是 `socks5h://`（域名交代理解析）而非 `socks5://`；或直接开 TUN/系统代理 |
| 节点 443 被占用 | `ss -tlnp | grep 443` 找占用进程；或改监听端口（客户端节点地址同步改） |
| 时间不对导致 TLS 失败 | Noise-PSK 无时钟窗依赖，但 TLS 1.3 证书校验依赖系统时钟——设备时钟偏差过大会握手失败 |

## 安全模型（摘要）

| 能力 | 防 | 不防 |
|---|---|---|
| 证书固定 + Noise-PSK 握手（前向安全） | 中间人解密/篡改、PSK 泄漏后历史握手回溯解密、握手重放/跨连接转发 | 端点被攻破；CA 模式依赖公共 CA 体系（可用叶证书硬 pin 收紧） |
| 无 ALPN 标准 HTTPS 形态 → **已升级为 Chrome 近似指纹**（`HYDRA_FINGERPRINT`，ALPN h2/http1.1、certCompression-brotli、TLS1.3 套件序前置） | 特征匹配 DPI | TLS 指纹级深度分析仍可识别（rustls 扩展顺序/key_share 不可调，仅为"最大近似"非 Chrome 同款 JA3/JA4，见 [指纹方案](docs/design/ClientHello指纹模仿方案与实施.md)）；自签模式有固有证书指纹（真证书路线消除） |
| 域名节点侧解析 + 日志脱敏 | 本机/节点明文浏览记录泄漏 | 应用层泄漏（WebRTC 等需应用侧处理） |
| 私有线缆格式 | 现有公共协议（Trojan/SS/VMess 等）DPI 规则 | 为本项目定制的新规则（用户基数小，性价比低） |

## 已知限制（如实标注）

- **单连接单流**：TCP 下无多流通道聚合（V3.4 已随 QUIC 移除）；连接级加权分发保留；温连接池为预热式（每请求仍独占一条节点连接），单连接多目标复用需 v4 帧化协议
- TUN 已交付（含 UDP-over-proxy 接管、DNS 经隧道、TCP 全端口动态接流），已知边界：无域名分流；动态监听上限 256 端口；Wintun 全链路 + 真机 v6 接管需管理员人工验证
- Android kill switch 为应用级：重连切换存在**毫秒级直连窗口**（先放旧黑洞再建新黑洞的权衡，反向依赖 OEM 原子替换行为）；分应用白名单下阻断范围为白名单应用；进程被杀则阻断消失恢复直连；数据面静默死亡（罕见路径）暂不触发自动重连——**OS 级保障请开启系统 Always-on「始终开启 + 屏蔽无 VPN 网络」**（specialUse 服务类型已不受 Android 15+ 自启/超时限制）；VPN 模式统计带（发送/接收/时长/活跃）暂未上报（FFI 缺 vpn_stats 接口，已排期下批）
- NAT 穿透已交付 v1：对称型 NAT 打洞成功率有限（自动回落节点中继）；真实 NAT 组合环境（hairpin/EIF/端口漂移）需人工实网验证
- 分流为域名后缀版（无 GeoIP）；订阅为自有格式（不对接机场）
- 分享链接含完整凭据时等同于交付节点，仅限可信渠道
- TCP 链路认证失败与目标失败在客户端侧均表现为建连失败（节点侧已认证后的目标失败有 2B 应答码）
- GUI 信任双路线均已支持：自签 pin 模式（默认）+ 真证书 CA 模式（设置页 trust=ca + 可选叶证书 SHA-256 硬 pin）
- **密钥落盘威胁模型（如实）**：Windows GUI 的认证密钥**明文**存于 `%APPDATA%\hydra\config.json`（依赖用户目录 ACL 保护，仅本机当前用户可读；DPAPI 加密待做）；Linux CLI 0600 文件权限；Android EncryptedSharedPreferences（Keystore 硬件级主密钥）。本机管理员/root 可读取——本工具不防本机高权限攻击者


## 开发路线

- [x] Phase A：认证接线、证书固定、故障切换、SSRF/资源上限、防追踪特征正常化（2026-10，QUIC 时代）
- [x] V3.2：Noise-PSK 握手 v2 双栈（2026-10）
- [x] 分享体系 v2：凭据链接 + 二维码 + 订阅 + 托盘（2026-10）
- [x] **TCP 转型 Wave 1-3：TLS + Noise-PSK + 私有帧新协议核心 → 默认传输切 TCP → QUIC/UDP 死路径删除（2026-10）**
- [x] **代码审查 45 项 + P0/P1 修复：故障切换语义、slowloris 防护、idle 看门狗、日志脱敏、PSK fail-fast（docs/review/05）**
- [x] **交付批次：真证书（PEM/ACME）路线 + 多节点证书配对根治 + BBR 部署加固（2026-10）**
- [x] **NAT 穿透 v1：TCP STUN + 节点信令（属主证明/限速）+ 同时打开打洞 + 中继兜底（docs/design/NAT穿透方案.md）**
- [x] **TUN 透明代理 v1 完整版：smoltcp 栈 + 路由豁免 + IPv6 双栈正向代理（动态 AnyIP）+ UDP ICMP 快速回落（docs/design/TUN模式方案.md）**
- [x] UI 重设计 P0-P2 第一至三批：节点页组视图/卡片化、订阅「＋ 新建」聚合入口、首页卡片式仪表盘（egui_plot 速率曲线）、设置页七分区折叠、palette 视觉规范全量应用（[方案 v3](docs/design/UI重设计方案-v3.md)；连接页已交付，剩余：main.rs 模块化拆分）
- [x] **全量代码审查 09 + P1/P2 修复：资源生命周期（连接看门狗/keepalive/计数表上限/sid 回收）、调度劫持（f64 校验/Online 下线探测）、GUI TUN 竞态降级、SSRF 单源、UDP 中继连接超时/DNS 缓存（docs/review/09）**
- [x] **Android M2 全局 VPN + M2.1 VPN 保护：VpnService 全接管 + TCP 任意端口动态接流 + DNS 经隧道 + kill switch 断线阻断自动重连 + 开机自启 + 分应用代理白黑名单（2026-10，v0.2.2 + Unreleased）**
- [x] **性能与运维批次：温连接池（每请求省一次节点握手）+ 节点 v4-only 降噪（DNS AAAA 本地过滤 + v4 优先建连）+ 托盘菜单禁用态 + 节点 /metrics（Prometheus）+ GUI 模块化拆分 21 文件（2026-10）**
- [x] **多节点并行下载 v1（CLI）**：`hydra-fetch`（Range 分块按节点评分加权 + 断点续传 + 单流回落 + keep-alive 隧道复用；方案经设计评审修正——公开低层 API 组合，hydra-core 零改动）（2026-10；GUI 前端待产品需求）
- [x] **UI v4 企业级设计 + v4.1 落地**：设计团队方案（55 条启发式审计 + Design Tokens 对比度实测）→ 状态三通道编码/公共组件库/破坏性确认 → 三主题运行时体系（Dark/Light/Abyss）+ 首页重排（2026-10，[方案 v4](docs/design/UI设计方案-v4-企业级.md)）
- [x] **CLI 分享链接自动配置**：`hydra://` 直传 CLI 即全配好（与 GUI/Android 一致，功能缺口补齐，2026-10）
- [x] **内核优化 13 项（四批）**：温池 stale 短超时 / 握手捎带 5→4 RTT / Metrics v2 / 弹性温池 / 节点 DNS 共享缓存 / Happy Eyeballs 并行建连 / UDP 分层缓冲 + 单调钟 / 节点侧 TFO / 评分归一化 / keepalive + TCP_USER_TIMEOUT（方案评审修正后执行，code review 回顾 3P0 修复，[执行方案](docs/design/内核优化执行方案-13项.md)）
- [x] **P2P 打洞同时打开握手角色修复**：角色按地址序分配（低=client）——真·同时打开时连接两端都是出站 socket，按连接方向分配会双端同为 client 互相等 msg2 而全败（2026-10）
- [ ] eframe/egui 升级 0.27→0.33+（根治 webbrowser 漏洞告警 + unmaintained 依赖群；21 文件 GUI 需适配）
- [x] ClientHello 指纹模仿（调研结论：ja-tools fork 供应链风险高，落地为 stock rustls 最大近似 + `HYDRA_FINGERPRINT=chrome|none`，[方案与实施](docs/design/ClientHello指纹模仿方案与实施.md)）
- [x] 门③重放测试以 TCP 形态重写（`hydra-protocol/src/handshake.rs` 真重放单测在库，roadmap 此前未勾——09 审查补正）
- [x] **rekey Tier1：连接最长寿命策略**（`HYDRA_MAX_CONN_AGE_SECS` 节点双侧 + 客户端 UDP 通道轮换；rustls 已自动刷新 TLS 流量密钥——定位防御纵深，2026-10）
- [ ] rekey Tier2（v3.3 正体）：**snow 0.9.6 具备完整 rekey API 但现协议 Noise 仅做认证（数据面 = TLS 1.3），对现协议无效果**——并入 v4 帧化协议一并决策（v4 数据面若为 TLS：换钥 = rustls refresh_traffic_keys 公开 API；若为 Noise 帧化：snow rekey 才有意义）

完整依据：[docs/design/TCP转型与加密选型方案.md](docs/design/TCP转型与加密选型方案.md) · [docs/review/00-审查总览与改进目标.md](docs/review/00-审查总览与改进目标.md)

## 许可证

**PolyForm Noncommercial 1.0.0 + 补充条款** — 见 [LICENSE](LICENSE)。

- **禁止商用**：任何商业性使用须事先获得版权所有者书面授权（联系方式见 LICENSE 补充条款与仓库主页）
- **限制地区**：禁止在法律法规禁止使用加密隧道/代理软件的司法管辖区安装、部署或使用本软件
- **合规责任**：使用者须自行遵守所在司法管辖区的全部适用法律，违规后果自负
- **追溯适用**：本许可证适用于本项目的**全部版本**——历史版本（此前以 MIT 公开的快照）同样不再允许任何商业使用，未来版本亦然
- 2026-10-05 前的 MIT 许可声明已被本许可证取代，不适用于任何商业场景

## 联系方式

- 项目: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)
- 安全漏洞: [Security Policy](SECURITY.md)（勿走公开 Issues，私密报告）
