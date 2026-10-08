# 更新日志（Changelog）

本项目所有显著变更记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased] - Android M2（全局 VPN + 任意端口 + DNS 经隧道）

### 新增

- **Android M2 全局 VPN**（VpnService）：`HydraVpnService`（establish TUN → fd
  交付 Rust 用户态栈 → 节点加密隧道）；consent 授权流程、onRevoke 系统撤销、
  通知停止动作、启动代数看门狗（20s 超时）；运行模式切换（设置页"全局 VPN/
  本地端口"双选）；VpnProtectHolder 进程级 protect 委托（code review 发现的
  陈旧服务引用问题——Rust 钩子首装生效后 Kotlin 侧更新 handler，实例销毁置空）
- **TCP 任意端口动态监听**（M2/R1）：SYN 驱动挂 listener（上限 256）——
  smoltcp 无通配监听的运行时补齐，全部 TCP 端口自动接流（tun.rs
  `tcp_syn_dst_port` + `ensure_dynamic_listener`；Rust FFI start_vpn/stop_vpn）
- **DNS 经隧道**：系统 DNS（v4/v6）随全局路由进节点解析（加密无泄漏）
- tun-core feature（hydra-client）：Android 复用用户态栈（PacketTransport 抽象
  + run_stack）不依赖 tun2 桌面设备层；gen-bindings.sh 改从 Android .so 生成

### 修复（code review 发现）

- **[高] protect 钩子陈旧引用**：start_vpn 的 Rust 钩子首装后捕获第一个
  HydraVpnService 实例，服务重建后旧引用导致 protect 永远失败 → 零流量。
  修为 VpnProtectHolder 进程级委托
- **[中] tcp_syn_dst_port v6 flags 偏移错位**（pkt[54]→pkt[53]）——新单测
  抓出的真实 bug，v6 SYN 端口解析此前恒返回 None
- **[低] 日志字符串拼接优先级**修正

### 新增测试

- R1 单元测试：tcp_syn_dst_port（v4/v6/SYN+ACK/UDP）、动态监听挂载/去重/上限

## [Unreleased] - 桌面 TUN UDP-over-proxy 接管 + DNS 经隧道（TUN 方案 v2 方向落地）

### 新增

- **TUN UDP-over-proxy 接管**（默认开，`HYDRA_TUN_UDP=0` 关闭）：公网目标 UDP
  （QUIC/HTTP3/DNS/P2P）不再代答回落 TCP，而是经节点 UDP 中继**加密隧道**
  转发——v4/v6 双栈；回包按流表（sid → 四元组）精确反解构造注入 TUN；
  中继通道断线自动重连（指数退避，每次按调度器当前最优节点）；keyed 会话
  支持多客户端 socket 到同一目标（`UdpChannel::send_to_ext/recv_from_ext`）；
  节点单连接会话上限 64 → 256（TUN 全流量场景）。端到端测试：进程内真节点
  + mock TUN 回环（`run_stack_udp接管_真节点mock回环端到端`）。
- **DNS 经隧道**（默认开，`HYDRA_TUN_DNS_DIRECT=1` 恢复 v1 直连）：公网系统
  DNS 不再自动豁免出物理网卡——查询随 UDP 隧道经节点解析（加密、无明文
  泄漏，TUN 方案明示的 v2 方向）；用户显式 `HYDRA_TUN_DNS` 恒豁免（内网
  resolver）。
- 客户端 TUN UDP 分发尊重 `HYDRA_ALLOW_PRIVATE_TARGETS`（与节点侧同款开关）：
  自建 LAN 节点场景放开私网目标入隧道（组播/广播恒拦）。

### 变更

- README/TUN 交付状态与已知边界同步重写：UDP 接管与 DNS 经隧道移入"已交付"。

## [Unreleased] - Android M1 + 审查 09 收尾（上批遗留技术项清账）

### 新增（Android M1）

- **真机可跑的本地代理应用**：Compose UI（节点多行/SNI/认证密钥掩码/自签 pin 与
  CA 双模式/证书 DER 导入/本地端口）→ 前台服务持有 HydraEngine（防 Android 11+
  Cached App Freezer 冻结后台进程，通知栏实时流量/连接数）→ EncryptedSharedPreferences
  密钥存储（R8 必须项：Keystore 主密钥 AES256-GCM，allowBackup=false）。
  cargo-ndk 交叉编译 arm64-v8a + x86_64 release so；桌面 JVM 冒烟回归通过。

### 修复（审查 09 上批遗留，P3 清账）

- **speedtest 并发探测**（限流 4）：串行探测 N 个离线节点最坏 5N 秒/轮、恢复延迟
  随节点数线性增长——拆分"并发探测/串行应用"后单轮 ≈ ⌈N/4⌉×5s。
- **NAT STUN 容错**：并发探测前 3 个服务器收集成功结果（此前只取前 2 个且
  `try_join!` 任一失败整体失败）；多服务器映射两两交叉比对防漏判。
- **STUN 事务 ID 换 `ring::rand`**（此前时间戳+计数器 xorshift 有效熵远低于 96 位）。
- **`proxy.rs` 远端 FIN 排水分支不再丢弃上行任务真实错误**（与对称分支一致）。
- **share_link**：`with_auth_key_bytes` assert→Result（builder 链上非法输入显式
  报错而非崩溃，GUI 调用点同步更新）；`with_cert_fp` 与解析侧同规则校验 64 hex；
  域名节点 `to_node_info` 报清晰错误；`parse_base64_share_links` 失败行告警 +
  支持 URL_SAFE_NO_PAD 变体（此前静默丢行）；`hex_encode_lower` 查表替换逐字节
  format!（叶证书 pin 热路径）。
- **节点**：`HYDRA_AUTH_MODE` 非 v3 启动期显式告警（TCP 仅实现 v3，此前静默拒绝
  一切连接无迹可查）；UDP 中继连接关闭时汇总 `overlimit_drops` 日志（此前完全
  不可观测）；fallback 伪装页补 `Date` 头（缺失即可被动统计的指纹）。
- **TUN**：私网目标 UDP 到达栈侧（豁免路由未生成的降级场景）静默丢弃，不再对
  内网目的回 ICMP 差错。
- **GUI/CLI**：配置临时文件名加 pid 唯一化（修双实例并发保存交错覆写坏配置）；
  **双实例互斥**（CLI-TUN 端口 52810 / GUI 端口 52811，内核级进程锁，崩溃自动
  释放——防两个 TUN 实例争抢路由/两 GUI 争抢系统代理状态）。
- **cert.rs 补测试**（此前零覆盖）：rcgen 生成真 PEM 对 → parse_pem_pair 往返
  + 坏输入显式报错。

### 文档

- README 已知限制补密钥落盘威胁模型（Windows 明文/ACL、Linux 0600、Android
  Keystore；不防本机高权限攻击者）。

## [0.2.1] - 2026-10-07

> 本版本包含两批交付：**全量代码审查 09 修复**（P1 全部 7 项 + P2 主体 + 文档清账）
> 与 **Android M0 骨架**。审查报告：[docs/review/09-全量代码审查报告.md](docs/review/09-全量代码审查报告.md)。
> 7 路并行深审（协议/数据面/服务/服务端/TUN/GUI+Android/框架符合度），P0 为零；
> 本批次修复 P1 全部 7 项、P2 绝大多数、以及文档/构建阻断项。clippy 零警告、
> 全工作区测试通过（304 项）。

### 安全与资源（P1）

- **节点 UDP 中继连接级空闲看门狗**（300s 无上行帧即主动关闭）——半开/静默
  连接此前可永久钉满连接额度（1000 条即全节点拒绝服务）；TCP/信令路径已有
  同款防护，UDP 新路径补齐。
- **客户端出站连接 TCP keepalive**（idle 60s/interval 10s，socket2）+ 全部
  出站建连收口 `connect_tcp_protected`——对端静默死亡（掉电/断网/NAT 回收）
  时中继双向 read 永久挂起、任务与缓冲泄漏。
- **不可达目标计数表加 60s TTL + 10 万条容量上限**——此前 key 空间无界，
  `--listen 0.0.0.0` 时任意 LAN 主机可分钟级注入数百 MB 内存。
- **分享链接数值参数范围校验**（`is_finite` + 上下界）+ 调度器写回入口防御
  clamp——恶意订阅 `bandwidth=NaN`（约 50% 概率胜出全部健康节点）/
  `loss_rate=-1e300`（评分恒第一且测速永不覆盖）的持久调度劫持封死。
- **客户端 UDP 会话号回收**：映射表 4096 容量上限 + LRU 淘汰复用 sid（淘汰
  先发下行 close，节点按换绑定语义重建）——此前单调分配永不回收，一次性
  目标高频出现约 1 小时耗尽 u16 空间，整条 UDP 通道永久报废。
- **GUI TUN 失败降级**：就绪信号与 TUN 失败信号竞态时（此前失败只进一行日志）
  自动回退设置系统代理并显著告警——不再出现"显示 TUN 已全局接管、实际流量
  明文直连且无系统代理"的错误安全态势。
- **Android R4 protect 全链路接线**：`hydra-core` 新增进程级出站 socket 保护
  钩子（`socket_protect` 模块），节点连接/直连建连均经 `TcpSocket` 阶段回调；
  `SocketProtect` 接口改为返回 `bool`，protect 失败即中止该连接（放行 = 回环）。
  uniffi Kotlin 绑定已再生成。

### 服务端（P2）

- UDP 中继：连接内 DNS 结果缓存（TTL 60s/128 条）+ 真实解析速率预算（1s
  窗口 ≤10 次）——封堵"同 session 换目标逐帧 getaddrinfo 打满 tokio blocking
  池、跨连接拖垮全节点 DNS"的放大路径；会话任务异常退出经通道上报、主循环
  删表项并下行 close（修僵尸会话黑洞）；会话满下行 close 通知客户端；上行
  `try_send` 失败区分队列满与会话已死。
- **SSRF 判定收敛单源**：`handler::classify_blocked_ip` 为唯一实现，UDP 路径
  复用（此前镜像已分叉）；补齐 TEST-NET-1/2/3、192.0.0.0/24——并修正上轮
  引入的 2001:db8::/32 段值笔误（`0x01db`→`0x0db8`，该段从未真正命中）。
- 信令：跨连接下行投递限时 5s（防黑洞客户端楔死他人信令连接）；写任务超时
  无条件 abort（修 fd/TLS 写半泄漏）；invite 日志脱敏 + `mask_peer_id` 多字节
  安全。
- **per-IP 并发连接上限**（默认 256，`HYDRA_PER_IP_CONNECTIONS` 可调，0=关闭）
  ——防单主机 ~25 conn/s 轮换钉满全部连接额度；accept 错误循环加 100ms 退避。
- `main.rs` 未知 CLI 参数/无法解析的位置参数显式报错退出（此前 `--confg`
  typo 会以默认 0.0.0.0:8080 静默启动）。

### 客户端 core（P2）

- HTTP 头阶段总 deadline（30s）——修 slowloris（逐段读重置 30s 超时、单连接
  可存续约 22 天）。
- Online 节点活性探测（连续 3 次失败转 Degraded，恢复探测成功即回 Online）；
  探测升级为**完整握手**（TCP+TLS+Noise-PSK+地址帧，目标用 UDP 中继保留前缀）
  ——修"Online 永不下线"与"PSK 错配时节点永久振荡"两个叠加缺陷。
- SOCKS5 greeting/request 改为分片安全的增量 `read_exact` 解析 + 方法协商
  修正（客户端未提供 no-auth 时回 0xFF 而非违约回 0x00）+ 请求后捎带早发
  数据不再丢弃。
- HTTP authority 解析重写：剥 userinfo、`rsplit_once(':')`、非法端口显式 400
  （此前 `evil.com:443x` 静默改连 80、裸 `::1` 产出空 host）。
- 本地协议错误不再误标健康节点 Offline（畸形 Host 头此前可连锁误标 3 个候选）；
  调度器平分取向统一（地址升序）；节点初始带宽下限 10.0（>10 节点时不再为负）。
- `connection_closed` 饱和递减（修 reset 竞态回绕 u64::MAX）；连接注册表
  prune 去除 O(n) 深拷贝。
- NAT：信令下行行读带 4096 上限（防无换行长行耗内存）；打洞候选截断 ≤32 条。
- `tcp_transport` 写地址帧补 5s 超时（建链序列最后一个无超时 I/O）。

### TUN（P2/P3）

- **私网段豁免路由**：RFC1918 + CGNAT（v4）、ULA fc00::/7（v6）回物理网关
  ——修"能上外网但访问不了路由器/NAS"（私网目标此前进 TUN 被节点 SSRF
  fail-closed 拒绝且无日志）；栈侧对私网 TCP 兜底丢弃 + 一次性告警。
- ICMPv4 全部静默丢弃（此前 smoltcp any-ip 对任意 IPv4 地址伪造 ping 应答）；
  IPv4 分片包（MF/offset）不再投喂栈；IPv6 组播目的/未指定源包静默丢弃
  （上轮 v4 修复的同源 v6 遗漏）。
- 系统 **IPv6 DNS 探测**（`detect_dns_servers_v6`）并入 v6 豁免——修纯 v6
  网络 DNS 失效与"v6 DNS over UDP 被拒 / over TCP 被代理"的分叉；Windows
  注册表只取 NameServer 行（不再把 DhcpIPAddress 等误收进豁免）。
- `stack_buf` 分配真正提到主循环外（06-P3-8 修复意图复核未达成，本次落地）。

### GUI / Android（P2）

- GUI：代理线程就绪前 panic 的 Disconnected 分支补清 stop_flag/handle/
  exit_receiver（修"启动代理"永久被拒，仅托盘可恢复）；导入分享链接覆盖
  全局密钥前显式告警（掩码前后值）；节点页"全部测速"按钮加进行中守卫。
- Android：节点地址解析失败显式报 `InvalidConfig`（此前域名节点被静默过滤、
  引擎以 0 节点"成功启动"）；JNA 依赖改用 **aar 变体**（此前桌面 jar，
  真机必 UnsatisfiedLinkError）；`build-rust.ps1` 断行字符串修复。

### 文档清账

- README：删除已实现的"无 UDP-over-proxy"与"GUI 仅 pin 模式"表述、残留死
  变量 `HYDRA_AGGREGATE`；补 `HYDRA_PER_IP_CONNECTIONS`/私网直连说明；
  roadmap 勾选已完成的门③ TCP 形态重放测试与连接页。
- 修正 TUN IPv6 默认值三处矛盾（CHANGELOG 0.2.0 历史条目保留原文，现状以
  README 为准：默认**开**）。
- 审查 08 遗留 4 条 P3（send_to 先登记后编码 / touch 锁外竞态 / is_full
  保留 / 测试 set_var）随本批次处理或在代码注释中如实标注。
- 审查报告与修复记录：[docs/review/09-全量代码审查报告.md](docs/review/09-全量代码审查报告.md)。

#### Android M0：hydra-core 抽取 + 工程骨架

##### 新增

- **hydra-core crate**：从 hydra-client 抽取 12 个平台无关模块（tcp_transport/
  proxy/nat/udp_relay/scheduler/speedtest/connections/routing/subscription/
  share_link/traffic/transport + 新增 `channel` 通道开启器抽象）为跨平台核心库，
  桌面与 Android 共用；零 env 读取、零平台专有代码，凭据一律显式参数传入。
- **hydra-android crate**：cdylib + uniffi 0.29 导出 `HydraEngine`
  （new/start/stop/boundAddr/stats，显式 NodeSpec/TrustMode/PSK hex 参数）与
  `SocketProtect` 回调接口（v2.1 R4 防环回钩子，Kotlin 调 `VpnService.protect`；
  运行时接线随 M2 tun_core）。附 Rust 冒烟测试。
- **android/ Gradle 工程**：Kotlin 2.2 + Compose（BOM）最小骨架；版本集中
  libs.versions.toml；abiFilters arm64-v8a + x86_64；R8 keep 规则（uniffi/JNI）；
  cargo-ndk 交叉编译脚本（scripts/build-rust.*）；JVM 单测注入 java.library.path，
  桌面直接加载 host 动态库跑 uniffi 启停冒烟（EngineSmokeTest）。
- uniffi Kotlin 绑定生成器（hydra-android 的 uniffi-bindgen bin）与再生成脚本。

##### 变更

- hydra-client 瘦身为桌面壳：全量 re-export hydra-core（GUI/CLI 引用路径不变），
  保留 tun.rs、env 凭据函数、TUN 配置构造、Windows 系统代理检测等桌面专有封装。
- workspace 新增成员 hydra-core、hydra-android；hydra-client 依赖收敛（rustls 等
  随模块移入 hydra-core）。

##### 修复

- 存量测试笔误三处：udp_frame.rs / udp_relay.rs 测试漏 `.unwrap()`；
  connections.rs 测试缺 `IpAddr` import；`test_eviction_cap` 自相矛盾断言
  （既断言淘汰最旧又断言最旧保留）修正为断言次新条目保留。

## [0.2.0] - 2026-10

> 0.2.0 是一次**路线级变更**：传输层从 QUIC/UDP 全面转向 TCP/TLS（因部署网络
> 存在 UDP 回程 QoS 丢包，tcpdump 实证），并在此基础上补齐真证书、NAT 穿透、
> TUN 透明代理三大交付批次。

### 新增

- **TCP/TLS 传输**（tokio-rustls，TLS 1.3）：无 ALPN、SNI 可自定义、节点证书
  固定（Pinning）；流量形态 = 普通 HTTPS 访问。
- **真证书（ACME）部署路线**：节点直接挂 PEM fullchain/key
  （`HYDRA_CERT_FILE`/`HYDRA_KEY_FILE`），客户端 `HYDRA_TRUST=ca` 信任公共 CA，
  可选叶证书 SHA-256 硬 pin（`HYDRA_CERT_SHA256`）防 CA 误签发——证书轮换不再
  破坏 pinning。
- **Noise-PSK 应用层握手**（snow NNpsk2）：前向安全、抗重放；confirm 以服务器
  叶证书 SHA-256 指纹 + TLS exporter **双通道绑定**，多节点部署零配对成本。
- **私有帧协议**：握手后 `[u16 BE 地址长度][目标地址]` + `[2B 应答码]`；认证
  失败零字节静默关流（无回显错误码，抗主动探测）。
- **NAT 穿透 v1（实验性）**：TCP STUN（RFC 5389）公网地址发现 + NAT 行为分类；
  节点信令（`HYDRA_P2P_SIGNAL=1`）协调下的 TCP 同时打开打洞，失败自动回落节点
  中继（CLI `--p2p/--peer/--node`）。
- **TUN 透明代理模式 v1**（feature `tun`，默认开启）：`0.0.0.0/1 + 128.0.0.0/1`
  路由接管 + 节点 IP/DNS 豁免 + 幂等清理，smoltcp 用户态栈终结后经既有节点链路
  转发（仅 TCP；`HYDRA_TUN_*` 系列环境变量配置）。
- **TUN IPv6 防泄漏**：TUN 模式可选对称接管 `::/1 + 8000::/1`（`HYDRA_TUN_IPV6=1`
  开启，默认关——用户态栈仅支持 IPv4，开启后 v6 包以 RST/ICMPv6 不可达快速
  失败回落 v4；节点 IPv6 地址进豁免清单；路由命令失败仅告警不阻断启动）。
- **节点转发空闲看门狗**（`HYDRA_IDLE_TIMEOUT_SECS`，默认 300s）防连接额度耗尽；
  节点 BBR + fq 一键内核调优（deploy/99-hydra-bbr.conf）。
- **密钥文件化**（节点 `HYDRA_AUTH_KEY_FILE`，Unix 0600 校验）替代 env 泄漏面。
- **分享体系 v2**：`hydra://` 链接携带完整凭据（`tp=tcp`，legacy `tp=quic` 告警
  回退）、二维码生成/识别、订阅导入、认证密钥恰好 32 字节双层校验。
- **桌面 GUI**（egui）：导航六区、系统托盘、配置持久化、Windows 系统代理一键
  开关、节点完整握手测速（TCP+TLS+Noise，密钥错误可区分，不再"假绿"）。
- **CI 与发布产物**：GitHub Actions 双矩阵（Windows/Linux）build/test/clippy；
  tag 触发 release（Windows 客户端 zip + Linux 节点 tar.gz）。

### 变更

- **默认传输切为 TCP**；分享链接缺省 `tp` 视为 `tcp`；`HYDRA_TRANSPORT=quic`
  告警回退 TCP。
- 客户端多节点故障切换/加权调度适配 TCP 链路：认证失败不误触发节点下线，
  目标失败（TargetUnreachable）不计节点故障、不污染评分。
- GUI 节点测速从"仅 TCP connect"升级为完整 `connect_target`（Noise-PSK 认证 +
  节点应答），错误分类：目标不可达 = 节点健康 ✓；握手失败 = 密钥错误 ✗；
  连接超时 = 节点不可达 ✗。
- `deploy/install.sh` 升级场景（unit 已存在且服务 active）安装后自动
  `systemctl restart hydra-node`；全新安装行为不变。
- `deploy/env.example` 与节点现状逐项对齐（补 `HYDRA_IDLE_TIMEOUT_SECS`、
  `HYDRA_P2P_SIGNAL` 等，移除 QUIC 残留项）。
- 全 workspace 版本统一 0.2.0；README 交付叙事按三视角评审校正
  （已交付 / 实验性 / 规划中三档）。

### 移除

- **QUIC/UDP 传输路径全量删除**（含 V3 协议的多流通道与字节级多路径聚合
  V3.4、obfs UDP 全包混淆模块 hydra-obfs crate）——git 历史可考。
- QUIC 时代环境变量（`HYDRA_MODE`/`HYDRA_OBFS_KEY`/`HYDRA_CC`/
  `HYDRA_BRUTAL_MBPS`/`HYDRA_STREAM_WINDOW`/`HYDRA_CONN_WINDOW`/
  `HYDRA_CHANNELS`/`HYDRA_AGGREGATE`/`HYDRA_STUN_ADDR`）。

### 已知限制（如实声明）

- TUN 仅接管 TCP（UDP 含 QUIC/HTTP3 在 TUN 内丢弃）；smoltcp 仅 IPv4 + 按端口
  列表监听；无 DNS 劫持；TUN 模式下 CN 域名分流失效。
- 单连接单流：TCP 下无多流聚合；连接级多节点加权分发保留。
- NAT 穿透为实验性：对称型 NAT 打洞成功率有限，中继兜底为主路径。
- GUI 暂仅支持自签 pin 模式（真证书部署走 CLI）。
- ClientHello TLS 指纹与浏览器有差异（规划项）。

## [0.1.0] - 2026-10

QUIC 时代初始版本：SOCKS5/HTTP 代理 → QUIC 多路复用隧道 → 多节点，
含认证接线、证书固定、故障切换、SSRF 过滤与分享体系 v1（详见 git 历史）。

[0.2.0]: https://github.com/fuzhusi/Hydra-Multipath-Proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fuzhusi/Hydra-Multipath-Proxy/releases/tag/v0.1.0
