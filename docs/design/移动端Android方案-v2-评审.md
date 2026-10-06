# 评审报告：《移动端Android方案-v2 —— 基于 TCP 转型后架构》

> 评审人：资深移动端架构师（Android + Rust 交叉方向） ｜ 评审对象：`docs/design/移动端Android方案-v2.md`（v2，2026-10-05 定稿稿）
> 评审环境：只读检查了 workspace 根 `Cargo.toml`、`hydra-client/src/` 全部 14 个源文件（含 `tun.rs` 2776 行、`proxy.rs` 1179 行）、v1 方案文档、README。
> **总体结论：需修订后开工**。方向（Rust core + Kotlin 壳 + VpnService）正确，但 v2 对「smoltcp 直喂 VpnService fd」这条最险路线的三大已知坑（通配监听、DNS、环回保护）一个都没有覆盖，且抽取边界描述与实际代码不符。修订清单见 §6，共 12 条。

---

## 1. 架构正确性

### 1.1 VpnService fd → smoltcp 路线的三个未覆盖的关键风险（最高优先级）

v2 §2（L44）称「Android 直接复用同一栈读 VpnService 的 fd」，§1（L19）称「tun.rs 的栈逻辑可抽取共用」。但对照 `hydra-client/src/tun.rs` 的模块文档，桌面 v1 TUN 有三条**已声明的限制**，在桌面场景可接受、在手机全局 VPN 场景是**致命或近致命**的，v2 全文未提：

**① 无通配监听 → 非白名单端口全部被 RST。**
`tun.rs` L25-27 与 `TunConfig` L73-74：smoltcp 只能按端口 LISTEN，桌面默认只拦 `80/443/8080/8443`，其余端口回 RST、应用表现为连接被拒。桌面用户可以改 `HYDRA_TUN_PORTS`，手机全局 VPN 里用户装一个用 993（IMAPS）、5228（GCM/FCM）、游戏端口、P2P 的 App 就直接坏。v2 §4 的决策表、§5 的 M2 验收标准（「手机全局流量经节点」）与该限制直接矛盾。**这是方案成立与否的前置问题，必须在 M2 之前给出解法**（备选：仿 tun2socks 思路在栈外包一层「未知端口也接受连接、目标按原始 IP+port 透传」的自定义处理——smoltcp 侧给每个流建 socket 是可行的，但这是新开发量，不是「复用」）。

**② DNS 路线与 VpnService 模型冲突。**
`tun.rs` L24 与 `lib.rs` L123：桌面 v1 无 DNS 劫持/fake-IP，DNS 服务器走豁免路由**直出物理网卡**。Android 上：
- 系统 DNS 由 `VpnService.Builder.setMtu/addDnsServer` 下发，指向的 DNS 流量会进 TUN（除非用 `addRoute` 精细排除，而公共 DNS 排除后手机可能根本拿不到可用解析）；
- v1 方案（L74）曾明确设计「tun2socks domain 模式把域名透传给 SOCKS5，手机本地不解析」——v2 去掉 tun2socks 后这条**天然占优的 DNS 设计随之消失**，却没有任何替代表述。
若沿用桌面「DNS 豁免直出」，等于手机明文 DNS 直连，既有泄漏面也有被运营商劫持的现实问题。**v2 必须补 DNS 设计**（建议：TUN 内劫持 53 端口 UDP/TCP → 域名透传给节点解析，即 v1 已有的 A6 能力；这同时要求栈侧支持 UDP 53 转发，见 ③）。

**③ UDP「直接复用」表述失实。**
v2 §1 L20、§4 L71 称 UDP 中继「直接复用」「可达」。但 `tun.rs` L15-17：桌面 TUN v1 **仅 TCP 转发**，IPv4 UDP 回 ICMP port unreachable。UDP-over-proxy 中继交付的是**协议层**能力（节点侧），而 **TUN 侧 UDP 会话表/端口映射/NAT 行为**是全新代码（可参考 `nat.rs` 的既有 NAT 逻辑，但接线不存在）。v2 把它写成免费复用，会直接低估 M2 工作量。

**④ 环回保护：Android 与桌面机制完全不同，方案未提。**
桌面防环路靠系统路由豁免（`route add`，`tun.rs` L355-705 的 RouteExecutor）。Android 上对应机制是两条：
- `VpnService.Builder.addRoute()` 只把需代理网段送进 TUN（排除节点 IP 网段——`compute_routes` 的纯函数逻辑可复用，Executor 换成 Builder 调用，这部分抽取判断 v2 是对的）；
- **但更关键的是 `VpnService.protect(fd)`**：Rust 核心自己发起的到节点的 TCP 连接，若不加 protect，其出站包会被自身 VPN 抓回 TUN 形成死循环（桌面靠路由豁免天然规避，Android 必须**显式 protect 每个 socket fd**）。这要求 Rust 侧创建 socket 后把 fd 回调给 Kotlin 层 protect，或由 Kotlin 创建 fd 注入 Rust——**这直接冲击 v2 §4「接口不绑定 Android 特有概念」的 iOS 双平台接口设计**。v2 完全没有提及。这是去 tun2socks 路线区别于 v1 路线的一个核心新难点（v1 路线下 SOCKS5 服务器同样需要 protect，但 hev-socks5-tunnel 有成熟的 `protectPath` 回调机制）。

**⑤ fd 读写与 tokio 的适配。** v2 L37 说「tokio runtime 在 Rust 侧」，正确，但未说 fd 模型：`ParcelFileDescriptor.detachFd()` 拿到 raw fd 后，应用 `tokio::io::unix::AsyncFd` 注册非阻塞读写（TUN fd 支持非阻塞），这是成熟做法但需要 JNI（`jni` crate）从 Kotlin 侧取 fd——接口上是一个 `int fd` 透传，不难，属「待验证」的工程细节而非风险。MTU 建议从桌面 1500 下调（手机蜂窝链路 + 加密封装，1200-1400 更稳，避免分片），v2 未提，小项。

### 1.2 smoltcp 成熟度 vs hev-socks5-tunnel（外部事实，部分待验证）

- smoltcp 定位是「嵌入式/测试用的用户态 TCP/IP 栈」，单线程轮询模型，真实桌面流量下吞吐中等；其乱序重排、窗口探查等在 0.11/0.12 持续完善，但**没有手机级海量并发短连接的生产背书**。已知的大型用户态栈替代案例（Mullvad 用自研 talpid + 原生 tun 设备 + rust 侧 wireguard，不走 smoltcp 做 TCP 终结）不能直接类比——**smoltcp 承载手机全部流量属于激进用法，待验证**。
- hev-socks5-tunnel 是 C 写的 IP 层隧道（v2rayNG/mihomo 同款），任意端口、UDP、DNS fake-IP 全覆盖，久经手机生产验证。v2 保留其作降级备选（L45）是对的，但**没有定义降级触发条件**。建议：M2 前置一个 2-3 天的 fd→smoltcp 冒刺（spike），用真实手机跑通「浏览器 + IM + 一个非白名单端口应用 + 断网重连」，不达标即切换备选，避免 M2 中途返工牵连 `android/` 工程结构。
- 折中建议：即使走 smoltcp 路线，「任意端口」问题的最稳妥解法仍是**不依赖 smoltcp LISTEN 白名单**——在 Rust 侧对入站 IP 包先做分类（TCP SYN 目的端口任意 → 动态创建 smoltcp socket 绑定该端口再接流），这属于 `tun_core` 的增强而非复用，工作量要计入 M2。

### 1.3 hydra-core 抽取边界：与实际代码清单不符

v2 §3 L53/L58 列的模块：`transport/scheduler/speedtest/connections/share_link/subscription/routing/splitter` + tun 拆分。对照 `hydra-client/src/` 实际 14 个文件：

| 实际文件 | 行数 | v2 是否提及 | 评审意见 |
|---|---|---|---|
| transport.rs | 5 | ✅ | 仅 5 行（转发壳），「传输」实体在 tcp_transport.rs |
| **tcp_transport.rs** | 476 | ❌ **漏列** | rustls+指纹+信任双路线实体在此，必须搬，v2 却只写了 transport |
| **proxy.rs** | 1179 | ❌ **漏列** | SOCKS 服务实体，M1（进程内 SOCKS）直接依赖，不搬 M1 无法做 |
| **nat.rs** | 726 | ❌ 漏列 | NAT/UDP 会话逻辑，UDP-over-proxy 的 TUN 侧接线要用 |
| **traffic.rs** | 442 | ❌ 漏列 | 流量统计，uniffi `stats()` 的数据源 |
| scheduler/speedtest/connections/subscription/routing/share_link | 147-730 | ✅ | 搬运判断正确；routing.rs L419 引用 `std::process::id()`，无 Windows 依赖，可搬 |
| lib.rs | 197 | 部分 | **含 Windows/桌面专有代码**：`windows_system_proxy_enabled()`（L148，reg 查询）、`hide_console_window()`（L133）、`auth_key_from_env()/node_certs_from_env()`（L33-61，桌面 env+文件路径模型）。这些不能进 hydra-core；且 env/文件路径读取模型在 Android 上要换成「Kotlin 传 bytes/字符串进 uniffi」——**这是 engine 接口设计的实际工作量，v2 未提** |
| tun.rs | 2776 | ✅ | 拆 `tun_core`/`tun_win` 的方向正确；但注意 2776 行中栈主循环、ICMP 生成、v6 动态 AnyIP、流管理耦合度需在抽取时先解耦，建议 M0 只做「能编译的拆分」，增强（通配端口、DNS 劫持、UDP）放 M2 |
| main.rs | 429 | —（CLI） | 留桌面，✅ |

**结论：v2 的抽取清单按文件名描述与仓库现状有出入（transport 5 行壳、漏 proxy/nat/traffic/tcp_transport），「splitter」文件不存在。** 按行数粗算实际搬运面 ≈ 5500+ 行，比 v2 列举面大；M0 估时 2-3 天偏紧，建议 3-5 天（含桌面回归手测）。

### 1.4 做对了的部分

- Rust core + Kotlin 壳总路线、uniffi 双平台接口预留、Compose UI、egui 不复用（见 §2）、单仓库、minSdk 26、保留 tun2socks 降级——判断均合理。
- 「M0 抽取后桌面行为零变化 + 全量测试作验收门」是正确的防回归手段。

---

## 2. 工程可行性

### 2.1 uniffi 2.x + tokio（可行，注意三点）

- **可行模式**：tokio runtime 由 Rust 在 `HydraEngine` 构造时创建（`Runtime::new()` 存于 Object 内），uniffi 的 `async fn`（uniffi ≥0.25 原生支持，对应「uniffi 2.x」时代成熟）经 `uniffi::tokio::async`（或自定义 foreign executor）桥接；Kotlin 侧拿到的是 `CoroutineScope` 兼容的 suspend 函数。状态推送（`status()/stats()`）用 uniffi **callback interface** 由 Rust 定期推或 Kotlin 轮询，推荐 Kotlin 轮询 + Flow，避免高频跨 FFI 回调。
- 注意点：① 回调里不能持有长锁/做重活（跨 JNI 单次开销 μs 级但高频会卡 UI 线程）；② `stop()` 要保证取消所有 tokio 任务后 join，Android 进程被杀场景（LAMV `onRevoke`）需幂等；③ uniffi 版本号语义：uniffi-rs 实际主版本仍在 0.x（如 0.28/0.29），方案写「uniffi 2.x」**表述有误，待验证其指代**（可能指 uniffi-kotlin-multiplatform 或 KMP 绑定 2.x）；不影响可行性，但文档应写准确版本并锁死。

### 2.2 cargo-ndk + ring 0.17 @ Windows 主机（低风险，有一个隐性利好）

- ring 0.17 的 Android 交叉编译在 cargo-ndk + NDK(r26/r27) clang 下是成熟路径；ring 0.17 预生成 asm，**不再需要 perl/yasm**（ring 0.16 时代的大坑已消失）。需注意：`ring` 的 `cc` 编译要求 NDK 的 `clang` 在 PATH（cargo-ndk 已处理），Windows 上偶尔有路径含空格/中文导致的构建脚本失败——工程目录无空格即可。
- **隐性利好（v2 未自我表彰但值得指出）**：workspace `Cargo.toml` L14-23 已把 rustls 0.23 显式 `default-features=false + ring`、避免 aws_lc_rs——这**恰好**移除了 Android 交叉编译最大的坑（aws-lc-sys 需要 cmake+NASM/Go）。方案应把这条写成「已具备的前置条件」而非泛泛的「桌面经验」。
- 三个 ABI 中建议首发 **arm64-v8a + x86_64（模拟器调试）**，armeabi-v7a 延后（ring/thumb 兼容偶尔要额外 flag，价值低）。

### 2.3 egui 不复用（同意）

egui 在 Android 可跑（winit/android-activity eframe 后端存在），但 IME 中文输入、系统返回键、无障碍、触控滚动均为二流体验，且无 Play 商店合规所需的原生组件生态。Kotlin Compose 是正确决策，v2 L21 一句话带过但方向无误。

---

## 3. 遗漏检查（对照 v1 方案 + README 已交付能力）

v2 明确「取代 v1」，但把 v1 中仍然成立的考虑点一并丢掉了。逐项：

| # | 遗漏点 | v1 有无 | 评审意见 |
|---|---|---|---|
| 1 | **PSK/证书在 Android 的存储安全** | 有（L80：EncryptedSharedPreferences/DataStore） | v2 只字未提。要求：PSK 用 EncryptedSharedPreferences（密钥入 Android Keystore）或 DataStore+Tink；证书 pin 的 der 以 bytes 传入 Rust（顺带解决 lib.rs env 模型替换）。**必须补进方案 §4 决策表** |
| 2 | **`VpnService.protect()` 防环回** | 隐含（tun2socks 自带 protectPath） | 见 §1.1④，v2 完全遗漏，属架构级遗漏 |
| 3 | **Always-on / Lockdown** | 有（L78「无额外开发」） | v1 的「无额外开发」说法本身过简：需处理 `onRevoke` 回调、Always-on 下系统冷启动重启 VPN（服务需能在无 UI 下自启并读持久化配置）、Lockdown 模式下启动期流量。v2 M3 提了 Always-on 一词但无设计 |
| 4 | **Doze / 电池优化白名单 / 息屏降频** | 有（L76） | v2 全丢。前台服务 + 常驻通知（v2 M2 验收有）只保证不被杀；Doze 下 keepalive 抖动、息屏降频开关需设计（README 已交付 keepalive 7-12s 抖动，是输入条件） |
| 5 | **分应用代理** | 有（L77：allowedApplications/disallowedApplications） | v2 M3 提了词，未提实现注意点：切分应用列表需**重启 VpnService**（Builder 参数不可热更），UX 要设计 |
| 6 | **proguard/R8** | 无（v1 也没有） | uniffi 生成的 Kotlin 绑定（JNA）需 keep 规则；Compose + release minify 是标配。应进 M1 工程搭建清单 |
| 7 | **隐私合规（Play 上架）** | 无 | VPN 类 App 在 Google Play 需隐私政策 + VpnService 用途声明；若不上架仅侧载可降级为「声明不做」。至少应在方案里明确目标渠道 |
| 8 | **断线重连 / VpnService 重建** | 有（L79） | v2 未提「节点故障切换已有」之外，**TUN 层重连**（网络切换 Wi-Fi↔蜂窝，fd 内核不死但链路失效）由谁负责：Rust 栈的 TCP 流会僵死，需流级超时清理（tun.rs 已有 IDLE_TIMEOUT=300s 可复用）+ Kotlin 层网络回调触发引擎 restart |
| 9 | **杀 App / 崩溃后的系统恢复** | 部分（v1 M2 验收） | v2 M2 验收有「杀 App 恢复正常」，✅；但应补「App 崩溃时 VpnService 前台服务仍在 → 引擎死、TUN 活，流量黑洞」的防护（engine 心跳看门狗或服务内自检停止自身） |
| 10 | **分享链接含 PSK 的安全决策** | 有（v1 L75/L96 讨论） | v2 §4 L68 拍板「维持现状」，可接受；但建议 Android 侧生成链接时默认**不含 k 字段**、显式开关才含（比桌面更保守，因为手机相册/剪贴板泄露面更大） |

---

## 4. 里程碑与工作量

| 里程碑 | v2 估时 | 评审意见 |
|---|---|---|
| M0 核心抽取 | 2-3 天 | **偏紧**。实际搬运面 ≈5500 行（见 §1.3），且 lib.rs 的 env/文件模型要改 uniffi 参数模型、2776 行 tun.rs 拆分需先解耦。建议 **3-5 天**；uniffi Kotlin 冒烟前置是 Android 工程骨架（Gradle+NDK），应显式列为 M0 的第一项（v2 只在 §6 提「需安装」） |
| M1 最小 App | 3-5 天 | 合理。注意 M1 就需要 proxy.rs + tcp_transport.rs 搬完，反向要求 M0 清单修正 |
| M2 全局 VPN | 3-5 天 | **明显偏乐观**。新增工作：fd 异步接线、通配端口方案、DNS 劫持、UDP 会话、protect 回调通道、网络切换重连、降级判据 spike。建议 **5-10 天**，且 spike 前置（见 §1.2） |
| M3 按需 | — | 合理，但建议把「存储安全（遗漏#1）」提进 M1/M2，不能压到 M3 |
| 依赖顺序 | — | M0→M1→M2 主线正确。补充两条并行线：① fd→smoltcp spike 不依赖 M0（可用现有 hydra-client + 一个 stub 引擎先跑），**应在 M0 期间并行**，其结论决定 android/ 是否引入 tun2socks 目录结构；② 降级决策点建议设在 M2 开工前而非 M2 中途 |

---

## 5. 结论

**方向可取、骨架正确，但按现状不可直接开工**：路线选择（smoltcp 直喂 fd）所依赖的三个前提（任意端口、DNS、protect 防环回）在现有 `tun.rs` 能力与 v2 文本中均无着落，且抽取清单与代码实况不符。完成 §6 修订（尤其 R1-R4）后即可开工。

## 6. 修订条款清单

1. **【R1·必须】补「任意端口」设计**（§2/§4）：明确 smoltcp 无通配 LISTEN 的应对（动态建 socket 接流方案或明确限制并写入产品预期），证据：tun.rs L25-27/L73-74；M2 验收标准「全局流量经节点」需相应改写为可测条款（含一个非 443/80 端口的应用用例）。
2. **【R2·必须】补 DNS 设计**（新 §）：Android 上 DNS 进 TUN，给出劫持→域名透传节点解析的方案（复用 v1 L74 的 A6 能力），并声明放弃「DNS 明文豁免直出」；相关 UDP 53 转发依赖 R3。
3. **【R3·必须】修正 UDP 复用表述**（§1 L20、§4 L71）：UDP-over-proxy 仅协议层复用；TUN 侧 UDP 会话/NAT 接线为新增开发（可复用 nat.rs 逻辑），计入 M2 工作量。证据：tun.rs L15-17。
4. **【R4·必须】补 VpnService.protect() 防环回机制**（§2/§4）：设计 socket fd 在 Rust/Kotlin 间的 protect 通道，并评估其对 §4 L69「接口不绑定 Android 特有概念」的影响（建议用 callback interface 抽象为「出站 socket 保护钩子」，iOS 侧空实现）。
5. **【R5】修正抽取清单**（§3）：按实际文件改写——搬 `tcp_transport/proxy/nat/traffic/connections/scheduler/speedtest/subscription/routing/share_link`（无 splitter 文件）；lib.rs 的 Windows 函数与 env 模型留桌面，uniffi 接口改为显式 bytes/参数传入。证据：§1.3 表格。
6. **【R6】M0 估时改 3-5 天**；并把「Android 工程骨架（Gradle/NDK/cargo-ndk）」列为 M0 第一项；M2 估时改 5-10 天。
7. **【R7】新增 M2 前置 spike**：fd→smoltcp 真机冒刺（含非白名单端口 + 网络切换），与 M0 并行，spike 不达标即启用 tun2socks 备选，决策点写死。
8. **【R8】补密钥/证书存储安全**（§4 决策表）：EncryptedSharedPreferences/Keystore，分享链接默认不含 PSK（§4 L68 相应加严）。
9. **【R9】补 Always-on/Doze 条款**（§5 M3 展开）：onRevoke、无 UI 自启、Lockdown、电池优化白名单引导、息屏降频开关（对照 v1 L76/L78）。
10. **【R10】补分应用代理实现注意**：改列表需重启 VpnService。
11. **【R11】补 proguard/R8 keep 规则**（M1 工程搭建清单）与隐私合规/上架渠道声明（新 § 或 §4）。
12. **【R12】文档纠偏**：「uniffi 2.x」改为实际 uniffi-rs 版本并锁定（uniffi-rs 主版本仍在 0.x，待验证所指）；§6 L86 把「rustls ring 单栈已避开 aws_lc_rs」明确写为已具备的前置条件（证据：根 Cargo.toml L14-28）；ABI 首发改 arm64-v8a + x86_64。

## 7. 待验证项汇总

- smoltcp 承载手机全部流量的吞吐/乱序表现（无同规模生产先例）——spike 验证。
- ring 0.17 + armeabi-v7a 在当前 NDK 版本的构建（首发不含则延后验证）。
- 「uniffi 2.x」具体所指版本（文档纠偏前无法核实）。
- VpnService fd 在非阻塞模式下与 AsyncFd 的 epoll 行为（标准做法，但需真机确认 MTU 与分片）。
