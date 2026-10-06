# Hydra 移动端（Android）方案 v2.1 —— 基于 TCP 转型后架构（修订版）

> 状态：**已按独立架构师评审（docs/design/移动端Android方案-v2-评审.md，12 条修订 R1-R12）全面修订，可开工**。
> 日期：2026-10-05 ｜ v2.1 修订记录见文末。
> 前置：桌面端 v0.2.0（TCP/TLS + Noise-PSK + TUN v1 + GUI 重设计）已交付。

---

## 0. 执行摘要（v2.1 修订要点）

v2 定稿稿经独立架构师评审判定「需修订后开工」：**「smoltcp 直喂 VpnService fd」路线漏掉三个致命前提**（任意端口、DNS、protect 防环回），且抽取边界与代码实况不符。v2.1 修订：

- **R1（必须）**：补「任意端口」设计——TUN 栈侧对任意 TCP SYN 动态建 socket 接流（不再依赖端口白名单）
- **R2（必须）**：补 DNS 设计——TUN 内劫持 53 端口 → 域名透传节点解析（放弃明文直出）
- **R3（必须）**：修正 UDP「直接复用」表述——TUN 侧 UDP 会话/NAT 接线为新增开发，计入 M2
- **R4（必须）**：补 `VpnService.protect()` 防环回机制——出站 socket 保护钩子（callback interface 抽象，iOS 空实现）
- R5-R12：抽取清单按实况修正、M0/M2 估时上调、M2 前置 spike 决策点、密钥存储安全、Always-on/Doze、分应用代理、proguard、合规、文档纠偏

---

## 1. 目标

把 Hydra 客户端带到 Android：手机全局流量经 VPS 节点出去，复用桌面端已验证的 Rust 核心（协议/认证/证书固定/故障切换/测速调度），不重写协议。

**与桌面端的复用边界**（v2.1 按代码实况修正）：

| 桌面模块 | 行数 | Android 处置 |
|---|---|---|
| hydra-protocol（握手/帧/STUN/属主证明） | — | 直接复用 |
| tcp_transport.rs（rustls 0.23 + 指纹 + 信任双路线） | 476 | **搬入 hydra-core**（v2 漏列） |
| proxy.rs（SOCKS 服务实体） | 1179 | **搬入 hydra-core**（M1 进程内 SOCKS 依赖；v2 漏列） |
| nat.rs（UDP 会话/NAT 逻辑） | 726 | **搬入 hydra-core**（UDP-over-proxy 的 TUN 侧接线要用；v2 漏列） |
| traffic.rs（流量统计） | 442 | **搬入 hydra-core**（uniffi stats() 数据源；v2 漏列） |
| scheduler/speedtest/connections/subscription/routing/share_link | 147-730 | 搬入（v2 判断正确） |
| tun.rs | 2776 | 拆 `tun_core`（smoltcp 栈 + 增强，平台无关）/ `tun_win`（Wintun 设备，留桌面） |
| lib.rs 的 Windows 专有函数（系统代理检测/隐藏控制台/env 模型） | — | **留桌面，不进 hydra-core**；uniffi 接口改为 Kotlin 显式传 bytes/参数（v2 漏列的接口工作量） |
| splitter | 不存在 | —（v2 笔误） |

实际搬运面 ≈ **5500+ 行**。

## 2. 架构（v2.1：Rust core + Kotlin 壳 + 三个已解风险）

```
┌────────────────────────────────────────────────────────┐
│ Android App（Kotlin + Jetpack Compose）                 │
│  ┌───────────────┐  ┌────────────────────────────────┐ │
│  │ VpnService    │  │ 设置/节点/订阅/连接 UI           │ │
│  │ (系统 TUN fd) │  │ 密钥存 EncryptedSharedPreferences│ │
│  └──────┬────────┘  └────────────────────────────────┘ │
│         │ IP 包（detachFd → AsyncFd 非阻塞读写）        │
│  ┌──────▼───────────────────────────────────────────┐  │
│  │ tun_core（smoltcp 栈增强版，复用自桌面 tun.rs）    │  │
│  │  · 任意端口动态建 socket 接流（R1）                │  │
│  │  · DNS 劫持：53 端口 → 域名透传节点解析（R2）      │  │
│  │  · UDP 会话表 → UDP-over-proxy（R3，新增接线）     │  │
│  │  · 出站 socket 保护钩子（R4，protect 回调）        │  │
│  │  · MTU 1200-1400（蜂窝链路，防分片）               │  │
│  └───────────────┬──────────────────────────────────┘  │
│  ┌───────────────▼──────────────────────────────────┐  │
│  │ hydra-core（Rust cdylib，uniffi→Kotlin）          │  │
│  │  · TCP/TLS 通道（复用 connect_target/调度/切换）   │  │
│  │  · 出站 fd 保护：callback interface 交 Kotlin     │  │
│  │    VpnService.protect(fd)（R4 防环回，iOS 空实现） │  │
│  └───────────────┬──────────────────────────────────┘  │
└──────────────────┼─────────────────────────────────────┘
                   │ TCP/TLS 443（Noise-PSK，chrome 指纹，protected fd）
             Hydra 节点 (VPS)
```

### 三个关键风险的解法（评审 R1-R4 落地）

| 风险 | 解法 |
|---|---|
| **R1 任意端口**：smoltcp 只能按端口 LISTEN，手机全局 VPN 下非白名单端口（IMAPS/FCM/游戏）全坏 | `tun_core` 增强：对入站 TCP SYN（任意目的端口）**动态创建 smoltcp socket 绑定该端口**接流（非 LISTEN 白名单模式）；流关闭回收。这属于 `tun_core` 增强开发（计入 M2），不是免费复用 |
| **R2 DNS**：系统 DNS 进 TUN，桌面式「豁免直出」在 Android 不可行（公共 DNS 排除后手机可能拿不到解析）且明文有泄漏/劫持面 | TUN 内劫持 53 端口（UDP/TCP）→ **域名透传节点解析**（复用桌面 A6 能力：节点侧解析本就是架构特性）。依赖 R3 的 UDP 53 转发 |
| **R3 UDP**：全局 VPN 下 UDP（DNS/QUIC/推送）必须处理 | TUN 侧新增 UDP 会话表/端口映射（NAT 行为，可参考 nat.rs 既有逻辑但接线为新增），转发走 UDP-over-proxy 协议（桌面同期已交付协议层）。计入 M2 工作量 |
| **R4 防环回**：Rust 自己到节点的出站连接会被自身 VPN 抓回 TUN 死循环 | 桌面靠路由豁免天然规避；Android 必须**显式 protect**：Rust 建连后把 socket fd 经 uniffi callback interface 回调 Kotlin 层调 `VpnService.protect(fd)`（抽象为「出站 socket 保护钩子」，iOS 空实现——不破坏双平台接口） |

### 其余风险对策（评审 §3 遗漏项补齐）

- **密钥/证书存储**：PSK 存 EncryptedSharedPreferences（密钥入 Android Keystore）；证书 der 以 bytes 经 uniffi 传入 Rust（顺带替换桌面 env/文件路径模型）；**Android 侧生成的分享链接默认不含 k 字段**（手机剪贴板/相册泄露面更大，比桌面更保守）
- **Always-on/Doze**：VpnService 前台服务 + 常驻通知；`onRevoke` 回调处理；Always-on 冷启动需服务无 UI 自启并读持久化配置；Lockdown 模式启动期流量；电池优化白名单引导；息屏降频开关（M3）
- **分应用代理**：VpnService 原生 allowed/disallowedApplications；**改列表需重启 VpnService**（Builder 不可热更）——UX 设计为「应用后提示重启」（M3）
- **proguard/R8**：uniffi 生成的 Kotlin 绑定需 keep 规则，进 M1 工程搭建清单
- **断线重连**：网络切换（Wi-Fi↔蜂窝）时 Rust 栈 TCP 流僵死——流级超时清理复用桌面 IDLE_TIMEOUT 机制 + Kotlin 网络回调触发引擎 restart
- **崩溃防护**：App 崩溃时 VpnService 前台服务仍在 → 引擎死 TUN 活 = 流量黑洞——服务内引擎心跳看门狗，超时自停
- **隐私合规**：VPN 类 App 上架 Play 需隐私政策 + VpnService 用途声明；仅侧载则降级为文档声明（渠道决策：首版仅侧载/官网分发）

## 3. 核心抽取：hydra-core（M0，估时 3-5 天）

抽取清单按 §1 表格执行（实际搬运面 ≈5500 行）；lib.rs 的 Windows 函数与 env/文件路径模型留桌面，uniffi 接口显式参数化。**M0 第一项 = Android 工程骨架**（Gradle + NDK + cargo-ndk + uniffi 冒烟）。

## 4. 前置 spike（M0 期间并行，决策点写死）

**fd→smoltcp 真机冒刺（2-3 天）**：现有 hydra-client + stub 引擎，真实手机跑「浏览器 + IM + 一个非白名单端口应用 + 断网重连」，验证 smoltcp 承载手机全部流量的吞吐/乱序/内存表现。**不达标即切换 tun2socks 备选**（v1 路线恢复，android/ 工程结构按此调整）——决策点固定在 M2 开工前。

## 5. 里程碑（v2.1 修订估时）

| 里程碑 | 内容 | 估时 | 验收 |
|---|---|---|---|
| M0 | Android 工程骨架（第一项）；hydra-core 抽取（≈5500 行）；uniffi Kotlin 冒烟；桌面全量回归 | **3-5 天** | 桌面全量测试绿；Kotlin 单测经 uniffi 启停引擎 |
| M0-并行 | fd→smoltcp spike（真机，非白名单端口 + 网络切换） | 2-3 天（并行） | 产出 go/no-go 决策（smoltcp vs tun2socks） |
| M1 | Compose 最小 App：节点表单/导入（EncryptedSharedPreferences 存 PSK）→ 进程内 SOCKS 可用 | 3-5 天 | 手机浏览器手动配代理可上网 |
| M2 | 全局 VPN：VpnService fd → 栈（含 R1 任意端口/R2 DNS/R3 UDP 会话/R4 protect）+ 一键开关 + 前台服务 | **5-10 天** | 全局流量经节点；含一个非 443/80 端口应用用例；杀 App 恢复正常 |
| M3 | 对齐桌面：测速/分享二维码/订阅/分应用代理/Always-on/Doze/息屏降频 | 按需 | 与桌面 GUI 功能对齐 |

## 6. 已具备的前置条件（ favourable 事实）

- workspace Cargo.toml 已将 rustls 0.23 显式 `default-features=false + ring`——**恰好移除了 Android 交叉编译最大的坑**（aws-lc-sys 需 cmake+NASM/Go）
- ring 0.17 预生成 asm，NDK clang 交叉编译为成熟路径（不再需要 perl/yasm）
- ABI 首发：**arm64-v8a + x86_64**（模拟器调试）；armeabi-v7a 延后
- rustls/tokio 生态与桌面完全同栈——认证、指纹、信任双路线白得

## 7. 待验证项

- smoltcp 承载手机全部流量的吞吐/乱序/内存（spike，go/no-go 决策点）
- ring 0.17 + NDK 各版本组合构建（首发 ABI 有限可规避）
- VpnService fd + AsyncFd 非阻塞行为的真机确认（MTU 1200-1400 与分片）

---

## 修订记录

- **v2.1（2026-10-05）**：按独立架构师评审（移动端Android方案-v2-评审.md，12 条 R1-R12）全面修订——R1 任意端口动态接流、R2 DNS 劫持透传、R3 UDP 表述修正、R4 protect 防环回钩子、R5 抽取清单实况修正、R6 估时上调、R7 spike 决策点、R8 存储安全、R9-R11 Always-on/分应用/proguard/合规、R12 文档纠偏（ABI/uniffi 版本表述）。
- v2（2026-10-05）：初稿（基于 QUIC 时代的 v1 讨论稿重写）。
