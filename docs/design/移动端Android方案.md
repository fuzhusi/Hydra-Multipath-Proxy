# Hydra 移动端（Android）框架方案 —— 讨论稿 v1

> 状态：**讨论中，未实施**。本文档用于确定技术路线后再动工。
> 日期：2026-10-04

---

## 1. 目标

把 Hydra 客户端带到 Android：手机流量经 VPS 节点出去，复用现有 Rust 核心（协议/连接池/认证/证书固定/故障切换），不重写协议。

**非目标（首版不做）**：多路径聚合（Phase C 才有）、iOS、节点端功能。

## 2. 三个候选架构

### 方案 A：Rust 核心复用 + Kotlin UI（推荐）

```
┌─────────────────────────────────────────────┐
│ Android App (Kotlin + Jetpack Compose)      │
│  ┌────────────┐  ┌───────────────────────┐  │
│  │ VpnService │  │ 设置/节点管理/状态 UI   │  │
│  │ (TUN 设备) │  └───────────────────────┘  │
│  └─────┬──────┘                             │
│        │ 包 → tun2socks (hev-socks5-tunnel) │
│        ▼                                    │
│  127.0.0.1:PORT (SOCKS5)                    │
│        │                                    │
│  ┌─────▼──────────────────────────────┐     │
│  │ hydra-core (Rust cdylib, 复用现有   │     │
│  │ proxy/pool/scheduler/transport)    │     │
│  │  ↕ uniffi 桥接 (JNI 自动生成)       │     │
│  └────────────────┬───────────────────┘     │
└───────────────────┼─────────────────────────┘
                    │ QUIC/UDP 443
              Hydra 节点 (VPS)
```

- **核心思路**：把 `hydra-client` 里平台无关的部分抽成 `hydra-core` crate，用 [uniffi-rs](https://github.com/mozilla/uniffi-rs) 生成 Kotlin 绑定；tokio runtime 在 Rust 侧跑，Kotlin 只调用 `start(config)/stop()/stats()` 和接收回调。
- **流量接入**：Android 上全局代理必须走 `VpnService`（系统 VPN API）。TUN 网卡原始 IP 包由 **tun2socks**（[hev-socks5-tunnel](https://github.com/hev-socks5/hev-socks5-tunnel)，C 库，v2rayNG/mihomo 同款）转成 SOCKS5，喂给进程内 Rust 代理。
- **业界先例**：WireGuard Android、Mullvad（Rust core + JNI）、v2rayNG（VpnService + tun2socks）——全是这个组合，成熟度高。
- **优点**：协议栈零重写，桌面/移动行为一致（认证、pinning、故障切换全部白得）；uniffi 同时支持 Swift，未来 iOS 只换 UI。
- **缺点/风险**：NDK 交叉编译工具链（Windows 主机用 cargo-ndk，成熟）；VpnService + tun2socks 是新组件（但都是现成开源件）。

### 方案 B：纯 Kotlin 重写协议（不推荐）

JVM 生态没有可用的原始 QUIC 栈（Cronet 是 HTTP/3 封装，不暴露裸 QUIC 流；quic4j 无人维护）。等于用另一门语言重写 quinn+rustls+整个协议，工作量大且两套实现永远不一致。**放弃。**

### 方案 C：仅代理模式（作为过渡里程碑保留）

不做 VPN，App 内嵌 SOCKS5（Rust core 监听 127.0.0.1），用户在 Wi-Fi 设置/支持代理的浏览器里手动指向。Android 上全局无解、体验差，**只作为 M1 开发里程碑**，不是最终形态。

## 3. 建议的工程结构

```
Hydra-Multipath-Proxy/
├── hydra-core/              # 新 crate：从 hydra-client 抽出平台无关核心
│   ├── src/lib.rs           #   uniffi 接口定义（Object: HydraEngine；方法 start/stop/stats）
│   └── Cargo.toml           #   依赖 hydra-protocol + proxy/pool/scheduler/transport 逻辑
├── hydra-client/            # 保留：桌面 CLI（改为薄壳调 hydra-core）
├── android/
│   ├── app/                 # Kotlin + Compose：UI、节点管理、VpnService、前台服务
│   ├── tun2socks/           # hev-socks5-tunnel 源码 + JNI 封装（NDK 编译）
│   └── build.gradle.kts
└── ...
```

构建：`cargo-ndk` 出 `arm64-v8a` / `armeabi-v7a` / `x86_64` 三个 .so；Windows 主机直接可构建。

## 4. 关键技术问题（设计阶段要想清楚的）

| 问题 | 现状/方案 |
|---|---|
| **DNS** | 我们架构天然占优：域名经加密通道交节点解析（A6 已做）。tun2socks 层用其 domain 模式把域名透传给 SOCKS5，手机本地不解析目标域名 |
| **PSK 与证书分发 UX** | 现在要求 `HYDRA_AUTH_KEY` + 证书文件。移动端方案：① 文件选择器导入 .der；② **扩展 `hydra://` 分享链接携带认证信息**（便利 vs 安全的取舍——链接含 PSK 时建议只在二维码/近场分享场景使用，这也是一个待讨论点） |
| **电池 / Doze** | VpnService 必须 foreground service + 常驻通知（v2rayNG 同款），系统不会杀；QUIC keepalive 7-12s 抖动已有，可加"息屏降频"选项 |
| **分应用代理** | VpnService 原生支持 `disallowedApplications`/`allowedApplications`，M3 做 |
| **Always-on VPN** | 系统"始终开启 VPN"设置即可，无额外开发 |
| **掉线重连** | 故障切换已做（节点级）；VpnService 重建立需要 App 层监听并重启 tun2socks |
| **配置持久化** | Android 侧用 DataStore/EncryptedSharedPreferences 存 PSK（Rust 侧不管） |

## 5. 建议的里程碑

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M0** 核心抽取 | 建 `hydra-core` crate，桌面 CLI 改薄壳；uniffi 绑定冒烟（Kotlin 调 start/stop） | 桌面测试 17/17 不变；Kotlin 单测能通过 uniffi 启停引擎 |
| **M1** 最小 App | Compose UI：手动填节点(地址:端口)+PSK+导入证书 → 进程内 SOCKS5 可用 | 手机浏览器手动配代理可上网（方案 C 形态） |
| **M2** 全局 VPN | VpnService + tun2socks 接入，App 内一键开关 | 手机全局流量经节点；杀 App/断网恢复正常 |
| **M3** 体验完善 | 延迟测试、节点状态显示、分享链接/二维码导入、分应用代理、Always-on | 与桌面 GUI 功能对齐 |

## 6. 待讨论的问题（动工前需要你拍板）

1. **要不要 M2 全局 VPN？** 只做 M1（代理模式）的话工作量减半，但 Android 上实用性有限。
2. **minSdk**：建议 API 26（Android 8.0，覆盖 97%+），VpnService API 14+ 就有，Compose 需要 21+，26 再省一批兼容坑。
3. **UI 框架**：建议 Jetpack Compose（现代、声明式，和本项目 Rust 侧风格一致）；如果要兼容老设备/更保守可选 XML View。
4. **`hydra://` 分享链接是否携带 PSK？** 携带=扫码即用很爽，但链接泄露=节点被白嫖。折中：链接带 PSK 但生成时二次确认 + 提示仅限近场分享。
5. **iOS 是否进路线图？** 影响现在抽象 core 的接口设计（uniffi 的 Swift 绑定几乎免费，建议核心按双平台设计，UI 只做 Android）。
6. **工程位置**：`android/` 放本仓库单仓库（推荐，CI 简单），还是独立仓库？

## 7. 工作量粗估（仅供参考）

- M0：1-2 天（core 抽取 + uniffi 踩坑）
- M1：3-5 天（Compose UI + Gradle/NDK 工具链搭起来是大头）
- M2：3-5 天（VpnService + tun2socks JNI + 前台服务）
- M3：按需迭代
