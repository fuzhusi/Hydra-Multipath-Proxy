# GUI 框架选型调研：hydra-client-gui 是否换框架

> 调研日期：2026-10-03。范围：技术调研，不改源码。
> 现状：`hydra-client-gui/src/main.rs` 1198 行，eframe/egui 0.27，内嵌 Noto Sans CJK，中文界面，tokio 同进程。

## 一、2025-2026 生态现状盘点

| 框架 | 最新版本(2026) | 活跃度/备注 | 架构 |
|---|---|---|---|
| egui/eframe | 0.33.x | 高频发布，Rerun/Zed 系工具链在用 | 立即模式，纯 Rust，GPU 自绘 |
| iced | 0.14（距 0.13 逾一年） | 社区大但发布节奏慢（被诟病） | Elm 架构，保留模式，wgpu |
| Slint | 1.16 | 商业公司维护，节奏稳定 | 声明式 .slint DSL；1.16 起弃用各平台 native 外观，Fluent 成为默认 |
| Dioxus | 0.7.x | React 风格，全栈方向，节奏偏慢 | 类 React VDOM |
| Xilem | 0.2 前身 Linebender 阶段 | **尚未 1.0，不建议生产** | 实验性 |
| gpui (Zed) | 随 Zed 演进 | 为 Zed 定制，文档少、API 不稳定 | **不建议外部采用** |
| Tauri | 2.11+ | star ~90k，最活跃；2.x 小版本 API 有变动需锁版本 | Rust 后端 + 系统 WebView 前端 |
| Electron | 35+ | 成熟但包体 100MB+、内存高 | Chromium + Node |
| Neutralino | 6.x | 轻，但 Rust 集成弱、生态小 | 系统 WebView + Node/C++ 扩展 |
| Flutter Desktop | 3.3x | 成熟，但 Dart 异构语言、包体 ~20MB+ | Skia 自绘 |
| Compose Multiplatform | 1.8+ | JetBrains 推动，JVM 包体大 | Kotlin |

## 二、对照本项目需求的逐项评估

需求：Windows 优先兼跨平台、托盘常驻、系统代理开关、实时速率图表、中文、小包体、tokio 同进程、单人低维护。

| 维度 | egui(现状) | Tauri 2 | iced | Slint | Dioxus |
|---|---|---|---|---|---|
| 中文渲染 | 内嵌字体即可（已解决） | 依赖 WebView，天然好 | shaper 改进中，复杂排版偶有毛边 | 自带 CJK 支持，好 | WebView 下好；自绘(blade)一般 |
| 托盘 | **无内建**，需 tray-icon crate（有官方 egui 示例，需 EventLoopProxy 桥接，可做） | **内建 TrayIcon API**，支持无窗纯托盘运行 | 无内建，需第三方 | 无内建 | 无内建 |
| 实时速率图表 | egui_plot 现成、每帧重绘是立即模式强项 | 前端图表库丰富（ECharts/uPlot） | 自绘 widget，要手写 | 有图表但生态小 | 同 Tauri |
| 包体积 | ~5-8MB，最小 | ~3-8MB（依赖系统 WebView2） | ~5-10MB | ~5-10MB | 同 Tauri |
| 内存 | 低（几十 MB） | 中（WebView2 进程 80-150MB） | 低 | 低 | 中 |
| tokio 集成 | 同进程同语言，最简单 | `tauri::async_runtime` 基于 tokio，command/emit 很顺 | 同进程，需自己桥接 | 同进程，回调模型 | 同进程，AsyncCmd 等 |
| Windows 观感 | 自绘，非 native 但可定制 | WebView 前端可做出任意现代观感 | 风格居中 | Fluent 默认（1.16 起） | 同 Tauri |
| 学习曲线(单人) | 已掌握 | 需学前端栈（+一门前端框架） | Elm 架构新范式 | DSL 新语法 | 类 React |
| 维护风险 | egui 半年一次破坏性升级（当前锁 0.27 落后约 5 个版本） | 2.x 小版本偶有 API/安全变动 | 发布慢 | 商业许可（GPL/ royalty / 商业三选一）⚠️ | 0.x 前不保证稳定 |

注：Slint 许可证（GPLv3 或商业授权）对个人开源项目可用 GPLv3，但闭源需付费，需留意。

## 三、同领域参照（代理客户端都在用什么）

| 客户端 | 技术栈 | 启示 |
|---|---|---|
| v2rayN | C# WPF → 6.x 起 Avalonia（保持 C# 生态内迁移） | 换框架首选"最小语义跳跃"；且迁移发生在需求倒逼（跨平台）时 |
| Clash Verge Rev | **Tauri 2**（Rust 后端 + React 前端），~90k star | Tauri 做代理客户端壳的成功范本；托盘速率显示等均可做（v2.5.2 还在修托盘样式细节，说明托盘细节有坑但可控）；内存占用社区评价较优 |
| Nekoray/nekobox | Qt (C++) | 重原生路线，单人项目很难负担 |
| Hiddify | Flutter | 移动+桌面一体时才划算 |
| FlClash | Flutter | 同上 |

结论：**本领域没有一个成功案例在用 egui/iced/Slint 做主壳**；带"订阅、图表、托盘、设置页"复杂度的客户端，主流选择是 Web 壳（Tauri）或成熟原生栈（Avalonia/Qt/Flutter）。egui 系客户端（如 sniffnet）多为监控/工具型单页界面——恰是本项目当前形态。

## 四、推荐矩阵

| 方案 | 收益 | 成本 | 风险 | 适配结论 |
|---|---|---|---|---|
| A. 留在 egui（升级 0.27→0.33 + tray-icon + egui_plot） | 零迁移成本；图表/重绘性能最好；包体内存最小；单人可控 | 升级有破坏性改动；托盘要自己桥接（有官方示例可抄）；UI 精致度上限低于 Web | egui 无 1.0，升级永续成本 | **当前规模下的最优解** |
| B. 换 Tauri 2 | UI 上限最高；托盘/自启/系统代理等插件生态全；tokio 官方集成；参照物多（Clash Verge Rev 可抄作业） | 新学前端框架；需重构为前后端分层；包体小但内存升到 ~100MB | WebView2 依赖；前端依赖链维护；单人负担翻倍 | 未来若要"产品级 UI"再换 |
| C. 换 iced | 纯 Rust 原生、架构正规 | Elm 范式重学；托盘/图表全手写；发布节奏慢 | 生态组件少 | 不推荐：收益配不上成本 |
| D. 换 Slint | DSL 声明式、嵌入式能力强 | **GPL/商业许可**；图表生态小 | 许可风险 | 不推荐 |
| E. 换 Dioxus | 类 React 心智 | 0.x 不稳定、节奏慢 | 桌面成熟度不如 Tauri | 若走 Web 路线不如直接 Tauri |

- **首选建议：留在 egui（方案 A）**。当前 1198 行的工具型 GUI 与 egui 能力匹配；真正的痛点（托盘、图表）都有成熟补件；换框架解决的是"观感焦虑"而非实际功能缺口。
- **保守建议：Tauri 2（方案 B）作为触发式迁移目标**。当出现以下任一信号再启动：① 需要订阅管理/规则配置等复杂表单页；② 想要移动端；③ 希望社区贡献前端。

## 五、若走 Tauri：架构草图与迁移策略

```
┌─ hydra-core (现有 Rust 逻辑，抽成 lib crate，不动) ─┐
│  hydra-node / hydra-client 逻辑、tokio runtime      │
└──────────────┬──────────────────────────────────────┘
               │ 调用方式二选一：
   ┌───────────┴───────────┐
   │ 方案1 同进程 (推荐)     │  Tauri command 直接 await
   │ Tauri 壳 = 新 main.rs  │  调 hydra-core 的 API（tokio 共享）
   └───────────────────────┘
   │ 方案2 进程隔离：core 常驻守护进程 + IPC(HTTP/UDS)，壳可独立重启，
   │   相当于把现有 hydra-client(main.rs 98 行的 API 客户端) 升级为进程协议
```

- **前端框架**：Svelte 5（包小、语法简单，适合单人）> Vue 3（中文生态最好，Clash Verge Rev 用 React）> React（生态最大但样板多）。图表首推 uPlot（体积/性能）。
- **迁移策略（渐进）**：
  1. 第一步先做与框架无关的重构：把 main.rs 的业务逻辑抽到 `hydra-core` lib，egui 壳变薄——这一步无论换不换都值得做；
  2. 新建 `hydra-client-tauri` 并行开发，功能对齐旧壳一个模块一个模块补；
  3. 两壳共存一个版本周期，Tauri 壳补齐托盘/自启/系统代理后切换默认，egui 壳保留为 fallback 一个版本后删除。

## 六、需要拍板的问题

1. GUI 的目标定位：个人工具（留 egui）还是打算开源运营/给他人用（Tauri 观感溢价明显）？
2. 是否接受引入前端技术栈（JS/TS + npm 链）作为长期维护面？
3. 内存预算：能接受 Tauri 常驻 ~100MB（vs egui 几十 MB）吗？

## 参考来源

- [2025 Survey of Rust GUI Libraries (daily.dev)](https://daily.dev)、[Top 23 Rust GUI Projects (LibHunt)](https://www.libhunt.com)、[awesome-rust](https://github.com/rust-unofficial/awesome-rust)
- [egui releases](https://github.com/emilk/egui/releases)、[egui tray 讨论 #737](https://github.com/emilk/egui/discussions/737)、[tray-icon 官方 egui 示例](https://github.com/tauri-apps/tray-icon/blob/dev/examples/egui.rs)、[egui_plot](https://crates.io/crates/egui_plot)
- [Dioxus 0.7 发布](https://dioxuslabs.com/blog/release-070)、[iced 0.14 (HN)](https://news.ycombinator.com/item?id=46185323)、[Slint changelog](https://slint.dev)
- [Tauri v2 Review (hysenlabs)](https://hysenlabs.com)、[Clash Verge / Clash Verge (V2EX, 2025-05)](https://hk.v2ex.com)
- v2rayN .NET 迁移讨论：[GitHub Issue #1500](https://github.com)
