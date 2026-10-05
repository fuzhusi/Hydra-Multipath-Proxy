# GUI 功能覆盖审查（对照 README「核心特性」全清单）

- 审查对象：`hydra-client-gui`（egui，五页导航：状态总览 / 节点 / 订阅 / 日志 / 设置）
- 基线：`cargo test --workspace` 205 通过 / 0 失败（本审查开始前实测确认）
- 审查方式：逐项对照 README「核心特性」与 `hydra-client` / `hydra-client-gui` 源码（文件:行）
- 结论先行：GUI 在「多节点加分发 + 故障自愈 + 系统代理 + 分享/订阅/托盘」上覆盖良好；
  **TUN 透明代理、双信任模式（HYDRA_TRUST）、多节点证书（HYDRA_NODE_CERTS）三大近期交付完全未暴露**，是本轮补齐目标。

---

## 一、README「核心特性」逐项核对

图例：✅ 已覆盖 / ⚠️ 部分覆盖 / ❌ 缺失

### 传输与加密

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| TCP/TLS 隧道（TLS 1.3 + Noise-PSK） | ✅ | `hydra-client-gui/src/main.rs:794-798`（ProxyServer 组装即完整 TCP/TLS + Noise 路径）；节点测速走完整 `connect_target`（`main.rs:427-473`） |
| 信任双路线（pin 默认 / ca 真证书 + 可选叶证书 SHA-256 pin） | ❌（pin 硬编码） | GUI 仅构造 `TlsTrust::pinned`：`main.rs:440`（测速）与 `main.rs:798` 依赖 `ProxyServer` 默认 pinned；`HYDRA_TRUST` / `HYDRA_CERT_SHA256` 无任何 UI 入口（全 GUI 无 `HYDRA_TRUST` 字样，grep 证实） |
| Noise-PSK 应用层握手 | ✅ | 认证密钥配置 + 测速完整握手（`main.rs:463`「认证/密钥错误（Noise 握手失败）」三分展示） |
| 私有帧协议 / 认证失败静默关流 | ✅（透明） | 协议内部行为，客户端库内实现，GUI 无需暴露 |
| DNS 隐私 | ✅（透明） | 客户端库不解析目标域名，GUI 无关 |

### 可靠性与性能

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| 节点故障切换 + 自愈 | ✅ | Offline 探测间隔 GUI 可调（`main.rs:3169-3182`，对应 `HYDRA_PROBE_INTERVAL_SECS`）；测速三分展示见下文「测速」行 |
| 连接级多节点加权分发 | ✅ | 代理线程组多节点：`main.rs:726-745`（添加全部有效节点）→ `ProxyServer::with_nodes` |
| 测速动态调度 | ✅ | 单节点手动测试（`main.rs:477-507`）+ 全量测试（`main.rs:557+`）；**错误三分展示已到位**：认证/密钥错误 / 节点不可达 / 超时三类根因分别透出（`main.rs:461-472`），节点列表以「✓ 已验证 / ✗ 原因 / 超时」呈现（`main.rs:2506` 附近） |
| BBR/fq、转发空闲看门狗（`HYDRA_IDLE_TIMEOUT_SECS`） | ➖ 节点侧变量，GUI 无关 | 均为 `hydra-node` 服务端能力/环境变量（README 部署章节、`hydra-node` 源码），GUI 是客户端，无对应 UI 属正常边界，**非缺口** |
| 半关闭语义、优雅停机 | ✅（透明） | 库/节点侧实现，GUI 停止代理路径完整（`main.rs:1077-1103`） |

### 安全与隐私

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| SSRF 目标过滤、资源上限、日志脱敏、密钥文件 | ✅（透明） | 客户端/节点库内部行为 |
| 单节点证书（HYDRA_NODE_CERT：路径/内嵌 DER/env 回落） | ✅ | `config.rs:321-337`（resolve_node_certs 三级回落）；节点页全局凭据区（`main.rs:2382-2402`） |
| **多节点证书（HYDRA_NODE_CERTS，按序对应）** | ❌ | `hydra-client/src/lib.rs:64` 已有 `node_certs_from_paths`，但 GUI 配置无 per-node 证书字段，`resolve_node_certs` 只产单证书向量；节点编辑对话框亦自述「全局单值」（`main.rs:3131`） |

### TUN 透明代理（实验性）

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| TUN 全流量接管 | ❌（仅占位） | 设置页 TUN 区全部禁用占位：「启用 TUN 模式」checkbox `add_enabled(false)`（`main.rs:3193-3208`），且 `self.config.tun_enabled = false` 强制回写（`main.rs:3208`）；config 字段标注「预留字段，不驱动任何行为」（`config.rs:96-98`） |
| 防环路 / IPv6 防泄漏 / v1 边界 | ❌（随 TUN 整体缺失） | CLI 已有系统代理环路告警（`hydra-client/src/main.rs:88-107`），GUI 无对应展示 |

### NAT 穿透（实验性）

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| TCP STUN / 打洞 / `--p2p` | ❌（CLI-only，暂不入 GUI） | 仅 `hydra-client/src/main.rs:109+`（parse_args 的 P2pArgs）与 `nat.rs`；GUI 无入口。**暂不入 GUI 的理由**：① 打洞需要「对端 id + 信令协调」的双端配合流程，是一次性运维动作而非常驻配置，对话式 CLI 更贴合；② README 将其划为「实验性」，交互定型前入 GUI 会随方案反复重画（UI v3 方案亦未收录）；③ GUI 与代理同进程，打洞建立的是**额外直连通道**，与 ProxyServer 生命周期管理耦合，需先定「通道注入」API 再谈 UI。建议：待 NAT 方案脱离实验性后，以「工具页一次性向导」形态入 GUI |

### 便利性

| 特性 | 状态 | 证据 |
| --- | --- | --- |
| 桌面 GUI 五页导航 / 速率卡 / 托盘 / 配置持久化 / 向导 | ✅ | `main.rs:22-52`（Tab）、`main.rs:144-147`（速率缓存）、`tray.rs`、`config.rs`（持久化 + 防抖保存）、`main.rs:381`（向导） |
| Windows 系统一键代理（注册表 + WinINet，崩溃恢复） | ✅ | `main.rs:2009-2093`（windows_proxy 模块）、panic hook（`main.rs:3377+`） |
| 分享体系（hydra:// + 二维码 + 导入双层校验） | ✅ | `main.rs:1177-1243`、`qr.rs` |
| 订阅 | ✅ | `subscription.rs` + `main.rs` 订阅页 |
| 国内直连分流（HYDRA_SPLIT=cn） | ❌ | `hydra-client/src/routing.rs:185` `split_enabled()` 仅读 env；GUI 无开关。属低频隐私向开关，列入后续 UI 方案（非本轮最小增量范围） |

---

## 二、预期缺口核实结论

1. **TUN 开关与状态**：❌ 核实成立。字段 `tun_enabled` 已预留且 serde 兼容，但 UI 禁用 + 恒回写 false；`hydra-client` 已有 `pub fn run_tun`（`tun.rs:1528`）与 `ProxyServer::tun_channel_opener`（`proxy.rs:288`），但 CLI 专用的 `tun_config_from_env` / `warn_system_proxy_loop` / `new_shutdown_token` 均为 main.rs 私有，GUI 无法复用接线——需在 hydra-client 加轻量 pub 入口。
2. **信任模式选择**：❌ 核实成立。GUI 固定 pinned，`HYDRA_TRUST=ca` 的 `TlsTrust::public_ca`（`tcp_transport.rs:123`）未被任何 GUI 路径触达。
3. **HYDRA_NODE_CERTS 多节点证书**：❌ 核实成立。库入口已有（`lib.rs:64`），GUI 配置模型与节点编辑弹窗均无 per-node 证书。
4. **GUI 测速错误三分展示**：✅ 已到位（认证错误 / 不可达 / 超时三分，见上表），无需补。
5. **NAT/P2P**：CLI-only，暂不入 GUI（理由见上）。
6. **空闲超时（HYDRA_IDLE_TIMEOUT_SECS）**：节点侧变量，GUI（客户端）无关，标注非缺口。
7. **国内直连分流**：GUI 未暴露（本审查新发现，低优先级）。
8. **HYDRA_SNI**：ca 模式下自定义域名必需，GUI 无输入（`DEFAULT_SNI` 恒用，`main.rs:447`）——补信任模式时应一并评估，本轮最小增量以提示文案披露。

## 三、界面问题小结（引 v3 方案既有结论，不展开）

见 [docs/design/UI重设计方案-v3.md](../design/UI重设计方案-v3.md)：TL;DR 结论为**保留 egui 走「强化路线」**——左侧窄侧栏 + 顶栏 + 内容区卡片、自定义暗色 Visuals、egui_plot 速率图、`egui_extras::Table` 连接表，**不迁移框架**（v3 方案 §技术路线评估）。main.rs 单文件 3200+ 行需按 v3 §P0 拆分模块。本轮补齐严格遵守「六区/设置页既有风格内最小增量」，不做大改版。

## 四、补齐建议清单

**本轮实施（最小增量，设置页/节点编辑弹窗内）：**
1. TUN 开关：设置页启用 toggle + TUN 地址（默认 10.7.0.1/30）+ 端口列表（默认 80,443,8080,8443）；Windows 系统代理已启用时显示环路警告（与 CLI 告警一致）；hydra-client 增加 pub 配置构造入口，GUI 代理线程叠加 `run_tun`，权限不足错误透传日志区。
2. 信任模式：设置页 radio「自签 pinning（默认）/ 真证书 CA」；ca 模式显示可选叶证书 SHA-256 输入（64 hex 校验）；影响 TlsTrust 构造点（测速 + ProxyServer）。
3. 多节点证书：节点编辑弹窗支持 per-node 证书路径（config 新增 `node_cert_paths` 映射），生成 `TlsTrust::pinned` 时按节点地址顺序收集；地址改名随迁。
4. 每项配 serde/逻辑单测；GUI 交互本身无法自动化，如实标注（验收以编译 + 单测 + 人工走查为准）。

**后续 UI 方案（v3）再做的：**
- TUN 运行状态卡（接管端口/路由/流量可视化）、NAT/P2P 工具页向导、HYDRA_SPLIT 分流开关、HYDRA_SNI 输入、按 v3 P0 拆分 main.rs 模块。
