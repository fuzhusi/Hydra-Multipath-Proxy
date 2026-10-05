# ClientHello 指纹模仿：调研结论与实施（路线 C）

> 状态：已实施（2026-06）。路线图 P1 项。本文档 = 调研报告 + 实施说明。
> 涉及代码：`hydra-client/src/tcp_transport.rs`（唯一出站 TLS 构造点）、`hydra-client/Cargo.toml`。

## 1. 背景

客户端出站 TLS ClientHello 由 rustls 0.23 生成，JA3/JA4 指纹与浏览器（Chrome）差异
明显，是当前最大的被动检测弱指纹：

- rustls 默认**无 ALPN**（真实浏览器必带 `h2, http/1.1`）；
- 扩展顺序是 rustls 固定写死的（`src/client/hs.rs`），与 Chrome 的顺序不同；
- 密钥组（key_share / supported_groups）集合与顺序是 rustls 形态；
- 无 GREASE、无 padding、无 certCompression 声明等浏览器标配。

**JA3 原理**：对 ClientHello 中 `TLSVersion + CipherSuites + Extensions +
EllipticCurves + EllipticCurvePointFormats` 五个字段拼接后取 MD5（[JA3 定义， Salesforce](https://github.com/salesforce/ja3)）。
**JA4 原理**：[FoxIO](https://github.com/FoxIO-LLC/ja4) 提出，`t13d1516h2_8daaf6152771_b186095e22b6`
式的结构化指纹（协议版本 + 套件/扩展计数与首字母 + ALPN + 套件/扩展哈希），比 JA3
更抗混淆、区分度更高。两者都只看 ClientHello 明文，无需解密——被动 DPI 一眼可得。

## 2. 生态调研（2026-06 现状）

| 候选 | 现状 | 结论 |
|---|---|---|
| [ja-tools](https://github.com/XOR-op/ja-tools)（原定路线） | 未发布到 crates.io，仅 git；7 star；最后提交 2025-03；实现方式是 `[patch.crates-io]` 把 `rustls` 整体替换为其 fork `rustls.delta`（**pinned v0.23.12**，2024 年中），提供 `rustls::craft::Fingerprint` 按 Chrome 等 profile 生成 CH | **否决**。见下文 A 路线分析 |
| `utls-rs` | crates.io 不存在（utls 是 Go 生态 [refraction-networking/utls](https://github.com/refraction-networking/utls)，无 Rust 移植） | 不存在 |
| [impit](https://github.com/apify/impit) / [rquest](https://docs.rs/crate/rquest/0.21.12) / [reqwest-impersonate](https://docs.rs/crate/reqwest-impersonate/0.11.40) | BoringSSL fork 全栈替换，产出的是 **HTTP 客户端**（reqwest 系） | 不适用：本项目是自定义 Noise-PSK-over-TLS 的裸 `TlsStream` 传输，不需要 HTTP 栈，也无法从 HTTP 客户端取流 |
| [wafrift-transport](https://crates.io/api/v1/crates/wafrift-transport) 等新 crate | 其 `tls-impersonate` feature 同样基于 rquest（BoringSSL），仍是 reqwest 中间件 | 同上，不适用 |
| rustls 上游 0.23.x | [CHANGELOG](https://github.com/rustls/rustls/blob/main/CHANGELOG.md)：0.23 全系**未提供** ClientHello 扩展顺序 / key_share 顺序 / GREASE 的配置口（随机化扩展顺序有 [PR #1730](https://github.com/rustls/rustls/pull/1730) 讨论但未提供公开 API） | stock 只能"最大近似" |
| 参照项目 | clash.meta/mihomo = Go + utls（成熟）；Rust 侧 hysteria2/g3proxy 等要么接受 rustls 指纹、要么 BoringSSL 全栈（[g3 issue #138](https://github.com/bytedance/g3/issues/138)） | Rust 生态确无"rustls + Chrome 指纹"的现成维护方案 |

## 3. 路线对比

| 路线 | 内容 | 工作量 | 风险 | 结论 |
|---|---|---|---|---|
| **A. ja-tools / rustls.delta fork** | git 依赖 + `[patch.crates-io]` 全工作区替换 rustls | 0.5–2 天 | **高**：① patch 无法 feature 门控——加上即**无条件**作用于全部构建（含 hydra-node 服务端与所有测试）；② fork 锁死 v0.23.12，错过上游 0.23.13→0.23.45 间约一年的安全修复与缺陷修复；③ 个人仓库、7 star、10 个月未更新，供应链与弃维护风险大；④ 与 tokio-rustls 0.26 组合未经验证 | **否决**（与"不破坏 252 项测试 / 供应链稳健"硬约束冲突） |
| **B. 现成库** | 直接提供 chrome 指纹 ClientHello 且兼容 tokio-rustls 0.26 的 crate | — | — | **不存在**（调研表中逐项排除） |
| **C. stock rustls 最大近似** | 只调 rustls 0.23 实际可调项：ALPN、密码套件顺序、certCompression(brotli)、SNI/resumption 等 | 0.5 天 | 低：纯 stock，无新依赖（仅 rustls 内置 brotli feature） | **采纳** |
| **D. 不可行替代** | — | — | — | 不需要：C 已可落地 |

## 4. 本项目选型与实施

**选型：路线 C**，feature `fingerprint`（**默认开启**——纯 stock 实现、无 fork 依赖、
节点侧连通性不受影响，故无需默认关闭降级）；运行时 `HYDRA_FINGERPRINT=none` 一键回退
stock rustls 行为。

Chrome 模式（`chrome`，默认）应用的 stock 可调项：

| 项 | Chrome 近似值 | rustls 可调性 |
|---|---|---|
| ALPN | `h2, http/1.1`（Chrome 顺序） | ✅ `ClientConfig.alpn_protocols` |
| 密码套件顺序 | TLS1.3 三套件 1301/1302/1303 前置（稳定排序，其余跟随） | ✅ `CryptoProvider.cipher_suites` |
| certCompression | brotli（rustls 经 feature 内置；Chrome 另有的 zstd rustls 无 → 如实缺席） | ✅ `cert_decompressors` + `rustls/brotli` |
| SNI | 保持开启（默认即开） | ✅ |
| 会话恢复 | **保持禁用**（与 Chrome 不同，反关联追踪优先，如实差异） | ✅ |
| 扩展顺序 / key_share 顺序 / GREASE / padding / 签名算法顺序 | rustls 固定形态，**不可调** | ❌ 无公开 API |

### ALPN 与伪装策略的取舍（任务书要求确认项）

原策略"无 ALPN = 普通 HTTPS 客户端"在**指纹层面反而更可疑**：无 ALPN 的浏览器级
TLS 流量几乎不存在，是显眼的 rustls 特征。Chrome 模式改发 `h2, http/1.1` 后：

- **节点连通性不受影响**：节点侧 rustls server 未配置 `alpn_protocols`，不会选择
  ALPN；客户端 `check_selected_alpn` 只在"服务器选择了不在我方列表的协议"时报错，
  服务器不选即通过。已按 E2E 测试路径验证（`cargo test --workspace` 全绿）。
- **Noise-PSK / exporter 通道绑定不受影响**：均运行在 TLS 记录层之上，与 ALPN 无关。
- 结论：chrome 模式（默认）下 ALPN 变化是纯收益；有特殊需求可 `HYDRA_FINGERPRINT=none`
  回到旧行为。

### 代码要点

- `hydra-client/src/tcp_transport.rs`：`FingerprintMode { Chrome, None }` +
  `fingerprint_mode_from_env()`（非法值告警回退默认）；`build_tls_connector` 将模式
  混入连接器缓存键（同信任内容不同模式不复用）；`build_client_config(trust, mode)`
  按模式生成 `ClientConfig`；`chrome_order_cipher_suites` 独立成函数便于单测。
- `hydra-client/Cargo.toml`：feature `fingerprint = ["rustls/brotli"]`，入 default。
- feature 关闭（`--no-default-features`）时：chrome 显式请求告警回退 none，行为与
  升级前完全一致。

### 测试

- `fingerprint_mode_解析与收敛`、`chrome_order_cipher_suites_1301_1302_1303前置`、
  `chrome_与none_配置断言`（ALPN 序列、brotli 解压器存在、none 模式无 ALPN）。
- 验收数字：`cargo test --workspace` **exit 0，262 passed / 0 failed**；
  `cargo build -p hydra-client --all-features` 零错误；`cargo clippy --workspace
  --all-targets` 零告警。
- 附带基线修复（预存破损，非本次引入）：`hydra-node/src/fallback.rs`
  `http_serve_fallback` 缺 `async` 与 `tokio::io::AsyncWrite` 导入，导致
  `cargo test --doc` 编译失败——补一行导入 + `async` 关键字，行为不变。

## 5. 局限（如实声明）

1. **这只是"最大近似"，不是 Chrome 指纹**：JA3/JA4 哈希值与 Chrome **不一致**
   （扩展顺序、key_share、GREASE、padding 不可调）。它消除的是最刺眼的
   "无 ALPN + 无证书压缩 + 套件顺序异常"特征，把弱指纹从"一眼 rustls"降为
   "非主流客户端"，**不能**通过 JA3/JA4 库的 chrome 匹配校验。
2. **指纹库会漂移**：Chrome 每 4 周一个版本，ClientHello 参数随版本变化；本文档
   与实现锚定调研时点（Chrome 13x / rustls 0.23.45）。需跟随上游：若未来 rustls
   提供 CH 定制 API（跟踪 [rustls#1730](https://github.com/rustls/rustls/pull/1730)
   等）或 rustls.delta 类 fork 成熟到可安全依赖，应重评路线 A/B。
3. ja-tools fork 路线未彻底关闭：若项目接受为安全更新做 fork 跟进，可重估。

## 6. 人工验证清单（真实指纹核查需第三方站点）

1. `HYDRA_FINGERPRINT` 未设（默认 chrome）启动客户端，正常建连浏览。
2. 访问 [browserleaks.com/tls](https://browserleaks.com/tls) /
   [ja3er.com](https://ja3er.com) 类站点（若经节点代理，站点报告的是**节点侧出站**
   指纹，不是客户端 CH；核查客户端 CH 需在客户端本机或用抓包）：
   - 本机抓包（Wireshark filter `tls.handshake.type == 1`）确认出站 CH：
     ALPN 含 h2/http/1.1、certCompression 含 brotli、TLS1.3 套件在前。
3. `HYDRA_FINGERPRINT=none` 启动，抓包确认 CH 恢复 rustls 原形态（无 ALPN）。
4. `HYDRA_FINGERPRINT=bogus` 启动，日志出现"非法（chrome|none）"告警且按 chrome 建连。
5. 节点连通回归：pin 模式与 CA 模式各跑一次 E2E（仓库测试已覆盖）。

## 7. 来源

- [XOR-op/ja-tools](https://github.com/XOR-op/ja-tools)（rustls.delta v0.23.12 fork patch）
- [refraction-networking/utls](https://github.com/refraction-networking/utls)（Go utls）
- [apify/impit](https://github.com/apify/impit)、[rquest](https://docs.rs/crate/rquest/0.21.12)、
  [reqwest-impersonate](https://docs.rs/crate/reqwest-impersonate/0.11.40)（BoringSSL 全栈系）
- [bytedance/g3 issue #138](https://github.com/bytedance/g3/issues/138)（g3proxy CH 定制诉求）
- [rustls PR #1730](https://github.com/rustls/rustls/pull/1730)（扩展顺序随机化讨论）
- [JA3](https://github.com/salesforce/ja3) / [JA4](https://github.com/FoxIO-LLC/ja4) 指纹定义
