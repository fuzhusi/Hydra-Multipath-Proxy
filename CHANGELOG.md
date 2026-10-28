# 更新日志（Changelog）

本项目所有显著变更记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [待开发计划]（按优先级排序，非当前 Unreleased）

> 2026-10-09 更新：kill switch / always-on 开机自启 / 分应用代理 / GUI 模块化
> 拆分 / 托盘菜单禁用态 / Prometheus metrics 均已交付（见下方 Unreleased 与
> [README](README.md) 开发路线），从本表移除。

| 优先级 | 项 | 说明 | 前置条件 |
|---|---|---|---|
| P1 | 温命中 e2e 回归测试 | 守住节点侧"地址帧等待 10s→300s"与客户端池 60s TTL 的耦合（hydra-client/tests 既有 spawn_node 基建，闲置 11-12s 后 checkout 仍成功） | — |
| P2 | **eframe/egui 升级（0.27 → 0.33+）** | 根治 RUSTSEC-2026-0257（webbrowser Unix 参数注入，当前已评估豁免：发布产物为 Windows GUI，不含漏洞路径）+ 清除 unmaintained 传递依赖群（instant/derivative 等）；21 文件 GUI 需适配 API 变更 | 专门会话，升级后逐页目检 |
| P2 | VPN 数据面死亡感知 | run_stack 罕见路径中途退出时经回调通知 Kotlin 触发 kill switch 重连（当前 UI 停留"运行中"） | Rust→Kotlin 回调 FFI |
| P2 | pump 写阻塞 + 节点 TCP keepalive | write_all 无超时（对端零窗口钉住 permit/fd）+ 节点出站无 keepalive（企业级评审 P2-1） | socket2 已在依赖树 |
| P2 | health/metrics 端点并发上限 | accept 无 Semaphore/per-IP（误绑非回环时未认证耗尽 fd）+ 拒绝非 loopback 绑定选项 | — |
| P2 | 信令慢滴防护 | 逐字节读每字节重置 90s——改整行 deadline 或连接寿命上限（慢滴 4.3 天/连接） | — |
| P3 | pump 双时钟统一 | 空闲看门狗 SystemTime 墙钟 vs 寿命 Instant 单调钟（NTP 前跳误杀） | — |
| P3 | UDP 中继 target 维度 metrics | UDP 路径不产 target_ok/fail（TCP 有） | — |
| P3 | hydra-fetch 重试预算合并 | worker 3 次 × fetch_chunk 内 3 次 = 单块最坏 9 次握手 | — |
| P3 | with_cert_fp 改 Result | 非法输入 panic（GUI 用户输入可达） | — |
| P3 | CLI/GUI TUN 互斥跨形态 | 52810/52811 分端口——GUI(TUN) 与 CLI(--tun) 可并发抢 /1 路由 | — |
| P3 | GUI 代理退出信号时序 | exit_tx 在 runtime drop 前发出，快速重启新旧路由竞态 | — |
| P3 | Windows 开机自启 + TUN | 注册表自启 + UAC 免提示 | — |
| P4 | 多节点并行下载 | **需产品决策**：独立下载器形态（CLI/GUI、断点续传）——CONNECT 隧道字节不透明，代理内无法实现 | 产品决策 |
| P4 | rekey 密钥轮换 | V3.3；TLS 1.3 每连接独立密钥已绑住单连接暴露面 | 随多路径协议恢复设计 |

### rekey 密钥轮换（V3.3）设计草案

- **动机**：长连接（BT/SSH/流媒体）持续数小时，单一密钥暴露面随时间增长
- **现状**：TLS 1.3 每连接独立密钥 + Noise-PSK 握手 → 每条连接密钥不同，
  已绑住单连接暴露面；rekey 仅对**超长连接**有增量价值
- **方案 A（TLS 层）**：rustls 发送 TLS 1.3 KeyUpdate——rustls 0.23 无主动触发 API（被动支持），需 patch 或等 upstream
- **方案 B（应用层）**：连接时长/流量超阈值时透明重建（断旧连新 + 应用层重连协议）——TCP 序列号不连续，对应用不透明
- **方案 C（会话层）**：多连接聚合协议（V3.4 恢复）内做 key rotation——依赖多路径协议恢复
- **结论**：短期维持现状（每连接独立密钥已足够）；V3.3 多路径恢复时一并设计 C 方案

## [0.2.7] - 2026-10-11

（本节即下方全部新增内容；[Unreleased] 清空待下轮）

## [0.2.9.3] - 2026-10-28

### 分享链接折行重组（复制时被插入换行导致证书/密钥丢失——v0.2.9.2 用户实测复现）

- **问题**：用户完整分享链接（带 `cc=` 证书本体）导入后节点行显示"未导入
  证书"。根因：链接经聊天工具/网页折行显示，复制时折行变**真换行**且断点
  落在参数中间（`loss_rate=0` | `.01`）——首行成了「合法但残缺」的链接
  （节点导入成功，密钥/证书全丢），后续行全部成坏行。
- **修复（hydra-core `parse_subscription`）**：折行重组——`hydra://` 行与其
  后含 `key=value` 对（含 `=` 且不以 `=` 结尾，排除 base64 padding 尾）的
  非 hydra 行合组，先试**拼接**（去全部空白）解析；失败回退组内逐行（既有
  行为）。纯垃圾坏行（无 `=`，如 `not-a-link`）不参与拼接、照常报错
  （query_pairs 会把裸段当无值 key 静默忽略，激进拼接会吞坏行）——
  「完整链接 + 尾部坏行」「每行 base64 订阅」「整体 base64」等既有场景
  零回归。桌面 GUI/CLI 与安卓端同享此修复。
- 测试：折行复现（cc/k 随拼接恢复）/ 多条折行各自重组 / 完整链接+坏行
  零回归 / 拼接仍失败回退 / 混合订阅存活；hydra-core 123 全绿、全仓
  30 测试二进制 0 失败、Gradle 51 通过、assembleRelease 成功。

## [0.2.9.4] - 2026-10-28

### 按节点独立认证密钥（多节点各持 PSK——全局单密钥覆盖致其余节点 Noise 握手必败，v0.2.9.3 实测）

- **问题**：多节点各自部署、各持 PSK——导入节点 2 的链接把全局唯一密钥
  覆盖成节点 2 的，节点 1 从此用错密钥做 Noise 握手（msg2 解密必败，
  用户实测"节点 1 单独正常、导入节点 2 并测试后节点 1 报 connection
  error: Noise 握手失败"）。证书已按节点独立（v0.2.9），密钥仍是全局
  单值——同一设计缺口的另一半。
- **core（hydra-core）**：`ProxyServer` 新增 `with_node_auth_keys`（addr →
  32B PSK，缺项回落全局）；`TcpCreds.key_for` 数据面/温池/TUN opener/UDP
  工厂全路径按节点取密钥；恢复探测/测速同步按节点取（用别节点 PSK 探测
  会把密钥覆盖误判成节点离线）；凭据就绪判定放宽——全局空但按节点全覆盖
  亦可启动。
- **FFI（hydra-android）**：`ParsedShare` 新增 `node_auth_keys`（逐链接
  `k=` 按地址记录）；`HydraEngine::new` / `VpnConfig` 新增 `node_auth_keys`
  参数（逐条校验 hex，坏值构造期显式报错；全局可空）；绑定重生成。
- **Kotlin**：`SecureStore` 新增 `node_auth_keys` 表；`NodeKeys` 纯逻辑
  助手（单节点取用 + 就绪判定）；导入逐条合并互不覆盖；引擎/VPN/连通性
  测试/自检全链路按节点取密钥；删除节点同步清理；VPN 预校验缺失密钥
  直接点名节点。
- 测试：Rust `per_node_auth_keys_ready_and_fallback`（就绪判定 + 回落）+
  `parse_share_records_per_node_auth_keys`；Kotlin `NodeKeysTest` 7 例；
  hydra-core 124 / hydra-android 15 / Gradle 58 全绿。

## [0.2.9.2] - 2026-10-28

- 重新分发 tag：与 [0.2.9] 同代码（含紧凑链接 cf= 修复），versionCode 11 /
  versionName 0.2.9.2——v0.2.9 同名资产覆盖后下载 CDN/浏览器缓存返回旧包，
  改用全新 tag/URL 分发（crate 版本号保持 0.2.9：Cargo 语义化版本不支持
  四段号）。

## [0.2.9] - 2026-10-28

### 安卓端紧凑分享链接（仅证书指纹 cf=）导入修复

- **问题**：紧凑分享链接（公开渠道只带 `cf=` 证书指纹、不带证书本体——桌面
  GUI 紧凑模式或其本机未配证书路径时生成）导入后，安卓端 `parse_share_text`
  只处理 `cc=` 本体，`cf` 信息被整个丢弃——节点行显示"未导入证书"且无法
  核对证书漂移（v0.2.9 首发后用户实测反馈，随 v0.2.9 tag 重打一并发布）。
- **FFI**：`ParsedShare` 新增 `node_cert_fps: HashMap<addr, fp>`——完整链接
  （`with_cert_der` 同置 cc 与 cf）与紧凑链接的指纹都按节点记录。
- **存储**：`SecureStore` 新增 `node_cert_fps` 表；删除节点同步清理。
- **导入**：紧凑链接导入反馈明确提示"未带证书本体——请在设置页导入证书
  DER 或索取完整分享链接"。
- **节点行四态**：证书本体（含 cf 一致确认）/ 本体与链接指纹不符（握手
  将失败的漂移预警——含回落全局场景）/ 仅指纹待导入 / 无证书；漂移预警
  直指修复路径（重新导入该节点分享链接）。
- 测试：Rust `parse_share_records_compact_fingerprints` + Kotlin statusFor
  8 例；全仓 Rust 30 二进制 0 失败、Gradle 51 测试通过。

### 安卓端多节点独立证书（修复全局单证书覆盖导致握手 BadSignature）

### 安卓端多节点独立证书（修复全局单证书覆盖导致握手 BadSignature）

- **问题**：安卓端只有一张全局证书，多节点场景后导入节点的证书覆盖先前
  节点——用 A 的证书连 B 节点握手必败 `invalid peer certificate: BadSignature`
  （自签证书 Subject/Issuer 同名，rustls 只报 BadSignature 无法自行定位），
  多节点容灾静默退化为单节点；桌面 GUI/CLI/Rust 内核均已支持，仅安卓缺失
  （详见 `docs/issu/ISSSU-Draft-android-per-node-cert.md`）。
- **FFI**：`ParsedShare` 新增 `node_certs: HashMap<addr, b64>`——
  `parse_share_text` 逐链接按地址记录 `cc=`（同地址重复导入以最后为准 =
  证书漂移修复路径；全局 `cert_der_b64` 保留首个作回落，坏 cc 不阻塞后续）。
- **存储**：`SecureStore` 新增 `node_certs` 表（`addr\tb64` 行格式），
  `HydraConfig.nodeCertB64Map` 缺项回落全局；旧配置空表全量由全局回落承接，
  行为与修复前一致。
- **导入**：各链接证书写入各自地址条目互不覆盖；删除节点同步清条目。
- **引擎**：信任根池 = 各节点证书（缺项回落全局）∪ 全局去重（Rust
  `Pinned` 本就是多张语义，内核与 FFI 签名零改动）。
- **连通性测试**：手动测试与引擎自检改用被测节点自己的证书——证书错配
  不再误报成节点故障。
- **错误提示**：`BadSignature`/`invalid peer certificate` 映射为「证书
  不匹配——请重新导入该节点的分享链接」（原文保留供排障）。
- **UI**：节点页每行显示证书 SHA-256 指纹前 16 位（与分享链接 `cf=` 同
  算法，识别证书漂移/导入错证书）；pin 模式无证书节点行红色警示；设置页
  全局证书标注回落项语义。
- 测试：Rust `parse_share_records_per_node_certs` 三场景 + Kotlin
  `NodeCertsTest` 14 例；`cargo test --workspace` 30 二进制 0 失败、
  Gradle 44 测试通过。

### 安卓端日志与健康观测（内核事件桥接 + 周期健康探测 + 网络事件 + 日志页增强）

- **hydra-android（Rust）**：新增 tracing `KernelLogLayer` → 进程级环形缓冲
  （500 条、满员丢最旧、seq 单调）；入环前按 `mask_target` 语义脱敏（URL /
  IPv4 / 域名 / [IPv6]:端口 → 短哈希，端口保留）；uniffi 新增
  `vpn_logs_since(seq) -> Vec<VpnLogEntry>` 与
  `VpnLogEntry { seq, level, message, ts_ms }` 增量拉取接口；`start_vpn` 首次
  安装「日志环 + 文件」双订阅器，新会话清空内容但保持 seq 单调。
- **Kotlin 日志**：1s 统计轮询内增量拉取内核日志（lastSeq 游标 + seq 去重，
  UI 上限 500、新在前）；用户点击连接开启新会话时清空，kill switch 自动重连
  保留断线原因/时间线，服务停止（含系统撤销）清空（纯内存不落盘）。
- **Kotlin 健康探测**：连接后默认 300s 周期（可配 1m/3m/5m/10m/关，SecureStore
  持久化），连接建立与网络切换即时探测；三项独立计时——节点 TCP 直连
  （protect 物理路径）/ 隧道内未 protect 的 DNS 查询（223.5.5.5:53，真实测
  TUN→中继→节点）/ 可选 HTTP 204（1.5s）。日志格式
  `✓ 健康检查（节点 … · 隧道DNS … · HTTP 204 …）` /
  `✗ 健康检查失败（…）`；连续 2 次 WARN + 通知栏「网络异常」，连续 5 次建议
  手动切换节点/网络（不自动切节点）。
- **网络事件**：ConnectivityManager 回调记录 WiFi/移动网络切换、断开、恢复并
  即时触发探测；Manifest 新增 `ACCESS_NETWORK_STATE`（仅注册回调所需，无数据面
  行为变更）。
- **日志页 UI**：级别徽章着色（INFO/WARN/ERROR）+ 级别阈值过滤 + 关键字搜索 +
  自动滚动开关 + 清空 + 导出（`files/exports/*.txt` + 剪贴板）/ 系统分享；
  全部走 HydraTheme 令牌 + TalkBack 语义。
- 测试：Kotlin 单测 +11（日志合并去重/容量/过滤/导出顺序、健康结果格式化/
  失败判定/告警阈值/DNS 报文编解码/间隔归一化与默认值）；Rust +4。
  `cargo test --workspace` 全绿、clippy 零告警、
  `:app:testDebugUnitTest` / `:app:assembleDebug` 成功。

### 安卓端规则代理（智能分流延伸到 VPN 模式）

- **hydra-android**：`VpnConfig` 新增 `rule_mode` / `rule_file`（Kotlin 传
  沙箱绝对路径）；`start_vpn` 规则模式构建规则引擎（文件缺失/解析失败安全
  降级为全局代理，永不断网）；DNS 直连联动（R2）；安卓直连走 protect 形态
  （无 bind，P1-3 守卫自动放行）；全局模式（开关 OFF）行为与基线逐字节一致
- **Kotlin**：连接页新增「分流：CN 直连」开关（仅 VPN 模式，主题令牌适配四
  主题 + TalkBack）；设置页新增「分流规则」（规则文件 SAF 导入，限 1MB 只读
  复制到沙箱）；规则模式 VPN DNS 换用 223.5.5.5 / 119.29.29.29（CN 域名解析
  近端 CDN，GeoIP 判准直连）；运行中切换提示重启 VPN 生效
- 已知边界：规则判定的 UDP 暂走节点中继（安卓 UDP 直发需 bind 源 IP，TCP
  直连正常）；详见设计文档 §九与评审台账 §〇-B

### 统一路由层：TUN 规则引擎与 SOCKS/HTTP 域名分流两套机制合一（技术债闭环）

- **RuleEngine 双模判定**（hydra-core/routing_rules.rs）：新增
  `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` 三类域名规则（大小写不敏感，
  容忍 `*.example.com` 写法）与 `decide_domain(host, port)`——顺序：用户域名
  规则（full→suffix→keyword）→ DST-PORT → 内置 CN 域名直连层（引用 routing
  模块既有表，默认启用、用户规则可覆盖）→ 默认 Proxy；`decide(SocketAddr)`
  不变（TUN 用）
- **ProxyServer 接入**（hydra-core/proxy.rs）：新增 `with_routing_engine`；
  SOCKS5 CONNECT / HTTP CONNECT / HTTP 代理三个分流判定点改为——引擎挂载时
  IP 目标走 `decide`（与 TUN 统一 IP 口径，含私网直连）、域名走
  `decide_domain`；未挂载走既有 `HYDRA_SPLIT` 内置域名表（CLI/未接线路径
  **零行为变更**）；直连失败回退节点语义不变
- **GUI 接线**（hydra-client-gui/proxy_control.rs）：分流开关 ON 时与 TUN
  **共用同一引擎实例**（同一规则文件 + 内置表，两条入口口径合一）；规则文件
  不可用时不挂引擎并告警（TUN 侧 builtin_cn 降级不变）
- 测试 +11（decide_domain 三类/优先级/内置层/非法行、try_direct 引擎挂载
  直连/未命中/未挂载基线、TUN 与 SOCKS 统一口径样例）；workspace 406 全绿，
  clippy 零告警；设计文档新增 §八「统一路由层」

### 修复：系统代理残留治理（用户实测"关闭代理后浏览器断网"根治）

- **根因**：GUI 非正常死亡（强杀/断电）后注册表残留 `ProxyEnable=1 →
  127.0.0.1:port` 死端口；`enable` 把坏状态当"用户原值"存槽位，`disable`
  忠实还原 → 每次"启动→关闭"都把坏状态还回来，断网反复出现
- **启动自愈**：GUI 启动时检出"启用中且指向无监听本机端口"的残留直接清除
  （双实例守卫后执行；端口无监听校验保证不误伤其他软件的活代理）+ 应用日志留痕
- **修复式保存**：`enable` 时发现旧值是死代理残留 → 槽位改存"无代理"，
  停机恢复为直接连接，不再把坏状态原样还回（断根循环）
- **WM_ENDSESSION 钩子**：系统关机/注销时也恢复系统代理（eframe 不转发该
  消息，comctl32 子类化挂顶层窗口；与按钮/托盘/panic 三路径互补，强杀/
  断电物理上无回调由启动自愈兜底）
- 单测 3 项：回环端口解析各格式 / 端口活死 bind 探测 / 死代理判定矩阵

## [0.2.6] - 2026-10-11

### Android 真机实测修复（模拟器 + 真实 VPS 节点端到端验证）

- **P0 配置覆盖清空**：大按钮 onConnect 曾用 UI 陈旧缓存 `persist(cfg)` 回写存储——深链导入后点连接会把导入的节点/密钥/证书整份覆盖清空（实测 prefs 3298B→2562B，服务读到 0 节点启动失败）。改为先刷新缓存再启动，绝不回写；深链导入信号到达即重读存储刷新 UI
- **UX 相机权限**：启动即弹相机授权 → 改为点「扫码导入」时按需请求（拒绝给出可操作提示）
- **SecureStore 落盘**：`apply()` → `commit()` 同步（配置体量小、频率低，正确性优先）
- **R8 缺类修复**：Tink/Guava 编译期注解 dontwarn 规则（release 构建此前失败）
- **JNA proguard 规则**：uniffi 绑定经 JNA 调 FFI，禁混淆
- **正式签名**：keystore 生成 + gradle release signingConfig（环境变量注入 CI，本地文件回退 debug 签名）；keystore 入 .gitignore 不入库

### 真机验证结论（Medium_Phone_API_37 模拟器 + 真实节点 43.133.91.218）

- ✅ M2 全局 VPN 端到端打通：`tun0` UP（10.7.0.1/30），隧道 RX 30MB/TX 688KB 实测流量，App 显示「✓ 全局 VPN 已接管」
- ✅ 深链导入 → Snackbar + 节点 Tab 徽标（R5 反馈动线）
- ✅ 四主题实拍（跟随系统动态取色/深色/浅色/深海）全部正确渲染
- ✅ TalkBack 语义（content-desc/stateDescription 经 uiautomator 确认）
- ⚠️ 已知遗留：VPN 模式统计带（发送/接收/时长/活跃）未上报（FFI 缺 vpn_stats 接口，需 run_stack 暴露计数器，排入下批）
## [0.2.5] - 2026-10-11

### 桌面端（同版本迭代）

- **智能分流（规则模式）**：TUN 新增规则分流——GeoIP-CN（v4 4115 段 + v6 2012 段内嵌表）+ 自定义 CIDR/端口规则，命中直连、其余走节点；直连走源地址绑定 + protect 钩子 + 短超时回退；UDP 分流接入直发池（NAT 表 + 来源白名单）；DNS 直连联动 + 端口 53 强制直连；设置页分流模式单选 + 规则文件入口
- 修复 UDP 回包校验和覆盖零载荷的致命缺陷（同时影响既有中继）+ NAT 会话回收释放 socket + 无物理源 IP 防回环风暴（评审 P0/P1 全闭环，台账 docs/review/10）


- 速率图窗口改 **10 秒滚动**（20 点 · 500ms；启动后从 1s 慢慢拉长至满窗定格），Y 轴离散档位 + 隐形档位线固定网格（消除随数据每帧重排的卡顿感）
- 三数据卡 `ui.columns(3)` 构造级等宽（Grid 列宽浮动致第三列溢出窗口）
- 折线图悬停显示**格式化上/下行网速**（替代原始 xy 坐标）；Catmull-Rom 样条平滑 + 端点钳 0
- 节点卡显示去端口 IP（全显），完整地址保留在悬停提示
- 托盘「退出」兜底强退（清理挂起时 8s 强制结束 + 先移除托盘图标防残留）
### Android 端 UI 重设计（v1.1 / 评审 R1-R13 全部落实）

- **品牌四主题**：跟随系统（Material You 动态取色，默认）/ 深色 / 浅色 / 深海 Abyss（青绿品牌色，对齐桌面三主题令牌）
- **连接主页大按钮形态**：112dp 圆钮 + 四态状态环（断开灰/连接中旋转/已连接绿/错误红）+ 28sp 状态大字 + 节点摘要 + 统计带（独立 composable，每秒跳字不触发整屏重组）
- **双模语义**：本地代理（启动/停止代理）与全局 VPN（连接/断开 VPN）同一按钮按 runMode 分流；VpnService 授权流挂点就绪
- **MainActivity 拆分**：52KB 单文件 → Theme/Home/Nodes/Settings/ShareImporter/EngineState 独立模块（装配壳 13KB）
- **可达性**：大按钮动态 contentDescription + stateDescription + liveRegion；动画随系统「关闭动画」设置静止；横屏两栏适配
- **评审修复（P1×2）**：运行中切换模式不再产生孤儿引擎（persist 停旧服务 + 双停兜底）；证书 SAF 导入移出主线程（防 ANR）
- 其他：LazyColumn 重复 key 崩溃修复、主题存 SharedPreferences（非 SecureStore）、导入成功 Snackbar + 节点 Tab 徽标
## [0.2.4] - 2026-10-10

### 批次：内核优化 13 项（四批）+ UI v4.1 三主题 + CLI 分享链接 + 打洞同时打开修复

### 新增

- **CLI 分享链接自动配置**：`hydra-client.exe "hydra://..."` 直传即全配好
  （此前分享链接只在 GUI/Android 生效，CLI 报"未设置 HYDRA_AUTH_KEY"）
- **UI v4.1 三主题运行时体系**：Dark/Light/Abyss 零锁切换 + 首页重排
  （Hero 条/三数据卡/快捷条/图表重构）+ 设计评审 12 条与 code review 修复
- **节点 DNS 共享缓存**（hydra-node/dns_cache.rs）：正向 60s/负缓存 10s/
  1024 LRU + 并发 64 闸——多客户端并发解析不再放大上游 DNS 压力
- **Happy Eyeballs 并行建连**（#6③）：首两候选 250ms 错峰竞速先到先用，
  黑洞候选不再吃满串行预算（失败尾延迟 20s → ~2-3s）
- **Metrics v2**：17 指标族——字节收支/四段握手延迟直方图/UDP 会话面/
  拒入四因分解（per_ip/capacity/tls/auth）
- **弹性温连接池**（#7）：cap 按 peak EWMA 弹性 clamp(2..8) + 周期清扫
- **节点侧 TCP Fast Open**（listen，Linux 门控）+ sysctl≥2 文档
- **温池 stale 短超时**（#1）：复用陈旧温连接 8s 快速失败（env 可调 2..20s）
- 本地 UI 测试包一键构建脚本（scripts/build-ui.ps1 → local-dist/）

### 优化

- **冷连接握手压缩**（#3）：握手与目标地址帧捎带合并，5→4 RTT
- **UDP 中继瘦身**（#9）：会话接收缓冲分层 8K→16K→64K（截断升档）+
  时钟统一单调 Instant（reap 不再受 NTP 墙钟回拨影响）
- **Android FdTransport 重写**（#2）：专职读/写线程 + poll 轮询停止位——
  停止代理不再卡死转圈（真机 bug 根治）
- **目标流 keepalive + TCP_USER_TIMEOUT 90s**（#12，Linux）：死目标 ~90s
  回收，不再等 300s idle 兜底
- 候选排序效用值归一化（#11）：和恒定 0.4/0.3/0.2/0.1 ∈ [0,1]
- pump 读唤醒常数化（#8）：1s 轮询替代不稳定时钟假设

### 修复

- **P2P 打洞同时打开握手角色**：角色改按地址序分配（低=client）——真·
  同时打开时连接两端都是出站 socket，按连接方向分配会双端同为 client
  互相等对方 msg2 而全败 → 白等 10s 窗口回落中继（Windows CI 实测）
- **GUI 粘贴导入分享链接丢弃凭据**：密钥/证书未入配置致启动报
  "未设置 HYDRA_AUTH_KEY"（真机反馈）
- **GUI 托盘退出即时收敛**：不再阻塞 5s 被系统判无响应 + 单实例冲突可见化
- **SEC-01/SEC-02（Android P1）**：VPN protect 钩子 vpnActive 门控（本地
  模式不再被残留钩子断网）；数据面死亡先建黑洞 TUN 防真实 IP 泄漏
- **企业评审 P0**：Cargo.lock 入库（缓存 key/复现性/审计）；wintun.dll
  签名强制校验；B-1 帧读取独立任务修复 select 取消不安全流失步
- 内核优化 code review 回顾 3P0：客户端 TFO 撤下（DEFER_CONNECT 与 tokio
  poll_writable 不兼容挂起）、Android 停机死锁、DNS 缓存键丢端口放大负缓存
- 节点 setsockopt extern 声明统一（clashing-extern-declarations，Linux CI）

## [0.2.3] - 2026-10-09

### 批次：UI v4 企业级批次（P0）+ 设计方案评审入库

### 新增

- **设计团队方案**（docs/design/UI设计方案-v4-企业级.md）：55 条启发式审计
  （2P0/13P1/23P2/17P3，全部带代码证据）+ Design Tokens v4（对比度 42 项
  WCAG 实测）+ 六页规格 + egui 实现映射（A/B/C 难度）；经方案评审 10 项
  修正后执行（NodeHealth 枚举签名、G-04 API、统计卡三档、虚拟表格移入
  不做清单）
- **状态三通道编码**（颜色+字形+文字，ND-01 P0 根治）：palette 新增
  NodeHealth 五态枚举 + health_color/symbol/label 单点判定
- **公共组件库 components.rs**：status_pill/banner/empty_state/
  ConfirmAction+draw_confirm_dialog（Esc 取消、级联删除红字说明）
- **破坏性操作全部确认**：删节点/删订阅（级联计数+本地文本提示）/清空日志
- **日志结构化**（LG-01/02 + 评审决策）：级别枚举着色/过滤/等宽 + 容量
  100→1000 + 导出到文件；⚠️/✗ 调用点迁移 add_warn/add_error
- **首页**：启动失败 DANGER 横幅（G-02）+ 无配置引导卡（OV-06）+ 统计卡
  三档列数（G-11 400px 溢出修复）+ 字号 token 化
- **侧栏**：三态状态徽章含「启动中」（TR-01）+ 选中左缘条（TR-02）+
  Ctrl+1..6 切页（G-05）+ 间距 token 清理（G-07）

### 批次：企业级全量代码评审（三路并行，~25k 行）

#### 结论

0P0 / 2P1 / 9P2 / 若干 P3——P1 与高危 P2 本版修复，其余入待开发计划。

### 结论

三路评审（协议+节点 / 核心库+下载器 / 客户端+Android+GUI）合计 **0 P0 / 2 P1 / 9 P2 / 若干 P3**——P1 与高危 P2 全部修复，其余入待开发计划。

### 修复（本批）

- **[P1] hydra-fetch 状态文件并发"原子写"失效**：多 worker 共享同一 `.json.tmp`，并发 save 交错写/丢更新——临时名加进程内唯一序号（残余边界如实标注：rename 顺序不受限，丢的只是已完成位，续传多重下已完成的块，数据不会错）
- **[P1] TUN UDP 中继 UdpCmd 无界通道**：重连退避窗口无人排空，QUIC/DNS 重负载可积压数百 MB——改有界 1024 + try_send Full 即丢包（UDP 语义）
- **[P2] TUN 网关未知仍继续接管**：豁免路由（含节点 IP /32）缺失 = 出站被自身 TUN 捕获的递归自环直至流表打满（fail-broken）——RoutePlan 增加 `gateway_resolved` 标记，run_tun fail-fast 拒绝启动
- **[P2] hydra-fetch worker 文件打开失败误用 content_changed**：会误删断点状态文件且文案误导——改走 fatal 终态（保留状态）
- **[P2] 服务器 200 响应（无视 Range）被判终态**：可恢复场景——新增 `RangeIgnored` 类别，编排层自动回落单流重跑
- **[P2] 温池 reaper 守卫固化缺陷**：无 runtime 的空尝试被 OnceLock 固化为已初始化——改 AtomicBool（空尝试不置位，可重试）
- **[P2] onRevoke/onDestroy 主线程同步 stopVpn**：FFI 持锁 shutdown 最长 3s 阻塞主线程——移独立守护线程
- **[P2] 分应用白名单全失效静默反转为全量接管**：establish 侧显式告警

### 记录入待开发计划（评审发现，未阻塞）

pump 写阻塞绕过空闲看门狗 + 节点无 TCP keepalive；health 端点无并发上限；信令逐字节慢滴（4.3 天/连接）；pump 双时钟（SystemTime/Instant）；UDP 中继无 target 维度 metrics；UDP 会话队列无字节预算；hydra-fetch 重试预算双层相乘；with_cert_fp panic；GUI 代理线程退出信号时序；CLI/GUI TUN 互斥跨形态缺口等——见待开发计划表新增行。

### 评审确认的既有强项

Noise-PSK 常时比较/通道绑定/重放防护、SSRF 解析后过滤+单源黑名单、UDP 会话表竞态处理、证书 0600 原子创建、信令属主证明+限速、VpnExitCallback 绑定字节级一致（本机重建 .so 再生 diff 为空）、TUN 路由回滚/崩溃清理、kill switch 跨代竞态处理。

### 批次：hydra-fetch 多节点下载器 + rekey Tier1

### 新增

- **hydra-fetch 多节点并行下载器（CLI）**：HTTP Range 分块按**节点评分加权**
  分散到多节点并行拉取 + 断点续传（状态文件 ETag/Last-Modified 强校验，参数
  漂移即失效防位图错位写花文件）+ 单流回落（无 Range/无 Content-Length）+
  可选整文件 SHA-256 校验 + worker 持久隧道复用（keep-alive，省每块握手）。
  走公开低层 API 组合（Scheduler + connect_channel/request_target +
  spawn_recovery_probe——设计评审修正：TcpCreds/open_target 私有且
  tun_channel_opener 无法指定节点，原设计会导致并行度退化为单节点；
  **hydra-core 零改动**）。目标站 TLS-in-TLS：webpki 公共 CA + 主机名校验 +
  **ALPN 锁定 http/1.1**（评审 P0：h2 协商成功即死锁）。已加入 release 产物。
- **rekey Tier1：连接最长寿命**（`HYDRA_MAX_CONN_AGE_SECS`，默认 0=关，
  clamp 60..604800）：节点侧 TCP pump 寿命 deadline（独立于空闲看门狗——
  活跃连接到期也关闭）+ UDP 中继 serve 寿命 + 客户端 TUN UDP 通道超龄主动
  轮换（break → 既有重连逻辑 = 新密钥）。**诚实定位**：超龄为强制关闭
  （数据路径无控制通道），rustls 已按套件约束自动刷新 TLS 流量密钥——
  本项是会话寿命/资源边界的防御纵深，非密码学必需。

### 方案评审 + spike 结论（先评审后执行的流程记录）

- 设计评审结论"需修正后执行"：下载器改公开低层 API 组合（原两条路径矛盾/
  不可行）；状态文件补参数校验；续传强校验（无校验器不续传 + If-Range 恒带）；
  目标 TLS ALPN 锁定。rekey Tier1 修正：客户端仅 UDP 通道实施（TCP 用户流
  节点侧已强制）；"优雅退役"改如实"强制关闭"；覆盖 UDP 中继 serve 路径。
- **snow spike（snow 0.9.6）**：`TransportState` 具备完整 rekey API
  （rekey_outgoing/rekey_incoming/rekey_manually + nonce 读取）；**但
  hydra-protocol 握手后即丢弃 TransportState（Noise 仅认证，数据面 = TLS 1.3）
  ——snow rekey 对现协议是无效果能力**。Tier2 并入 v4 帧化协议一并决策
  （v4 数据面 TLS → rustls refresh_traffic_keys；Noise 帧化 → snow rekey）。

### 测试

- hydra-fetch 14 项单测（HTTP 解析含 chunked/EOF、BodyReader 三帧式与前缀
  边界、状态文件校验/原子写、SHA-256 已知向量）；hydra-node 新增 pump 寿命
  deadline 单测（活跃也关闭）。

### 批次：性能与运维（温连接池 + 托盘禁用态 + 节点 /metrics）

### 新增

- **温连接池（pre-warm，P2 性能最大单项）**：v3 协议一条连接只服务一个目标，
  浏览器式短请求每条付一次 TCP+TLS1.3+Noise 握手（实测 300–500ms）。新
  `hydra-core::pool::ChannelPool`：握手在上一请求转发期间后台完成（每节点
  ≤2 根温连接、60s TTL），请求到达取用现成通道直发目标帧——**握手延迟归零，
  零协议变更，新旧两端完全兼容**。温连接失败一律弃连回退全新握手，不参与
  节点评分/故障切换判定（纯优化层）；SOCKS/HTTP/TUN 三路径统一受益。
  配套：`tcp_transport` 拆分 `connect_channel`/`request_target` 两阶段
  （`connect_target` 原签名保留为便捷封装，nat/udp_relay/speedtest 等旧
  调用方零改动）。
- **节点侧配套**：已认证后的地址帧等待从 AUTH_TIMEOUT(10s) 改为连接空闲
  看门狗（默认 300s）——Noise 后与转发期同信任级别（额度/per-IP/空闲看门狗
  全在管），否则温连接 10s 即被节点关闭、池永远打不中；慢速攻击防护仍在
  认证前阶段（TLS/Noise 的 10s）。
- **托盘菜单禁用态**（五项攻坚遗留）：「启动代理/停止代理」按运行状态启用/
  禁用（启动中禁启动、停止态禁停止），与 tooltip 同一状态源同步。
- **节点 /metrics（Prometheus 文本端点）**：随 `HYDRA_HEALTH_ADDR` 健康端点
  开关（同端口 `/metrics` 路径），零依赖手写渲染。计数面：连接总数/活跃数/
  拒入数（per-IP 超限 + 额度耗尽）、目标建连成败、UDP 中继连接数、uptime/
  版本。Grafana 抓取即出面板。

### 独立评审记录

- 评审 pass；P2 修复：托盘菜单禁用态被 tooltip 去重块门控（首帧跳过导致
  停止态「停止代理」可点）——移出去重块（自带状态去重）。已知边界：
  温连接 TargetUnreachable 保守回退全新握手（多付一次握手，语义更稳）；
  池无周期清扫（残留 ≤2×节点数，节点侧 300s 自行释放）；温命中 e2e 回归
  测试（守住 10s→300s 耦合）列入后续补测。

### 修复

- **[中] 客户端无 RUST_LOG 时完全静默**（真机部署反馈：功能正常但零输出，
  用户误以为未启动；节点侧 /metrics 佐证连接计数正常）：裸 `fmt::init()`
  无 RUST_LOG 时默认 error 级。改为 `HYDRA_LOG_LEVEL`（默认 info；RUST_LOG
  存在时优先）——兑现 README 环境变量表既有承诺（节点侧同款模式），另加
  启动横幅（版本 + 日志级别）。GUI 同款初始化。info 级安全：目标地址已在
  日志层脱敏。

### 批次：Android 启停修复（真机实测 bug）

### 修复

- **[高] VPN 模式应用内"停止代理"失效**：MainActivity 对两种运行模式统一用
  `EngineService.ACTION_STOP` 构造停止 intent，而 `HydraVpnService` 的停止
  常量是 `ACTION_VPN_STOP`——服务收到未知 action 后落入 else 分支**被当成
  启动**：点停止 → 伪启动 → Rust 返回"VPN 已在运行"→ UI 一直转并显示
  "启动失败"，同时旧引擎从未收到停止指令、继续接管全部流量（真机实测）。
  三层修复：
  - 停止按钮按运行模式使用各自服务的 ACTION_STOP 常量（根因）；
  - 两个服务 `onStartCommand` 只认显式 `ACTION_START`（或无 action）启动，
    未知 action 一律忽略（防同类回归）；
  - 启动/停止竞态守卫：启动期间收到停止时，过期的启动结果不覆盖 UI 状态、
    刚启动的引擎立即终止（防"UI 显示已停止而引擎仍在跑"的僵尸态；
    EngineService 的阻塞握手 `eng.start()` 返回后二次校验 generation）。

### 批次：Android VPN 保护（kill switch + 开机自启 + 分应用代理）

### 新增

- **断线阻断（kill switch，默认开）**：隧道建立失败/中断时保持全接管路由的
  「黑洞 TUN」（不消费 → 内核队列满丢弃 = 流量被阻断、真实 IP 零泄漏），
  指数退避（3s→30s，含 jitter）自动重连；分应用过滤 TUN 建立失败时回退
  全量阻断（阻断永不回退直连）。用户显式停止才恢复直连；首页/通知栏均展示
  阻断与重试状态，重连期间「停止代理（重连中）」按钮保持可达。
- **开机自动启动 VPN**（默认关）：BootReceiver（BOOT_COMPLETED → 已授权 +
  已配置才静默拉起）；设置页开关。可靠的 Always-on 路径是系统设置（免一切
  自启限制），设置页提供深链引导。
- **分应用代理**：白名单（仅所选应用走 VPN）/ 黑名单（所选应用直连），
  VpnService addAllowed/DisallowedApplication 实现；设置页模式切换 +
  应用选择器（Manifest `<queries>` 声明包可见性，Android 11+ 可正常列出；
  草稿式多选、「完成」一次持久化）。

### 修复（随本批）

- **[高] FGS dataSync → specialUse**：Android 15+ 对 dataSync 前台服务有
  6h/24h 强制超时——会静默杀死 VPN/本地引擎并击穿 kill switch 承诺，且
  BOOT_COMPLETED 启动受限（开机自启恒失败）。两个服务换 specialUse 类型
  （用途声明入 Manifest），无超时、自启恢复可用；补 onTimeout 防御性收敛。
- **[高] 配置错误 fd 泄漏**：Rust `start_vpn` 配置校验失败发生在 fd 接管
  之前，Android 已 detach 的 fd 无人认领——kill switch 重试逐轮泄漏直至
  fd 耗尽。双修复：fd 接管前移至一切校验之前（错误路径连 fd 一起释放）；
  Kotlin 侧启动前预校验（节点 IP:port / 64 hex 密钥 / pin 证书非空），
  配置类错误直接「启动失败」不进重连循环。
- **[中] 失效包名防御**：分应用列表含已卸载包名时部分系统使 establish 持续
  失败——建立前 PackageManager 校验剔除 + 失败回退全量黑洞。
- 启动/停止竞态守卫补全（重连 UI 写入前复检 generation）；取消异常穿透；
  onRevoke 补齐计数复位；看门狗与重连循环互斥。

### 独立评审记录

- 首轮评审 fail（4 P1 / 3 P2 / 7 P3），全部处置：包可见性（P1）→ Manifest
  queries；fd 泄漏（P1）→ Rust 接管前移 + Kotlin 预校验；6h 超时（P1）→
  specialUse；失效包名（P1）→ 校验剔除 + 全量回退。黑洞 TUN 保序（先放后建
  的毫秒直连窗口）记为已知边界（反向依赖 OEM 原子替换行为，真机验证后再换）。
- 真机验收清单见评审报告：kill switch 抓包（TCP 挂起超时/UDP 丢包/DNS 超时）、
  分应用正反断连、卸载已选应用后重连、Android 15+ 6h 长跑与开机自启、
  空配置启动路径、启停竞态连点。

## [0.2.2] - 2026-10-09

### 批次：节点侧 v4-only 降噪（DNS AAAA 本地过滤 + v4 优先建连）

#### 修复

- **[中] v4-only 节点 ENETUNREACH 噪音**（线上实测单节点单日 1.5 万条
  error）：TUN/VPN 模式下客户端系统 DNS 应答中的 AAAA 记录经 UDP 中继
  原样回流，应用拿 v6 地址建连 → TUN 以字面 v6 目标交节点 → 无 IPv6 出口
  的节点直连 v6 秒败（客户端回落 v4 功能无碍，但 error 噪音掩盖真问题）。
  双保险修复：
  - **DNS AAAA 本地过滤**（新增 `hydra-node::dns_aaaa`）：节点无 v6 出口
    路由（UDP connect 探测全球单播，进程级缓存）时，对目标端口 53 的标准
    查询直接合成 NODATA 应答——不建会话、不出上游流量，客户端 OS 回落 A
    记录，v6 目标从源头消失；`HYDRA_DNS_FILTER_AAAA=1/0` 强制开/关；
  - **目标建连 v4 优先逐候选回落**：`resolve_and_connect` 域名解析结果
    整理为 v4 优先候选列表（保序全量去重），15s 总预算内逐候选尝试
    （Happy Eyeballs 式），SSRF 过滤逐候选复查；中间失败降 debug 级。
- 独立 code review 修复：拦截路径下行写失败不再贯穿会话路径；opcode≠QUERY
  放行（NOTIFY/UPDATE 不掺和）；非相邻重复候选去重；补 AAAA 拦截 duplex
  级集成测试与 NODATA 帧逐位断言。

### 批次：Android M2（全局 VPN + 任意端口 + DNS 经隧道）

#### 新增

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

#### 修复（code review 发现）

- **[高] protect 钩子陈旧引用**：start_vpn 的 Rust 钩子首装后捕获第一个
  HydraVpnService 实例，服务重建后旧引用导致 protect 永远失败 → 零流量。
  修为 VpnProtectHolder 进程级委托
- **[中] tcp_syn_dst_port v6 flags 偏移错位**（pkt[54]→pkt[53]）——新单测
  抓出的真实 bug，v6 SYN 端口解析此前恒返回 None
- **[低] 日志字符串拼接优先级**修正

#### 新增测试

- R1 单元测试：tcp_syn_dst_port（v4/v6/SYN+ACK/UDP）、动态监听挂载/去重/上限

### 批次：桌面 TUN UDP-over-proxy 接管 + DNS 经隧道（TUN 方案 v2 方向落地）

#### 新增

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

#### 变更

- README/TUN 交付状态与已知边界同步重写：UDP 接管与 DNS 经隧道移入"已交付"。

### 批次：Android M1 + 审查 09 收尾（上批遗留技术项清账）

#### 新增（Android M1）

- **真机可跑的本地代理应用**：Compose UI（节点多行/SNI/认证密钥掩码/自签 pin 与
  CA 双模式/证书 DER 导入/本地端口）→ 前台服务持有 HydraEngine（防 Android 11+
  Cached App Freezer 冻结后台进程，通知栏实时流量/连接数）→ EncryptedSharedPreferences
  密钥存储（R8 必须项：Keystore 主密钥 AES256-GCM，allowBackup=false）。
  cargo-ndk 交叉编译 arm64-v8a + x86_64 release so；桌面 JVM 冒烟回归通过。

#### 修复（审查 09 上批遗留，P3 清账）

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

#### 文档

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
