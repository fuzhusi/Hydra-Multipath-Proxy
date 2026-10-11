# 安卓端 UI 重设计方案 v1 评审报告

> 评审对象：docs/design/安卓端UI重设计方案-v1.md ｜ 日期：2026-10-11
> 参照：桌面端UI重设计方案-v4.md（令牌源头 + R1/R2/R4 修正项）、android/.../MainActivity.kt 现状（1264 行）
> 对比度均按 WCAG 2.x 相对亮度公式实算，保留两位小数。

---

## 总结论：**需修订后实施**（架构方向正确，无阻断性错误；但存在 1 个 P0 对比度矛盾、2 个 P0 遗漏项，修订成本低，随 T1–T5 一并落实即可）

---

## 一、主题架构（四模式）

**判定：方向正确，实现细节需补三条规范。**

1. 四模式（System 动态 / Dark / Light / Abyss）是 Compose M3 的标准做法，与现状 `HydraTheme` 的 `dynamicDarkColorScheme/dynamicLightColorScheme` 分支（MainActivity.kt:150-167）兼容。正确实现要点：
   - **分支顺序**：`when(mode) { System -> if (SDK>=31) dynamic*(ctx) else 中性蓝灰板; Dark/Light/Abyss -> 静态品牌板 }`。现状 <31 回落 `MaterialTheme.colorScheme`（默认紫）的问题必须在 <31 分支给出**静态中性板**而非默认板，方案 §3.1 已提到"中性蓝灰板"，建议在 T1 中明确色值（可直接复用 Dark 板，标注"品牌近似"即可）——**待验证**：中性板取 Dark 还是独立灰板，影响 <31 设备观感，建议 T1 定稿时截图确认。
   - **品牌板对 CompositionLocal 的注入**：只替换 `MaterialTheme.colorScheme` 不够。方案未提 **Abyss 的 accent2 紫 #8B5CF6 与状态语义色（success/warning/danger）如何下发**。建议：语义色收进自定义 `LocalHydraColors = staticCompositionLocalOf<HydraColors>`（`staticCompositionLocalOf` 而非 `compositionLocalOf`——主题色不变化时读值不走重组订阅，主题切换属整体替换场景，二者皆可行，但 static 开销更低），在 `HydraTheme(mode)` 内 `CompositionLocalProvider`。若强行塞进 `ColorScheme`（如借用 tertiary 装 accent2），语义会被 M3 组件默认用法误消费，不推荐。
   - **System 模式的动态取色与品牌组件的兼容坑**：动态板下 `colorScheme.primary` 是壁纸色，"大按钮 accent 环"若直接读 `colorScheme.primary` 则四模式视觉不一致。建议组件层定义 `val accentColor = hydraColors?.accent ?: colorScheme.primary` 的统一取值口，一处收敛。
2. **SecureStore 存主题：过重，判定 ✗**。主题偏好非敏感数据，存 Android Keystore 加密的 SecureStore 有三个实际代价：(a) 每次启动多一次 Keystore 解锁 IO（低端机可感知）；(b) SecureStore 若绑定单设备密钥，备份/换机迁移时主题丢失（无害但怪）；(c) 与节点凭据混存同一文件，`uiTheme` 字段会跟着凭据读写路径走，耦合。**建议改 DataStore Preferences（或现状若无依赖则 SharedPreferences 即可，单字段场景 SharedPreferences 完全够）**，key `uiTheme`，枚举名存字符串。方案 §3.1 与 T1 需同步改。注意现状 `SecureStore` 同时存节点/密钥（MainActivity.kt:174-200 ShareImporter），**不要**因此把整个 store 换掉，只把主题这一个字段挪出去。

---

## 二、对比度核算（WCAG 实算值）

对照桌面 v4 令牌表（含其 R1/R2/R4 修正）：

### Abyss（bg #0A1220，L=0.0060）
| 前景 | 色值 | 对 bg | 判定（正文≥4.5 / 大字≥3） |
|---|---|---|---|
| text | #D8E4F0 | **14.53:1** | ✓ |
| accent（状态环/大字） | #2DD4BF（L=0.5785） | **11.22:1** | ✓ |
| success（"已连接"绿字） | #34D399 | **9.75:1** | ✓ |
| danger（错误态字） | #F87171 | **6.78:1** | ✓ |
| warning | #FBBF24 | **11.23:1** | ✓ |
| accent2 紫 | #8B5CF6 | **4.43:1** | ✓（大字/图形）；作正文差 0.07，仅限大字与装饰 |
| **on_accent（按钮内文字）** | 深字 #0A1220 对 accent | **11.22:1** ✓ | **白字对 accent 仅 1.67:1 ✗**（桌面 v4 R4 记 1.86，实测 1.67——待验证其算式，但结论一致：必须深字） |

### Dark（bg #12141C，L=0.0071）
| 前景 | 色值 | 对 bg | 判定 |
|---|---|---|---|
| text #E8EAF2 | | **15.30:1** ✓ | |
| accent #4C8DFF | | **5.74:1** ✓ | |
| success #34D399 | | **9.56:1** ✓ | |
| danger #F87171 | | **6.64:1** ✓ | |
| warning #FBBF24 | | **11.01:1** ✓ | |
| on_accent | 白字对 accent | **3.20:1** | 仅大字/粗体达标；**建议对齐桌面 R4：Dark 也用深墨字 #12141C on accent（5.74:1）**，或按钮文字 ≥18sp 粗体 |

### Light（bg #F5F6FA，L=0.9223）
| 前景 | 色值 | 对 bg | 判定 |
|---|---|---|---|
| text #1A1D29 | | ≈**14.6:1** ✓ | 待验证（按公式推算，未逐通道列算） |
| accent #2563EB | | **4.79:1** ✓ | |
| on_accent 白字 | | **5.17:1** ✓ | Light 可用白字（与桌面 R4"Light 用深墨"不一致——待验证桌面 R4 的适用范围，Android 端实测白字已达标） |
| success #059669 | | **3.49:1** | ✓ 仅限状态大字（28sp）；作 14sp 正文不达标——方案统计带若用绿字标速度需换 accent/text |
| **warning #D97706** | | **2.95:1 ✗** | **P0 矛盾**：桌面 v4 R2 已裁定加深至 #B45309（实算 4.65:1 ✓），但 v4 令牌表 L78 仍写 #D97706。Android 方案 §3.1 说"令牌完全一致"，若照抄表值即带入不达标色。**Android 必须锚定 R2 修正值 #B45309，并回改桌面 v4 表（建议另开一条令牌源勘误）** |
| danger #DC2626 | | **4.47:1** | 边缘达标（正文 4.5 差 0.03），仅用于大字/横幅底可接受 |

**Abyss accent 上白字还是深字：深字（#0A1220），实测 11.22:1，白字 1.67:1 直接否决。**

---

## 三、首页大按钮形态

**判定：形态成立，四个细节需写进方案。**

1. **无障碍**：112dp 圆钮远超 48dp 最小触摸目标 ✓；但必须 `Modifier.semantics { role = Role.Button; contentDescription = 由状态动态生成："启动代理"/"停止代理"/"连接 VPN"/"连接中…" }`——按钮内是 Text，TalkBack 默认能读，但外环是自绘 Canvas（状态环），环上的动画信息 TalkBack 读不到，需在 Box 层给 `stateDescription`（如"当前状态：已连接"）+ `liveRegion = LiveRegionMode.Polite` 让状态变化播报。旋转/呼吸动画必须 ` SharedPreferences/开发者选项"移除动画"`与 `LocalAccessibilityManager`/`animateFloatAsiana` 的 `visibilityThreshold` 无关——正确做法：检测 `Settings.Global.ANIMATOR_DURATION_SCALE == 0f` 或用 `LocalContext` 读系统动画缩放，为 0 时跳过无限循环动画（省电 + 前庭安全）。
2. **四态动画实现要点**：旋转环用 `rememberInfiniteTransition().animateFloat(0f→360f, tween(1000, LinearEasing))` + `Modifier.drawBehind { drawArc(...) }`（不要用 `rotate()` 包整个按钮——会连内文一起转）；呼吸环用 scale 0.98→1.04 + 环 alpha 联动，`tween(1200, FastOutSlowInEasing, RepeatMode.Reverse)`。**关键**：`rememberInfiniteTransition` 在状态离开"连接中"时必须停止——用 `if (state==Connecting)` 条件包裹整个动画组合，否则已连接后动画仍在跑，浪费电且 Compose 不会自动回收。
3. **状态胶囊与前台通知同源（EngineState）：有坑，需写明**：(a) `EngineState` 现状是 object 单例（MainActivity.kt:196 直接 `EngineState.addLog`），跨进程不可用——前台服务如果将来跑在独立进程（`:vpn` 进程是 VpnService 惯例），单例同源立刻失效。方案应加一句：**UI 与通知同源仅限同进程；M2 若分进程，状态源改为 Binder/AIDL 或服务端广播，EngineState 只做 UI 侧镜像**。(b) `MutableStateFlow` 单例 + `collectAsState` 时，Activity 重建不丢状态 ✓，但要防"通知已停、UI 还在 Connecting"的半更新：状态迁移必须是引擎侧单写入口，UI 只读。
4. 112dp 圆钮在 `windowInsets` 底部有 NavigationBar 的小屏（5 寸 640dp 高）上，配合状态大字 28sp + 统计带 + 日志 2 行，`verticalScroll` 必须有；方案 §3.2 未写滚动降级，建议补。

---

## 四、遗漏项（P0×2，P1×3）

| # | 遗漏 | 级别 | 说明 |
|---|---|---|---|
| G1 | **VpnService 权限流（M2 prepare launcher）** | P0 | 现状 MainActivity.kt 已用 `rememberLauncherForActivityResult(StartActivityForResult)` 的模式处理扫码；M2 的 `VpnService.prepare(ctx)` 返回 Intent → launcher 启动系统授权页 → `onActivityResult` 判 OK 后才 startService。方案 D5 只说"权限流直接挂入"，**未写明挂在哪**：建议大按钮点击 handler 内同步 `prepare()`，非 null 即 launch，授权结果落地前按钮进"连接中"禁用态。T2 的 HomeScreen 需预留 `vpnPermissionLauncher` 参数位（或上提到 MainActivity 装配层），避免 M2 时改 HomeScreen 签名。 |
| G2 | **深链导入入口在新首页的位置** | P0 | 现状 `hydra://` 深链（MainActivity.kt:126-145）是静默 Toast 导入，新首页信息架构（§3.2）里没有任何"导入成功"的落点——用户从微信点链接进来只看到一条 Toast，首页无反馈。建议：导入成功后切到"节点"Tab 并 Toast/快照条；或首页节点摘要卡下加一次性"刚导入 N 个节点"横幅。方案需补这条动线。 |
| G3 | 横屏 / 折叠屏 | P1 | §3.2 线框是纵向单列。大按钮 112dp + 状态大字在横屏会顶出统计带；折叠屏展开态（~600dp+ 宽）单列拉伸难看。最低成本规范：横屏/宽屏（`WindowSizeClass.WidthCompact 以下除外）时改为"按钮居左、统计带居右"的两栏 Row，或简单 `widthIn(max=480.dp)` 居中。不阻塞本轮，但 T2 布局代码要留 Column 宽度上限，避免返工。 |
| G4 | TalkBack 标签全覆盖 | P1 | 除大按钮外：状态胶囊（contentDescription="连接状态：已连接"）、统计带三格（"上传速率每秒 1.2 兆字节"格式化读法）、NavigationBar 三 Tab 现状已带 label ✓。建议在 T5 验收加一项"TalkBack 走查三 Tab"。 |
| G5 | POST_NOTIFICATIONS / CAMERA 权限请求时机 | P2 | 现状 onCreate 一次性弹两个权限（MainActivity.kt:105-121），重设计后建议 CAMERA 延迟到扫码动作触发时再请求（现状已偏late-bound 但仍是启动即弹），顺手改进，不强求。 |

---

## 五、T4 拆分计划与重组性能

**判定：拆分粒度合理，方向对，但缺两条性能护栏。**

1. T4 的文件边界（Theme / Home / Nodes / Settings / MainActivity 装配）与现状 52KB 单文件的职责划分吻合，✓。补充建议：
   - **ShareImporter、EngineState 不属于任何 Screen**，T4 清单里没提它们的去处——建议 `data/ShareImporter.kt`、`state/EngineState.kt`（或 engine/），否则"MainActivity 只留装配"落不下去（现状这两个 object 都在 MainActivity.kt 里）。
   - Theme.kt 拆出后 `Shapes`（现状 161-165 行）随行，避免两个文件各定义一套。
2. **重组性能隐患（按风险排序）**：
   - **EngineState 是单例可变状态**：若各 Screen 直接读它的多个字段，任何一次 `addLog`/流量跳变会触发整个 Screen 级重组。现状统计带每秒更新（1.2 MB/s 这类），若把整屏放在一个 `collectAsState` 上，统计跳字会连带大按钮环重绘。**护栏：状态收细为多个 `StateFlow`（连接状态 / 流量 / 日志），Screen 内各字段各自 `collectAsStateWithLifecycle`，统计带抽成独立 `@Composable` 且参数用基本类型（Long、String）而非整包 data class，让 Compose 强跳过（strong skipping 未开时靠 equals）**。
   - `EngineState` 单例如果在 composable 里以 `EngineState.xxx` 直接读（不走 State），**根本不触发重组**——状态永远不刷新的 bug 比 performance 更常见，T4 时统一走 StateFlow，禁止单例字段直读。
   - LazyColumn（节点列表）item key 必须稳定（现状未验证，待验证），否则导入合并后全列表重组。
   - lambda 参数用 `MethodReference`/`remember` 稳定引用，避免每帧新建 lambda 使子组件跳过失效（Compose 编译器已大部分处理，低风险，列出备查）。

---

## 六、逐条修订建议

| # | 级别 | 建议 |
|---|---|---|
| R1 | P0 | Abyss/Dark 按钮内文字一律**深字**：Abyss 用 #0A1220（11.22:1），Dark 用 #12141C（5.74:1）；白字方案否决（1.67:1 / 3.20:1）。与桌面 v4 R4 对齐 |
| R2 | P0 | Light warning 锚定桌面 R2 修正值 **#B45309**（4.65:1），不要照抄 v4 令牌表的 #D97706（2.95:1）；并建议对桌面 v4 文档发一条令牌表勘误 |
| R3 | P0 | 主题持久化从 SecureStore 改为 **SharedPreferences 或 DataStore Preferences**（单字段、非敏感）；SecureStore 继续只管凭据/节点 |
| R4 | P0 | 补 M2 权限流落点：`VpnService.prepare` launcher 挂在大按钮点击链路（G1），T2 预留参数位 |
| R5 | P0 | 补深链导入后的首页/Tab 反馈动线（G2），避免静默 Toast |
| R6 | P1 | 语义色/accent2 用 `staticCompositionLocalOf` 的 `HydraColors` 注入，动态模式下组件经统一取值口回退 `colorScheme.primary`（一节.1） |
| R7 | P1 | 大按钮动画三条护栏：条件挂载 InfiniteTransition（态离即停）、`drawBehind` 画环不转内文、系统动画缩放为 0 时禁循环动画（三节.1/.2） |
| R8 | P1 | EngineState 拆多 StateFlow + 各自 collectAsStateWithLifecycle + 统计带独立 composable；写明"同源仅限同进程，M2 分进程时换 Binder 通道"（三节.3 / 五节.2） |
| R9 | P1 | 补横屏/宽屏最低规范：内容列 `widthIn(max=480.dp)` 居中起步，两栏方案留待 M3（G3） |
| R10 | P1 | T4 拆分清单补 ShareImporter / EngineState 去处（data/、state/），Shapes 随 Theme.kt 走 |
| R11 | P1 | TalkBack：大按钮/状态胶囊加 contentDescription + liveRegion；T5 验收加 TalkBack 走查（G4） |
| R12 | P2 | §3.2 线框补纵向滚动降级说明（小屏 + 28sp 大字 + 统计带 + 日志同屏）；<31 中性板色值在 T1 定稿并截图 |
| R13 | P2 | Light success #059669（3.49:1）仅限状态大字，禁用于 14sp 正文——写进组件规范注记；danger #DC2626（4.47:1）同理限大字/横幅 |

---

*待验证汇总：<31 中性板取色、桌面 v4 R4 白字 1.86 的算式出入（实测 1.67）、Light text 对比度通道级复算、节点列表 item key 现状。*
