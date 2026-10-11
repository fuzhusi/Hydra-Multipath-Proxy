# Android 端 UI 重设计方案 v1.1 —— 品牌主题与连接主页重构（评审修订定稿）

> 日期：2026-10-11 ｜ 状态：**评审修订定稿，可实施**（评审报告：安卓端UI重设计方案-v1-评审.md，R1-R13 全部合入）
> 前置：M0/M1 已交付（hydra-android uniffi 引擎 + Compose 三 Tab 骨架 + 本地 SOCKS 模式可用）。
> 设计令牌源头与桌面端对齐：docs/design/桌面端UI重设计方案-v4.md（v4.1）。

## 〇、v1.1 修订记录（评审 R1-R13 合入）

- **R1（P0）对比度**：Abyss 大按钮内**必须深字 #0A1220**（accent×白仅 1.67:1）；Dark on_accent 同用深墨（白字 3.20:1 不达标）；Light warning 锚定 **#B45309**（4.65:1，#D97706 仅 2.95——桌面 v4 文档表已同步回改）
- **R2（P0）主题存储降级**：uiTheme 非敏感 → **SharedPreferences**（不用 SecureStore，避免 Keystore IO 与凭据耦合）
- **R3（P0）品牌语义色注入**：`staticCompositionLocalOf` 的 `HydraColors`（success/warning/danger/状态环色等 colorScheme 之外的语义色）——**只换 MaterialTheme.colorScheme 不够**
- **R4（P0）M2 权限流挂点**：HomeScreen 预留 `vpnPrepareLauncher`（ActivityResultContracts.StartActivityForResult，VpnService.prepare 返回 Intent）参数位；大按钮点击按 runMode 分流（本地直启 / VPN 先 prepare 后 start）
- **R5（P0）深链导入反馈动线**：导入成功后首页状态胶囊下弹 Snackbar「已导入 N 个节点」，并高亮节点 Tab 徽标（替代现状静默 Toast）
- **R6（P1）横屏/宽屏**：大按钮 + 统计带改 Row 平铺（宽 ≥600dp 两栏）；home 内容包 verticalScroll
- **R7（P1）TalkBack**：大按钮 contentDescription 随状态、状态环用 semantics 状态描述、统计带每格有标签
- **R8（P1）动画可达性**：状态环旋转/呼吸动画用 `rememberInfiniteTransition`，**系统动画缩放为 0（关闭动画）时静止**； respectful of remove-animations
- **R9（P1）EngineState 进程边界**：现状单例仅限同进程可用——M2 若 VpnService 分进程须换 Binder/AIDL（方案注明，本轮单进程不受影响）
- **R10（P1）重组性能**：统计带拆独立 `@Composable` + 独立 StateFlow（每秒跳字不得触发整屏重组）
- **R11（P2）T4 拆分清单补全**：ShareImporter→ui/import/、EngineState→state/（去处明确）
- **R12（P2）深色大按钮描边**：Dark 模式 accent 按钮加 1dp accent 描边防与卡底融合
- **R13（P2）通知与状态同源校验**：前台通知文案读取同一 EngineState（M2 接线时验证）

---

## 一、现状审计

| # | 现状 | 判定 |
|---|---|---|
| 1 | 主题 = 跟随系统深浅 + Android 12+ Material You 动态取色；**<31 API 设备回落 `MaterialTheme.colorScheme` 默认紫色** | ✗ 无品牌、旧设备形态差 |
| 2 | 与桌面三主题（Dark/Light/Abyss）零关联——同一产品的两端视觉割裂 | ✗ 品牌割裂 |
| 3 | 首页（连接页）= StatTile 平铺表单式，无「连接」这个核心动作的视觉锚点 | ✗ 主操作埋没 |
| 4 | 深浅切换只跟系统——用户无法在 App 内强制深/浅（坐地铁强光/夜间躺床场景） | ✗ 缺手动控制 |
| 5 | 单文件 MainActivity.kt 52KB（主题/三屏/导入/对话框全在里面） | ✗ 待拆分（随实施顺手） |

## 二、疑问与决策（自问自答，决策加粗）

| # | 疑问 | 决策 |
|---|---|---|
| D1 | 主题策略：跟系统动态取色 vs 品牌三主题 vs 混合？ | **混合四选**：跟随系统（Material You 动态，默认）/ 深色 / 浅色 / 深海（Abyss，对齐桌面创想主题）。动态取色是 Android 平台惯例不能丢；品牌三主题对齐桌面；默认"跟随系统"尊重平台 |
| D2 | 首页形态：表单式 vs **VPN 大按钮式** vs 仪表盘式？ | **VPN 大按钮式**（WireGuard/v2rayNG/NordVPN 业界共识）：中央大圆钮拇指可达、状态环一眼可读；StatTile 精简为按钮下方一条统计带 |
| D3 | 色值源与桌面共享？ | **是**——同一套令牌语义（bg_app/bg_card/accent/success/warning/danger/text 三级），桌面 palette.rs 与 Android Theme.kt 各自实现、文档锚定同值。Abyss 令牌完全一致 |
| D4 | 导航结构变吗？ | **不变**：三 Tab（连接/节点/设置）+ NavigationBar；本轮不引入抽屉/二级页 |
| D5 | M2（VpnService 全局 VPN）的 UI 预留？ | 大按钮语义双模：本地模式 =「启动代理」，VPN 模式 =「连接 VPN」（M2 接线时按钮/状态环/权限流直接挂入，不改布局）；设置页已留 Always-on/分应用入口 |

## 三、设计规范

### 3.1 四种主题模式

| 模式 | 行为 |
|---|---|
| 跟随系统（默认） | API≥31：Material You 动态取色（深浅随系统）；<31：系统深浅 + 中性蓝灰板 |
| 深色 | 品牌静态板（= 桌面 Dark 令牌的 Android 映射） |
| 浅色 | 品牌静态板（= 桌面 Light） |
| 深海 Abyss | 品牌静态板（= 桌面 Abyss：bg #0A1220 / card #101B2E / accent 青绿 #2DD4BF / 紫点缀 #8B5CF6） |

选择持久化到 SecureStore（`uiTheme` 字段，默认 system）。

### 3.2 连接主页（Home）信息架构

```
┌──────────────────────────────┐
│  Hydra        [状态胶囊: ●已连接] │  ← 顶栏右置状态胶囊
│                              │
│        ╭──────────╮          │
│        │          │          │
│        │  ◉ 大按钮  │          │  ← 112dp 圆钮：外环=状态环（转圈/呼吸动画）
│        │  启动/停止 │          │     内文=当前动作（启动代理/连接 VPN/停止）
│        ╰──────────╯          │
│     状态大字：已连接 / 已断开…    │
│     节点摘要：43.133.x.x · 312ms │
├──────────────────────────────┤
│ ↑ 1.2 MB/s  ↓ 8.4 MB/s  ⏱ 12m │  ← 统计带（三格）
├──────────────────────────────┤
│ [最近日志 2 行（可点进设置看全部）] │
└──────────────────────────────┘
```

- 状态四态 × 视觉：已断开（灰环灰字）/ 连接中（accent 环旋转 + CircularProgressIndicator）/ 已连接（success 环 + 绿字）/ 错误（danger 环 + 横幅）
- 状态胶囊与通知（前台服务）同一状态源（EngineState），UI/通知永不漂移

### 3.3 组件规范

- 卡片：RoundedCornerShape(16dp)、elevation 0、bg = surfaceVariant 系（动态模式）或令牌（品牌模式）
- 行高 ≥48dp（触摸目标）；开关/选择行统一 `SettingSwitchRow` 风格
- 字阶：状态大字 28sp / 卡标题 16sp / 正文 14sp / 辅助 12sp（Android sp 随系统字体缩放）

## 四、实施计划

1. **T1 Theme.kt 独立文件**：ThemeMode 枚举（System/Dark/Light/Abyss）+ 品牌色板（对齐桌面令牌）+ HydraTheme(mode) 重构（动态分支保留）+ SecureStore 持久化
2. **T2 HomeScreen 重构**：大按钮 + 状态环 + 状态胶囊 + 统计带 + 节点摘要卡（双模语义：本地/VPN）
3. **T3 设置页主题选择**：四选卡片行（跟随系统/深色/浅色/深海）
4. **T4 MainActivity 拆分**：HydraTheme→Theme.kt、HomeScreen→ui/HomeScreen.kt、NodesScreen→ui/NodesScreen.kt、SettingsScreen→ui/SettingsScreen.kt（MainActivity 只留装配与状态接线）
5. **T5 验收**：`gradlew assembleDebug` + JVM 单测全绿；四主题截图（系统深/系统浅/品牌深/品牌浅/Abyss 五态实拍）
