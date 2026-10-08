# 移动端 UI 设计（M1）

> 上位文档：[移动端应用交互设计-M1](移动端应用交互设计-M1.md)（交互/状态机/错误矩阵）。
> 本文是**视觉层**设计：色彩 token、字阶、几何体系、逐页线框、组件规格、
> 状态×视觉映射、无障碍。§9 为实现对照——每个规格条目标注落点与偏差。
> 版本：v1.0（2026-10-08）。

---

## 0. 工艺

Jetpack Compose + Material 3。Android 12+ 使用动态取色（壁纸派生 scheme），
Android <12 回退默认深色 scheme。**所有颜色经语义角色引用（colorScheme.*），
禁止硬编码色值**——深浅色与不同壁纸下自动协调。

## 1. 设计原则

1. **状态先行**：连接页第一视觉是引擎状态（ON/OFF 圆标 + 大按钮），一眼可判；
2. **失败可读**：错误用 errorContainer/error 角色，且必伴"下一步"文案；
3. **数值等宽**：地址、流量、延迟一律 Monospace（稳定性与可扫读）；
4. **少即是多**：M1 不做主题切换/彩蛋动效；层级靠 M3 tonal 色阶表达。

## 2. 色彩系统（语义角色 → 用途）

| 角色 | 用途 | 深色行为 |
|---|---|---|
| `tertiary` / `onTertiary` | 运行态圆标底/字 | 动态色自动派生 |
| `tertiaryContainer` / `onTertiaryContainer` | 运行态状态主卡底/文字 | 同上 |
| `primary` / `onPrimary` | 主按钮、启动中圆标、加载圈 | — |
| `errorContainer` / `error` / `onErrorContainer` | 失败主卡底、错误文字、删除确认 | — |
| `surfaceVariant` / `onSurfaceVariant` | 停止态主卡、普通卡、辅助文字、图标弱化 | — |
| `surface` | 页面与卡片基底 | — |
| `outline` | 停止态圆标描边底 | — |

**引擎状态 × 主卡视觉映射**（连接页第一卡）：

| 状态 | 容器色 | 圆标底 | 圆标字 |
|---|---|---|---|
| 已停止 | surfaceVariant | outline | onSurface 系（"OFF"） |
| 启动中 | surfaceVariant | primary | —（转圈 onPrimary） |
| 运行中 | tertiaryContainer | tertiary | onTertiary（"ON"） |
| 启动失败 | errorContainer | —（无圆标改动） | —（标题"启动失败"+ error 文案） |

节点卡状态圆点：`tertiary`（已配置即绿点；连通性测试结果文字 ✓ 用 tertiary、
✗ 用 error）。

## 3. 字阶与图标

| M3 样式 | 用途 |
|---|---|
| headlineSmall | 页面标题（"Hydra"/"设置"） |
| titleLarge | 状态主卡状态词（运行中/已停止…） |
| titleMedium / titleSmall | 统计数值 / 卡片分区标题（"凭据""事件""节点"） |
| bodyMedium / bodySmall | 正文 / 说明与辅助（onSurfaceVariant） |
| labelSmall | 卡内标签（"↑ 发送"、监听标签） |

数值/地址/日志：`FontFamily.Monospace`（事件日志 11sp，监听地址跟随 body）。
图标仅用 material-icons-core：Home / List(节点) / Settings / Add / Delete；
其余场景用文字按钮（"复制""测试""📷 扫码"）——不引入 10MB extended 包。

## 4. 几何体系

| 项 | 值 |
|---|---|
| 页面水平边距 | 16dp |
| 卡内边距 | 14dp（状态主卡 20dp） |
| 组件纵向间距 | 10–12dp（卡内条目 3–4dp） |
| 圆角 | 状态主卡 20dp；普通卡/对话框默认（12dp）；按钮 14dp |
| 主按钮高度 | 52dp（全宽）；字 16sp |
| 状态圆标 | 72dp 圆；加载圈 36dp；节点状态点 8dp |
| 触控目标 | ≥48dp（IconButton/TextButton 默认满足） |

## 5. 逐页线框

### 5.1 连接页（四态）

```text
┌──────────────────────────────────┐
│ Hydra                            │  headlineSmall
│ M1·本地 SOCKS5/HTTP 引擎…（辅助） │  bodySmall / onSurfaceVariant
│                                  │
│ ╔══════════════════════════════╗ │
│ ║        ⬤ (72dp 圆标)         ║ │  状态色见 §2 映射；启动中=转圈
│ ║          运行中               ║ │  titleLarge
│ ║  运行 0:03 · 活跃 2 · 累计 5  ║ │  bodyMedium / onTertiaryContainer（仅运行态）
│ ╚══════════════════════════════╝ │  圆角 20 / tertiaryContainer
│                                  │
│ ┌──────────────────────────────┐ │
│ │        ▶ 启动代理 (52dp)      │ │  主按钮/停止=errorContainer
│ └──────────────────────────────┘ │
│                                  │
│ ┌─ 本地监听（浏览器代理填这个）──┐ │
│ │ 127.0.0.1:1080      [复制]    │ │  Monospace + TextButton
│ └──────────────────────────────┘ │
│ ┌─ ↑ 发送 ─────┐ ┌─ ↓ 接收 ───┐ │  StatTile ×2（Monospace titleMedium）
│ ┌─ 节点 ───────────────────────┐ │
│ │ 2 个节点已配置             › │ │  点击去节点页
│ └──────────────────────────────┘ │
│ ┌─ 事件 ────────── [全部(12)] ──┐ │
│ │ 20:41  ✓ 引擎已就绪…          │ │  最近 8 条 · Monospace 11sp
│ │ …                             │ │
│ └──────────────────────────────┘ │
└──────────────────────────────────┘
```

失败态：主卡变 errorContainer，标题"启动失败"，卡内追加 error 原因文案；
按钮恢复"▶ 启动代理"（可重试）。

### 5.2 节点页

```text
空态：                          有节点：
│                              │  ┌─ ● 1.2.3.4:443 ──── [测试][🗑] ─┐
│      还没有节点               │  │   ✓ 123ms                      │
│  点击右下角「导入节点」：      │  └────────────────────────────────┘
│  · 扫描桌面端分享二维码        │  （测试结果行：✓ tertiary / ✗ error）
│  · 粘贴 hydra:// 链接         │
│  · 手动输入 IP:端口           │      (＋) FAB「导入节点」
```

导入对话框：说明文案 → [📷 扫码] [导入] 行 → 多行粘贴框 → 剪贴板预填提示
（primary）→ 错误行（error）→ "或手动输入 IP:端口 ›"。手动添加/删除确认
均为独立 AlertDialog。

### 5.3 设置页

```text
│ 设置 (headlineSmall)
│ ┌─ 凭据 ────────────────────────┐
│ │ 认证密钥（64 hex） [显示/隐藏] │  supportingText 实时长度校验
│ │ [自签 pin] [真证书 CA]         │  FilterChip
│ │ [导入节点证书 DER] / 已导入✓   │  + 剪贴板 cc= 已含时的提示
│ └───────────────────────────────┘
│ ┌─ 高级 ────────────────────────┐  SNI / 监听端口
│ [保存配置（加密存储）] (52dp→48) │  密钥长度非法时禁用
│ v0.2.2 · Keystore 加密…（辅助）  │
```

### 5.4 全局组件

- 事件"全部"对话框：LazyColumn 420dp + [复制全部] / [关闭]；
- Toast 承载导入/保存/复制的结果反馈（LaunchedEffect 消费，不重放）。

## 6. 组件规格表

| 组件 | 规格 |
|---|---|
| 状态主卡 | 圆角 20 / 边距 20 / 纵向间距 8；圆标 72dp；状态词 titleLarge |
| 启停按钮 | 全宽 52dp / 圆角 14 / 16sp；停止态 errorContainer 配色 |
| StatTile | 普通卡 + labelSmall 标签 + Monospace titleMedium 数值；两列等宽 |
| 监听地址卡 | Row：标签+地址（Monospace）左对齐，[复制] 右缘 |
| 节点卡 | 8dp 状态点 + 地址（Monospace）+ [测试] + [删除]；测试结果行 11sp |
| 事件行 | `HH:mm:ss  消息`，11sp Monospace，onSurfaceVariant |
| 空态 | 标题 titleMedium + 引导 body（居中，32dp 边距） |

## 7. 无障碍与适配

- 触控目标 ≥48dp；色彩对比由 M3 角色保证（on* 配对使用）；
- 字体缩放：全部 sp；布局纵向滚动（连接/设置页 verticalScroll，节点页 LazyColumn）；
- 深浅色 + 动态色自动；通知渠道 IMPORTANCE_LOW（不打扰）。

## 8. 实现对照与已知偏差

| 规格条目 | 落点（MainActivity.kt 等） | 状态 |
|---|---|---|
| §2 状态映射 | HomeScreen 状态主卡 + HydraTheme | ✅（本批去硬编码） |
| §3 字阶/图标 | 各 Composable | ✅ |
| §4 几何 | 页边距/卡内边距/按钮高度 | ✅ |
| §5.1 连接页四态 | HomeScreen | ✅ |
| §5.2 节点页六要素 | NodesScreen + 对话框 | ✅（本批补空态图标） |
| §5.3 设置页 | SettingsScreen | ✅ |
| §5.4 事件全部对话框 | HomeScreen | ✅（本批新增） |
| §6 组件表 | 各组件 | ✅ |
| 主题圆角体系（Shapes） | HydraTheme Shapes(8/12/20) | ✅（本批补齐） |
| 节点页空态图标 | Icons.Outlined.List 48dp + 文案 | ✅（本批补齐） |
| 页面标题一致性 | 节点页 headlineSmall 标题行 | ✅（本批补齐） |
