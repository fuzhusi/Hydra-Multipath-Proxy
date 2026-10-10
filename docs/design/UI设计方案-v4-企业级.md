# Hydra 客户端 GUI 设计方案 v4 —— 企业级工具软件定位

> 状态：**设计方案（待评审）** · 前序：`UI重设计方案-v3.md`（已交付）· 衔接：`eframe升级方案-0.27到0.33.md`（已评审待执行）
> 基线代码：`hydra-client-gui/src/`（26 个 .rs，模块化已完成）· egui/eframe **0.27.2**（计划升级 0.33）
> 面向读者：执行实施的工程师。规格具体到 hex/px/行号，可直接写代码。

---

## 目录

1. [定位与设计原则](#1-定位与设计原则)
2. [现状基线](#2-现状基线)
3. [启发式审计（Nielsen 十原则 × 六页）](#3-启发式审计)
4. [Design Tokens v4](#4-design-tokens-v4)
5. [信息架构与导航](#5-信息架构与导航)
6. [状态可视化强化（多通道编码）](#6-状态可视化强化)
7. [每页重设计规格](#7-每页重设计规格)
8. [深浅色主题策略](#8-深浅色主题策略)
9. [可访问性规范](#9-可访问性规范)
10. [egui 实现映射总表](#10-egui-实现映射总表)
11. [分阶段实施计划](#11-分阶段实施计划)
12. [不做清单](#12-不做清单)
13. [文案规范](#13-文案规范)

---

## 1. 定位与设计原则

**定位一句话**：给开发者/运维用的多节点安全代理控制台——个人项目，按企业级内部工具（infrastructure tool）标准做，不按消费级 App 做。

七条设计原则（v4 全部决策的裁决依据，冲突时按序号优先）：

| # | 原则 | 含义 | 反例（v4 拒绝） |
|---|---|---|---|
| P1 | **状态可见性第一** | 代理是否在跑、节点是否健康、流量走哪条路，任何页面 3 秒内可判读，且**多通道编码**（颜色+形状+文字，不只靠色） | 仅靠色点区分在线/离线 |
| P2 | **信息密度优先** | 一屏尽量多有效信息；紧凑行高、小间距、无装饰留白；数据用等宽数字 | 大卡片大留白仪表盘 |
| P3 | **低装饰** | 装饰必须有信息价值，否则删除；emoji 图标过渡期后统一为单色图标字体 | 插画空态、渐变、阴影 |
| P4 | **键盘可达** | 高频操作有快捷键；全部对话框 Esc 关 / Enter 主操作；焦点态可见 | 仅鼠标 hover 才能发现的功能 |
| P5 | **破坏性操作防误** | 删除/清空/退出必须确认，级联影响必须显式说明 | 一点即删 |
| P6 | **诚实呈现** | 不确定的就写"未测/调度参考"，失败就说失败；禁用项显式禁用并说明原因 | 假复选框、含糊成功文案 |
| P7 | **egui 现实主义** | 每条规格标注 A（现有 API）/ B（自绘可行）/ C（需升级或高成本）；C 级全部归入"升级后"章节 | 依赖 Web 级自由布局的设想 |

---

## 2. 现状基线

代码结构（均已核实）：

```
hydra-client-gui/src/
├── main.rs        HydraApp 状态中心（窗口 800×600，min 400×300，main.rs:257-259）
├── app.rs         构造/防抖落盘/日志入口/启动按钮状态机
├── ui_shell.rs    eframe::App 主循环 + 侧栏(160px) + 对话框集中渲染 + 托盘接线
├── ui_overview.rs 首页：2×2 统计卡 + egui_plot 速率曲线 + 快捷操作卡
├── ui_nodes.rs    节点页：组标签 + 组头栏 + 1–3 列卡片网格 + 3 个对话框
├── ui_subscriptions.rs 订阅页：行式列表 + 编辑对话框 + 「＋新建」菜单
├── ui_connections.rs   连接页：汇总卡 + 7 列 Grid 表格（500ms 快照差分速率）
├── ui_logs.rs     日志页：纯文本滚动列表（100 行上限）
├── ui_settings.rs 设置页：七分区 CollapsingHeader
├── ui_node_edit.rs 节点编辑对话框
├── palette.rs     色板/字号/间距单源（v3 交付）
├── theme.rs       card_frame + 字体装载 + apply_dark_theme
└── nodes/groups/speed_history/... 纯逻辑层
```

关键既有机制（v4 沿用，不推翻）：
- 单源色板：全部 UI 用色引 `palette::*`（theme.rs:61-67 装配进 `Visuals::dark()`）；
- 卡片 Frame：`card_frame`（theme.rs:8-15）= BG_CARD + 1px BORDER + 圆角 8 + 内边距 MD/外边距 XS；
- 速率历史 120 点 × 500ms（speed_history.rs:28），曲线窗口 60s；
- 连接页快照节流 500ms、仅激活页拉取（ui_shell.rs:96-100）；
- 启停状态机 `start_button_state`（app.rs:110-121，有单测）；
- 重绘周期恒定 500ms（ui_shell.rs:329）。

---

## 3. 启发式审计

严重度定义：**P0** = 阻断核心任务/数据丢失风险；**P1** = 高频任务明显受损或误导；**P2** = 效率/一致性受损；**P3** = 打磨项。
证据格式：`文件:行号`；标注「渲染行为推断」的为基于 egui 已知机制的推断，实施前需目检确认。

### 3.1 全局（骨架/主题/横切）—— G 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| G-01 | P1 | #4 一致性 | 主题对比度注释与实际色值漂移：注释写 ACCENT `#7AB3FF`，palette.rs 实际 `#5C9DFF`，注释中的对比度数值随之全部失真；且无亮色主题路径 | theme.rs:55 vs palette.rs:17 |
| G-02 | P1 | #1/#9 状态可见 | 反馈通道只有日志页：配置保存失败、订阅更新失败、代理异常退出全部 `add_log`，用户不在日志页即无感知；无 toast/横幅通道 | app.rs:320,324-334；ui_shell.rs:56,70 |
| G-03 | P2 | #4 一致性 | 图标语言未统一：v3 计划 egui_phosphor 图标字体（v3 文档 L252），实际全部 emoji（🏠🛰📡🔗📜⚙、⚡🔗✏🗑📥💾）；emoji 跨平台字形/着色不可控，与企业工具气质不符 | nodes.rs:63-72；ui_nodes.rs:309-339 |
| G-04 | P1 | #7 键盘可达 | 焦点可见性未定制：`apply_dark_theme` 未设置 `widgets.focused`，键盘 Tab 时焦点态默认过弱 | theme.rs:60-95 |
| G-05 | P1 | #7 灵活高效 | 无全局快捷键：页签切换、启停、测速全部鼠标路径 | ui_shell.rs:268-284 |
| G-06 | P2 | #3/#7 用户可控 | 对话框不支持 Esc 关闭 / Enter 提交（全部 8 个 egui::Window 均无按键处理） | ui_node_edit.rs:233-243、ui_nodes.rs:426-438、ui_shell.rs:170-175、ui_subscriptions.rs:233-243 等 |
| G-07（清除清单含 ui_shell.rs:287 第二个 add_space） | P2 | #4 一致性 | 间距脱轨 6 处：2.0px×2、6.0px×1、`XS+2.0`(=6)×2、2.0px 外边距×1，破坏 4px 基数 | ui_shell.rs:266,283；ui_subscriptions.rs:71；ui_nodes.rs:66,154,251 |
| G-08 | P3 | #4 一致性 | 圆角双轨未 token 化：卡片 8（theme.rs:12）vs 窗口/菜单 6（theme.rs:90-91），数值散落 | theme.rs:12,90-91 |
| G-09 | P1 | #5 错误预防 | 破坏性操作零确认零撤销：删节点、删订阅、清空日志、退出程序全部一点生效 | ui_nodes.rs:331-359；ui_subscriptions.rs:116-121,177-179；ui_logs.rs:32-37；ui_settings.rs:390-401 |
| G-10 | P3 | #10 帮助 | 日志容量 100 行上限，对排障用途过小；且日志是唯一排障出口 | app.rs:331-333 |
| G-11 | P1 | #2 拟真/防错 | 最小窗口 400×300 时水平溢出：侧栏固定 160，内容区 240px，首页统计卡 2 列 × min 130 + 间距 > 240px，第二列被裁（渲染行为推断+算术：main.rs:259、ui_shell.rs:261、ui_overview.rs:45-46） | main.rs:259；ui_shell.rs:261；ui_overview.rs:44-51 |
| G-12 | P3 | — 性能 | 恒定 500ms 全帧重绘：空闲时也持续消耗 CPU（托盘隐藏后亦然） | ui_shell.rs:329 |

### 3.2 首页（状态总览）—— OV 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| OV-01 | P1 | #8 极简/密度 | 统计卡固定 2×2 且单卡 max 320px：≥900px 宽窗口右侧留白超过 40%，信息密度骤降；与节点页的自适应 1–3 列策略不一致 | ui_overview.rs:44-54 |
| OV-02 | P2 | #1 状态可见 | 速率曲线完全禁交互（无 hover 读数、无峰值标注），仅装饰价值；企业场景常需读取某时刻数值 | ui_overview.rs:246-256 |
| OV-03 | P2 | #4 一致性 | TUN checkbox 是**配置项**却放在仪表盘快捷卡（与设置页同字段双入口），仪表盘语义被污染；「系统代理」按钮同理但可辩护为高频动作 | ui_overview.rs:320-336 vs ui_settings.rs:219-236 |
| OV-04 | P2 | #1/#8 | 最近日志摘要无级别区分、与日志页信息重复，且不可点击定位 | ui_overview.rs:369-377 |
| OV-05 | P3 | #2 拟真 | 卡标题「当前节点（调度参考）」把诚实性说明塞进标题括号，拗口；说明应下沉为卡内注释行 | ui_overview.rs:106 |
| OV-06 | P2 | #10 帮助 | 新用户引导只存在于日志区文本（`wizard_lines` 写进日志），首页无引导卡；无配置时第一屏是四个「—」 | app.rs:279-297；ui_overview.rs:128-145 |
| OV-07 | P2 | #1 状态可见 | 曲线空态：plot 空轴区仍占 180px，"代理未运行"提示在卡外下方，状态与容器分离 | ui_overview.rs:244,287-292 |

### 3.3 节点页 —— ND 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| ND-01 | **P0** | #1 状态可见 | 节点健康状态**单通道依赖色相**：10px 色点四态（绿/黄/红/灰）无形状差异、在线/劣化无文字通道；色盲用户完全无法区分 在线/劣化/离线/未测——代理工具的核心信息不可判读 | ui_nodes.rs:257-262；palette.rs:70-82（仅返回色） |
| ND-02 | P1 | #9 防错恢复 | 测过但失败的节点显示灰色「超时」：`latency_color（仅保留给首页延迟中位数；节点卡延迟着色按状态表：劣化=WARNING）(None)→TEXT_FAINT`，与红色状态点自相矛盾（点红字灰），用户误以为未测 | palette.rs:61-62；ui_nodes.rs:239-243,292-296 |
| ND-03 | P1 | #5 错误预防 | 删除节点一点即删无确认；🗑 按钮与其它图标按钮同排紧挨，误触即数据丢失 | ui_nodes.rs:331-359 |
| ND-04 | P2 | #1 状态可见 | 组头摘要「在线 X / 离线 Y」不含未测数：`group_summary` 只计 checked 节点，未测多时摘要失真（8 节点只测 1 个在线会显示「在线 1 / 离线 0」） | nodes.rs:119-138；ui_nodes.rs:161-170 |
| ND-05 | P2 | #6 识别 | 卡片操作全 emoji 无文字（⚡🔗✏⇥🗑），功能靠 hover tooltip 发现；「⇥」表示"另存为手动"语义过晦涩 | ui_nodes.rs:309-339 |
| ND-06 | P2 | #7 灵活高效 | 无搜索、无延迟排序（v3 承诺的"延迟排序"未落地：v3 文档 L23 竞品采纳项、L178「⇅延迟」线框）；节点多时只能逐组翻 | ui_nodes.rs 全文 |
| ND-07 | P3 | #4 一致性 | 卡片本体不可点、无 hover 反馈（Frame 无 hovered 态），交互 affordance 缺失——可点区域仅四个小图标 | ui_nodes.rs:247-253（渲染行为推断） |
| ND-08 | P3 | #1 | 来源徽标 [手动]/[订阅名] 用 FAINT/ACCENT 两色区分（有文字兜底，问题轻），但 ACCENT 被用作"订阅"语义而非交互语义，色义混用 | ui_nodes.rs:278-287 |
| ND-09 | P2 | #1 状态可见 | 组测速/全部测速只有 spinner +「全部测速中…」，无 `n/m` 进度；串行测速无法预估剩余时长 | ui_nodes.rs:30-33,173-179 |

### 3.4 订阅页 —— SB 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| SB-01 | **P0** | #5 错误预防 | 删除订阅零确认且**级联删除该订阅独占的节点**；对 `hydra-text://` 本地导入分组，删除即永久丢失粘贴原文（无法重新拉取）——用户完全无感知 | ui_subscriptions.rs:116-121；subscription_actions.rs:50-74；groups.rs:16,175-180 |
| SB-02 | P2 | #8 极简 | 页头常驻 80+ 字说明段落（三行小字），帮助文本应收纳 | ui_subscriptions.rs:72 |
| SB-03 | P2 | #4 一致性 | 订阅是纯文本行不是卡片：名称/计数/时间/4 个按钮挤一行，窄窗口换行错乱；与节点页卡片语言、v3 订阅卡网格设计均不一致 | ui_subscriptions.rs:89-124（渲染行为推断） |
| SB-04 | P3 | #5 错误预防 | 「更新全部订阅」进行中不禁用可重复点击（队列串行兜底不会坏，但按钮态误导） | ui_subscriptions.rs:62-68 |
| SB-05 | P3 | #4 一致性 | 展开节点行内操作文案风格与节点页不一致（"🔗 分享"带文字 vs 节点页纯图标"🔗"） | ui_subscriptions.rs:151-171 vs ui_nodes.rs:312 |
| SB-06 | P2 | #1 状态可见 | 订阅无更新结果徽标：成功/失败只在日志；列表只有「从未/时间戳」，用户无法在页内判断哪条订阅挂了 | ui_subscriptions.rs:79-87 |

### 3.5 连接页 —— CN 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| CN-01 | P1 | #7 灵活高效 | 无过滤/搜索/暂停/列排序（v3 承诺的搜索+暂停+排序表，v3 文档 L24、L200-204）；连接数上百时不可用 | ui_connections.rs 全文 |
| CN-02 | P2 | — 性能 | 全量 Grid 渲染无虚拟化：行数线性增加每帧行开（egui Grid 机制已知，渲染行为推断）；v3 计划的 egui_extras::Table 未引入（Cargo.toml 无此依赖） | ui_connections.rs:123-209；Cargo.toml |
| CN-03 | P3 | #2 拟真 | 目标列脱敏为短哈希（安全正确）但无解释，用户首见会困惑「这不是我的域名」；说明仅藏在代码注释 | ui_connections.rs:140-148 |
| CN-04 | P2 | #1 状态可见 | 「直连」vs 代理节点仅文字区分，无图标/徽标通道；流量方向已有 ↑绿↓蓝+箭头（合格，保持） | ui_connections.rs:150-162 |
| CN-05 | P3 | #7 | 表头纯展示不可排序不可视（`ui.weak` 文本） | ui_connections.rs:129-135 |
| CN-06 | P3 | #8 极简 | 汇总卡与表格卡分离，两卡高度只为一行汇总，密度低 | ui_connections.rs:78-100,102-104 |

### 3.6 日志页 —— LG 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| LG-01 | P1 | #1/#9 状态可见 | 日志无级别：`add_log(String)` 单通道，错误/警告/信息同色，靠 ⚠️✗ emoji 内嵌文本区分；无法过滤 | app.rs:324-334；ui_logs.rs:22-25 |
| LG-02 | P2 | #4 一致性 | 日志非等宽渲染（默认 Proportional），时间戳/地址列不对齐；连接页同数据都用了 monospace | ui_logs.rs:22-25 vs ui_connections.rs:145 |
| LG-03 | P3 | #4 一致性 | 「刷新」按钮无意义：页面本就 500ms 重绘，按钮仅 request_repaint | ui_logs.rs:38-40；ui_shell.rs:329 |
| LG-04 | P2 | #5 错误预防 | 清空日志零确认（且 100 行上限下清空损失有限，但与 G-09 同批修）；无导出 | ui_logs.rs:32-37 |
| LG-05 | P3 | #10 | 100 行上限使排障价值有限（G-10 页内实例） | app.rs:331-333 |
| LG-06 | P3 | #3 用户可控 | 无显式"自动滚动"暂停开关（egui `stick_to_bottom` 上滚自动解除，但没有状态指示，用户不知道是否跟随） | ui_logs.rs:18-21 |

### 3.7 设置页 —— ST 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| ST-01 | P1 | #6 识别/诚实 | 禁用假复选框冒充配置项：「主题: □ 深色（当前唯一主题）」「□ 开机自启（规划中）」——以可交互控件形态展示不可用功能；企业软件应隐藏未实现项或用显式"规划中"徽标 | ui_settings.rs:298-299,330-334 |
| ST-02 | P2 | #1 状态可见 | 「需重启代理生效」提示散落两处且都是小字/警告文本；运行中改配置无全局"待生效"指示，用户极易误以为已生效 | ui_settings.rs:202-204；ui_node_edit.rs:223-226 |
| ST-03 | P2 | #8 极简 | 全局凭据区安全警告是两行长段落（折叠区内滚动），关键安全信息权重不足 | ui_settings.rs:31-38 |
| ST-04 | P3 | #4 一致性 | 探测间隔 DragValue 无单位后缀（`.suffix("s")` 未用），说明文字与控件分离 | ui_settings.rs:125-139 |
| ST-05 | P3 | #6 识别 | 七分区同视觉权重无分组（凭据/核心=高频，安全/TUN=中频，系统/外观/关于=低频），无页内导航 | ui_settings.rs:24-402 |
| ST-06 | P2 | #5 错误预防 | 「退出程序（停止代理并清理系统代理）」在折叠区内红色文本按钮，一点即退无确认（虽有干净关停流程，误触代价高） | ui_settings.rs:390-401 |

### 3.8 骨架/托盘 —— TR 组

| ID | 级别 | Nielsen | 问题 | 证据 |
|---|---|---|---|---|
| TR-01 | P1 | #1/#4 状态一致 | 侧栏底部运行状态只有两态（🟢运行中/⚪已停止），缺「启动中」——与首页三态（●◐○）状态机不一致，启动的 1–3s 内两处显示矛盾 | ui_shell.rs:289-293 vs ui_overview.rs:65-71 |
| TR-02 | P3 | #6 识别 | 导航选中态依赖 SelectableLabel 默认高亮，选中/hover 区分弱，无左缘 accent 指示条 | ui_shell.rs:268-284 |
| TR-03 | P3 | #1 | 原生标题栏为静态文本；运行状态不进标题栏（托盘 tooltip 已同步状态，ui_shell.rs:384-390） | main.rs:268-273 |

### 3.9 审计统计

| 级别 | 数量 | 占比 |
|---|---|---|
| **P0** | 2 | ND-01、SB-01 |
| **P1** | 13 | G-01/02/04/05/09/11、OV-01、ND-02/03、CN-01、LG-01、ST-01、TR-01 |
| **P2** | 22 | G-03/06/07、OV-02/03/04/06/07、ND-04/05/06/09、SB-02/03/06、CN-02/04、LG-02/04、ST-02/03/06、TR-02 |
| **P3** | 18 | G-08/10/12、OV-05、ND-07/08、SB-04/05、CN-03/05/06、LG-03/05/06、ST-04/05、TR-03 |
| **合计** | **55** | — |

> 注：P0 仅 2 项是因为 v3 已把骨架性问题（布局/导航/主题底座）修完；剩余问题集中在**状态表达、防误操作、效率工具**三层，正是 v4 的靶心。

---

## 4. Design Tokens v4

### 4.1 色彩语义系统

四级表面 + 三级文本 + 五语义色，深浅双主题。所有对比度按 WCAG 2.1 相对亮度公式实测（本节数值均经脚本计算，非估算）。

#### 深色主题（当前默认）

| Token | Hex | 用途 | 关键对比度（实测） |
|---|---|---|---|
| `BG_PANEL` | `#1B1E24` | 应用底/面板（不变） | — |
| `BG_SIDEBAR`（新增） | `#171A20` | 侧栏底，比面板深半档形成分区 | TEXT on it **14.46:1** |
| `BG_CARD` | `#22262E` | 卡片/窗口（不变） | — |
| `BG_EXTREME` | `#121418` | 输入框/折叠区底（不变） | — |
| `BG_FAINT` | `#242830` | 斑马纹/hover 底（不变） | — |
| `BORDER` | `#2E333D` | 卡片描边/分隔线（不变，装饰性，无对比度义务） | vs CARD 1.20:1（装饰） |
| `BORDER_STRONG`（新增） | `#5A6374` | 输入框描边/必需边界 | vs BG_EXTREME **3.05:1** ✓非文本 3:1 |
| `TEXT` | `#E8EAED` | 正文（不变） | on PANEL **13.85** / CARD **12.58** / EXTREME **15.30** |
| `TEXT_WEAK` | `#A8B0BC` | 次要说明（不变） | on PANEL **7.63** / CARD **6.93** ✓ |
| `TEXT_FAINT` | **`#848D9A`**（改值，原 `#7A828F` 3.91:1 不达标） | 占位/未测态 | on PANEL **4.98** / CARD **4.52** ✓正文 4.5:1 |
| `ACCENT` | `#5C9DFF` | 选中/主按钮/链接（不变） | on CARD **5.58** ✓ |
| `TEXT_ON_ACCENT`（新增） | `#0D1522` | ACCENT 底上的按钮文字（**深墨**，白字仅 2.72:1 不可用） | on ACCENT **6.73** ✓ |
| `SUCCESS` | `#7DE297` | 成功/在线/上行（不变） | on CARD **9.53** ✓ |
| `WARNING` | `#FFD666` | 警告/劣化/启动中（不变） | on CARD **10.88** ✓ |
| `DANGER` | `#FF8A80` | 危险/离线/错误（不变） | on CARD **6.64** ✓ |
| `INFO`（新增） | `#6CB6FF` | 中性提示/排队中 | on CARD **7.06** ✓ |
| `SUCCESS_BG`（新增） | `#1E2B23` | 成功横幅底 | SUCCESS 字 on it **9.26**，正文 **12.23** |
| `WARNING_BG`（新增） | `#322A18` | 警告横幅底 | WARNING 字 **10.18**，正文 **11.77** |
| `DANGER_BG`（新增） | `#32201E` | 危险横幅底 | DANGER 字 **6.76** |
| `INFO_BG`（新增） | `#182533` | 信息横幅底 | INFO 字 **7.23** |

状态色点在卡片底上的非文本对比度（WCAG 1.4.11 ≥3:1）：SUCCESS **9.53** / WARNING **10.88** / DANGER **6.64** / TEXT_FAINT **4.52** —— 全部达标。
焦点环：1.5px ACCENT，on CARD **5.58:1** ✓。

#### 浅色主题（随 eframe 升级引入，见 §8）

| Token | Hex | 关键对比度（实测） |
|---|---|---|
| `BG_PANEL` | `#F3F4F6` | — |
| `BG_SIDEBAR` | `#E9EBEE` | TEXT on it **13.23** |
| `BG_CARD` | `#FFFFFF` | — |
| `BG_EXTREME` | `#FFFFFF`（输入框=白底+描边） | — |
| `BG_FAINT` | `#F6F7F9` | — |
| `BORDER` | `#D9DCE1` | 装饰性 |
| `BORDER_STRONG` | `#878F9A` | vs 白 **3.27:1** ✓ |
| `TEXT` | `#1F2328` | on CARD **15.80** / PANEL **14.35** |
| `TEXT_WEAK` | `#57606A` | on CARD **6.39** ✓ |
| `TEXT_FAINT` | `#6E7781` | on CARD **4.55** ✓ |
| `ACCENT` | `#0969DA` | on CARD **5.19** ✓ |
| `TEXT_ON_ACCENT` | `#FFFFFF` | on ACCENT **5.19** ✓（浅色主题用白字） |
| `SUCCESS` | `#1A7F37` | **5.08** ✓（点 5.08 ✓） |
| `WARNING` | `#9A6700` | **4.87** ✓ |
| `DANGER` | `#CF222E` | **5.36** ✓ |
| `INFO` | `#0550AE` | **7.59** ✓ |
| `SUCCESS_BG / WARNING_BG / DANGER_BG / INFO_BG` | `#E6F4EA / #FBF3DF / #FBE9EA / #E7F0FA` | 横幅**正文用 TEXT**（≥13.9），语义色仅用于图标字形（≥4.4 ✓非文本） |

**横幅用色规则**（两主题通用）：横幅/提示底色用 `*_BG`，正文一律 `TEXT`，语义色只上图标字形与左缘 3px 竖条——避免浅色横幅上语义色正文 4.4:1 的临界值。

#### 语义色使用纪律

- ACCENT 只表示**交互态**（选中/主按钮/链接/焦点），不再用于"订阅"这类实体分类（修 ND-08：来源徽标统一 TEXT_WEAK 底+文字，不抢交互色）；
- 流量方向全局固定：**上行=SUCCESS 绿 + `↑`，下行=ACCENT 蓝 + `↓`**（首页卡 ui_overview.rs:169-178、曲线图例 273-284、连接表 164-176 已一致，成文为规范）；
- 语义色不作装饰：非状态/非交互区域禁用彩色。

### 4.2 字号阶梯（5 级 + 2 条纪律）

| Token | px | 用途 | 变更 |
|---|---|---|---|
| `FONT_HEADING` | 18 | 页面标题、统计卡大数字 | 复用到统计数字，**废除 `FONT_TITLE + 3.0（共 7 处）` 散点**（ui_overview.rs:74,117,170,175,195；ui_connections.rs:82 共 6 处） |
| `FONT_TITLE` | 15 | 卡片标题/节点名/分区标题 | 不变 |
| `FONT_BODY` | 13 | 正文/按钮/表格/导航 | 不变 |
| `FONT_SECONDARY` | **12**（原 11.5） | 次要说明/标签/hint | 取整对齐像素网格 |
| `FONT_BADGE` | **11**（原 10.5） | 徽标/来源标记 | 中文最小可读下限 11px |

纪律：① 全 UI 最小字号 11px（中文）；② 数字/地址/日志/时间戳一律 `.monospace()`（连接页已做，日志页随 LG-02 修复）。

### 4.3 间距系统（4px 基数）

| Token | px | 用途 |
|---|---|---|
| `SPACING_XS` | 4 | 行内元素间/卡片外边距 |
| `SPACING_SM` | 8 | 卡片间/表单行距/item_spacing |
| `SPACING_MD` | 12 | 卡片内边距/网格列距 |
| `SPACING_LG` | 16 | 区块间距/页面水平安全边距 |
| `SPACING_XL` | 24 | 页面级分区 |

**清除清单**（G-07）：2.0px → XS（ui_shell.rs:283、ui_subscriptions.rs:71）；6.0px → SM（ui_shell.rs:266）；`XS+2.0` → `SPACING_SM`（ui_nodes.rs:66,154）；卡片外边距 2.0 → 0（ui_nodes.rs:251，列间距已由 Grid spacing 提供）。

### 4.4 圆角 / 描边

| Token | 值 | 用途 |
|---|---|---|
| `RADIUS_CARD` | 8 | 卡片/横幅 |
| `RADIUS_CTRL` | 6 | 按钮/输入框/菜单/窗口（现状默认，token 化收口） |
| 描边宽度 | 1px | 卡片 BORDER、输入框 BORDER_STRONG、分隔线 |
| 焦点描边 | 1.5px ACCENT | 键盘焦点控件（`widgets.focused`） |

### 4.5 palette.rs 目标 diff（P0 落地版）

```diff
 // ── 底色（暗色优先）──
 pub const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x1B, 0x1E, 0x24);
+/// 侧栏底（比面板深半档，形成导航分区；浅色主题见 palette::light）
+pub const BG_SIDEBAR: egui::Color32 = egui::Color32::from_rgb(0x17, 0x1A, 0x20);
 pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(0x22, 0x26, 0x2E);
 pub const BG_EXTREME: egui::Color32 = egui::Color32::from_rgb(0x12, 0x14, 0x18);
 pub const BG_FAINT: egui::Color32 = egui::Color32::from_rgb(0x24, 0x28, 0x30);
+/// 输入框描边/必需边界（非文本对比度 3.05:1 on BG_EXTREME）
+pub const BORDER_STRONG: egui::Color32 = egui::Color32::from_rgb(0x5A, 0x63, 0x74);
 pub const BORDER: egui::Color32 = egui::Color32::from_rgb(0x2E, 0x33, 0x3D);

 // ── 语义色 ──
 pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x5C, 0x9D, 0xFF);
+/// ACCENT 底上的按钮文字（白字仅 2.72:1，必须用深墨）
+pub const TEXT_ON_ACCENT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x15, 0x22);
 pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(0x7D, 0xE2, 0x97);
 pub const WARNING: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xD6, 0x66);
 pub const DANGER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x8A, 0x80);
+/// 中性提示/排队中（7.06:1 on BG_CARD）
+pub const INFO: egui::Color32 = egui::Color32::from_rgb(0x6C, 0xB6, 0xFF);
+// 横幅底：正文用 TEXT，语义色只上图标字形与左缘竖条
+pub const SUCCESS_BG: egui::Color32 = egui::Color32::from_rgb(0x1E, 0x2B, 0x23);
+pub const WARNING_BG: egui::Color32 = egui::Color32::from_rgb(0x32, 0x2A, 0x18);
+pub const DANGER_BG: egui::Color32 = egui::Color32::from_rgb(0x32, 0x20, 0x1E);
+pub const INFO_BG: egui::Color32 = egui::Color32::from_rgb(0x18, 0x25, 0x33);

 // ── 文本三级 ──
 pub const TEXT: egui::Color32 = egui::Color32::from_rgb(0xE8, 0xEA, 0xED);
 pub const TEXT_WEAK: egui::Color32 = egui::Color32::from_rgb(0xA8, 0xB0, 0xBC);
-/// 三级：占位/未验证状态点
-pub const TEXT_FAINT: egui::Color32 = egui::Color32::from_rgb(0x7A, 0x82, 0x8F);
+/// 三级：占位/未验证（改值：原 #7A828F 在卡片底 3.91:1 不达正文标准；现 4.52:1）
+pub const TEXT_FAINT: egui::Color32 = egui::Color32::from_rgb(0x84, 0x8D, 0x9A);

 // ── 字号层级 ──
 pub const FONT_HEADING: f32 = 18.0;
 pub const FONT_TITLE: f32 = 15.0;
 pub const FONT_BODY: f32 = 13.0;
-pub const FONT_SECONDARY: f32 = 11.5;
-pub const FONT_BADGE: f32 = 10.5;
+pub const FONT_SECONDARY: f32 = 12.0;
+pub const FONT_BADGE: f32 = 11.0;   // 全 UI 最小字号（中文下限）
+
+// ── 圆角 token（消除 theme.rs 双轨散点）──
+pub const RADIUS_CARD: f32 = 8.0;
+pub const RADIUS_CTRL: f32 = 6.0;
```

函数层新增（多通道编码核心，见 §6）：

```rust
/// 节点状态的形状通道：与 status_color 配对使用（色+形+字三通道）。
/// 在线 ● ｜ 劣化 ◐ ｜ 离线 ✕ ｜ 未测 ○
pub fn status_symbol(connected: bool, checked: bool) -> &'static str {
    if !checked { "○" } else if connected { "●" } else { "✕" }
}
/// 劣化 = 在线但延迟 ≥500ms（与 status_color 的 WARNING 分支同一判定）
pub fn is_degraded(connected: bool, latency_ms: Option<u64>) -> bool {
    connected && latency_ms.is_some_and(|ms| ms >= 500)
}
```

theme.rs 修订：`apply_dark_theme` 中 `window_rounding/menu_rounding` 改引 `palette::RADIUS_CTRL`（修 G-08）；补 `vis.widgets.active.bg_stroke = Stroke::new(1.5, ACCENT)（0.27 无 focused 字段，焦点环走 bg_stroke；升级后迁真 focused 态） = Stroke::new(1.5, ACCENT)`（修 G-04）；theme.rs:52-59 对比度注释按 §4.1 数值重写（修 G-01）。

---

## 5. 信息架构与导航

### 5.1 结论：六页保持不变，页内重组

v2 确立的六页 IA（状态总览/节点/订阅/连接/日志/设置）经审计无结构性缺陷：每页任务单一、无重复页、分享/导入入口已收敛。**v4 不动页面集合，只做页内分区与跨页一致性**。v3 曾提议的"分享独立成页"继续否决（分享是节点/订阅的低频子动作，不配一页）。

侧栏改造（对应 TR-01/TR-02/G-05）：

```
┌────────────────┐
│ Hydra          │  ← 品牌区：heading 18 + small "Multipath Proxy"
│ Multipath Proxy│
│ ───────────────│
│ ▌🏠 首页        │  ← 选中态：左缘 3px ACCENT 竖条 + BG_FAINT 底（B 级自绘）
│  🛰 节点        │
│  📡 订阅        │
│  🔗 连接        │     Ctrl+1..6 切页（A 级）
│  📜 日志        │
│  ⚙ 设置        │
│ ───────────────│
│ ● 代理运行中    │  ← 状态胶囊三态（修 TR-01）：
│                │     ● 运行中 SUCCESS / ◐ 启动中… WARNING / ○ 已停止 FAINT
└────────────────┘
```

### 5.2 页内标准分区（跨页一致性骨架）

每页自上而下五段，全部页面遵守（含间距 token）：

```
① 页头     标题 FONT_HEADING strong ｜右侧动作区（右对齐按钮组）   → 下距 SM
② 横幅区   条件性：凭据缺失(WARNING)/待重启生效(P2)/订阅失败            → 下距 SM
③ 工具区   组标签 / 搜索 / 过滤 / 视图切换（仅需要的页）               → 下距 SM
④ 内容区   卡片流或表格（ScrollArea，ui_shell.rs:300-312 既有包裹保留）
⑤ 页脚注   一行 FONT_SECONDARY 说明（可选）
```

### 5.3 跨页一致性规则

| 规则 | 内容 |
|---|---|
| 同一动作同一形态 | 「测速」在节点卡/订阅展开/首页永远是：`⚡`（升级后 phosphor `lightning`）+ 进行时 Spinner + 完成后徽标；三处共用同一渲染函数 |
| 同一数据同一颜色 | 上行绿/下行蓝；在线绿/劣化黄/离线红/未测灰——任何页面不得重定义 |
| 同一状态同一文案 | 运行状态词表固定：`运行中 / 启动中… / 已停止`（启停）、`在线 / 在线·慢 / 离线 / 未测试 / 测速中…`（节点）、`活跃 / 已关闭`（连接）；见 §13 文案规范 |
| 空态三件套 | 一句现状 + 一句出路 + 一个动作按钮（详见各页状态矩阵） |
| 破坏性操作 | 一律红色文案 + 确认对话框（§6.5 统一组件） |
| 时间格式 | `%Y-%m-%d %H:%M`（订阅页 ui_subscriptions.rs:84 已是，全局统一） |

---

## 6. 状态可视化强化

代理工具的核心可判读性。原则：**语义状态必须三通道（颜色 + 形状/字形 + 文字），连续量必须数字 + 颜色增强**。依据 WCAG 1.4.1（不依赖颜色）。

### 6.1 代理运行状态（全局唯一状态机）

来源：`proxy_running` + `proxy_starting`（app.rs:110-121 状态机扩展）。

| 状态 | 颜色 | 形状 | 文案 | 出现位置 |
|---|---|---|---|---|
| 已停止 | TEXT_FAINT | ○ 空心 | 「已停止」 | 首页卡/侧栏底/状态胶囊 |
| 启动中 | WARNING | ◐ + Spinner | 「启动中…」按钮禁用 | 同上（修 TR-01：侧栏补第三态） |
| 运行中 | SUCCESS | ● 实心 | 「运行中」 | 同上 |

封装组件 `status_pill()`（§6.5），三处调用同一函数，消灭 TR-01。

### 6.2 节点健康状态（修 ND-01，P0 核心）

| 状态 | 判定 | 颜色 | 形状字形 | 文字徽标 | 延迟显示 |
|---|---|---|---|---|---|
| 未测试 | `!checked` | TEXT_FAINT | ○ | 「未测试」 | `—` |
| 测速中 | `node_testing_addr == addr` | ACCENT | Spinner | 「测速中…」 | `—` |
| 在线 | connected && <500ms | SUCCESS | ● | 「在线」 | `45ms`（SUCCESS 色 + monospace） |
| 劣化 | connected && ≥500ms | WARNING | ◐ | 「在线·慢」 | `520ms`（WARNING 色） |
| 离线 | !connected && checked | DANGER | ✕ | 「离线」 | 「超时」**改 DANGER 色**（修 ND-02） |

节点卡第一行渲染规范（替换单色点）：

```
● hk-01  [手动]                        ●在线  45ms
└ 10px 色点        └ 来源徽标           └ 状态徽标（色+形+字） └ 延迟（数字+色）
```

实现（B 级，~40 行）：10px 色点保留（快速扫视通道）+ 状态词徽标（`FONT_BADGE`，语义色文字）+ 形状字形前缀。色盲用户靠「●/◐/✕/○ + 在线/在线·慢/离线/未测试」双通道完全可辨。

### 6.3 流量方向（现状合格，成文规范）

上行 `↑` SUCCESS / 下行 `↓` ACCENT，箭头即形状通道，数字即文本通道。首页卡、曲线图例、连接表三处已一致（ui_overview.rs:169-178,273-284；ui_connections.rs:164-176）。P1 升级 phosphor 后箭头换 `arrow-up`/`arrow-down` 图标字形，规则不变。

### 6.4 订阅健康状态（修 SB-06，P1）

| 状态 | 颜色+形 | 文字徽标 |
|---|---|---|
| 从未更新 | FAINT ○ | 「从未更新」 |
| 更新中/排队 | INFO ◐ + Spinner | 「更新中… / 排队 n」 |
| 更新成功 | SUCCESS ● | 「✓ 更新于 2026-10-10 14:30」 |
| 更新失败 | DANGER ✕ | 「✗ 更新失败」（hover 显示错误详情） |

数据来源：`SubscriptionConfig` 增 `last_result: Option<Result<(), String>>`（config.rs 持久化字段，`#[serde(default)]` 向后兼容），在 `poll_subscription_updates`（subscription_actions.rs:137-153）写入。

### 6.5 新增公共组件库（新建 `components.rs`，全部 B 级）

| 组件 | 签名（示意） | 用途 | 行数 |
|---|---|---|---|
| `status_dot` | `(ui, color, symbol, size)` | 色点+字形叠加 | 25 |
| `status_pill` | `(ui, color, symbol, text)` | 圆角胶囊：`*_BG` 底 + 语义色字形 + TEXT 文字 | 30 |
| `latency_badge` | `(ui, latency, checked)` | 延迟/超时/未测统一渲染（修 ND-02 单点） | 25 |
| `banner` | `(ui, kind, text, action)` | `*_BG` 底 + 左缘 3px 语义竖条 + 图标字形 + 正文 TEXT + 动作按钮（替换 ui_nodes.rs:62-84 手写横幅） | 45 |
| `empty_state` | `(ui, title, hint, action)` | 空态三件套 | 30 |
| `confirm_destructive` | `(ctx, action: ConfirmAction)` | 统一确认对话框：红色标题 + 级联说明 + 「确认删除/取消」 | 60 |

`components.rs` 合计约 **220 行**，P0 一次性落地；全部页面改调组件（散点替换另计）。

---

## 7. 每页重设计规格

通用网格：内容区水平安全边距 `SPACING_LG`(16)；卡片列宽 300–400 自适应（节点页现状 ui_nodes.rs:214-220 保留）；表格/卡片间距 `SPACING_SM`(8)。

### 7.1 首页（ui_overview.rs）

```
① 页头  「首页」 + 右侧 [status_pill 运行状态]
② 引导区  仅无配置时：empty_state("三步开始使用", ①设置→全局凭据 ②订阅→新建 ③回这里启动, [前往设置])
③ 统计卡  2×2；可用宽 ≥640 时 4×1（A 级：num_columns 按宽度取值）
         ① 运行状态：pill + 启停大按钮 + 监听地址
         ② 当前节点：调度参考（括号说明下沉为卡内 small 注释行，修 OV-05）
         ③ 今日流量：⬇ ACCENT / ⬆ SUCCESS（大数字 FONT_HEADING monospace）
         ④ 活跃节点：n/总 + 延迟中位 + 活跃连接
④ 速率曲线卡  180px；空态改为**卡内**居中 empty_state（修 OV-07），代理运行后显示曲线
⑤ 快捷卡  [⚡ 全部节点测试] [系统代理：开/关] [查看全部日志 →]
         ＋ 最近 3 条日志（带级别色点，点击跳日志页并滚动到底）
```

变更明细：
- **删除 TUN checkbox**（修 OV-03，P1）：TUN 是配置项，归设置页；快捷卡只留"动作"不留"配置"；
- 统计卡响应式：`stat_cols = if avail_w >= 640 { 4 } else { 2 }`（修 OV-01 + G-11 的首页部分，A 级 ~15 行）；
- 曲线 hover 读数（OV-02）**P2/C 级**：egui_plot 0.3x 的 hover 回调+自定义 surface，随升级评估；
- 错误呈现（G-02 页内实例）：启动失败时运行状态卡内加一行 DANGER 错误摘要（取最近一条 Error 级日志）。

**状态矩阵**

| 态 | 表达 |
|---|---|
| loading | 状态卡 ◐启动中 + 按钮「⏳ 启动中…」禁用；曲线区「等待首个采样点…」 |
| empty（无节点） | 当前节点卡 `—`「暂无节点」+ 页顶引导卡（OV-06） |
| error（启动失败） | pill 回「已停止」+ 卡内 DANGER 错误行 + 日志 Error 条目 |
| running | pill ● 运行中；曲线滚动；统计卡实时 |
| disabled | 系统代理按钮（未运行/TUN 时禁用 + on_disabled_hover_text，现状保留） |

### 7.2 节点页（ui_nodes.rs）

```
① 页头  「节点」 + 右侧 [搜索框🔍 P1] [排序: 默认/延迟↑ P1] [⚡ 全部测速] [🔗 分享节点]
② 横幅  凭据缺失 → banner(WARNING)（改用 §6.5 banner 组件）
③ 工具区  组标签行（保留，升级后换图标字体）；测速中 → 按钮内进度「测速中 3/12」（修 ND-09）
④ 组头栏  「全部节点 · 8」｜ ● 在线 3 ｜ ◐ 劣化 1 ｜ ✕ 离线 2 ｜ ○ 未测试 2 ｜ [⚡测本组]
         （补未测计数与劣化计数，修 ND-04；计数用 §6.2 三通道徽标）
⑤ 内容区  节点卡网格（1–3 列保留）：
         第一行  ● hk-01 [手动] ｜ 右对齐 ●在线 45ms
         第二行  [⚡测速] [🔗分享] [✏编辑/⇥另存] [🗑删除]   ← P1 升级后 [⚡][share][pencil][trash]+文字
         删除 → confirm_destructive（修 ND-03）
⑥ 页脚注  一行订阅说明（保留 ui_nodes.rs:374）
```

**状态矩阵**

| 态 | 表达 |
|---|---|
| loading（组测速） | 页头按钮变「测速中 n/m」禁用；进行中的卡片操作行显示 Spinner+「测速中…」 |
| empty（无节点） | empty_state("还没有节点", "订阅源批量拉取，或手动/分享导入", [＋ 新建 → 转订阅页]) |
| empty（组内空） | 「本组暂无节点」（现状保留） |
| error（节点超时） | ✕ 离线红徽标 + 「超时」红字（ND-02 修正后与状态点同色） |
| running/disabled | 测速互斥禁用（09-G-3 保留）；订阅节点无编辑按钮（只读语义保留） |

### 7.3 订阅页（ui_subscriptions.rs）

```
① 页头  「订阅」 + 右侧 [🔄 更新全部订阅(更新中禁用,修SB-04)] [＋ 新建 ▾]
② 工具区  （删除常驻说明长段，修 SB-02：收纳进「＋ 新建」菜单底部 small 一行）
③ 内容区  订阅卡片（修 SB-03，改 card_frame 卡式行）：
         ┌──────────────────────────────────────────────┐
         │ 订阅A            ●✓ 更新于 2026-10-10 14:30   │
         │ 订阅 · sub.example.com ｜ 6 节点               │
         │ [立即更新] [展开节点▾] [编辑] [删除]  ← 右对齐  │
         └──────────────────────────────────────────────┘
         状态徽标 = §6.4；更新失败 hover 显错误详情
         展开区：缩进节点清单（保留）+ 单节点操作统一调 §6.5 组件（修 SB-05）
④ 删除订阅 → confirm_destructive（修 SB-01）：
   标题「删除订阅「订阅A」？」正文「将同时移除仅被该订阅认领的 3 个节点；
   本地导入分组的粘贴内容将一并丢失，无法恢复。[ ] 我已知晓」（级联 0 节点时不显示红字句）
```

**状态矩阵**

| 态 | 表达 |
|---|---|
| loading | 行内「更新中…」+ Spinner（排队显示「排队中」INFO）；页头按钮禁用 |
| empty | empty_state("暂无订阅源", "从 URL/文件/分享链接添加", [＋ 新建]) |
| error | 卡片 ✕ 更新失败徽标（DANGER）+ hover 详情；下次成功自动清除 |
| running | 正常 |
| disabled | 「更新全部」更新中禁用 |

### 7.4 连接页（ui_connections.rs）

```
① 页头  「连接」 + 右侧 [搜索目标/节点 P1] [⏸ 暂停刷新 P1]
② 工具条卡（合并汇总卡，修 CN-06）：
   ● 活跃 12 ｜ ○ 已关闭 34 ｜ 右侧 small「每 500ms 自动刷新；已关闭保留 60s」
③ 表格  7 列保留（目标/节点/↑速率/↓速率/累计/时长/状态）
   - 目标列旁 small 首行注释「目标已脱敏为短哈希，hover 查看」（修 CN-03）
   - 「直连」行加 ⤵ 直连徽标（INFO 色字形+文字，修 CN-04）
   - 状态列 ●活跃/○已关闭 保留（已合规）
   - 排序/虚拟化 → P2 egui_extras::Table（CN-01 收尾、CN-02、CN-05）
```

**状态矩阵**

| 态 | 表达 |
|---|---|
| loading | 持续 500ms 自动刷新（现状）；暂停按钮切「▶ 继续」+ 表头右侧「已暂停」pill |
| empty（代理未运行） | empty_state("暂无连接", "代理未运行——启动后经代理的连接显示在这里", [▶ 启动代理]) |
| empty（运行中无流量） | empty_state("暂无连接", "代理运行中——发起的连接将实时显示", 无动作) |
| running | 正常表格 |
| disabled | —（页面无配置项） |

### 7.5 日志页（ui_logs.rs）

```
① 页头  「运行日志」 + 右侧级别过滤 [☑信息(n) ☑警告(n) ☑错误(n)] + [导出 P2]
② 内容区  等宽字体（修 LG-02）行式列表，stick_to_bottom 保留；
   每行 = [HH:MM:SS] 级别点+文本；警告行 WARNING、错误行 DANGER 着色（修 LG-01）
③ 底栏  [清空日志（红字+确认）] ｜「自动跟随」pill（上滚自动变「已暂停，点此回底部」，修 LG-06）
   删除「刷新」按钮（修 LG-03）
```

**状态矩阵**：empty = 「暂无日志」居中；error 态 = 级别着色+过滤；loading = n/a（流式）。

结构化改造：`LogLevel {Info, Warn, Error}` + `logs: Vec<(LogLevel, String)>`；`add_log` 保持签名（→Info），新增 `add_warn/add_error`，迁移现有 ⚠️/✗/失败 类调用点约 10 处（app.rs:146,152,320、ui_shell.rs:56,70,378、subscription_actions.rs:143-150、ui_node_edit.rs:66-90 等按前缀甄别）。

### 7.6 设置页（ui_settings.rs）

```
分区保持七段，改动：
- 「开机自启（规划中）」：禁用 Checkbox 改为一行文字 + 「规划中」徽标（FONT_BADGE, FAINT 底）（修 ST-01）
- 「主题」项：P0 直接隐藏；P1 随双主题落地改为三选 radio（跟随系统/深色/浅色）
- 探测间隔 DragValue 加 .suffix("s")（修 ST-04）
- 全局凭据警告改 banner(WARNING) 组件（修 ST-03）
- 「退出程序」→ confirm_destructive（修 ST-06）
- P2：proxy_running 且配置有"需重启生效"类变更时，页顶 banner(WARNING)
  「有修改将在下次启动代理后生效：信任模式、认证密钥」（修 ST-02）
```

**状态矩阵**：error = 证书路径不存在/密钥格式错误红字（现状保留）；disabled = 规划中项徽标化；其余 n/a。

### 7.7 对话框（跨页，6 个 Window 统一规格）

- 尺寸：default_width 480–520（现状保留）；标题 = 「动词 + 对象」（「导入分享链接」「编辑节点 1.2.3.4:4433」）；
- 底部按钮排布：主操作（strong）在左、取消在右（现状一致）；
- **Esc = 取消，Enter = 主操作**（焦点不在多行输入框时，修 G-06）；
- 校验错误：红字 `✗ 现象（原因）` 紧跟字段下方，提交失败不关窗（现状已符合，成文）。

---

## 8. 深浅色主题策略

### 8.1 分期（与 eframe 升级方案 §8 主题机制严格衔接）

| 阶段 | egui 版本 | 策略 |
|---|---|---|
| **P0（现在）** | 0.27 | 维持 `apply_dark_theme` 硬钉深色（0.27 无 ThemePreference，现状即正确做法）；但完成 palette.rs v4 diff（§4.5），把**所有**新 token 以深色值定义，浅色值以注释形式预留——保证升级时零设计决策 |
| **P1（随升级）** | 0.33 | ① `HydraApp::new` 首帧前显式 `ctx.set_theme(egui::ThemePreference::Dark)`——根治升级方案 §2.8 指出的"System 默认导致白闪/主题覆盖"；② palette 拆为 `palette/mod.rs`（语义访问层）+ `palette/dark.rs` + `palette/light.rs`（§4.1 浅色列直接可用）；③ `theme.rs` 的 `apply_theme` 按 `egui::Theme::Dark/Light` 分别构建 `Style`，经 `ctx.set_style_of(theme, style)` 双份装配（0.29+ API）；④ 设置页「外观」主题三选：**深色（默认）/浅色/跟随系统**，选择持久化进 GuiConfig，`on_exit` 前每帧差分应用 |
| **P2（可选）** | 0.33 | 托盘图标随主题换色（当前托盘图标硬编码蓝底 tray.rs:167-207，不跟随）；曲线网格/坐标轴配色进 token |

### 8.2 双主题工程约束

- **禁止运行时 gamma 合成主题色**：`selection.bg_fill = ACCENT.gamma_multiply(0.45)`（theme.rs:87）保留（它是选中态不是主题色），但 `*_BG` 横幅底必须是常量 hex，两主题各一份——gamma 合成在浅色底上会失真；
- 页面代码**只引 `palette::*` 语义名**，不感知主题（v3 已建立该纪律，palette 拆分后自动维持）；
- 升级期回归清单（并入 eframe 升级方案 §3 第 3 条 逐页目检）：每页在浅色下目检横幅/徽标/色点/选中态四类元素。

---

## 9. 可访问性规范

| 项 | 规范 | 落点 |
|---|---|---|
| 正文对比度 | ≥4.5:1 | §4.1 全部文本 token 实测达标（TEXT_FAINT 已从 3.91 提到 4.52） |
| 大字（≥18px 常规/≥14px 粗体） | ≥3:1 | 统计数字 FONT_HEADING 全部 ≥12:1 |
| 非文本 UI（色点/描边/焦点环） | ≥3:1 | 状态点 4.52–10.88 ✓；BORDER_STRONG 3.05/3.27 ✓；焦点环 5.58/5.19 ✓ |
| 最小字号 | 中文 ≥11px | FONT_BADGE=11（v4 起强制，10.5 废除） |
| 不依赖颜色（WCAG 1.4.1） | 语义状态三通道 | §6 全部状态矩阵：颜色+字形（●◐✕○）+文字词 |
| 色盲可辨 | 红/绿、蓝/黄不得为唯一区分 | 上行绿 vs 下行蓝：有 ↑↓ 箭头+图例文字；延迟绿黄红：有数字本身；节点四态：见 §6.2 |
| 焦点可见性 | 键盘焦点 1.5px ACCENT 描边 | `widgets.focused.fg_stroke`（G-04 修复） |
| 键盘操作 | 页级 Ctrl+1..6；对话框 Enter/Esc；原生 Tab 遍历 | G-05/G-06 |
| hover 补充 | 截断文本必须 on_hover_text 全量 | 现状已执行（ui_overview.rs:93-99,113-121 等），成文为纪律 |

---

## 10. egui 实现映射总表

评级：**A** = 现有 0.27 API 直接可行；**B** = 自定义 painting 可行（有成本）；**C** = 需 0.33 升级后或高成本。

| 设计项 | 对应审计 | 评级 | 实现方式 | 行数量级 |
|---|---|---|---|---|
| palette v4 diff（新 token/改值） | G-01/07/08 | A | palette.rs + theme.rs 常量改造 | 100 |
| components.rs 组件库（dot/pill/badge/banner/empty/confirm） | §6.5 | B | circle_filled + Frame 自绘 | 220 |
| 节点三通道状态徽标 | ND-01 | B | 组件 + 节点卡改造 | 40（页面侧） |
| 「超时」改危险色 | ND-02 | A | latency_badge 内部分支 | 5 |
| 删除确认（节点/订阅/清日志/退出） | ND-03/SB-01/LG-04/ST-06 | A | egui::Window + ConfirmAction 枚举 | 70 |
| 日志级别结构化+着色+过滤 | LG-01 | A | Vec<(Level,String)> + checkbox 过滤 | 90 |
| 日志等宽 | LG-02 | A | `.monospace()` | 5 |
| 侧栏三态状态胶囊 | TR-01 | B | bottom_up 布局内调 status_pill | 15 |
| 侧栏选中态左缘条 | TR-02 | B | `ui.painter().rect_filled` 3px | 25 |
| 全局快捷键 Ctrl+1..6 | G-05 | A | `ctx.input(\|i\| i.key_pressed(..))` | 25 |
| 对话框 Esc/Enter | G-06 | A | input 检查 + 焦点判断 | 50 |
| 首页引导卡（无配置） | OV-06 | A | empty_state + Tab 跳转 | 60 |
| 首页统计卡响应式列数 | OV-01/G-11 | A | Grid num_columns 按宽度 | 15 |
| 曲线空态入卡内 | OV-07 | A | 分支渲染 | 15 |
| 间距脱轨清理 | G-07 | A | 6 处数值替换 | 20 |
| 焦点样式强化 | G-04 | A | visuals.widgets.focused | 15 |
| **palette 双主题拆分**（dark.rs/light.rs/语义层） | §8 | A*（*随 0.33） | 模块化 + set_style_of | 150 |
| ThemePreference::Dark 显式 + 主题三选持久化 | §8/ST-01 | C | `ctx.set_theme`（0.29+ API） | 40 |
| emoji → egui_phosphor 图标 | G-03 | A（随升级锁版本） | 全 UI 散点替换 + Cargo 依赖 | 150（散点） |
| 节点搜索 + 延迟排序 | ND-06 | A | filter + sort_by_key（参照 connections 的纯函数范式） | 120 |
| 测速进度 n/m | ND-09 | A | pending_node_tests.len() 计数 | 20 |
| 组头补未测/劣化计数 | ND-04 | A | group_summary 扩展三元组 | 30 |
| 订阅卡片化 + 结果徽标 | SB-02/03/06 | A/B | card_frame + last_result 字段 | 130 |
| 订阅更新禁用防重入 | SB-04 | A | add_enabled | 10 |
| 连接页搜索 + 暂停 | CN-01 | A | filter + bool 开关 | 80 |
| 直连徽标 | CN-04 | A | 徽标组件复用 | 10 |
| 连接页虚拟化表格+排序 | CN-02/05 | C | egui_extras::Table（新依赖，随升级锁版本） | 200 |
| 曲线 hover 读数 | OV-02 | C | egui_plot 0.3x hover API 评估后做 | 80 |
| 待重启生效横幅 | ST-02 | A | 配置差分标记 + banner | 60 |
| 设置假禁用项清理 | ST-01 | A | 文字+徽标替换 | 30 |
| 探测间隔后缀 | ST-04 | A | `.suffix("s")` | 2 |
| 日志导出+上限 1000 | LG-04/05 | A | std::fs::write + 容量常量 | 60 |
| 首页去 TUN 配置项 | OV-03 | A | 删块 + 设置页保留 | 10 |
| 空闲降频重绘 | G-12 | A | 有 activity 才 `request_repaint_after(500ms)`，静止时 2s | 30 |
| TUN checkbox 移除后的设置页回归 | OV-03 | A | — | 已含 |

---

## 11. 分阶段实施计划

### P0 —— 低成本高收益（eframe 0.27 上即可做；估 ~2 人日，~800 行含测试）

| # | 内容 | 覆盖 | 验收标准 |
|---|---|---|---|
| 1 | palette.rs v4 diff + theme.rs 收口（RADIUS token、focused 样式、注释修正） | G-01/04/08 | `cargo test -p hydra-client-gui`（palette 单测更新后）通过；grep 全库无 `FONT_TITLE + 3.0`、无 2.0/6.0 间距散点 |
| 2 | components.rs 组件库 6 件 | §6.5 | 组件有单测（status_symbol/status_color 配对完整性）；节点卡/横幅/空态改调组件后截图目检 |
| 3 | 节点三通道状态徽标 + 超时红字 | ND-01/02 | 四种节点状态（未测/在线/劣化/离线）在灰度截图（去色）下仍可分辨；「超时」文字为 DANGER 色 |
| 4 | 统一删除确认（节点/订阅/清空日志/退出） | ND-03/SB-01/G-09/ST-06/LG-04 | 四处操作均先弹确认；订阅确认框正确显示级联节点数；Esc=取消 |
| 5 | 日志级别结构化（Level 枚举 + 着色 + 过滤 + 等宽） | LG-01/02 | 启动代理/制造一次订阅失败：错误红、警告黄、过滤 checkbox 生效 |
| 6 | 侧栏三态胶囊 + Ctrl+1..6 + 对话框 Esc/Enter | TR-01/G-05/06 | 启动期间侧栏显示「◐ 启动中…」；Ctrl+3 切订阅页；任意对话框 Esc 关闭 |
| 7 | 首页：引导卡 + 统计卡响应式 + 曲线空态入卡 + 启动失败错误行 | OV-06/01/07/G-02 | 无配置首启可见三步引导卡；窗口 ≤480px 统计卡单列不溢出 |
| 8 | 间距/最小字号/统计数字 token 清理 | G-07/§4.2 | grep 无 10.5/11.5 字号、无硬编码间距 |

### P1 —— 随 eframe 0.33 升级同批（升级会话 + ~2 人日，~750 行）

| # | 内容 | 覆盖 | 验收标准 |
|---|---|---|---|
| 1 | **eframe 升级本体**（前置，按 eframe升级方案 §3 执行） | — | 升级方案验收全过 |
| 2 | `set_theme(ThemePreference::Dark)` + palette 双主题拆分 + 主题三选 | §8/ST-01 | 浅色 Windows 下启动无白闪；切浅色后全页目检横幅/徽标/色点；选择重启后保持 |
| 3 | emoji → egui_phosphor（版本与 0.33 锁齐） | G-03 | 全 UI 无 emoji；图标单色随主题 |
| 4 | 节点搜索 + 延迟排序 + 测速进度 n/m + 组头三元计数 | ND-06/09/04 | 20 节点按延迟排序正确（单测）；测速显示 n/m；组头含未测数 |
| 5 | 订阅卡片化 + 更新结果徽标 + 禁用防重入 | SB-02/03/04/06 | 失败订阅显示 ✕ 徽标 + hover 详情；更新中按钮禁用 |
| 6 | 连接页搜索 + 暂停 + 工具条合并 + 直连徽标 | CN-01/04/06 | 过滤即时生效；暂停后表格冻结、按钮变继续 |
| 7 | 首页去 TUN 配置项 + 最小窗口尺寸复核（400×300 下全页无溢出） | OV-03/G-11 | 400×300 逐页目检无水平滚动条/裁切 |

### P2 —— 锦上添花（升级后，估 ~1.5 人日，~450 行）

| # | 内容 | 覆盖 | 验收标准 |
|---|---|---|---|
| 1 | 连接页 egui_extras::Table（虚拟化 + 列排序） | CN-01/02/05 | 500 行连接滚动流畅（无全量布局）；点表头排序 |
| 2 | 曲线 hover 读数 + 峰值标注 | OV-02 | hover 显示时刻+速率；窗口期内峰值有标记 |
| 3 | 「待重启生效」横幅 | ST-02 | 运行中改信任模式 → 页顶横幅出现，重启后消失 |
| 4 | 日志导出文件 + 上限 1000 | LG-04/05 | 导出 .log 可读；上限常量 1000 |
| 5 | 日志「自动跟随」状态 pill | LG-06 | 上滚变「已暂停」，点按回底部 |
| 6 | 空闲降频重绘 | G-12 | 静止时 CPU 占用可测下降（任务管理器目检） |
| 7 | 标题栏运行状态（「[运行中] Hydra」） | TR-03 | 启停时标题栏即时变化 |

依赖与风险：P2-1 需新增 `egui_extras` 依赖（版本随 0.33 锁齐）；P2-2 依赖 egui_plot 0.3x hover API 形态，实施前先 spike 验证；P1-2 浅色主题需按 §8.2 约束逐页目检，工期已含在升级会话的目检清单。

---

## 12. 不做清单

为守住"企业级工具"定位，以下设计**明确拒绝**（含理由）：

| 不做 | 理由 |
|---|---|
| 微动效堆砌（页面切换淡入、卡片 hover 缩放、数字滚动动画） | egui `animate_value_with_time` 可做但违背低装饰原则；工具软件动效=等待感。仅保留 egui 默认 hover/按下反馈 |
| 消费级空态插画/吉祥物 | 与企业工具气质冲突；空态用「一句话+出路+动作」三件套 |
| 自绘标题栏（`decorated(false)` 一体化） | v3 已否决；拖拽/最大化/半屏贴靠自造轮子，收益仅美观 |
| 拖拽排序（easy-dnd 等） | 订阅数量少（个位数）；上移/下移按钮不够用之前不引入 DnD 依赖 |
| 多强调色主题商店 / 主题色切换器 | 一个 ACCENT 是纪律不是限制；换色破坏"颜色=语义"的映射 |
| 舒适/紧凑双密度模式 | 维护两套规格的长期成本 > 收益；只做一套紧凑规格（v4 即是） |
| 阴影/毛玻璃/渐变卡片 | egui 无原生支持（自绘高成本），且与 P3 低装饰冲突 |
| 大圆角（>10px）/全屏 hero 区/消费级 onboarding 轮播 | 工具软件密度优先 |
| 每连接限速/阻断等超范围功能 | UI 方案不扩功能边界（连接页只读，P1 的"暂停刷新"是视图冻结不是功能开关） |

---

## 13. 文案规范

基调：**简洁中文 + 少量英文技术词**；祈使句，省略主语，不用人称（"您/你"都不用）。

### 13.1 词表（状态词全局唯一，禁止同义变体）

| 域 | 唯一词表 |
|---|---|
| 代理运行 | `运行中` `启动中…` `已停止` |
| 节点健康 | `在线` `在线·慢` `离线` `未测试` `测速中…` |
| 连接 | `活跃` `已关闭` `直连` |
| 订阅 | `从未更新` `更新中…` `排队中` `更新失败` |
| 按钮动词 | `启动代理` `停止代理` `全部测速` `测本组` `立即更新` `更新全部` `导入` `保存` `删除` `分享` `编辑` `另存为手动` |

### 13.2 结构规则

- **按钮**：动词开头，≤6 字；主操作加粗；危险操作红色文案 + 确认；
- **错误消息** = 现象 + 原因 + 动作，模板 `✗ {现象}（{原因}，{动作}）`，例：
  `✗ 证书文件不存在：C:\certs\n1.der（路径错误或文件已移动，点「浏览替换」重新选择）`（对齐 ui_settings.rs:97 现有风格）；
- **空态** = 现状一句 + 出路一句 + 动作按钮；
- **tooltip** = 解释"这是什么/为什么禁用"，禁用态用 `on_disabled_hover_text`（现状已执行，成文）；
- **数字与单位**：跟随既有 `format_bytes/format_speed` 紧凑风格（`12.4 MB/s`、`45ms`、`1.2 GB`），数字与单位间一个空格、`ms` 除外；
- **标点**：中文全角标点；代码/路径/地址/键名以等宽渲染，不加引号；
- **禁用**：语气词（哦/啦/呀）、波浪号、连续感叹号、"亲爱的"、营销语（"极速""安全无忧"）；
- **英文技术词白名单**（不翻译）：SOCKS5、TUN、TLS、DER、CA、ACME、hex、URL、SNI、pin。
