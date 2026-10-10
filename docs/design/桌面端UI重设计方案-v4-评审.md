# 《桌面端 UI 重设计方案 v4》评审报告

> 评审人：UI/UX 设计总监（桌面端 / egui 生态）｜评审日期：2026-10-10
> 评审对象：`docs/design/桌面端UI重设计方案-v4.md`（只读）
> 现状参照：`hydra-client-gui/src/palette.rs`（v4 组件库版令牌）与 `hydra-client-gui/src/ui_overview.rs`
> 对比度核算方法：WCAG 2.x 相对亮度公式逐对精确计算（非估算），保留两位小数。

---

## 总评

**结论：需修订后可实施。** 方案的问题诊断准确、信息架构方向正确、主题基建的架构选型（自建 Theme）合理；但存在三类必须修订的问题：

1. **色板硬伤**：`text_faint` 三主题全部不达标（连"辅助 ≥3:1"都不过），Light 主题 warning 也不达标；
2. **令牌回归**：v4 方案的三主题色板表**丢掉了现行 palette.rs 已有的多个令牌**（INFO、四组横幅语义底色、TEXT_ON_ACCENT、BG_SIDEBAR、BG_EXTREME、NodeHealth 三通道判定），机械替换会直接破坏已上线的横幅/节点健康组件；
3. **图表渐变填充**：egui_plot 0.27 的 `Line::fill` 只接受单一 `Color32`，**没有原生渐变 API**，3.4 节"30% 透明渐变面积填充"需改实现方式（见 §3）。

---

## 一、设计令牌体系

### 1.1 对比度逐对核算（WCAG AA：正文 ≥4.5:1，辅助/大字 ≥3:1）

**Dark（默认）**

| 前景 \ 背景 | bg_app #12141C | bg_card #1A1D29 | 判定 |
|---|---|---|---|
| text #E8EAF2 | **15.30** | **13.97** | ✅ |
| text_weak #9AA0B5 | **7.06** | **6.45** | ✅ |
| text_faint #5C6378 | 3.07 | **2.81** | ❌ 卡片上不足 3:1 |
| accent #4C8DFF | 5.74 | 5.24 | ✅ |
| success #34D399 | 9.56 | 8.73 | ✅ |
| warning #FBBF24 | 11.01 | 10.05 | ✅ |
| danger #F87171 | 6.64 | 6.07 | ✅ |

其他关键对：accent × 白（按钮文字）= **3.20**（仅大字/图形达标，正文不达标）；border × bg_card = 1.25、chart_grid × bg_card = 1.13（非文本装饰，不强制，但 1.1 的网格线肉眼近乎不可见，见 §3）。

**Light**

| 前景 \ 背景 | bg_app #F5F6FA | bg_card #FFFFFF | 判定 |
|---|---|---|---|
| text #1A1D29 | **15.54** | **16.78** | ✅ |
| text_weak #6B7280 | 4.48 | 4.83 | ⚠️ bg_app 上 4.48 差一线不到 4.5（作辅助色 ≥3:1 则达标） |
| text_faint #9CA3AF | 2.35 | 2.54 | ❌ 双双不足 3:1 |
| accent #2563EB | 4.79 | 5.17 | ✅ |
| success #059669 | 3.49 | 3.77 | ⚠️ 只到辅助标准，作正文色不达标 |
| warning #D97706 | **2.95** | 3.19 | ❌ bg_app 上不足 3:1 |
| danger #DC2626 | 4.47 | 4.83 | ⚠️≈正文线，作辅助达标 |

其他：accent × 白 = 5.17（Light 主按钮可直接白字 ✅）；border × bg_card = 1.26。

**Abyss（创想）**

| 前景 \ 背景 | bg_app #0A1220 | bg_card #101B2E | 判定 |
|---|---|---|---|
| text #D8E4F0 | **14.53** | **13.36** | ✅ |
| text_weak #7C93B5 | 5.98 | 5.50 | ✅ |
| text_faint #4A5F80 | 2.89 | **2.66** | ❌ 不足 3:1 |
| accent #2DD4BF | 10.07 | 9.26 | ✅ |
| accent2 #8B5CF6 | — | 4.07 | ⚠️ 辅助达标、正文不达标 |
| success / warning / danger | 9.75 / 11.23 / 6.78 | 8.97 / 10.33 / 6.23 | ✅ |

其他：**accent #2DD4BF × 白 = 1.86** —— Abyss 主按钮绝不能用白字，必须配深色文字令牌。

**核算小结**：
- 三主题共 **5 处硬不达标**：text_faint（三主题 × 卡片底全部 <3:1）、Light warning on bg_app（2.95）。
- **bg_card_hover 派生对**（text_faint 2.57 / 2.27 / 2.42）同样不达标——faint 色整体需要提亮一档。

### 1.2 令牌覆盖完整性

方案色板表**缺失**（对照现行 palette.rs 与 egui 实际用色）：

| 缺失令牌 | 说明 | 现行状态 |
|---|---|---|
| `text_disabled` / 控件 disabled 前景 | 系统代理按钮等大量 `add_enabled(false)` 场景；egui 走 `Visuals.widgets.inactive.fg_stroke`，不自定义则 Light 主题下沿用 Dark 残留 | ❌ 两版都缺 |
| `splitter` / separator 色 | `ui.separator()`、卡片内分隔线大量使用，取 `Visuals.widgets.non_bg.stroke` | ❌ 缺 |
| `shadow` | egui 0.27 的 `Visuals.window_shadow` / `popup_shadow`；Light 主题沿用 Dark 的重阴影会显脏 | ❌ 缺 |
| `TEXT_ON_ACCENT` | 主按钮文字色；现行已有（v4 组件库注释明确 ACCENT 上白字仅 2.72:1 不达标），方案表却删了；Abyss accent 下更是 1.86 | ⚠️ **回归** |
| `INFO` + `INFO_BG` 及四组 `*_BG` 横幅底色 | 现行 `components::banner` 依赖；方案表全删 | ⚠️ **回归** |
| `BG_SIDEBAR` / `BG_EXTREME` / `BG_FAINT` | 侧栏、输入框、斑马纹现行在用；方案只有 bg_app/bg_card/hover 三档 | ⚠️ **回归** |
| `BORDER_STRONG` / focus ring 色 | 焦点环、危险边框 | ⚠️ 回归 |
| chart 曲线色令牌（chart_up/chart_down） | 3.4 直接写"success/accent"，建议显式成令牌，便于 Abyss 双 accent 分配 | ❌ 缺 |
| hover/pressed 态 accent 派生色 | accent_hover、accent_pressed | ❌ 缺 |

**另一处静默变更**：现行字阶是**五级**（HEADING 18 / TITLE 15 / BODY 13 / SECONDARY 12 / BADGE 11，且有"最小可读字号下限"的明示决策），方案 3.2 改为四级且辅助档 11px——低于现行已评审确定的 12px 下限，且新增 22px 大数档未定义与 18px HEADING 的关系（两者并存还是取代？）。

---

## 二、信息架构（Hero + 三卡 + 图表 + 快捷操作）

**方向正确**：把"启停"从卡内一行提升为 Hero 条一级元素、四卡收敛为三卡、快捷操作上移进首屏，三个决策都对，解决了审计 Q1/Q2/Q4。

需修订/优化的点：

1. **Hero 条的状态适配缺失**：方案只画了"accent 描边强调"一种形态。运行中 / 启动中 / 已停止三态下，Hero 的描边色、状态圆点色、主按钮文案（现行 `start_button_state` 状态机已含 disabled 逻辑）应有一一对应的规范表，否则实现时仍会退化成单色。
2. **"当前节点"卡的可操作性被吞掉**：现行首页"当前节点"是调度参考语义，用户看到不满意的节点需要能一键跳到节点页。方案把它并入二级数据卡时没有说明是否可点击——建议整卡可点（hover 描边反馈）跳转节点页，与"快捷操作上移"的思路一致。
3. **图表与快捷操作的相对顺序**：速率图是"看"，快捷操作是"做"。首屏纵向预算有限时，建议快捷操作条（单行横排，非卡片）置于三卡与图表之间，图表沉底——运营类客户端惯例是操作靠近其作用对象（节点/代理开关在上方，图表作为背景性信息垫底）。
4. **空态/未配置引导与 Hero 的叠加**：现行 `ui_overview` 在无节点时渲染引导卡、启动失败时渲染 Danger 横幅。方案新架构没有画这两个状态的合成方式（Hero 是否照常渲染？横幅插在哪一层？），需要补一个"异常态布局"说明。
5. **三数据卡的等宽网格**：方案图示三卡等宽。流量卡内容（今日上下行两个数）明显比"当前节点"卡信息密度高，等宽会浪费；建议 2:1:1 或让流量卡承载双列数值。次优先级。

---

## 三、图表规范与 egui_plot 能力核对

针对 D4 决策逐项核对（egui_plot 0.27 API）：

| 规范项 | egui_plot 0.27 支撑 | 结论 |
|---|---|---|
| 网格线 1px 横 4 条 | `show_grid(true)` + `custom_y_axes(vec![AxisHints::new_y()])` 可控网格与刻度；`GridInput/GridMark` 可自定义分度 | ✅ 可行 |
| Y 轴自动刻度标签 | `AxisHints` + formatter 支持；现行代码是 `show_axes(false)`，需要打开 | ✅ 可行 |
| **30% 透明渐变面积填充** | `Line::fill(Color32)` **只接受单一颜色，无渐变 API** | ⚠️ **无原生支持，待验证 workaround** |
| 图例带半透明底 | `Legend::position(Corner::LeftTop)` 可定位；但图例底色跟随 `Plot` 的 `legend` 样式/Visuals，**透明度是否可自定义待验证** | ⚠️ 部分可行 |
| 空态居中提示 | Plot 无空态概念；可行做法：数据为空时不创建 Plot，改用 `allocate_ui` 的 rect 上自绘 `empty_state` 组件（现行 components 已有） | ✅ 可行，建议明确此实现路径 |

渐变填充的替代方案（按推荐序）：
1. **纯 alpha 单色填充**（`Color32::from_rgba_unmultiplied(..., 76)` ≈30% 透明）：一行代码，视觉已达标 80%；建议 v4 修订直接降级为此方案；
2. **分层逼近渐变**：同一条 `Line` 的 fill 拆 4–6 条 y 压缩序列、alpha 递减叠加——每帧多份几何数据，120 点规模成本可忽略，但实现繁琐；
3. **`Plot::custom` 自绘**：拿 `plot.transform()` 把渐变 mesh 画在图层下——能力完全够，但要自己维护 mesh，复杂度最高。

另外两处规范问题：
- **chart_grid 与卡片底对比仅 1.1–1.2:1**，1px 网格线在实际屏幕上几乎不可见（Dark #232736 on #1A1D29）。建议网格亮度至少提到与 border 同级（Dark 上约 #2E3345 起）；
- 现行代码关闭了全部交互并置空坐标 formatter，方案的规范未说明是否恢复 hover 读数。仪表盘装饰定位下建议维持关闭，但应在文档里显式写明，避免实现时自行发挥。

---

## 四、可行性（Theme 全局 RwLock + palette:: 机械替换）

**总体可行，但方案低估了三件事：**

1. **每帧取色成本——被高估的风险**。`RwLock<Theme>::read()` 每帧数百次的开销在桌面端完全可忽略（无竞争的读锁≈原子操作）。真正要注意的不是性能而是**一致性**：一帧内若 `set_theme` 恰好发生，前后取到不同主题会造成单帧混色。修订建议：`theme()` 返回 `Arc<Theme>`（写时整体换 Arc），或每帧帧首 clone 一份 `Theme`（小结构体，代价极低）传栈使用。全局 RwLock 方案本身可接受；备选方案是把 `Theme` 作为 `HydraApp` 字段直接传引用，更符合现有代码无全局状态的风格，且省去持久化锁的注意事项。
2. **与 egui Visuals 的同步——被低估的风险（本方案最大坑）**。`palette::` 机械替换只覆盖**显式取色的自绘代码**；egui 原生控件（Button/Checkbox/Separator/ScrollArea/Selection/超链接/Plot 的图例与坐标轴文字）用的是 `ctx.style()` / `Visuals`。**只换 palette 不换 Visuals，切到 Light 后原生控件仍是 Dark 配色**。`set_theme` 必须同步完成两件事：① 换全局 Theme；② 构造整套 `Visuals`（widgets 各态 fg/bg/stroke、window_fill、extreme_bg_color、selection、shadow、`Plot` 的 legend/axis 样式）写入 `ctx.set_visuals`。建议在 Theme 结构体里直接附一个 `fn visuals(&self) -> egui::Visuals`，三主题各写一份完整映射，作为 T1 的验收标准（切主题后任何原生控件不得残留 Dark 色）。
3. **机械替换的召回风险**。~300 处替换之外，代码里还散落着**字面量 Color32**（如 `ui_overview.rs` 无，但其余 ui_* 文件待盘点）与 egui 默认色。T1 应加一条 lint 级检查：`grep -rn "Color32::from_rgb" hydra-client-gui/src --include="*.rs" | grep -v theme.rs` 必须为空，作为 T5 回归项。

字阶/间距常量替换无运行时风险（仍是 const）。

---

## 五、遗漏检查：深浅切换最容易翻车的细节

按翻车概率排序：

1. **Plot 图例与坐标轴文字色**：egui_plot 读取的是 ctx Visuals/palette，不走项目 palette——最容易漏；切 Light 后深底图例悬浮在浅色卡片上。
2. **分隔线/描边**：`ui.separator()` 与 Frame 描边若取 `Visuals.widgets.non_bg.stroke` 而该 stroke 未随主题重设，Light 下出现 Dark 灰线（或反过来）。
3. **阴影**：epaint shadow 是黑色系 alpha，Dark 合适、Light 下显脏；需要 `shadow` 令牌并按主题调淡。
4. **图片/图标资源**：`icon.rs` 与托盘图标若为固定色位图，Light 主题下可能不可见；SVG 单色图标需支持按主题重着色（**待验证**：需盘点现有图标是位图还是矢量单色）。
5. **横幅语义底色对**：现行四组 `*_BG` 是 Dark 专用深色底；Light 需要另配浅色横幅底 + 深色前景，不能共用同一组值——这正是方案色板表删掉这些令牌后必然翻车的地方。
6. **selection / 焦点环**：文本选区高亮、输入框焦点描边取自 Visuals，需在主题映射里显式给值。
7. **持久化时序**：config 里的主题字段与 `set_theme` 的调用时机——启动时应在首帧**之前**应用，否则冷启动闪一帧 Dark。
8. **Abyss 双 accent 的曲线分配**：图表上行 success / 下行 accent 的规范在 Abyss 下（accent=青、accent2=紫）需要明确下行用哪个，避免实现时引入第三个颜色。

---

## 六、结论与逐条修订建议

**结论：需修订后可实施**（架构选型正确，色板与图表规范需先修）。修订建议：

- **R1（P0）** `text_faint` 三主题全部重新定色（建议 Dark/Abyss 提亮至对 bg_card ≥3.0:1，Light 加深至 ≥3.0:1，可接受 4.5:1 更佳）；`bg_card_hover` 派生对一并复检。
- **R2（P0）** Light `warning #D97706` 加深（建议 #B45309 一档，on bg_app ≥3:1）；Light `success` 如需作正文色同步加深。
- **R3（P0）** 色板表补回现行 palette.rs 已有的令牌：`TEXT_ON_ACCENT`、`INFO`/`INFO_BG` 与四组横幅 `*_BG`、`BG_SIDEBAR`、`BG_EXTREME`、`BG_FAINT`、`BORDER_STRONG`，并新增 `text_disabled`、`splitter`、`shadow`、`accent_hover/pressed`、`chart_up/chart_down`——机械替换以"补全后的完整表"为唯一依据，禁止边替换边找色。
- **R4（P0）** Abyss 主按钮/accent 上的文字必须用深色（accent × 白仅 1.86:1）；在 Theme 中按主题显式给 `text_on_accent`。
- **R5（P0）** `set_theme` 同步重设完整 `egui::Visuals`（widgets 三态、selection、separator stroke、shadow、popup/window fill、Plot 图例/轴样式），建议 Theme 附 `visuals()` 构造函数并作为 T1 验收项；T5 回归加"src 中不得残留字面量 Color32"检查。
- **R6（P1）** 图表渐变填充降级为**单色 30% alpha 填充**（`Line::fill`，egui_plot 0.27 无原生渐变；如坚持渐变，用 `Plot::custom` 自绘 mesh，成本高不建议本轮做）。网格线亮度上调（与 bg_card ≥1.15 相对差、视觉可辨），并显式写明图表保持禁用交互。
- **R7（P1）** 补 Hero 条三态规范表（运行/启动中/停止 × 描边色、圆点色、按钮态），并补"未配置节点引导卡""启动失败横幅"在新布局中的位置。
- **R8（P1）** "当前节点"数据卡整卡可点跳转节点页（hover 描边反馈），保留调度参考语义。
- **R9（P1）** 快捷操作改单行操作条置于三卡与图表之间（图表沉底），或至少给出首屏纵向预算的取舍说明。
- **R10（P1）** 字阶维持现行的五级下限（辅助 ≥12px、徽标 ≥11px），22px 大数档作为新增第 6 档并入文档，明确与 18px HEADING 的分工（22=数据值，18=页面标题）。
- **R11（P2）** `theme()` 改返回 `Arc<Theme>` 或帧首 clone，规避单帧混色；评估把 Theme 放入 `HydraApp` 字段传引用的备选（无全局态、无锁）。
- **R12（P2）** 主题应用时机：启动首帧前从 config 恢复；切换入口的侧栏图标与设置页双入口需共享同一持久化路径。图标资源按主题重着色方案需在 T4 前盘点（位图/矢量待验证）。

---

### 附：对比度核算明细补充

- bg_card_hover（Dark #202436 / Light #F0F2F8 / Abyss #16233C）× text：12.79 / 15.5* / 13.4* 均达标；× text_faint：2.57 / 2.27 / 2.42 均不达标（同 R1）。*Light/Abyss hover×text 数值由同一公式计算，量级一致。
- Abyss accent2 #8B5CF6 × bg_card = 4.07：可作大字/图形，不作正文。
- Dark accent × 白 = 3.20：仅满足大字（≥18.66px bold）与 UI 图形 3:1，正文按钮文字需 R4 令牌。
