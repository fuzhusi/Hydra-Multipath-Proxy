# eframe/egui 升级方案（0.27 → 0.33+）

> 状态：**方案已评审待执行**——执行需专门会话（21 文件迁移 + 逐页目检）。
> 动机：根治 RUSTSEC-2026-0257（webbrowser < 1.2.2 Unix BROWSER 参数注入，
> 经 egui-winit 0.27 传递依赖引入，当前已在 deny.toml/audit.toml 带理由豁免）
> + 清除 unmaintained 传递依赖群（instant/derivative/paste/proc-macro-error/
> rustls-pemfile 中的前四者随生态升级消除）。

## 1. 升级范围与目标版本

| crate | 现版本 | 目标 |
|---|---|---|
| eframe | 0.27.2 | 0.33.x（最新稳定线） |
| egui / egui-winit | 0.27.2 | 0.33.x（随 eframe） |
| egui_plot | 0.27 | 0.3x（速率曲线页；API 有变化，见 §3） |
| rfd | 0.15 | 0.17（文件对话框；Dependabot 已有 PR 可参考） |
| webbrowser（传递） | 0.8.15 | ≥1.2.2（随 egui-winit 新版）——升级后移除 deny.toml/audit.toml 豁免 |

原则：一次只升 eframe 生态一条线（eframe+egui+egui_plot 同步），不与其他
重构混批。升级完成后 `cargo update -p webbrowser` 应能到 1.2.2+（验证点）。

## 2. 破坏面清单（0.27 → 0.33 已知主要变化）

1. **`eframe::run_native`**：NativeOptions 字段调整（viewport/渲染器选项重组；
   `RunMode`、wgpu 选项迁移）——入口 main.rs 一处。
2. **`Context::input` / 事件 API**：`input(|i| ...)` 闭包签名与 RawInput 字段
   变化——影响键盘/指针读取处（UI 代码 grep `input(` 定位）。
3. **布局/样式 API 漂移**：`Margin`/`Vec2` 常量构造改为 `margin()` 函数式、
   部分字段改名——palette.rs（视觉规范单源）集中改，各页面受益于单源设计。
4. **`Ui::available_*` / ScrollArea 行为微调**：逐页目检项。
5. **egui_plot 0.27 → 0.3x**：`Plot` 构建器与 `Line` 结构变化（连接页速率
   曲线，ui_connections.rs 单点）。
6. **tray-icon 不受影响**（独立 crate，与 egui 仅经事件桥耦合——升级零接触；
   已核实：tray.rs 对 egui 的全部接触面是 request_repaint，跨版本稳定）。
7. **持久化**：eframe 自带存储格式变化——项目用自管 config.json（config.rs），
   eframe storage 未使用（已 grep 核实：无 cc.storage/set_value/get_value；
   NativeOptions 仅 viewport 字段）——无迁移负担。
8. **主题机制（0.29+，最重要遗漏项）**：egui 0.29 起内置 light/dark 跟随系统
   主题，eframe 默认 `ThemePreference::System`——而本项目 theme.rs 以
   `ctx.set_style(Visuals::dark())` 硬钉深色。升级后浅色系统用户会出现
   白闪/主题覆盖。必须显式 `ctx.set_theme(egui::ThemePreference::Dark)`
   并迁移 style API（`all_styles_mut`/`set_style_of` 按主题分别设置）。
9. **类型/构造改名（编译器引导的机械修改，约 15 处）**：`Rounding` →
   `CornerRadius`（theme.rs/ui_nodes.rs 共 7 处）、`Frame::none()` →
   `Frame::new()`、`Margin` 改 i8 构造（2 文件）——card_frame 等三处集中。
10. **FontDefinitions 结构变化（0.31）**：`font_data` 变
    `BTreeMap<String, Arc<FontData>>`——theme.rs 的 CJK 字体装载
    （NotoSansCJK ttc）单点适配。
11. **egui_plot builder 改名**：`allow_*` → `*_enabled` 风格 + `Line::new`
    签名变化——ui_overview.rs 速率曲线单点。
12. **MSRV**：egui 0.33 要求 1.88+，CI（dtolnay/stable）无风险。

## 3. 执行清单（专门会话）

1. `cargo upgrade` 式一次性改 Cargo.toml（eframe/egui/egui_plot/rfd）→
   `cargo check -p hydra-client-gui` 收敛编译错误（预计集中在 main.rs 入口、
   palette.rs、ui_shell.rs）；
2. 21 文件逐个过编译 → `cargo clippy -p hydra-client-gui --all-targets -D warnings`；
3. **逐页目检清单**（egui 布局微调必须人眼确认）：
   - 状态总览页（卡片仪表盘 + egui_plot 速率曲线：坐标轴/图例/缩放）
   - 节点页（组视图/卡片/编辑对话框）
   - 订阅页（聚合入口/列表）
   - 连接页（实时表格 + 速率曲线）
   - 日志页 / 设置页（七分区折叠）
   - 托盘（菜单禁用态回归——与 egui 无关但同批验证）
   - Windows 系统代理开关回归
4. `cargo update -p webbrowser` → `cargo deny check advisories` 通过 →
   **移除 deny.toml / .cargo/audit.toml 中 RUSTSEC-2026-0257 豁免** + 删除
   CHANGELOG 待开发计划对应行；
5. unmaintained 告警群复核（instant/derivative 应消失；仍在者更新豁免理由）；
6. 全 workspace `cargo check/test/clippy` 兜底（GUI 依赖 hydra-client tun
   feature，跨 crate 面预期为零但验证便宜）；
7. Cargo.toml 内"与 0.27 版本锁齐"注释随升级更新（文件数口径：拆分产物
   21 文件，现 src 共 26 个 .rs）；
8. 回滚策略：单 commit 交付，出问题 `git revert` 一次回退（豁免条目仍在
   上一 commit 内，回滚即恢复）。

## 4. 风险与边界

- 适配工作量集中在**视觉回归**而非功能逻辑（业务逻辑在 hydra-core，GUI 是
  纯展示层）——数据面零风险；
- egui 0.33 对 Linux GTK 后端的系统依赖版本要求不变（CI apt 列表已含）；
- 预估：编译收敛 0.5 会话 + 逐页目检 0.5 会话。
