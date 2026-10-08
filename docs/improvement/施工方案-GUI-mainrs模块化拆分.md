# 施工方案：GUI main.rs 模块化拆分

> 状态：**待评审**
> 对象：`hydra-client-gui/src/main.rs`（当前 6331 行）
> 原则：**纯搬移重构**——不改任何运行时逻辑、不改公开行为、不引入新依赖；
> 只做「代码块搬家 + 可见性标注 + use/mod 声明」。
> 行号基准：2026-10-08 工作树（commit `efcb0a0` 后，未提交文件不影响本文件）。

---

## 1. 背景与目标

`main.rs` 单文件 6331 行，同时承载：色板规范、纯逻辑函数（组过滤/导入建组/测速目标）、
`HydraApp` 结构体与 ~90 个方法（代理生命周期、分享导入、订阅管理、节点测速）、
六页 UI 渲染、托盘接线、Windows 系统代理注册表操作、33 个单元测试。

**目标**

1. 按职责拆为 ~20 个模块文件，除个别测试密集文件外单文件 ≤ ~800 行；
2. 行为零变化：`cargo test` 用例数不变（crate 共 64，其中 main.rs 的 33 个全部保留）、
   clippy `-D warnings` 保持全绿；
3. `main.rs` 缩减为 crate 根（mod 树 + `struct HydraApp` + `fn main`，约 250 行）。

**非目标**

- 不重构任何方法体内部逻辑（含 `update()` 内联的分享对话框渲染——本次整块随迁，后续可单独立项）；
- 不重命名类型/方法/字段，不改配置文件格式与托盘/日志行为；
- 不引入子目录层级（与既有 `config.rs`/`tray.rs`/`qr.rs`/`icon.rs`/`subscription.rs` 保持同级的扁平风格）。

---

## 2. 关键设计决策

### D1：`struct HydraApp` 留在 main.rs（crate root），不移入 app.rs

Rust 隐私模型：crate root 中定义的类型，其**私有字段对全 crate 所有子模块可见**
（root 的一切私有项对其后代可见）。因此：

- 全部 ~90 个方法的 impl 块可合法分布到任意子模块（同 crate 多 inherent impl 合法）；
- ~70 个字段**无需加 `pub(crate)`**，字段声明区零 diff。

若把结构体移入 `app.rs`，所有字段必须改 `pub(crate)`，噪音大且与「纯搬移」冲突。
**代价**：main.rs 保留 ~155 行结构体定义——可接受，它是全 crate 的「状态中心」声明。

### D2：内联 `mod palette` / `#[cfg(windows)] mod windows_proxy` 平移为同名文件

内联模块 → 文件模块后**模块路径完全不变**（`palette::ACCENT`、`windows_proxy::enable`），
全部调用点零改动。这是零风险搬运。

### D3：纯函数按领域归入模块，统一 `pub(crate)`

现散落在 crate root 的自由函数（组过滤、导入建组、测速目标等）是「UI 与单测共用」的
纯逻辑（文件内注释已明确此定位）。归入领域模块并标 `pub(crate)`，消费方模块显式 `use`。

### D4：`impl HydraApp` 按职责拆三个层次

- **动作层**（不可渲染、可被托盘/快捷路径调用）：代理生命周期、测速、分享导入、订阅管理；
- **UI 层**：`impl eframe::App`（update 主循环 + 页面分发）+ 每页一个文件；
- `update()` 主循环**整块搬移**到 `ui_shell.rs`，内部不抽取。

### D5：测试随被测物归位

现有单一 `mod tests`（5558–6331，33 个用例）按「测试谁、住在谁家」拆到各模块的
`#[cfg(test)] mod tests`（`use super::*;` 语义不变）。用例数拆分前后必须一致（见 §7）。

### D6：执行方式 = 脚本物理切割 + 编译器驱动修 use

6300 行手工剪切必然手滑。用一次性 Python 脚本按**行号区间**切割生成新文件并缩减
main.rs（区间先经批 0 校验），`use`/`pub(crate)`/mod 声明手工补齐，`cargo check` 迭代清零。
脚本为一次性工具不入库；本方案 §5/§6 的行号区间表是切割的**唯一事实来源**。

---

## 3. 模块依赖方向（预期）

```
main.rs (root: mod 树 + struct HydraApp + fn main)
   │
   ├─ 纯逻辑层:  palette / speed_history / nodes / groups / probe / theme / windows_proxy
   │                （不依赖 HydraApp；nodes/groups 依赖 config::GuiConfig）
   ├─ 动作层:   app / node_test / proxy_control / share_io / subscription_actions
   │                （impl HydraApp 方法；依赖纯逻辑层）
   └─ UI 层:     ui_shell / ui_overview / ui_nodes / ui_subscriptions / ui_node_edit /
                  ui_settings / ui_logs / ui_connections
                     （impl HydraApp / impl eframe::App；依赖动作层引用的方法 + 纯逻辑层）
```

Rust 模块无循环限制，同 crate 内互相引用编译期即可解耦；此图是**阅读导览**而非编译约束。

---

## 4. 目标文件结构总表

| # | 新文件 | 内容（概要） | 来源行号（main.rs） | 预计行数 |
|---|--------|--------------|--------------------:|---------:|
| 0 | `main.rs`（保留） | crate 属性、mod 树、struct HydraApp、`fn main` | 1–21 + 646–798 + 5505–5554 | ~250 |
| 1 | `palette.rs` | 内联色板模块整体平移 | 20–105 | ~90 |
| 2 | `speed_history.rs` | `SpeedHistory` + impl | 110–203 | ~95 |
| 3 | `nodes.rs` | `Tab`、`NodeStatusInfo`、`GROUP_MANUAL`、`node_group_of`、`filter_nodes_by_group`、`group_summary`、`median_online_latency`、`best_online_node` | 237–336、205–232 | ~135 |
| 4 | `groups.rs` | 分享导入/手动建组/订阅合并纯逻辑：`LOCAL_TEXT_SOURCE_PREFIX`、`next_import_group_name`、`next_manual_group_name`、`apply_subscription_node_update`、`GroupImportResult`、`import_share_links_as_group`、`build_form_share_url`、`subscription_source_label` | 338–644 | ~310 |
| 5 | `app.rs` | `impl Default`、`impl Drop`、`new`、`wizard_lines`、`maybe_save_config`、`add_log`、`start_button_state` | 800–886、1018–1228、1514–1525、963–979 | ~330 |
| 6 | `probe.rs` | `probe_runtime`、`PROBE_TARGET_*`、`probe_target_from`、`probe_target` | 888–899、992–1015 | ~70 |
| 7 | `node_test.rs` | `test_node_connection`、`start_node_test`、`poll_sys_proxy_check`、`poll_node_test_results`、`test_all_nodes`、`start_group_test`、`poll_health_check_results` | 1230–1513 | ~285 |
| 8 | `proxy_control.rs` | `run_proxy_until_stopped`（自由函数）+ `start_proxy`、`poll_start_receiver`、`set_system_proxy`、`remove_system_proxy_static`、`remove_system_proxy`、`stop_proxy`、`shutdown_and_wait_for_exit` | 901–961、1526–2198 | ~780 |
| 9 | `share_io.rs` | 分享/导入/二维码/手动添加动作：`export_share_links`、`import_share_links`、`build_share_link`、`open_share_dialog`、`apply_imported_link`、`set_import_status`、`import_paste_submit`、`import_paste_load_file`、`manual_add_submit`、`set_manual_status`、`import_from_qr_image`、`poll_qr_import_result` | 2199–2601 | ~405 |
| 10 | `subscription_actions.rs` | 订阅管理动作：`add_subscription`、`delete_subscription`、`queue_subscription_update`、`update_all_subscriptions`、`start_next_subscription_update`、`poll_subscription_updates`、`apply_subscription_update` | 2602–2792 | ~195 |
| 11 | `ui_shell.rs` | `impl eframe::App for HydraApp`（`on_exit` + `update` 主循环，整块含内联对话框）+ 托盘接线：`poll_tray_commands`、`handle_close_request`、`sync_tray_tooltip` | 2793–3118、3491–3559 | ~400 |
| 12 | `ui_connections.rs` | `refresh_connections`、`sorted_connections`、`ui_connections` | 3119–3331 | ~215 |
| 13 | `theme.rs` | `setup_custom_fonts`、`apply_dark_theme`、`card_frame` | 3332–3365、5468–5503、981–990 | ~115 |
| 14 | `windows_proxy.rs` | `#[cfg(windows)]` 系统代理注册表操作整体平移 | 3366–3488 | ~125 |
| 15 | `ui_overview.rs` | `ui_overview`、`system_proxy_on_cached` | 3560–3904 | ~350 |
| 16 | `ui_nodes.rs` | `ui_nodes`、`ui_nodes_dialogs` | 3905–4462 | ~560 |
| 17 | `ui_subscriptions.rs` | `ui_subscriptions`、`ui_sub_add_dialog` | 4463–4786 | ~325 |
| 18 | `ui_node_edit.rs` | `open_node_edit`、`cert_status_text`、`save_node_edit`、`ui_node_edit_dialog` | 4787–5025 | ~240 |
| 19 | `ui_settings.rs` | `ui_settings` | 5026–5415 | ~390 |
| 20 | `ui_logs.rs` | `ui_logs` | 5416–5466 | ~55 |

合计约 6330 行（±use 头增量），与原文件守恒；最大文件 `proxy_control.rs` ~780 行。

**边界微调记录**（切割时以函数边界为准，区间表只精确到方法起点；相邻方法归属以 §5 为准）：

- `test_node_connection`（1230，缩进 `async fn`）归 `node_test.rs`——它是 `start_node_test` 的关联辅助；
- `add_log`（1514）夹在测速与代理方法之间，归 `app.rs`（全 crate 使用的日志入口，属应用骨架）；
- `card_frame`（981–990）虽被多页使用，归 `theme.rs`（视觉规范职责）而非任一页面。

---

## 5. 函数级映射表（移动单元 = 顶层项）

| 项（当前行号） | 去处 | 可见性变化 |
|----------------|------|-----------|
| `mod palette {…}`（20–105） | palette.rs | 不变（模块内已 pub） |
| `struct SpeedHistory` + impl（110–203） | speed_history.rs | struct/方法 → `pub(crate)`（方法供 proxy_control 采样线程与 ui_overview 读） |
| `median_online_latency`（205）、`best_online_node`（221） | nodes.rs | → `pub(crate)` |
| `enum Tab` + impl（241–271） | nodes.rs | enum/`ALL`/`label` → `pub(crate)` |
| `struct NodeStatusInfo`（273–278） | nodes.rs | struct + 字段 → `pub(crate)`（字段被 app/node_test/ui 多处读写） |
| `GROUP_MANUAL`（282）、`node_group_of`（286）、`filter_nodes_by_group`（296）、`group_summary`（317） | nodes.rs | → `pub(crate)` |
| `LOCAL_TEXT_SOURCE_PREFIX`（344）、`next_import_group_name`（347）、`next_manual_group_name`（359）、`apply_subscription_node_update`（377）、`GroupImportResult`（455）、`import_share_links_as_group`（472）、`build_form_share_url`（539）、`subscription_source_label`（620） | groups.rs | → `pub(crate)` |
| `impl Default for HydraApp`（800）、`impl Drop`（879） | app.rs | 不变 |
| `probe_runtime`（891） | probe.rs | → `pub(crate)` |
| `run_proxy_until_stopped`（912） | proxy_control.rs | → `pub(crate)`（测试用） |
| `start_button_state`（971） | app.rs | → `pub(crate)` |
| `card_frame`（983） | theme.rs | → `pub(crate)` |
| `PROBE_TARGET_DEFAULT/ENV`（999/1002）、`probe_target_from`（1005）、`probe_target`（1013） | probe.rs | → `pub(crate)` |
| `setup_custom_fonts`（3332）、`apply_dark_theme`（5468） | theme.rs | → `pub(crate)` |
| `#[cfg(windows)] mod windows_proxy {…}`（3366–3488） | windows_proxy.rs | 模块内不变 |
| `impl HydraApp` 方法（1018–2792、3119–3331、3491–5467） | §4 #5–#12、#15–#20 | 方法 → `pub(crate)`（跨模块调用必需；同文件互调的也统一加，避免逐个判断） |
| `impl eframe::App for HydraApp`（2793–3118） | ui_shell.rs | trait 方法不改 |
| `async fn main`（5505–5554） | main.rs | 不变 |
| `mod tests`（5556–6331） | 按 §7 拆分 | `#[cfg(test)]` |

> `pub(crate)` 收敛策略：**宁多勿漏**——所有被移动的自由函数与 impl 方法统一 `pub(crate)`，
> 由 clippy（`unused` 系 lint 在 `-D warnings` 下）反向揪出过度暴露再收紧。
> impl 方法加 `pub(crate)` 不属于 API 暴露面扩大（crate 本身是 bin，crate 外不可见）。

---

## 6. 测试归位表（33 个用例，拆分前后总数必须一致）

| 目标模块 | 用例（含测试夹具） | 数 |
|----------|--------------------|---:|
| palette.rs | `latency_color_thresholds`、`node_status_color_states` | 2 |
| app.rs | `start_button_state_transitions` | 1 |
| probe.rs | `probe_target_defaults_to_cloudflare_443`、`probe_target_env_override` | 2 |
| proxy_control.rs | `proxy_binds_within_3s`、`start_stop_restart_binds_within_3s_each_round`、`concurrent_load_does_not_delay_bind`（夹具 `test_proxy`、`free_port`） | 3 |
| nodes.rs | `node_group_of_claims_follow_subscription_nodes`、`filter_nodes_by_group_none_all_manual_and_sub`、`filter_nodes_by_group_empty_config_and_no_subs`、`group_summary_counts_online_offline_only_when_checked`、`median_online_latency_ignores_offline_and_unchecked`、`best_online_node_picks_lowest_latency`（夹具 `group_fixture`） | 6 |
| groups.rs | `next_import_group_name_skips_existing_subscription_names`、`import_as_group_creates_named_group_and_filters`、`import_as_group_rejects_duplicate_and_invalid`、`import_as_group_rolls_back_when_no_node_claimed`、`local_text_source_reparse_produces_same_links`、`form_share_url_builds_parseable_link_from_addr_and_port`、`form_share_url_accepts_domain_address`、`form_share_url_rejects_invalid_port_and_empty_address`、`form_share_url_embeds_auth_key_when_given`、`form_share_url_requires_readable_cert_file`、`form_share_url_feeds_group_import_end_to_end`、`next_manual_group_name_skips_existing_subscription_names`、`manual_form_creates_named_group_and_filters`、`manual_form_rejects_bad_input_and_duplicate_name`、`subscription_source_label_classifies_sources`（夹具 `share_link_line`） | 15 |
| speed_history.rs | `speed_history_caps_at_120_and_keeps_latest`、`speed_history_daily_accumulates_deltas`、`speed_history_monitor_restart_does_not_go_negative`、`speed_history_reset_samples_keeps_daily_totals`（夹具 `sample_stats`） | 4 |

全部 33 个用例均为纯函数/无状态测试（不实例化 `HydraApp`），可安全随模块迁移。

---

## 7. 执行步骤

**批 0：基线与区间校验**（已完成）

- [x] 基线：`cargo clippy -p hydra-client-gui --all-targets -- -D warnings` 零告警；
      `cargo test -p hydra-client-gui` 64 通过 / 0 失败
      （其中 main.rs `mod tests` 贡献 33 = 30 `#[test]` + 3 `#[tokio::test]`，
      其余 31 个位于 config.rs(23)/qr.rs(4)/subscription.rs(4)，不受本次拆分影响）；
- [ ] 逐区间校验 §4 表首行内容与行号一致（防止行号漂移）；
- [ ] `git status` 确认 `hydra-client-gui/` 无未提交改动（拆分在干净基线上做）。

**批 1：零引用面模块（纯移动）**——palette.rs、windows_proxy.rs、theme.rs

- palette/windows_proxy 为内联模块平移，调用点零改动；
- theme.rs 三个自由函数迁出后，在消费模块（app.rs 尚未拆出，先在 main.rs root 加临时
  `use theme::{…}`，批 3 时随 new() 一起迁移）补 use；
- `cargo check -p hydra-client-gui` 通过。

**批 2：纯逻辑模块 + 测试归位**——speed_history.rs、nodes.rs、groups.rs、probe.rs

- 各自由函数加 `pub(crate)`，测试按 §7 迁入各文件；
- main.rs root 与残留调用点补 `use crate::…`；
- `cargo check` + `cargo test -p hydra-client-gui`（此时应已有 ~19 个用例在各模块跑通）。

**批 3：HydraApp 动作层**——app.rs、node_test.rs、proxy_control.rs、share_io.rs、subscription_actions.rs

- 按方法逐块迁出（impl 块整体剪切 → 新文件 `use crate::HydraApp;` + 领域 use）；
- 方法统一加 `pub(crate)`；
- `cargo check` 迭代至零错误，`cargo test` 全量 33 用例。

**批 4：UI 层**——ui_shell.rs、ui_connections.rs、ui_overview.rs、ui_nodes.rs、
ui_subscriptions.rs、ui_node_edit.rs、ui_settings.rs、ui_logs.rs

- `impl eframe::App` 整块 → ui_shell.rs；托盘接线三方法随迁；
- 各页方法迁入对应文件；`update()` 内部一字不改；
- main.rs 收敛为 §4 #0 形态（mod 树 + struct + main，清理不再使用的 root use）。

**批 5：终检与收尾**

- [ ] `cargo clippy -p hydra-client-gui --all-targets -- -D warnings` 零输出；
- [ ] `cargo test -p hydra-client-gui` 用例数 = 基线（64，其中本文件拆出的 33 个按 §7 归位）；
- [ ] `cargo check --workspace`（确认未波及 workspace 其他 crate）；
- [ ] `cargo test --workspace`（兜底）；
- [ ] 抽查 `git diff`：移动块与源逐字一致（除缩进不变、仅新增 `pub(crate)`/`//!` 头/use 行）；
- [ ] `wc -l` 报告各文件行数，对照 §4 预计值；
- [ ] 单 commit 提交（`refactor(gui): main.rs 模块化拆分——6331 行拆为 21 文件，行为零变化`），
      可整体 revert。

> CI 的 Linux 矩阵本机无法验证；因所有 `#[cfg(windows)]` 块整体搬移、属性随块走，
> 非 Windows 侧风险极低，由 push 后 CI 兜底（方案在提交说明中注明）。

---

## 8. 风险与对策

| # | 风险 | 对策 |
|---|------|------|
| R1 | 行号漂移导致切错块 | 批 0 逐区间校验首行；切割脚本对每个区间断言首行内容 |
| R2 | `#[cfg(windows)]` 项漏移/属性丢失 | windows_proxy 整体平移；字段/方法级 cfg 属性随块剪切；本机 Windows 覆盖 cfg(windows) 编译路径 |
| R3 | unused import / 未用 `pub(crate)` | clippy `-D warnings` 是 CI 硬门槛，终检同命令清零 |
| R4 | 测试拆分后丢失或重复 | §7 表驱动迁移；批 2/3/5 各跑一次 `cargo test` 比对用例数 |
| R5 | 大 diff 掩盖逻辑改动 | 移动块逐字一致（脚本切割）；review 阶段用「旧文件按区间重组 = 新文件集合」的机械核对 + 抽查 |
| R6 | 私有字段跨模块访问编译错 | D1 保证结构体留 root，天然合法；若出现，说明有字段被误判——修可见性而非改逻辑 |
| R7 | 回滚困难 | 全部改动单 commit；批间 `cargo check` 保证每批可编译 |

---

## 9. 验收标准

1. `main.rs` ≤ 300 行（目标 ~250）：仅 mod 树、struct HydraApp、`fn main`；
2. 单文件最大 ≤ 800 行（`proxy_control.rs`）；
3. `cargo clippy --all-targets -- -D warnings` 与 `cargo test` 全绿，用例数 = 64（基线）；
4. 33 个用例分布与 §7 一致；
5. `git diff` 中无任何方法体内部改动（新增行仅限：`//!` 模块头、`use`、`pub(crate)`、mod 声明、测试 `mod tests` 包裹行）；
6. 提交说明注明「Linux 侧由 CI 矩阵兜底」。

---

## 10. 评审记录

（待评审后回填：评审人、结论、修订项）
