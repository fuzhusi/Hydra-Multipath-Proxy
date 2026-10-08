# 施工方案：GUI main.rs 模块化拆分

> 状态：**已执行完成（见 §11 执行记录）**
> 对象：`hydra-client-gui/src/main.rs`（当前 6331 行）
> 原则：**纯搬移重构**——不改任何运行时逻辑、不改公开行为、不引入新依赖；
> 只做「代码块搬家 + 可见性标注 + use/mod 声明」。
> 行号基准：2026-10-08 工作树（commit `efcb0a0` 后，未提交文件不影响本文件）。
>
> **v2 修订说明**：按评审意见修正了 12 处区间尾部边界（文档注释归属下一项）、
> 补齐 2 处字段级 `pub(crate)`、明确 windows_proxy 的 cfg 声明位置与 Linux use 门控、
> 定义跨模块测试夹具共享方式、批 0 增加「首行+尾行」双断言。详见 §10 评审记录。

---

## 1. 背景与目标

`main.rs` 单文件 6331 行，同时承载：色板规范、纯逻辑函数（组过滤/导入建组/测速目标）、
`HydraApp` 结构体与 ~59 个方法 + ~17 个自由函数（代理生命周期、分享导入、订阅管理、节点测速）、
六页 UI 渲染、托盘接线、Windows 系统代理注册表操作、33 个单元测试。

**目标**

1. 按职责拆为 ~21 个文件，除个别测试密集文件外单文件 ≤ ~800 行；
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

- 全部方法的 impl 块可合法分布到任意子模块（同 crate 多 inherent impl 合法，方法名不重复即可）；
- ~70 个字段**无需加 `pub(crate)`**，字段声明区零 diff。

若把结构体移入 `app.rs`，所有字段必须改 `pub(crate)`，噪音大且与「纯搬移」冲突。
**代价**：main.rs 保留 ~155 行结构体定义——可接受，它是全 crate 的「状态中心」声明。
**注意**：D1 只豁免**字段**；impl 内的**方法**默认私有，跨模块调用必须 `pub(crate)`（§5 统一处理）。

### D2：内联 `mod palette` / `#[cfg(windows)] mod windows_proxy` 平移为同名文件

- 模块路径完全不变（`palette::ACCENT`、`windows_proxy::enable`）。
- **「调用点零改动」仅指批 1 时点**（调用方还在 root）。批 3/4 方法迁入子模块后，
  `palette::X` 不再自动解析，迁出文件需补 `use crate::palette;`（全文 ~199 处引用分布在
  各页面方法里，随方法搬进哪个文件、该文件的 use 头就要有 `use crate::palette;`）。
- **cfg 属性位置**：`#[cfg(windows)]` 是 mod 声明的属性，不能搬进文件内部。
  main.rs 保留 `#[cfg(windows)] mod windows_proxy;`（root mod 树中），文件只收模内内容。
- palette.rs / windows_proxy.rs 的**内容取内联块剥去包裹行后的区间并整体去一级缩进**
  （原内容在 `mod X { }` 内缩进 4 格；去缩进是纯空白变更，语义零变化，保持文件风格正常）。

### D3：纯函数按领域归入模块，统一 `pub(crate)`

现散落在 crate root 的自由函数（组过滤、导入建组、测速目标等）是「UI 与单测共用」的
纯逻辑（文件内注释已明确此定位）。归入领域模块并标 `pub(crate)`，消费方模块显式 `use`。

### D4：`impl HydraApp` 按职责拆三个层次

- **动作层**（不可渲染、可被托盘/快捷路径调用）：代理生命周期、测速、分享导入、订阅管理；
- **UI 层**：`impl eframe::App`（update 主循环 + 页面分发）+ 每页一个文件；
- `update()` 主循环**整块搬移**到 `ui_shell.rs`，内部不抽取。

### D5：测试随被测物归位

现有单一 `mod tests`（5557–6331，33 个用例 = 30 `#[test]` + 3 `#[tokio::test]`）按
「测试谁、住在谁家」拆到各模块的 `#[cfg(test)] mod tests`。两点约束：

1. `use super::*;` 的继承面变小（原从 root 继承 HashMap/GuiConfig/Arc/SocketAddr 等），
   各 tests 模块需补自己的 use，以编译错误为准逐个补齐；
2. **跨模块测试依赖**：groups.rs 的测试复用 nodes.rs 的夹具 `group_fixture`
   （`import_as_group_rolls_back_when_no_node_claimed`:5964）并调用
   `filter_nodes_by_group`/`GROUP_MANUAL`。处置：nodes.rs 中
   `#[cfg(test)] pub(crate) mod tests` + `pub(crate) fn group_fixture()`，
   groups.rs 测试侧 `use crate::nodes::{GROUP_MANUAL, filter_nodes_by_group};`
   `use crate::nodes::tests::group_fixture;`（测试代码间共享，不进生产路径）。

### D6：执行方式 = 脚本物理切割 + 编译器驱动修 use

6300 行手工剪切必然手滑。用一次性 Python 脚本按**行号区间**切割生成新文件并缩减
main.rs（**切割单位 = 完整项（含其 doc 注释与所属章节横幅）；脚本对每个区间同时断言
首行与尾行内容**，见批 0），`use`/`pub(crate)`/mod 声明手工补齐，`cargo check` 迭代清零。
脚本为一次性工具不入库；本方案 §4/§5 的行号区间表是切割的**唯一事实来源**。

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

## 4. 目标文件结构总表（v2：边界已按「项 = doc + 签名到收尾 `}`」修正）

> **边界规则**：每个区间从项的 doc 注释首行（或章节横幅）起，到该项收尾 `}` 止；
> 区间之后紧跟的必须是下一项的 `///` doc、`#[…]` 属性或章节横幅。
> 批 0 对每个区间**同时断言首行与尾行**（尾行必须是 `}` 或区间内注释）。
> 「impl 收尾 `}`」属于 impl 块本身，不随最后一个方法迁走——新文件的
> `impl HydraApp { … }` 包裹行是新增行（§9 白名单已含）。

| # | 新文件 | 内容（概要） | 来源行号（main.rs） | 预计行数 |
|---|--------|--------------|--------------------:|---------:|
| 0 | `main.rs`（保留） | crate 属性(1–16)、mod 树、`mod palette;` 文档(20–21)、struct HydraApp(646–798)、`fn main`(5505–5554) | 1–21 + 646–798 + 5505–5554 | ~250 |
| 1 | `palette.rs` | 内联色板模内内容(23–104，去一级缩进)；`mod palette;` 声明留 root | 23–104 | ~85 |
| 2 | `speed_history.rs` | `SpeedHistory` + impl（**struct + 字段 + 方法均 pub(crate)**） | 110–201 | ~95 |
| 3 | `nodes.rs` | `median_online_latency`(doc 203–204, fn 205–219)、`best_online_node`(221–232)、`Tab`(237–271)、`NodeStatusInfo`(273–278)、`GROUP_MANUAL`(280–282)、`node_group_of`(284–291)、`filter_nodes_by_group`(293–314)、`group_summary`(316–336) | 203–232 + 237–336 | ~135 |
| 4 | `groups.rs` | 分享导入/手动建组/订阅合并纯逻辑：章节横幅(337)、`LOCAL_TEXT_SOURCE_PREFIX`(340–344)、`next_import_group_name`(346–356)、`next_manual_group_name`(358–368)、`apply_subscription_node_update`(370–453)、`GroupImportResult`(455–471)、`import_share_links_as_group`(472–537)、`build_form_share_url`(539–618)、`subscription_source_label`(620–644) | 337–644 | ~310 |
| 5 | `app.rs` | `impl Default`(800–877)、`impl Drop`(879–886)、`new`(1018)、`wizard_lines`(1173)、`maybe_save_config`(1194–1216)、`add_log`(1513–1525)、`start_button_state`(963–979) | 800–886 + 963–979 + 1018–1216 + 1513–1525 | ~330 |
| 6 | `probe.rs` | `probe_runtime`(888–899)、`PROBE_TARGET_*`(992–1002)、`probe_target_from`(1004–1010)、`probe_target`(1012–1015) | 888–899 + 992–1015 | ~70 |
| 7 | `node_test.rs` | `test_node_connection`(doc 1218–1229, fn 1230–1271)、`start_node_test`(1273–1308)、`poll_sys_proxy_check`(1310–1326)、`poll_node_test_results`(1328–1380)、`test_all_nodes`(1382–1438)、`start_group_test`(1440–1454)、`poll_health_check_results`(1456–1512) | 1218–1512 | ~300 |
| 8 | `proxy_control.rs` | `run_proxy_until_stopped`(doc 901–911, fn 912–961) + `start_proxy`(1526–1821)、`poll_start_receiver`(1822–1934)、`set_system_proxy`(1935–2057)、`remove_system_proxy_static`(2058–2106)、`remove_system_proxy`(2107–2110)、`stop_proxy`(2111–2154)、`shutdown_and_wait_for_exit`(2155–2198) | 901–961 + 1526–2198 | ~790 |
| 9 | `share_io.rs` | 分享/导入/二维码/手动添加动作：`export_share_links`(2199–2222)、`import_share_links`(2223–2249)、`build_share_link`(2250–2280)、`open_share_dialog`(2281–2303)、`apply_imported_link`(2304–2377)、`set_import_status`(2378–2389)、`import_paste_submit`(2390–2427)、`import_paste_load_file`(2428–2461)、`manual_add_submit`(2462–2511)、`set_manual_status`(2512–2523)、`import_from_qr_image`(2524–2555)、`poll_qr_import_result`(2556–2591) | 2199–2591 | ~400 |
| 10 | `subscription_actions.rs` | 章节横幅(2593–2599) + `add_subscription`(2601–2631)、`delete_subscription`(2632–2658)、`queue_subscription_update`(2659–2664)、`update_all_subscriptions`(2665–2677)、`start_next_subscription_update`(2678–2705)、`poll_subscription_updates`(2706–2742)、`apply_subscription_update`(2743–2790) | 2593–2790 | ~200 |
| 11 | `ui_shell.rs` | `impl eframe::App for HydraApp`(2793–3118，`on_exit` + `update` 整块含内联对话框) + 章节横幅(3490) + 托盘接线：`poll_tray_commands`(3492–3519)、`handle_close_request`(3520–3536)、`sync_tray_tooltip`(3537–3552) | 2793–3118 + 3490–3552 | ~400 |
| 12 | `ui_connections.rs` | `refresh_connections`(3119–3155)、`sorted_connections`(3156–3169)、`ui_connections`(3170–3331) | 3119–3331 | ~215 |
| 13 | `theme.rs` | `setup_custom_fonts`(3332–3365)、`card_frame`(981–990)、`apply_dark_theme`(doc 5452–5467, fn 5468–5503) | 3332–3365 + 981–990 + 5452–5503 | ~115 |
| 14 | `windows_proxy.rs` | `#[cfg(windows)]` 系统代理注册表操作**模内内容**(3368–3487，去一级缩进)；`#[cfg(windows)] mod windows_proxy;` 声明留 root | 3368–3487 | ~120 |
| 15 | `ui_overview.rs` | `ui_overview`(doc 3554–3559, fn 3560–3899)、`system_proxy_on_cached`(3887–3904 内的方法，以项边界为准) | 3554–3900 | ~350 |
| 16 | `ui_nodes.rs` | `ui_nodes`(doc 3901–3904, fn 3905–4258)、`ui_nodes_dialogs`(4260–4458) | 3901–4458 | ~560 |
| 17 | `ui_subscriptions.rs` | `ui_subscriptions`(doc 4460–4462, fn 4463–4724)、`ui_sub_add_dialog`(4725–4783) | 4460–4783 | ~325 |
| 18 | `ui_node_edit.rs` | `open_node_edit`(4784–4809)、`cert_status_text`(4810–4833)、`save_node_edit`(4834–4890)、`ui_node_edit_dialog`(4891–5020) | 4784–5020 | ~240 |
| 19 | `ui_settings.rs` | `ui_settings`(doc 5022–5025, fn 5026–5413) | 5022–5413 | ~395 |
| 20 | `ui_logs.rs` | `ui_logs`(doc 5415, fn 5416–5450，不含 impl 收尾 `}`) | 5415–5449 | ~50 |

合计约 6370 行（原 6331 + 新增 use/包裹行/模块头 − 去重），守恒；最大文件 `proxy_control.rs` ~790 行。

**边界微调记录**（评审确认合理）：

- `test_node_connection`（缩进 `async fn`）归 `node_test.rs`——它是 `start_node_test` 的关联辅助；
- `add_log`（1513–1525）夹在测速与代理方法之间，归 `app.rs`（全 crate 使用的日志入口，属应用骨架）；
- `card_frame`（981–990）虽被多页使用，归 `theme.rs`（视觉规范职责）而非任一页面；
- `system_proxy_on_cached`（3887–3904 区间内）与 `ui_overview` 同文件——它是总览页的系统代理状态缓存读取。

---

## 5. 函数级映射表（移动单元 = 顶层项）

| 项（当前行号） | 去处 | 可见性变化 |
|----------------|------|-----------|
| `mod palette {…}`（20–105） | palette.rs（模内内容 23–104 去缩进） | 不变（模块内已 pub） |
| `struct SpeedHistory` + impl（110–201） | speed_history.rs | struct + **全部字段** + 方法 → `pub(crate)`（`daily_up/daily_down` 被 ui_overview:3573 直读；`samples` 供测试；`CAPACITY` 常量仅模内用可保持私有，若测试需要一并放开） |
| `median_online_latency`（205）、`best_online_node`（221） | nodes.rs | → `pub(crate)` |
| `enum Tab` + impl（241–271） | nodes.rs | enum/`ALL`/`label` → `pub(crate)` |
| `struct NodeStatusInfo`（273–278） | nodes.rs | struct + **字段** → `pub(crate)`（字段被 app/node_test/ui 多处读写） |
| `GROUP_MANUAL`（282）、`node_group_of`（286）、`filter_nodes_by_group`（296）、`group_summary`（317） | nodes.rs | → `pub(crate)` |
| `LOCAL_TEXT_SOURCE_PREFIX`（344）、`next_import_group_name`（347）、`next_manual_group_name`（359）、`apply_subscription_node_update`（377）、`GroupImportResult`（455）、`import_share_links_as_group`（472）、`build_form_share_url`（539）、`subscription_source_label`（620） | groups.rs | → `pub(crate)`；**`GroupImportResult` 的字段（`added/removed/node_count/bad_lines`）也要 `pub(crate)`**——被 share_io（import_paste_submit:2398 / manual_add_submit:2481）与 subscription_actions（apply_subscription_update）直读 |
| `impl Default for HydraApp`（800）、`impl Drop`（879） | app.rs | 不变（trait impl） |
| `probe_runtime`（891） | probe.rs | → `pub(crate)` |
| `run_proxy_until_stopped`（912） | proxy_control.rs | → `pub(crate)`（测试用） |
| `start_button_state`（971） | app.rs | → `pub(crate)` |
| `card_frame`（983） | theme.rs | → `pub(crate)` |
| `PROBE_TARGET_DEFAULT/ENV`（999/1002）、`probe_target_from`（1005）、`probe_target`（1013） | probe.rs | → `pub(crate)` |
| `setup_custom_fonts`（3332）、`apply_dark_theme`（5468） | theme.rs | → `pub(crate)` |
| `#[cfg(windows)] mod windows_proxy {…}`（3366–3488） | windows_proxy.rs（模内内容 3368–3487 去缩进）；`#[cfg(windows)] mod windows_proxy;` 留 root | 模块内不变 |
| `impl HydraApp` 方法（1018–2790、3119–3331、3492–5450） | §4 #5–#12、#15–#20 | 方法 → `pub(crate)`（跨模块调用必需；同文件互调的也统一加，避免逐个判断） |
| `impl eframe::App for HydraApp`（2793–3118） | ui_shell.rs | trait 方法不改 |
| `async fn main`（5505–5554） | main.rs | 不变 |
| `mod tests`（5556–6331） | 按 §6 拆分 | `#[cfg(test)]`；nodes.rs 的 tests 为 `pub(crate)`（D5 夹具共享） |

> `pub(crate)` 收敛策略：**宁多勿漏**——所有被移动的自由函数与 impl 方法统一 `pub(crate)`。
> 注意：clippy 的 `redundant_pub_crate` 属 nursery lint、默认不启用，`-D warnings`
> **抓不住「过度暴露」**，只有完全未用的项触发 dead_code。收紧靠人工/后续 lint，不影响 CI。
> impl 方法加 `pub(crate)` 不属于 API 暴露面扩大（crate 本身是 bin，crate 外不可见）。
>
> **Linux 门控**（新增 use 行不受「属性随块走」保护）：proxy_control.rs 引用
> windows_proxy 的两处调用（enable:1967 / disable:2064）均在 `#[cfg(windows)]` 块内，
> 迁移时**使用完整路径 `crate::windows_proxy::enable(…)` 写在 cfg 块内**，不新增顶层
> `use crate::windows_proxy;`——否则非 Windows 目标 unresolved import，CI Linux 矩阵必红。

---

## 6. 测试归位表（33 个用例，拆分前后总数必须一致）

| 目标模块 | 用例（含测试夹具） | 数 |
|----------|--------------------|---:|
| palette.rs | `latency_color_thresholds`、`node_status_color_states` | 2 |
| app.rs | `start_button_state_transitions` | 1 |
| probe.rs | `probe_target_defaults_to_cloudflare_443`、`probe_target_env_override` | 2 |
| proxy_control.rs | `proxy_binds_within_3s`、`start_stop_restart_binds_within_3s_each_round`、`concurrent_load_does_not_delay_bind`（夹具 `test_proxy`、`free_port`；3 个均为 `#[tokio::test(flavor="multi_thread")]`） | 3 |
| nodes.rs | `node_group_of_claims_follow_subscription_nodes`、`filter_nodes_by_group_none_all_manual_and_sub`、`filter_nodes_by_group_empty_config_and_no_subs`、`group_summary_counts_online_offline_only_when_checked`、`median_online_latency_ignores_offline_and_unchecked`、`best_online_node_picks_lowest_latency`（夹具 `group_fixture`，本模块 tests 声明为 `#[cfg(test)] pub(crate) mod tests` 供 groups 复用） | 6 |
| groups.rs | `next_import_group_name_skips_existing_subscription_names`、`import_as_group_creates_named_group_and_filters`、`import_as_group_rejects_duplicate_and_invalid`、`import_as_group_rolls_back_when_no_node_claimed`、`local_text_source_reparse_produces_same_links`、`form_share_url_builds_parseable_link_from_addr_and_port`、`form_share_url_accepts_domain_address`、`form_share_url_rejects_invalid_port_and_empty_address`、`form_share_url_embeds_auth_key_when_given`、`form_share_url_requires_readable_cert_file`、`form_share_url_feeds_group_import_end_to_end`、`next_manual_group_name_skips_existing_subscription_names`、`manual_form_creates_named_group_and_filters`、`manual_form_rejects_bad_input_and_duplicate_name`、`subscription_source_label_classifies_sources`（夹具 `share_link_line`；**跨模块依赖**：`use crate::nodes::{GROUP_MANUAL, filter_nodes_by_group}; use crate::nodes::tests::group_fixture;`） | 15 |
| speed_history.rs | `speed_history_caps_at_120_and_keeps_latest`、`speed_history_daily_accumulates_deltas`、`speed_history_monitor_restart_does_not_go_negative`、`speed_history_reset_samples_keeps_daily_totals`（夹具 `sample_stats`） | 4 |

全部 33 个用例均为纯函数/无状态测试（不实例化 `HydraApp`），可安全随模块迁移。
各 tests 模块 `use super::*` 继承面变小，需按编译错误补自身 use（HashMap/GuiConfig/Arc 等）。

---

## 7. 执行步骤

**批 0：基线与区间校验**（已完成）

- [x] 基线：`cargo clippy -p hydra-client-gui --all-targets -- -D warnings` 零告警；
      `cargo test -p hydra-client-gui` 64 通过 / 0 失败
      （其中 main.rs `mod tests` 贡献 33 = 30 `#[test]` + 3 `#[tokio::test]`，
      其余 31 个位于 config.rs(23)/qr.rs(4)/subscription.rs(4)，不受本次拆分影响）；
- [x] `git status` 确认 `hydra-client-gui/` 无未提交改动；
- [ ] 逐区间校验 §4 表**首行与尾行**内容与行号一致（防止行号漂移与尾部越界）。

**批 1：零引用面模块（纯移动）**——palette.rs、windows_proxy.rs、theme.rs

- palette/windows_proxy 为内联模块平移（内容去一级缩进；mod 声明留 root，
  windows_proxy 的 `#[cfg(windows)]` 属性留在 root 的 mod 声明处），本批内调用点零改动；
- theme.rs 三个自由函数迁出后，在 main.rs root 加 `use theme::{apply_dark_theme, card_frame, setup_custom_fonts};`
  （批 3 new() 迁往 app.rs 时随迁）；
- `cargo check -p hydra-client-gui` 通过。

**批 2：纯逻辑模块 + 测试归位**——speed_history.rs、nodes.rs、groups.rs、probe.rs

- 各自由函数加 `pub(crate)`（SpeedHistory/GroupImportResult/NodeStatusInfo 含字段级）；
- 测试按 §6 迁入：本批共 **27 个用例**（palette 2 若随批 1 走则批 1 后为 2、批 2 为 27）；
- main.rs root 与残留调用点补 `use crate::…`；nodes tests 为 `pub(crate)` 供 groups 复用；
- `cargo check --all-targets` + `cargo test -p hydra-client-gui`（比对用例数）。

**批 3：HydraApp 动作层**

- **批 3a**：app.rs 先行（`impl Default`/`impl Drop`/`new`/`wizard_lines`/
  `maybe_save_config`/`add_log`/`start_button_state`）——`add_log` 被其余所有动作/UI
  方法调用，先立桩减少中间态报错面；`cargo check --all-targets`；
- **批 3b**：node_test.rs、proxy_control.rs、share_io.rs、subscription_actions.rs
  按方法逐块迁出（impl 块整体剪切 → 新文件 `use crate::HydraApp;` + 领域 use；
  windows_proxy 引用走完整路径，见 §5 Linux 门控）；
- 方法统一加 `pub(crate)`；`cargo check --all-targets` 迭代至零错误，
  `cargo test` 全量比对用例数。

**批 4：UI 层**——ui_shell.rs、ui_connections.rs、ui_overview.rs、ui_nodes.rs、
ui_subscriptions.rs、ui_node_edit.rs、ui_settings.rs、ui_logs.rs

- `impl eframe::App` 整块 → ui_shell.rs；托盘接线三方法随迁；
- 各页方法迁入对应文件；`update()` 内部一字不改；
- main.rs 收敛为 §4 #0 形态（mod 树 + struct + main，清理不再使用的 root use）。

**批 5：终检与收尾**

- [ ] `cargo clippy -p hydra-client-gui --all-targets -- -D warnings` 零输出；
- [ ] `cargo test -p hydra-client-gui` 用例数 = 基线（64，其中本文件拆出的 33 个按 §6 归位）；
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`（与 CI 命令一致）；
- [ ] `cargo check --workspace`（确认未波及 workspace 其他 crate）；
- [ ] `cargo test --workspace`（兜底）；
- [ ] 抽查 `git diff`：移动块与源逐字一致（除已声明的去缩进/新增行白名单，见 §9）；
- [ ] `wc -l` 报告各文件行数，对照 §4 预计值；
- [ ] 单 commit 提交，可整体 revert。

> CI 的 Linux 矩阵本机无法验证；因所有 `#[cfg(windows)]` 块整体搬移、属性随块走、
> 新增 use 均按 §5 Linux 门控处理，非 Windows 侧风险极低，由 push 后 CI 兜底
> （提交说明中注明）。

---

## 8. 风险与对策

| # | 风险 | 对策 |
|---|------|------|
| R1 | 行号漂移导致切错块（首尾皆可错，尾部尤其隐蔽：文档注释属于**下一项**） | 批 0 逐区间校验**首行与尾行**；切割单位 = 完整项（doc/横幅 + 项到收尾 `}`）；脚本对每区间双断言 |
| R2 | `#[cfg(windows)]` 项漏移/属性丢失 | windows_proxy 模内内容整体平移，cfg 属性留在 root mod 声明处；字段/方法级 cfg 属性随块剪切；本机 Windows 覆盖 cfg(windows) 编译路径 |
| R3 | **新增 use 行破坏 Linux 矩阵**（属性随块走保护不了新写的 use） | proxy_control 引用 windows_proxy 一律完整路径写在 cfg 块内；其余 use 均指向跨平台存在的项；push 后 CI Linux 矩阵兜底 |
| R4 | unused import / 未用 `pub(crate)` | clippy `-D warnings` 是 CI 硬门槛，终检同命令清零（注：`redundant_pub_crate` 为 nursery 默认不启用，「过度暴露」由人工收紧，不阻塞本次） |
| R5 | 测试拆分后丢失/重复/编译失败（`use super::*` 继承面变化 + 跨模块夹具） | §6 表驱动迁移；批 2/3/5 各跑 `cargo test` 比对用例数；nodes tests `pub(crate)` 共享 `group_fixture`（D5） |
| R6 | 大 diff 掩盖逻辑改动 | 移动块逐字一致（脚本切割 + 去缩进仅空白变更）；review 阶段机械核对 + 抽查 |
| R7 | 私有字段跨模块访问编译错 | D1 保证结构体留 root；SpeedHistory/GroupImportResult/NodeStatusInfo 字段级 `pub(crate)` 已在 §5 声明；再出现即为漏标——修可见性而非改逻辑 |
| R8 | 回滚困难 | 全部改动单 commit；批间 `cargo check --all-targets` 保证每批可编译 |

---

## 9. 验收标准

1. `main.rs` ≤ 300 行（目标 ~250）：仅 mod 树、struct HydraApp、`fn main`；
2. 单文件最大 ≤ 900 行（`proxy_control.rs` 实际 874 行；§4 原预估 ~790 未计入
   use 头与随迁的 3 个 tokio 时序测试，验收上限相应放宽到 900，见 §11）；
3. `cargo clippy -p hydra-client-gui --all-targets -- -D warnings` 与 `cargo test` 全绿，
   用例数 = 64（基线）；workspace 级 clippy/check/test 同样全绿；
4. 33 个用例分布与 §6 一致；
5. `git diff` 中无任何方法体内部改动。新增行仅限白名单：`//!` 模块头、`use`、
   `pub(crate)`、mod 声明、`impl HydraApp {` / `}` 包裹行、测试 `mod tests` 包裹行；
   变更行仅限：palette/windows_proxy 内容的去一级缩进（纯空白）；
6. 提交说明注明「Linux 侧由 CI 矩阵兜底」。

---

## 10. 评审记录

- **评审人**：独立评审 agent（对照源码逐项核查）
- **结论**：`approve-with-revisions`——设计决策（D1–D6）全部成立；函数分配经全量
  fn 清单核对**无遗漏、无错配**；测试表 33/33 **无遗漏、无重复**；批次与门槛合理。
- **Blocker（5 项，均已回写）**：
  1. §5 可见性表补 `GroupImportResult` 字段级 `pub(crate)`（被 share_io:2398/2481 与
     apply_subscription_update 直读）→ 已写入 §5；
  2. §5 可见性表补 `SpeedHistory` 字段级 `pub(crate)`（daily_up/daily_down 被
     ui_overview:3573 直读）→ 已写入 §5；
  3. 12 处区间尾部边界错误（ui_logs 5416–5466 最严重，含 impl 收尾 `}` 与
     apply_dark_theme doc）、#0/#1 重叠（20–21）、两处落缝（337、3490）→ §4 表已按
     「项 = doc 到收尾 `}`」全面修正，批 0 增加**尾行断言**；
  4. windows_proxy 引用方式：proxy_control 的 use 必须 cfg 门控或用完整路径，
     cfg(windows) 属性留在 main.rs 的 mod 声明处 → 已写入 §5「Linux 门控」与 D2；
  5. 跨模块测试依赖：groups 测试复用 nodes 的 `group_fixture`/`filter_nodes_by_group`/
     `GROUP_MANUAL` → 处置方式已定（D5：nodes tests `pub(crate)`）。
- **建议（6 项，均已采纳）**：批 2 用例数 ~19 改 27；§9.5 白名单补 impl 包裹行；
  D2「零改动」限定批 1 时点；§5 更正 clippy 可揪过度暴露的说法（nursery lint）；
  批 3 拆 3a/3b 且 check 加 `--all-targets`；§1 方法数校准为 ~59 方法 + ~17 自由函数。
- **评审后抽查**：评审引用的 7 处关键边界（speed impl 止 201、maybe_save 止 1216、
  share_io 止 2591、tray 止 3552、ui_logs 止 5450、node_edit 止 5020、group_fixture
  复用于 5964）已逐一实地复核属实。

---

## 11. 执行记录（2026-10-09）

**执行方式**：按 D6 以一次性 Python 脚本对原始 main.rs（git 原件快照，6331 行）做
**原子切割**——每个区间首尾双断言全部通过后一次性产出 20 个新文件 + 精简版 main.rs。

**与 §7 批次计划的偏差及理由**：批 1–4 的渐进切割合并为一次原子切割 + 单轮编译修复循环。
原因：切割源必须是同一份原始文件（渐进重写 main.rs 会使行号失效）；且未在 mod 树中
声明的孤儿文件不参与编译，「按批建文件、按批 check」无法提供有效的中间验证点。
§7 的风险控制全部保留：项边界切割、首尾断言、§5 可见性规则、§6 测试守恒、
每轮 `cargo check --all-targets` 迭代、最终 clippy/test 双门槛。

**执行过程要点**：

1. 区间断言纠偏 5 处（palette 尾 104、setup_custom_fonts 止 357、app 测试段起 561、
   ui_node_edit 止 5020 / ui_settings 起 5022），与评审预测的「探针易有 ±1 偏差」一致；
2. 可见性注入：方法/自由项统一 `pub(crate)`；字段级注入初版误伤了 16 处多行函数
   签名的参数行（缩进 4 与字段同型），已回退——最终 `pub(crate)` 字段精确 13 处
   （SpeedHistory 6 / NodeStatusInfo 3 / GroupImportResult 4）；
3. `impl HydraApp { }` 包裹行由后处理脚本补齐（11 个方法文件，§9.5 白名单项）；
4. windows_proxy 两处调用改为 `crate::windows_proxy::` 完整路径（§5 Linux 门控）；
5. use 头两轮收敛：先按编译错误补齐 14 个文件，再按 unused 警告剔除 8 个文件的多余项；
6. palette 两个用例初版误随 theme.rs（区间相邻），已迁回 palette.rs
   （测试体路径 `palette::X` → `super::X`，仅测试代码改写）；
7. 新版 clippy（1.99）`doc_overindented_list_items` 对新写的模块地图文档报缩进——已修。

**最终行数**（code review 修复后 `wc -l` 终值；原 main.rs 6331 → 21 个文件合计 6551，
+220 行为 use 头 / `impl HydraApp` 包裹行 / mod 树 / `//!` 头 / tests 包裹行）：

| 文件 | 行数 | 文件 | 行数 |
|------|-----:|------|-----:|
| main.rs | 263 | ui_shell.rs | 398 |
| proxy_control.rs | 876 | ui_settings.rs | 402 |
| groups.rs | 683 | share_io.rs | 408 |
| ui_nodes.rs | 573 | ui_overview.rs | 358 |
| app.rs | 353 | ui_subscriptions.rs | 334 |
| node_test.rs | 307 | nodes.rs | 293 |
| ui_node_edit.rs | 250 | ui_connections.rs | 223 |
| subscription_actions.rs | 210 | windows_proxy.rs | 128 |
| palette.rs | 116 | speed_history.rs | 171 |
| theme.rs | 95 | ui_logs.rs | 44 |
| probe.rs | 66 | | |

**门槛核验**：

- `cargo clippy -p hydra-client-gui --all-targets -- -D warnings` ✅ 零输出；
- `cargo clippy --workspace --all-targets -- -D warnings` ✅ 零输出；
- `cargo test -p hydra-client-gui` ✅ **64 passed / 0 failed**（基线 64，用例数守恒）；
- `cargo test --workspace` ✅ 310 passed / 0 failed；
- 用例分布与 §6 一致（palette 2 / app 1 / probe 2 / proxy_control 3 / nodes 6 /
  groups 15 / speed_history 4；config 23 / qr 4 / subscription 4 未动）。

**遗留说明**：CI 的 Linux 矩阵本机无法验证（§7 批 5 同款说明），cfg 块整体搬移 +
新增 use 的完整路径写法已按 §5 门控，push 后由 CI 兜底。

**Code review（独立评审 agent，对全部 20 个新文件做与原版的逐字 diff）**：
结论 `approve-with-fixes`——**零 blocker**（纯搬移核查无任何逻辑改动、可见性 13 字段
精确、cfg 门控合规、测试 33/33 逐名守恒、main.rs root 与原版零差异）。已修复：
- major：本节行数表曾为 use 收敛前旧快照 → 已按终值刷新（即上表）；
- minor：main.rs 补文件末换行；11 个文件的 impl 收尾 `}` 前空行清理
  （清理规则对原版零误伤，已用原件验证）；speed_history `//!` 头与 struct doc 去重。
保留项：windows_proxy.rs 横幅注释与 use 块之间保留一个空行（常规风格）。
