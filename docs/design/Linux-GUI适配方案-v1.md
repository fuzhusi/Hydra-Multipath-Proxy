# Linux（Ubuntu）GUI 适配方案 v1

> 2026-11-02 · 状态：**已实施**（CI 产出 Linux 全套客户端产物）
> 关联：v0.2.9.5（CLI --tun 互斥端口修复 9a80f9f + 本方案）

## 一、背景与现状

用户在 Ubuntu 实测发现：官方 Linux 产物 `hydra-linux-x64.tar.gz` **没有 GUI**——
`release.yml` 的 build-linux job 只编 `hydra-node` + `hydra-fetch`（job 注释明言
"客户端 GUI 走 Windows 包"），而 README 却声称包含 "GUI/CLI/hydra-fetch 三二进制"。
桌面 GUI（eframe/egui）本身是跨平台框架，代码层早已大量 `cfg(windows)` 分支
（windows_proxy 模块、系统代理告警、unused_mut 规避等），**从未被 Linux 编译
验证过**——是打包缺口而非框架缺口。

代码审计结论（本方案实施前逐项核实）：

| 关注点 | 现状 | Linux 适配动作 |
|---|---|---|
| eframe/egui 0.27 | winit x11rb（纯 Rust X11）+ xkbcommon-dl（运行时 dlopen） | 无需改码；CI 装 libxkbcommon-dev/libwayland-dev 兜底 |
| `windows_proxy.rs`（注册表系统代理） | `#[cfg(windows)]` 模块级隔离 | 无需改码 |
| `winreg`/`windows-sys` 依赖 | `[target.'cfg(windows)'.dependencies]` 已 target-gated | 无需改码 |
| `tray-icon` 0.19 托盘 | 无 cfg 门；Linux 走 libappindicator（GTK3） | CI 装 libgtk-3-dev + libayatana-appindicator3-dev；**代码零改动** |
| `rfd` 0.15 文件对话框 | 默认 gtk3 后端 | 同上（GTK 已装）；运行时 Ubuntu 桌面自带 |
| TUN 透明代理 | `hydra-client` tun feature 跨平台（CLI `--tun` 已在 Ubuntu strace 实测） | 无需改码；权限要求见下 |
| 开机自启 | 仍是"规划中"禁用勾选（无任何平台代码） | 本版不做 |
| 单实例互斥 | 端口守卫（52810/52811/52812）纯 Rust std | 无需改码 |

## 二、目标（v1）

1. **CI 产出 Linux 全套客户端**：`hydra-client-gui`（GUI）+ `hydra-client`（CLI）+
   `hydra-node` + `hydra-fetch` 四二进制，进 `hydra-linux-x64.tar.gz`。
2. **桌面集成**：tar 内附 `.desktop` 文件与 256×256 PNG 图标，解压即用说明
   （复制到 `~/.local/{bin,share/applications,share/icons}` 三处即可出现在
   应用列表，无需 root）。
3. **TUN 权限如实呈现**：Linux TUN 需 `root`/`CAP_NET_ADMIN`——设置页 TUN
   开关下加 `cfg(target_os = "linux")` 提示文案；失败时既有错误路径给出准确
   原因（v0.2.9.5 已修好报错文案）。
4. **验证闭环**：CI 在 ubuntu-24.04 上 clippy -D warnings + 构建 + 二进制冒烟
   （`hydra-client --help` 可执行、GUI 二进制存在且可执行）。

## 三、非目标（v1 明确不做）

- **系统代理一键开关（Linux）**：GNOME/KDE 各有 gsettings/dBus 路径，且发行版
  差异大——v1 不实现，`cfg(windows)` 之外的系统代理 UI 已有 `cfg(not(windows))`
  分支（开关置灰）。浏览器侧用手动代理或 TUN。
- **AppImage / deb 包**：tar.gz + 手动复制已覆盖自建用户群（与节点侧同形态）；
  打包格式升级留待有真实需求时。
- **开机自启（XDG autostart）**：Windows 端同为"规划中"，两平台一起做避免
  功能面不对齐。

## 四、实施明细

### 4.1 CI（release.yml build-linux job）

```yaml
- apt 安装 GUI 构建依赖：libgtk-3-dev libayatana-appindicator3-dev
  libxkbcommon-dev libwayland-dev（构建期链接 GTK3/appindicator；
  xkbcommon/wayland 为运行时 dlopen，装 dev 兜底）
- cargo build --release -p hydra-node -p hydra-fetch -p hydra-client -p hydra-client-gui
- 冒烟：hydra-client --help 退出码 0；四个二进制存在且可执行
- 打包：tar.gz = 四二进制 + hydra-client-gui.desktop + app-256.png +
  LINUX-README.txt（packaging/linux/）
```

### 4.2 桌面集成资产（packaging/linux/）

- `hydra-client-gui.desktop`：Exec/Icon 指向 `~/.local/bin`、`~/.local/share/icons`
  安装路径（LINUX-README 给三条 `cp` 命令）。
- `app-256.png`：从 `assets/app.ico` 内嵌 PNG 直接提取（256×256，无损）。
- `LINUX-README.txt`：安装三步 + TUN 权限说明（sudo 直启 / `setcap
  cap_net_admin+ep` 二选一）+ 已知限制（无系统代理一键开关）。

### 4.3 GUI 代码（最小改动）

- `ui_settings.rs`：TUN 区域加 `#[cfg(target_os = "linux")]` 一行提示文案
  （权限要求与 setcap 方式），Windows 路径逐字节不变。
- 其余**零改动**——托盘/对话框/单实例/主题在 Linux 走各自后端。

## 五、验证

| 项 | 方式 |
|---|---|
| Windows 回归 | 本机 `cargo test --workspace` + `cargo clippy -p hydra-client-gui -- -D warnings`（全绿） |
| Linux 编译 | CI ubuntu-24.04：clippy -D warnings + release 构建（GTK/appindicator 链接即验证） |
| Linux 冒烟 | CI：`hydra-client --help` 退出码 0；四二进制 `test -x` |
| 真机 UX | 用户 Ubuntu 实测：解压 → 三条 cp → 应用列表启动 → 本地代理模式连接；TUN 带 sudo 实测（后续反馈迭代） |

## 六、已知限制（如实）

1. ~~Linux 无系统代理一键开关~~ → **v1.1 已承接**（linux_proxy 快照-恢复 +
   启动自愈，对齐 windows_proxy 语义）；TUN 是全接管唯一路径，需权限。
2. ~~托盘在 Wayland 会话依赖 AppIndicator~~ → **v1.1 直接禁用托盘**（见下）。
3. 深链 `hydra://` 桌面关联未注册（Windows 亦未注册到安装器）——两平台一致，
   留待桌面关联统一批次。

## 七、v1.1 修订（全项目 code review 落地，2026-11-03）

审查发现（P0）：tray-icon 0.19 官方约束 Linux 后端**必须**在创建线程持有
gtk 事件循环（tray-icon-0.19.3/src/lib.rs:17），eframe 0.27 为 winit/glutin
循环不提供——v1 原方案"代码零改动"的判断**不成立**：图标不出现、菜单/点击
事件永不触发、且关窗默认"隐藏到托盘"= 窗口假死（无任何唤回入口）。

修订内容：
1. **托盘 Linux 整体禁用**：tray-icon 依赖 target-gate 到 not(linux)
   （顺带解除 libappindicator/libxdo 链接依赖），tray.rs 模块/字段/轮询函数
   全部 cfg 隔离；关窗语义 = 真退出（on_exit 完整收敛：停代理/还原系统代理/
   落盘——已从 eframe 源码核实）。设置页与 LINUX-README 明示。
2. **系统代理承接**：linux_proxy 模块实现快照-恢复 + 启动自愈（原方案列为
   非目标——既有的裸 gsettings 覆写会抹掉用户自有代理，属数据丢失缺陷）。
3. **CI 打包勘误**：.desktop 的 Exec 依赖桌面会话 PATH（装完不重登必失败）
   ——LINUX-README 改为 sed 写入绝对路径；补 libxkbcommon-x11-0/libegl1/
   libgl1 运行时依赖；移除 22.04 支持声明（glibc 门槛，未验证）；
   install.sh 标注仅适用仓库布局。
4. CI 的 apt 清单保留 libayatana-appindicator3-dev（tray-icon 依赖虽已
   target-gate 出 Linux 构建图，多装无害；与 ci.yml 保持逐包一致）。
