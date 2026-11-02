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

1. Linux 无系统代理一键开关（见非目标）；TUN 是全接管唯一路径，需权限。
2. 托盘在 Wayland 会话依赖 AppIndicator 扩展（GNOME 默认带 AppIndicator
   支持的发行版可用；纯 Wayline 无托盘槽位时托盘静默不可见，主窗功能不受影响）。
3. 深链 `hydra://` 桌面关联未注册（Windows 亦未注册到安装器）——两平台一致，
   留待桌面关联统一批次。
