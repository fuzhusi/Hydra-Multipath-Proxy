Hydra Linux 客户端安装说明（Ubuntu 24.04 构建；22.04 未验证——glibc 版本门槛见下）
=============================================================

包内容
------
  hydra-client-gui    桌面 GUI（egui；订阅/分享/连接页/TUN；无托盘，见已知限制）
  hydra-client        CLI（含 --tun 透明代理）
  hydra-node          节点侧服务
  hydra-fetch         多节点并行下载器
  hydra-client-gui.desktop   应用列表入口文件
  hydra-client-gui.png       应用图标（256×255，沿用 app.ico 内嵌位图）
  hydra-node.service / install.sh / env.example / README.md
                      节点侧部署用（install.sh 面向仓库布局，对本包平铺
                      解压目录不适用——节点手动部署见 README.md）

安装（无需 root，三条命令 + 一次补丁）
--------------------------------------
  mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/256x256/apps
  cp hydra-client-gui hydra-client hydra-node hydra-fetch ~/.local/bin/
  cp hydra-client-gui.desktop ~/.local/share/applications/
  cp hydra-client-gui.png ~/.local/share/icons/hicolor/256x256/apps/hydra-client-gui.png
  # [重要] .desktop 的 Exec 依赖 PATH，而 GUI 会话未必包含 ~/.local/bin
  #（装完包不重新登录时几乎必然不含）——把绝对路径写进入口文件：
  sed -i "s|^Exec=.*|Exec=$HOME/.local/bin/hydra-client-gui|" \
    ~/.local/share/applications/hydra-client-gui.desktop
  # 同理修正 Icon 路径（部分桌面环境对主题图标缓存较严格）：
  sed -i "s|^Icon=.*|Icon=$HOME/.local/share/icons/hicolor/256x256/apps/hydra-client-gui.png|" \
    ~/.local/share/applications/hydra-client-gui.desktop

之后在应用列表搜 "Hydra" 即可启动；或直接命令行运行 ~/.local/bin/hydra-client-gui。
（应用列表不出现/点击无反应时，先执行上面两条 sed 再重试；无需注销重登）

运行时依赖（Ubuntu 桌面默认自带；最小安装/服务器版需自行安装）
  sudo apt install libgtk-3-3 libxkbcommon0 libxkbcommon-x11-0 \
    libwayland-client0 libegl1 libgl1
  # libxkbcommon-x11-0：X11 会话键盘输入必需（缺失启动即 panic）；
  # libegl1/libgl1：glow 渲染器运行时 dlopen

TUN 全局接管（需要权限）
------------------------
  推荐：给二进制授网络管理能力后普通用户运行（Wayland/X11 均可用）
      sudo setcap cap_net_admin+ep ~/.local/bin/hydra-client-gui
  注意：重新 cp 覆盖升级后 capability 会静默丢失——TUN 突然报权限错误时
  重新执行一次 setcap 即可。
  （sudo 直启方式在 Wayland 会话下因环境变量重置通常打不开窗口，不推荐。）
  无权限时打开 TUN 会得到明确报错（需 root/CAP_NET_ADMIN），本地代理
  （SOCKS5/HTTP）模式不受影响，无需任何权限。

已知限制
--------
  · 无系统托盘：tray-icon 的 Linux 后端要求 gtk 事件循环（与 eframe 事件
    循环不兼容）——关闭窗口即退出（自动停止代理并还原系统代理设置），
    代理需常驻请保持窗口开启或使用 CLI/系统服务形态。
  · 总览页「系统代理」开关可用（GNOME gsettings / KDE kioslaverc）：开启前
    自动快照原有配置、停止/退出/异常退出自动还原；崩溃残留由下次启动自愈
    （仅当指向本机回环死端口，不误伤其他软件代理）。
  · 开机自启暂未实现（Windows 端同为规划中）。
  · glibc 门槛：产物在 ubuntu-24.04（glibc 2.39）构建，22.04 及更早版本
    可能报 GLIBC 版本符号缺失——未验证，如有需要请自行源码构建。
