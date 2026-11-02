Hydra Linux 客户端安装说明（Ubuntu 22.04/24.04 桌面验证形态）
=============================================================

包内容
------
  hydra-client-gui    桌面 GUI（egui；托盘/订阅/分享/连接页/TUN）
  hydra-client        CLI（含 --tun 透明代理）
  hydra-node          节点侧服务
  hydra-fetch         多节点并行下载器
  hydra-client-gui.desktop   应用列表入口文件
  hydra-client-gui.png       应用图标（256×256）

安装（无需 root，三条命令）
--------------------------
  mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/256x256/apps
  cp hydra-client-gui hydra-client hydra-node hydra-fetch ~/.local/bin/
  cp hydra-client-gui.desktop ~/.local/share/applications/
  cp hydra-client-gui.png ~/.local/share/icons/hicolor/256x256/apps/hydra-client-gui.png

之后在应用列表搜 "Hydra" 即可启动；或直接命令行运行 ~/.local/bin/hydra-client-gui。

运行时依赖（Ubuntu 桌面默认自带；最小安装/服务器版需自行安装）
  sudo apt install libgtk-3-3 libayatana-appindicator3-1 libxkbcommon0 libwayland-client0

TUN 全局接管（需要权限，二选一）
--------------------------------
  方式一：sudo 启动 GUI（sudo ~/.local/bin/hydra-client-gui）
  方式二：给二进制授网络管理能力后普通用户运行
      sudo setcap cap_net_admin+ep ~/.local/bin/hydra-client-gui
  无权限时打开 TUN 会得到明确报错（需 root/CAP_NET_ADMIN），本地代理
  （SOCKS5/HTTP）模式不受影响，无需任何权限。

已知限制
--------
  · Linux 不提供"一键系统代理"（GNOME/KDE 路径各异，后续版本评估）——
    浏览器手动配 SOCKS5/HTTP 或使用 TUN。
  · GNOME 纯 Wayland 会话若无托盘槽位（AppIndicator 扩展），托盘图标
    可能不可见；主窗口功能不受影响。
  · 开机自启暂未实现（Windows 端同为规划中）。
