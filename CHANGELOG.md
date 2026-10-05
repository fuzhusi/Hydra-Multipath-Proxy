# 更新日志（Changelog）

本项目所有显著变更记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.2.0] - 2026-10

> 0.2.0 是一次**路线级变更**：传输层从 QUIC/UDP 全面转向 TCP/TLS（因部署网络
> 存在 UDP 回程 QoS 丢包，tcpdump 实证），并在此基础上补齐真证书、NAT 穿透、
> TUN 透明代理三大交付批次。

### 新增

- **TCP/TLS 传输**（tokio-rustls，TLS 1.3）：无 ALPN、SNI 可自定义、节点证书
  固定（Pinning）；流量形态 = 普通 HTTPS 访问。
- **真证书（ACME）部署路线**：节点直接挂 PEM fullchain/key
  （`HYDRA_CERT_FILE`/`HYDRA_KEY_FILE`），客户端 `HYDRA_TRUST=ca` 信任公共 CA，
  可选叶证书 SHA-256 硬 pin（`HYDRA_CERT_SHA256`）防 CA 误签发——证书轮换不再
  破坏 pinning。
- **Noise-PSK 应用层握手**（snow NNpsk2）：前向安全、抗重放；confirm 以服务器
  叶证书 SHA-256 指纹 + TLS exporter **双通道绑定**，多节点部署零配对成本。
- **私有帧协议**：握手后 `[u16 BE 地址长度][目标地址]` + `[2B 应答码]`；认证
  失败零字节静默关流（无回显错误码，抗主动探测）。
- **NAT 穿透 v1（实验性）**：TCP STUN（RFC 5389）公网地址发现 + NAT 行为分类；
  节点信令（`HYDRA_P2P_SIGNAL=1`）协调下的 TCP 同时打开打洞，失败自动回落节点
  中继（CLI `--p2p/--peer/--node`）。
- **TUN 透明代理模式 v1**（feature `tun`，默认开启）：`0.0.0.0/1 + 128.0.0.0/1`
  路由接管 + 节点 IP/DNS 豁免 + 幂等清理，smoltcp 用户态栈终结后经既有节点链路
  转发（仅 TCP；`HYDRA_TUN_*` 系列环境变量配置）。
- **TUN IPv6 防泄漏**：TUN 模式可选对称接管 `::/1 + 8000::/1`（`HYDRA_TUN_IPV6=1`
  开启，默认关——用户态栈仅支持 IPv4，开启后 v6 包以 RST/ICMPv6 不可达快速
  失败回落 v4；节点 IPv6 地址进豁免清单；路由命令失败仅告警不阻断启动）。
- **节点转发空闲看门狗**（`HYDRA_IDLE_TIMEOUT_SECS`，默认 300s）防连接额度耗尽；
  节点 BBR + fq 一键内核调优（deploy/99-hydra-bbr.conf）。
- **密钥文件化**（节点 `HYDRA_AUTH_KEY_FILE`，Unix 0600 校验）替代 env 泄漏面。
- **分享体系 v2**：`hydra://` 链接携带完整凭据（`tp=tcp`，legacy `tp=quic` 告警
  回退）、二维码生成/识别、订阅导入、认证密钥恰好 32 字节双层校验。
- **桌面 GUI**（egui）：导航六区、系统托盘、配置持久化、Windows 系统代理一键
  开关、节点完整握手测速（TCP+TLS+Noise，密钥错误可区分，不再"假绿"）。
- **CI 与发布产物**：GitHub Actions 双矩阵（Windows/Linux）build/test/clippy；
  tag 触发 release（Windows 客户端 zip + Linux 节点 tar.gz）。

### 变更

- **默认传输切为 TCP**；分享链接缺省 `tp` 视为 `tcp`；`HYDRA_TRANSPORT=quic`
  告警回退 TCP。
- 客户端多节点故障切换/加权调度适配 TCP 链路：认证失败不误触发节点下线，
  目标失败（TargetUnreachable）不计节点故障、不污染评分。
- GUI 节点测速从"仅 TCP connect"升级为完整 `connect_target`（Noise-PSK 认证 +
  节点应答），错误分类：目标不可达 = 节点健康 ✓；握手失败 = 密钥错误 ✗；
  连接超时 = 节点不可达 ✗。
- `deploy/install.sh` 升级场景（unit 已存在且服务 active）安装后自动
  `systemctl restart hydra-node`；全新安装行为不变。
- `deploy/env.example` 与节点现状逐项对齐（补 `HYDRA_IDLE_TIMEOUT_SECS`、
  `HYDRA_P2P_SIGNAL` 等，移除 QUIC 残留项）。
- 全 workspace 版本统一 0.2.0；README 交付叙事按三视角评审校正
  （已交付 / 实验性 / 规划中三档）。

### 移除

- **QUIC/UDP 传输路径全量删除**（含 V3 协议的多流通道与字节级多路径聚合
  V3.4、obfs UDP 全包混淆模块 hydra-obfs crate）——git 历史可考。
- QUIC 时代环境变量（`HYDRA_MODE`/`HYDRA_OBFS_KEY`/`HYDRA_CC`/
  `HYDRA_BRUTAL_MBPS`/`HYDRA_STREAM_WINDOW`/`HYDRA_CONN_WINDOW`/
  `HYDRA_CHANNELS`/`HYDRA_AGGREGATE`/`HYDRA_STUN_ADDR`）。

### 已知限制（如实声明）

- TUN 仅接管 TCP（UDP 含 QUIC/HTTP3 在 TUN 内丢弃）；smoltcp 仅 IPv4 + 按端口
  列表监听；无 DNS 劫持；TUN 模式下 CN 域名分流失效。
- 单连接单流：TCP 下无多流聚合；连接级多节点加权分发保留。
- NAT 穿透为实验性：对称型 NAT 打洞成功率有限，中继兜底为主路径。
- GUI 暂仅支持自签 pin 模式（真证书部署走 CLI）。
- ClientHello TLS 指纹与浏览器有差异（规划项）。

## [0.1.0] - 2026-10

QUIC 时代初始版本：SOCKS5/HTTP 代理 → QUIC 多路复用隧道 → 多节点，
含认证接线、证书固定、故障切换、SSRF 过滤与分享体系 v1（详见 git 历史）。

[0.2.0]: https://github.com/fuzhusi/Hydra-Multipath-Proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fuzhusi/Hydra-Multipath-Proxy/releases/tag/v0.1.0
