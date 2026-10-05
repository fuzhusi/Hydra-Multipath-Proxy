# Hydra Multipath Proxy

> **交付状态：v1.0 可交付产品**（2026-10）。自签与真证书双部署路线、多节点加权分发、故障自愈、GUI 全功能均已交付并通过 125 项自动化测试。

基于 Rust 的多链路代理：本地 SOCKS5/HTTP 代理 → **TCP/TLS 加密隧道（TLS 1.3 + Noise-PSK）** → 多个自建节点 → 互联网。支持**节点故障切换与自愈**、**连接级多节点加权分发**、**前向安全握手**、**真证书（ACME）部署**与**扫码即用的凭据分享**。

> **项目性质**：个人自用工具，AI 辅助开发。安全设计与实现经过多轮独立审查（报告见 [docs/review/](docs/review/)），所有能力以本 README 所述为准——未列出的能力即为未实现，不做夸大宣传。
>
> **TCP 转型（2026-10）**：因部署网络存在 UDP 回程 QoS 丢包（tcpdump 实证），项目已从 QUIC/UDP 全面转向 **TCP 443 + TLS**（方案见 [docs/design/TCP转型与加密选型方案.md](docs/design/TCP转型与加密选型方案.md)）。QUIC/UDP 路径与 obfs UDP 混淆模块已删除（git 历史可考）。

---

## 核心特性

### 传输与加密
- **TCP/TLS 隧道**（tokio-rustls，TLS 1.3），无 ALPN（流量形态 = 普通 HTTPS 访问），SNI 可自定义（默认 `hydra.node`），节点证书固定（Pinning）防中间人
- **双信任路线**：自签证书 pinning（`HYDRA_TRUST=pin`，默认）与 **ACME 真证书**（节点直接挂 PEM fullchain，客户端 `HYDRA_TRUST=ca` 信任公共 CA，可选叶证书 SHA-256 硬 pin 防误签发）——证书轮换不再破坏 pinning
- **Noise-PSK 应用层握手**（snow，NNpsk2：前向安全、无时钟窗依赖、抗重放；confirm 以**服务器叶证书 SHA-256 指纹 + TLS exporter** 双通道绑定——指纹取 TLS 协商出的对端证书，多节点部署零配对成本）
- **私有帧协议**：握手后 `[u16 BE 地址长度][目标地址]` + `[2B 应答码]`，线缆格式私有（通用 DPI 规则零命中）
- **认证失败静默关流**：版本字节非法 / 握手失败 / 认证失败一律零字节关闭，不回显任何可区分错误码，主动探测无法识别节点身份
- **DNS 隐私**：客户端不解析目标域名，域名只经加密通道交节点解析，明文域名永不离开本机
- **证书双路线已交付**：自签 pinning（默认）与 ACME 真证书（PEM 直挂），见「3b. 真证书部署」

### 可靠性与性能
- **节点故障切换 + 自愈**：传输失败自动标记 Offline、切换下一节点（最多 3 候选）；后台探测器周期探测（TCP connect + TLS 握手时延），节点恢复自动重新上线
- **连接级多节点加权分发**：多节点按评分承接新连接，杀节点不中断
- **测速与动态调度**：主动探测 RTT + 被动吞吐差分（按节点字节计数）+ 故障衰减，实测数据写回节点评分
- **NAT 穿透（实验性）**：TCP STUN（RFC 5389）公网地址发现 + NAT 映射行为分类（EIM/对称型）；节点信令（`HYDRA_P2P_SIGNAL=1`）协调下的 **TCP 同时打开打洞**，失败自动回落节点中继——CLI `hydra-client --p2p <我的id> --peer <对方id> --node <节点>`（方案与实现记录见 docs/design/NAT穿透方案.md）
- **拥塞与转发调优**：节点侧一键启用内核 **BBR + fq**（deploy/99-hydra-bbr.conf）；转发空闲看门狗（`HYDRA_IDLE_TIMEOUT_SECS`）防连接额度耗尽
- **半关闭语义**：双向转发一侧 EOF 时显式 shutdown 对侧写端（浏览器提前关写侧不挂起响应）

### 安全与隐私
- **SSRF 目标过滤**：节点拒绝 loopback/链路本地/RFC1918/ULA 目标（含 IPv4-mapped/NAT64 内嵌绕过），云元数据地址不可达
- **资源上限**：最大并发连接数（Semaphore 强制）、认证阶段超时静默关流
- **日志脱敏**：访问目标一律 SHA-256 短哈希，明文仅 `RUST_LOG=debug` 可见
- **密钥文件化**：节点支持 `HYDRA_AUTH_KEY_FILE`（Unix 0600 校验），替代 env 泄漏面

### 便捷性
- **桌面 GUI**（egui，中文）：左侧导航六区（状态总览/节点管理/订阅/分享/设置/日志）、状态卡实时速率、**系统托盘**（关窗到托盘、托盘菜单启停/退出）、配置持久化 + 首启向导、Windows 系统代理一键设置（注册表+WinINet，崩溃自动恢复）
- **分享体系 v2**：`hydra://` 链接可携带完整凭据（认证密钥/节点证书），**二维码生成 + 图片识别导入 + 粘贴/文件导入**，扫码即用；带"完整链接=持有节点"安全提示
- **订阅**：自有格式（多行/逐行 base64/整体 base64），URL 或本地文件，自动合并节点
- **国内直连分流**（`HYDRA_SPLIT=cn`）：内置 ~130 条 CN 域名后缀表 + 用户扩展文件，默认关闭（隐私优先）

---

## 快速开始

### 环境要求

- Rust 1.70+（构建）；Windows / Linux / macOS 运行
- 一台有公网 IP 的 VPS（推荐开放 **TCP 443**）

### 1. 编译

```bash
cargo build --release
```

### 2. 生成认证密钥（客户端与节点必须一致）

```bash
openssl rand -hex 32
# 输出示例: a1b2c3d4...（64 个 hex 字符，解码后 32 字节）
```

### 3. 启动节点（VPS 上）

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."
./target/release/hydra-node 0.0.0.0:443
```

首次启动自动生成自签证书并持久化（默认 `hydra-node-cert.der` / `hydra-node-key.der`，日志打印证书 SHA-256 指纹）。**把 `hydra-node-cert.der` 复制到客户端设备。**

生产部署一键化（systemd + BBR 内核调优 + 防火墙指引）：`sudo ./deploy/install.sh`。

### 3b. 真证书部署（可选，推荐长期使用）

节点侧把 ACME 证书直接挂给 Hydra（支持 PEM fullchain，自动识别）：

```bash
export HYDRA_CERT_FILE=/etc/letsencrypt/live/your.domain/fullchain.cer
export HYDRA_KEY_FILE=/etc/letsencrypt/live/your.domain/private.key
export HYDRA_SNI=your.domain    # 证书 SAN 对应的域名
```

客户端侧改用公共 CA 信任 + SNI 校验（无需分发证书文件）：

```bash
export HYDRA_TRUST=ca
export HYDRA_SNI=your.domain
# 可选加固：叶证书硬 pin（证书指纹，防 CA 误签发）
export HYDRA_CERT_SHA256=<64位hex>
```

更多部署方式（systemd / Docker / 安装脚本 / 排障表）：见 [docs/guides/部署指南.md](docs/guides/部署指南.md)。

### 4. 启动客户端

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."                    # 与节点一致
export HYDRA_NODE_CERT=/path/to/hydra-node-cert.der    # 节点证书文件
./target/release/hydra-client --listen 127.0.0.1:1080 1.2.3.4:443 [更多节点...]
```

### 5. 配置浏览器

- SOCKS5 代理：`127.0.0.1:1080`（SOCKS v5），或 HTTP 代理同端口
- 或使用 GUI 的"Windows 系统代理"一键开关

### 6. 验证

```bash
curl -x socks5h://127.0.0.1:1080 https://www.google.com
```

### 6b. TUN 透明代理模式（免配置全局代理，v1，需管理员/root）

在 SOCKS 监听之外叠加启动 TUN 虚拟网卡，接管系统 TCP 流量——应用**无需配置代理**：

```bash
# Windows：以管理员身份运行；wintun.dll（与 exe 同架构）放在 exe 目录或 PATH
# Linux：root 或 CAP_NET_ADMIN（/dev/net/tun）
./hydra-client --tun 1.2.3.4:443            # 或 HYDRA_TUN=1
```

- **防环路**：节点 IP / 系统 DNS / TUN 网段自动加入路由豁免（/32 回物理网关）；
  物理网关自动探测（`HYDRA_TUN_GW` 可手动指定）。退出/崩溃由 drop guard +
  下次启动幂等清理恢复路由。
- **流量路径**：`0.0.0.0/1 + 128.0.0.0/1 → TUN` → smoltcp 用户态 TCP 栈终结 →
  每条流经既有节点链路（故障切换/TargetUnreachable/流量统计语义零分叉）。
- **环境变量**：`HYDRA_TUN_ADDR`（默认 `10.7.0.1/30`）、`HYDRA_TUN_EXCLUDE`
  （额外豁免 IP，逗号分隔）、`HYDRA_TUN_DNS`/`HYDRA_TUN_GW`（手动指定探测结果）、
  `HYDRA_TUN_PORTS`（拦截端口列表，默认 `80,443,8080,8443`）。
- **v1 边界（如实声明）**：仅 TCP——UDP（含 QUIC/HTTP3）直接丢弃；无 DNS 劫持
  （DNS 明文经豁免路由直出物理网卡）；smoltcp 无通配监听，只拦截
  `HYDRA_TUN_PORTS` 列表内端口（列表外端口对应用收到 RST）；无域名分流
  （TUN 模式下 CN 分流失效，全部经节点）。Windows 系统代理开启时会告警环路风险。
- **依赖开关**：feature `tun` 默认开启（`tun2` + `smoltcp 0.11` + `tokio-util`）；
  `cargo build -p hydra-client --no-default-features` 可编出无 TUN 的最小客户端。

**人工验证清单**（自动化测试覆盖不到真实设备路径，需管理员环境手动确认）：
①管理员启动后 `curl https://ifconfig.me`（无 `-x`）出口 IP = 节点 IP；②节点 IP
豁免生效（代理自身连接不走 TUN，无环路断网）；③Ctrl+C 退出后 `route print`
确认路由已清理、网络自动恢复；④进程强杀后重新启动能幂等清理残留路由。

### GUI 客户端（推荐）

```bash
./target/release/hydra-client-gui
```

首次启动按界面引导：①粘贴认证密钥 ②选择节点证书文件 ③添加节点 ④启动代理。配置持久化后双击即用。GUI 亦可在节点列表点"分享"生成**二维码**，在其他设备上"从图片导入"扫码即用。

---

## 配置参考

### 环境变量总表

| 变量 | 端 | 说明 |
|---|---|---|
| `HYDRA_AUTH_KEY` | 双端 | 预共享密钥（hex，解码后**恰好 32 字节**），**必填**；Noise-PSK 的 PSK |
| `HYDRA_AUTH_KEY_FILE` | 节点 | 密钥文件路径（替代 env，Unix 0600 校验） |
| `HYDRA_AUTH_MODE` | 双端 | 握手版本：`auto`（默认）/ `v2`（legacy，仅 QUIC 时代）/ `v3`；TCP 路径固定 v3 |
| `HYDRA_NODE_CERT` | 客户端 | 节点证书 .der 文件路径（pin 模式单节点） |
| `HYDRA_NODE_CERTS` | 客户端 | 逗号分隔的多节点证书路径，**顺序与节点参数一一对应**（pin 模式多节点） |
| `HYDRA_TRUST` | 客户端 | 信任模式：`pin`（默认，自签 pinning）\| `ca`（真证书/公共 CA） |
| `HYDRA_CERT_SHA256` | 客户端 | ca 模式可选：叶证书 SHA-256 硬 pin（64 hex 字符，防 CA 误签发） |
| `HYDRA_SNI` | 客户端 | SNI 伪装域名（默认 `hydra.node`；真证书部署填证书 SAN 域名） |
| `HYDRA_LISTEN` | 双端 | 监听地址（节点默认 `0.0.0.0:8080`，推荐 `0.0.0.0:443`；客户端默认 `127.0.0.1:1080`；CLI 参数优先） |
| `HYDRA_TRANSPORT` | 客户端 | legacy 兼容项：`quic` 值告警回退 tcp（QUIC 路径已移除）；缺省即 TCP |
| `HYDRA_IDLE_TIMEOUT_SECS` | 节点 | 转发空闲超时（默认 300s，双向无数据即断开，防连接额度耗尽） |
| `HYDRA_PROBE_INTERVAL_SECS` | 客户端 | Offline 节点恢复探测周期（默认 30s） |
| `HYDRA_SPLIT` | 客户端 | `cn` 启用国内域名直连分流（默认关闭） |
| `HYDRA_DIRECT_DOMAIN_FILE` | 客户端 | 自定义直连域名列表（一行一域名） |
| `HYDRA_SPEEDTEST` | 客户端 | `0` 关闭测速评分（恢复探测保留） |
| `HYDRA_NODE_CONFIG` | 节点 | 节点 toml 配置文件路径（自动探测 `./node.toml` → `/etc/hydra/node.toml`） |
| `HYDRA_CERT_FILE` / `HYDRA_KEY_FILE` | 节点 | 证书/私钥路径（默认 `hydra-node-cert.der` / `hydra-node-key.der`） |
| `HYDRA_CERT_DOMAINS` | 节点 | 证书 SAN（默认 `hydra.node,localhost`） |
| `HYDRA_MAX_CONNECTIONS` | 节点 | 最大并发连接数（默认 1000，Semaphore 强制） |
| `HYDRA_HEALTH_ADDR` | 节点 | 健康检查 TCP 端点（如 `127.0.0.1:8081`，`GET /health`；未设=关闭） |
| `HYDRA_ALLOW_PRIVATE_TARGETS` | 节点 | `1` 放行私有目标（默认拒绝，仅测试/本地开发用） |

优先级统一为：**命令行参数 > 环境变量 > 配置文件 > 默认值**。GUI 场景下配置文件 > 环境变量。

> QUIC 时代的环境变量（`HYDRA_MODE`/`HYDRA_OBFS_KEY`/`HYDRA_CC`/`HYDRA_BRUTAL_MBPS`/`HYDRA_STREAM_WINDOW`/`HYDRA_CONN_WINDOW`/`HYDRA_CHANNELS`/`HYDRA_AGGREGATE`/`HYDRA_STUN_ADDR`）已随 QUIC/UDP 路径移除：TCP 拥塞控制与缓冲由内核栈管理。

### 节点 toml 配置示例

```toml
# node.toml（环境变量同名小写字段，全部可选）
listen_addr = "0.0.0.0:443"
auth_key_file = "/etc/hydra/auth.key"   # 推荐：密钥文件化，替代 env
max_connections = 1000
cert_file = "/etc/hydra/cert.der"
key_file = "/etc/hydra/key.der"
health_addr = "127.0.0.1:8081"
```

---

## 协议规格（客户端 ↔ 节点，单条 TCP/TLS 流）

```
TCP 建连 → TLS 1.3（证书 pinning + SNI；无 ALPN；禁会话恢复）
→ [0x03][Noise-PSK 握手]            msg1(48B) → msg2(48B) → confirm_c(32B) → confirm_s(32B)
    confirm = HKDF-SHA256(handshake_hash, salt = 证书指纹 ‖ TLS exporter, info = 方向)
→ [地址帧]   [target_len u16 大端][target]（≤1024B，域名/IPv4/IPv6:port）
→ [应答 2B]  [0x00][code]：0x00 成功 / 0x01 目标连接失败（含 SSRF 拒绝）/ 0x02 节点侧 DNS 失败
→ 双向裸转发（半关闭：一侧 EOF → 显式 shutdown 对侧写端）
```

- 握手前的任何异常（版本字节非 0x03、握手失败、超时）＝**零字节静默关闭**，无应答码回显（防主动探测）
- 目标失败属认证后的应用层错误，回 2B 应答码后关闭
- 证书指纹通道绑定：指纹取 **TLS 协商出的对端叶证书**（pin/CA 两模式均已被 TLS 认证），多节点/证书轮换零额外配置

---

## 项目结构

```
Hydra-Multipath-Proxy/
├── hydra-protocol/     # 协议定义：Noise-PSK 握手、TCP 私有帧、日志脱敏、错误类型
├── hydra-node/         # 代理节点：TCP/TLS 服务、握手认证、SSRF 过滤、健康检查
├── hydra-client/       # 客户端库：SOCKS5/HTTP、故障切换、测速调度、分流、分享链接
├── hydra-client-gui/   # 桌面 GUI：导航六区、系统托盘、二维码分享、订阅、配置持久化
├── config/             # 节点 toml 样例
├── deploy/             # systemd unit / Docker / install.sh / env.example / 99-hydra-bbr.conf（BBR+fq 内核调优）
└── docs/
    ├── design/         # TCP 转型与加密选型方案、V3 协议设计、GUI 选型、安卓方案
    ├── review/         # 审查报告（QUIC 时代存档，TLS/握手/SSRF 设计仍有效）
    ├── improvement/    # 改进计划、施工方案、验收报告、任务书（存档）
    ├── assessment/     # 部署运维 + 终端用户双视角评估
    └── guides/         # 部署指南（systemd/Docker/排障表）
```

> `hydra-obfs` crate（QUIC 全包混淆）已随 UDP 路径删除。

## 测试

```bash
cargo test --workspace
```

当前 **153 通过 / 0 失败 / 0 忽略**。TCP 转型验收门（`hydra-client/tests/test_tcp_transport.rs`）：
- 64KB / 1MB / 10MB 三档 E2E 回显逐字节相等（10MB 走 SOCKS5 代理全链路）
- 错误 PSK → 静默关流，错误信息无可区分应用错误码
- 半关闭：写端 shutdown 后读端读到完整回显再读到干净 EOF
- 默认传输 = TCP；多节点测速动态调度路由切换

覆盖：握手双栈互通/篡改拒绝/真重放拒绝；SSRF 拒绝；分流直连；日志脱敏；二维码往返；流量统计与按节点计数；恢复探测；STUN 编解码与 NAT 分类；节点信令路由与全链路 invite/accept；loopback 同时打开打洞端到端。

## 安全模型（摘要）

| 能力 | 防 | 不防 |
|---|---|---|
| 证书固定 + Noise-PSK 握手（前向安全） | 中间人解密/篡改、PSK 泄漏后历史握手回溯解密、握手重放/跨连接转发 | 端点被攻破；CA 模式下依赖公共 CA 体系（可用叶证书硬 pin 收紧） |
| 无 ALPN 标准 HTTPS 形态 | 特征匹配 DPI | 白名单式深度审查（自签证书有固有指纹；真证书路线消除该指纹） |
| 域名节点侧解析 + 日志脱敏 | 本机/节点明文浏览记录泄漏 | 应用层泄漏（WebRTC 等需浏览器侧处理） |

## 已知限制（如实标注）

- **单连接单流**：TCP 下无多流通道聚合（V3.4 已随 QUIC 移除）；连接级多节点加权分发保留
- 分流为域名后缀版（无 GeoIP）；订阅为自有格式（不对接机场）
- 分享链接含完整凭据时等同于交付节点，仅限可信渠道
- TCP 链路无应用错误码通道：认证失败与目标失败在客户端侧均表现为建连失败（节点侧已认证后的目标失败可回 2B 应答码，且不再误触发节点故障切换）
- ClientHello TLS 指纹与浏览器有差异（Rust 生态无 uTLS 等价物，ja-tools 路线为规划项）；非认证 IP 反代静态页（抗主动探测）待实施
- GUI 暂仅支持自签 pin 模式（真证书部署走 CLI；GUI 支持在 UI 方案 P1 阶段补齐）

## 开发路线

- [x] Phase A：认证接线、证书固定、故障切换、SSRF/资源上限、防追踪特征正常化（2026-10，QUIC 时代）
- [x] V3.2：Noise-PSK 握手 v2 双栈（2026-10）
- [x] 分享体系 v2：凭据链接 + 二维码 + 订阅 + GUI 重排 + 托盘（2026-10）
- [x] **TCP 转型 Wave 1：TLS + Noise-PSK + 私有帧新协议核心（2026-10）**
- [x] **TCP 转型 Wave 2：默认传输切 TCP、分享链接 tp=tcp、GUI 适配（2026-10）**
- [x] **TCP 转型 Wave 3：删除 QUIC/UDP 死路径与 obfs 模块（2026-10）**
- [x] **代码审查 45 项 + P0/P1 修复：故障切换语义、slowloris 防护、idle 看门狗、日志脱敏、PSK fail-fast（2026-10，报告见 docs/review/05）**
- [x] **交付批次：真证书（PEM/ACME）部署路线 + 多节点证书配对根治 + BBR 部署加固（2026-10）**
- [x] **NAT 穿透 v1（实验性）：TCP STUN 探测/分类 + 节点信令 + TCP 同时打开打洞 + 中继兜底（2026-10，见 docs/design/NAT穿透方案.md）**
- [ ] UI 重设计实施（方案已定稿：docs/design/UI重设计方案-v3.md，P0-P2 约 10 人日）
- [ ] 多节点并行下载（HTTP Range 切块多节点拼装——TCP 下的差异化方向）
- [ ] ClientHello 指纹模仿（ja-tools 路线，协议优化评估 P1）

完整依据：[docs/design/TCP转型与加密选型方案.md](docs/design/TCP转型与加密选型方案.md) · [docs/review/00-审查总览与改进目标.md](docs/review/00-审查总览与改进目标.md)

## 许可证

MIT — 见 [LICENSE](LICENSE)。

## 联系方式

- 项目: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)
