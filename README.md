# Hydra Multipath Proxy

基于 Rust 的多链路代理：本地 SOCKS5/HTTP 代理 → QUIC 加密隧道 → 多个自建节点 → 互联网。支持**节点故障切换与自愈**、**连接级多节点分发**、**单节点多流通道聚合（V3.4）**、**双模式线缆伪装**、**前向安全握手**与**扫码即用的凭据分享**。

> **项目性质**：个人自用工具，AI 辅助开发。安全设计与实现经过多轮独立审查（报告见 [docs/review/](docs/review/)），所有能力以本 README 所述为准——未列出的能力即为未实现，不做夸大宣传。

---

## 核心特性

### 传输与加密
- **QUIC 加密隧道**（quinn + rustls，TLS 1.3 AEAD），ALPN 伪装为标准 `h3`，SNI 可自定义（默认 `hydra.node`），证书固定（Pinning）防中间人
- **双栈认证**：`v2` HMAC-SHA256 令牌（兼容）与 **`v3.2` Noise-PSK 握手**（snow，NNpsk2：前向安全、无时钟窗依赖、抗重放、证书指纹+TLS exporter 双通道绑定），`HYDRA_AUTH_MODE=auto|v2|v3` 双栈平滑迁移
- **双模式线缆**：`masquerade`（默认，流量形态=访问普通 h3 网站）与 `obfs`（QUIC 全包 ChaCha20 混淆为均匀随机字节流，重度审查环境逃生舱；独立第二密码）
- **认证失败静默关流**：不回显任何可区分错误码，主动探测无法识别节点身份
- **DNS 隐私**：客户端不解析目标域名，域名只经加密通道交节点解析，明文域名永不离开本机

### 可靠性与性能
- **节点故障切换 + 自愈**：传输失败自动标记 Offline、切换下一节点（最多 3 候选）；后台探测器周期探测，节点恢复自动重新上线
- **拥塞控制三选**：`brutal`（自研固定速率，对抗丢包，配 `HYDRA_BRUTAL_MBPS`）/ `bbr`（quinn 内置，实验性）/ `cubic`（默认）——**客户端与节点双侧生效**
- **连接级多节点分发**（`HYDRA_AGGREGATE=1`）：多节点按评分加权承接新连接，杀节点不中断
- **单节点多流通道聚合**（`HYDRA_CHANNELS=2..16`，实验性）：同一节点的 N 条 QUIC 流承载一条连接，上行 ACK/NACK 重传、乱序重排（32MiB 有界窗口）、杀流接管；256MB 强制门校验通过
- **QUIC 流控调优**：单流 8MiB / 连接级 32MiB（默认），支撑高码率视频跨境链路
- **测速与动态调度**：探测 RTT + 被动吞吐差分 + 故障衰减，实测数据写回节点评分

### 安全与隐私
- **SSRF 目标过滤**：节点拒绝 loopback/链路本地/RFC1918/ULA 目标（含 IPv4-mapped/NAT64 内嵌绕过），云元数据地址不可达
- **资源上限**：最大并发连接数（Semaphore 强制）、认证前 10s 宽限看门狗、每流固定认证块配额、每源垃圾包令牌桶
- **日志脱敏**：访问目标一律 SHA-256 短哈希，明文仅 `RUST_LOG=debug` 可见
- **密钥文件化**：节点支持 `HYDRA_AUTH_KEY_FILE`（Unix 0600 校验），替代 env 泄漏面

### 便捷性
- **桌面 GUI**（egui，中文）：左侧导航六区（状态总览/节点管理/订阅/分享/设置/日志）、状态卡实时速率、**系统托盘**（关窗到托盘、托盘菜单启停/退出）、配置持久化 + 首启向导、Windows 系统代理一键设置（注册表+WinINet，崩溃自动恢复）
- **分享体系 v2**：`hydra://` 链接可携带完整凭据（认证密钥/节点证书/obfs 密钥），**二维码生成 + 图片识别导入 + 粘贴/文件导入**，扫码即用；带"完整链接=持有节点"安全提示
- **订阅**：自有格式（多行/逐行 base64/整体 base64），URL 或本地文件，自动合并节点
- **国内直连分流**（`HYDRA_SPLIT=cn`）：内置 ~130 条 CN 域名后缀表 + 用户扩展文件，默认关闭（隐私优先）

---

## 快速开始

### 环境要求

- Rust 1.70+（构建）；Windows / Linux / macOS 运行
- 一台有公网 IP 的 VPS（推荐开放 **UDP 443**）

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
| `HYDRA_AUTH_KEY` | 双端 | 预共享密钥（hex，解码后 ≥16 字节），**必填** |
| `HYDRA_AUTH_KEY_FILE` | 节点 | 密钥文件路径（替代 env，Unix 0600 校验） |
| `HYDRA_AUTH_MODE` | 双端 | 认证版本：`auto`（默认，双栈）/ `v2` / `v3` |
| `HYDRA_NODE_CERT` | 客户端 | 节点证书 .der 文件路径，**必填** |
| `HYDRA_SNI` | 客户端 | SNI 伪装域名（默认 `hydra.node`，须与节点证书 SAN 匹配） |
| `HYDRA_LISTEN` | 双端 | 监听地址（节点默认 `0.0.0.0:8080`，客户端默认 `127.0.0.1:1080`；CLI 参数优先） |
| `HYDRA_MODE` | 双端 | 线缆模式：`masquerade`（默认）\| `obfs` |
| `HYDRA_OBFS_KEY` | 双端 | obfs 独立第二密码（未设置则拒绝启用 obfs 模式） |
| `HYDRA_CC` | 双端 | 拥塞控制：`brutal` \| `bbr`（实验性）\| `cubic`（默认） |
| `HYDRA_BRUTAL_MBPS` | 双端 | brutal 模式带宽上限（Mbps；两端都设才双向生效） |
| `HYDRA_STREAM_WINDOW` / `HYDRA_CONN_WINDOW` | 双端 | QUIC 流控窗口 MB（默认 8 / 32） |
| `HYDRA_CHANNELS` | 客户端 | 单节点多流通道聚合流数 2..16（未设=关闭） |
| `HYDRA_AGGREGATE` | 客户端 | `1` 启用连接级多节点加权分发（默认关闭） |
| `HYDRA_PROBE_INTERVAL_SECS` | 客户端 | Offline 节点恢复探测周期（默认 30s） |
| `HYDRA_SPLIT` | 客户端 | `cn` 启用国内域名直连分流（默认关闭） |
| `HYDRA_DIRECT_DOMAIN_FILE` | 客户端 | 自定义直连域名列表（一行一域名） |
| `HYDRA_SPEEDTEST` | 客户端 | `0` 关闭测速评分（恢复探测保留） |
| `HYDRA_WARM_UP` | 客户端 | 连接池预热连接数（默认 2，0..8） |
| `HYDRA_NODE_CONFIG` | 节点 | 节点 toml 配置文件路径（自动探测 `./node.toml` → `/etc/hydra/node.toml`） |
| `HYDRA_CERT_FILE` / `HYDRA_KEY_FILE` | 节点 | 证书/私钥路径（默认 `hydra-node-cert.der` / `hydra-node-key.der`） |
| `HYDRA_CERT_DOMAINS` | 节点 | 证书 SAN（默认 `hydra.node,localhost`） |
| `HYDRA_MAX_CONNECTIONS` | 节点 | 最大并发连接数（默认 1000） |
| `HYDRA_HEALTH_ADDR` | 节点 | 健康检查 TCP 端点（如 `127.0.0.1:8081`，`GET /health`；未设=关闭） |
| `HYDRA_STUN_ADDR` | 节点 | STUN 服务器（公网地址发现，报入 /health） |
| `HYDRA_ALLOW_PRIVATE_TARGETS` | 节点 | `1` 放行私有目标（默认拒绝，仅测试/本地开发用） |

优先级统一为：**命令行参数 > 环境变量 > 配置文件 > 默认值**。GUI 场景下配置文件 > 环境变量。

### 节点 toml 配置示例

```toml
# node.toml（环境变量同名小写字段，全部可选）
listen_addr = "0.0.0.0:443"
auth_key_file = "/etc/hydra/auth.key"   # 推荐：密钥文件化，替代 env
mode = "masquerade"                      # masquerade | obfs
max_connections = 1000
cert_file = "/etc/hydra/cert.der"
key_file = "/etc/hydra/key.der"
health_addr = "127.0.0.1:8081"
stun_addr = "stun.l.google.com:19302"    # 公网地址发现（报入 /health）
```

---

## 协议规格（客户端 ↔ 节点，QUIC 双向流内）

### 认证（每条流首部，版本字节判别）

| 首字节 | 版本 | 字节序列 |
|---|---|---|
| `0x00` | v2（兼容） | 64B token：时间戳(8) + HMAC-SHA256(32) + nonce(16) + reserved(8)，30s 时间窗 |
| `0x03` | v3.2 | Noise-PSK 握手：msg1(48) → msg2(48) → confirm_c(32) → confirm_s(32)；HKDF 绑定证书指纹+TLS exporter；前向安全、无时钟窗、confirm 不匹配即拒 |

### 连接建立与数据面

```
[认证] → [模式标签 1B] → [目标地址帧] → [节点应答 2B] → [双向数据]
模式标签：0x00=现行单流 / 0x01=channel 多流（HYDRA_CHANNELS）
地址帧：  2 字节大端长度 + "host:port"
节点应答：0x00 成功 / 0x01 目标连接失败 / 0x02 节点侧 DNS 失败
channel 帧：[cid 8B][seq 4B][len 2B][payload ≤65535B]，seq=0xFFFFFFFF 保留为 ACK 控制帧
```

- 认证失败的流**零字节静默关闭**（防主动探测）
- 节点故障经 `RESET_STREAM/STOP_SENDING` 显式传播错误码：0x11 目标连接失败 / 0x12 DNS 失败 / 0x13 转发错误

---

## 项目结构

```
Hydra-Multipath-Proxy/
├── hydra-protocol/     # 协议定义：认证 token、Noise 握手、日志脱敏、错误类型
├── hydra-obfs/         # 双模式线缆：obfs 混淆层（AsyncUdpSocket）、拥塞控制、流控调优
├── hydra-node/         # 代理节点：QUIC 服务、双栈认证、channel 汇聚、STUN、健康检查、SSRF 过滤
├── hydra-client/       # 客户端库：SOCKS5/HTTP、连接池、故障切换、测速调度、分流、路由
├── hydra-client-gui/   # 桌面 GUI：导航六区、系统托盘、二维码分享、订阅、配置持久化
├── config/             # 节点 toml 样例
├── deploy/             # systemd unit / Docker / install.sh / env.example
└── docs/
    ├── review/         # 三维度审查 + 复审报告（稳定性/安全性/防追踪/PhaseA/五项攻坚）
    ├── design/         # V3 协议设计（4 agent 委员会）、GUI 选型、安卓方案
    ├── improvement/    # 改进计划、施工方案、验收报告、任务书
    ├── assessment/     # 部署运维 + 终端用户双视角评估
    └── guides/         # 部署指南（systemd/Docker/排障表）
```

## 测试

```bash
cargo test --workspace
```

当前 **238 通过 / 0 失败 / 2 ignore**（ignore 均已文档化：V3.2 门③ QUIC 级重放测试脚手架待查[重放防御由真重放单元测试覆盖]、STUN 联网冒烟[需外网]）。

覆盖：端到端 SOCKS5/HTTP → 认证 → 节点 → 目标；**故障切换与自愈**；**多节点加权分发**；**通道聚合 64MB 杀流接管**；**256MB 通道校验和**；握手双栈互通/篡改拒绝；SSRF 拒绝；分流直连；日志脱敏；二维码往返；连接池/缓冲池/恢复探测/错误码传播。

## 安全模型（摘要）

| 能力 | 防 | 不防 |
|---|---|---|
| 证书固定 + Noise-PSK 握手 | 中间人解密/篡改、静态密钥泄漏回溯解密（v3 前向安全） | 端点被攻破 |
| masquerade 模式 | 特征匹配 DPI | 白名单式深度审查（自签证书有固有指纹） |
| obfs 模式 | 特征匹配 DPI | 流量统计/白名单审查（"不明加密 UDP"本身可疑） |
| 域名节点侧解析 + 日志脱敏 | 本机/节点明文浏览记录泄漏 | 应用层泄漏（WebRTC 等需浏览器侧处理） |

完整分析见 [docs/review/03-防追踪性审查报告.md](docs/review/03-防追踪性审查报告.md)。

## 已知限制（如实标注）

- 跨节点**字节级**聚合需要节点间协议（V3.4 v2+），当前为连接级分发 + 单节点内多流通道
- P2P 打洞需信令服务器设计（V3.5）；STUN 目前仅用于公网地址发现
- 客户端 TLS 指纹与浏览器有差异（Rust 生态无 uTLS 等价物，架构级约束）
- 分流为域名后缀版（无 GeoIP）；订阅为自有格式（不对接机场）
- 分享链接含完整凭据时等同于交付节点，仅限可信渠道
- rustls 0.23 / ring 0.17 收敛依赖 quinn 0.11 迁移，暂缓

## 开发路线

- [x] Phase A：认证接线、证书固定、故障切换、SSRF/资源上限、防追踪特征正常化（2026-10）
- [x] V3.4 v2：单节点多流通道聚合 + 上行 ACK/NACK 重传（2026-10）
- [x] 分享体系 v2：凭据链接 + 二维码 + 订阅 + GUI 重排 + 托盘（2026-10）
- [x] V3.2：Noise-PSK 握手 v2 双栈（2026-10）
- [ ] V3.4 v2+：跨节点字节级聚合（节点间 relay 协议，设计已定稿）
- [ ] V3.2 补全：rekey 棘轮、门③测试脚手架修复
- [ ] V3.5：P2P 打洞（信令设计）

完整依据：[docs/improvement/任务书-五项攻坚.md](docs/improvement/任务书-五项攻坚.md) · [验收报告](docs/improvement/验收报告-五项攻坚.md) · [审查总览](docs/review/00-审查总览与改进目标.md)

## 许可证

MIT — 见 [LICENSE](LICENSE)。

## 联系方式

- 项目: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)
