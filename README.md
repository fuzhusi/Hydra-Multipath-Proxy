# Hydra Multipath Proxy

基于 Rust 的多链路聚合代理协议，通过多个自建节点并行传输实现带宽聚合和故障恢复。

> **项目状态**：个人项目，由 AI 辅助开发。2026-10 完成了一轮三维度（稳定性/安全性/防追踪性）专项审查与 Phase A 安全加固，审查报告见 [docs/review/](docs/review/00-审查总览与改进目标.md)。

## 当前真实能力（如实清单）

以下特性**已实现并在真实数据路径上可验证**：

- **认证传输**：节点必须配置预共享密钥（PSK + HMAC-SHA256 token，30 秒时间窗）。未认证的流被**静默关闭**，不回显任何可区分的错误码，抵御主动探测
- **证书固定（Pinning）**：节点首次启动生成自签证书并**持久化到磁盘**；客户端将该证书加入本地信任根，执行标准 webpki 校验——链路上的中间人无法解密或篡改
- **故障切换**：节点连接失败/流损坏/响应超时 → 自动标记 Offline、清空其连接池、**切换下一节点重试**（最多 3 个候选节点）
- **伪装特征**：ALPN 使用标准 `h3`，SNI 默认 `hydra.node`（可覆盖），keepalive 7–12 秒随机抖动，禁用 TLS 会话恢复（阻断跨连接关联追踪）
- **DNS 隐私**：客户端不解析目标域名，域名只经 QUIC 加密通道交给节点解析，目标域名永不以明文离开本机
- **资源上限**：节点用 Semaphore 强制最大并发连接数；认证前每流只接受固定长度的认证块，防止资源耗尽
- **SOCKS5 + HTTP 代理**：本地 `127.0.0.1:1080`，支持 CONNECT/GET/POST、域名与 IPv4/IPv6 目标
- **地址帧健壮性**：目标地址带 2 字节长度前缀，双方 `read_exact` 读取，杜绝流式截断
- **桌面 GUI**（egui，中文界面）：节点管理、健康检查、代理启停、系统代理设置

**尚未实现**（README 历史版本曾错误声称已实现，审查后如实标注）：

- ⏳ **多路聚合 / 分片重组**：Splitter/Assembler 代码存在但**未接入数据路径**，当前所有流量走单节点单流。这是下一阶段（Phase C）的核心工作
- ⏳ **自动测速与动态调度**：旧测速逻辑已删除，测速将在 Phase B 重写
- ⏳ **流量统计**：模块存在但未接线，GUI 显示恒 0
- ⏳ **NAT 穿透 / 配置文件 / BBR**：未实现

## 快速开始

### 环境要求

- Rust 1.70+
- Windows / Linux / macOS

### 1. 编译

```bash
cargo build --release
```

### 2. 生成认证密钥（客户端与节点必须一致）

```bash
# 任意方式生成 32 字节随机密钥的 hex
openssl rand -hex 32
# 输出示例: a1b2c3d4...（64 个 hex 字符）
```

### 3. 启动节点

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."   # 上一步生成的密钥
./target/release/hydra-node 0.0.0.0:443          # 端口自由指定（推荐 443）
# 或者用环境变量：HYDRA_LISTEN=0.0.0.0:443 ./target/release/hydra-node
```

节点首次启动会生成自签证书并保存（默认当前目录 `hydra-node-cert.der` / `hydra-node-key.der`），日志会打印证书 SHA-256 指纹。**把 `hydra-node-cert.der` 复制到客户端机器。**

> **端口建议**：Hydra 是 QUIC/UDP 协议。与 Hysteria2/TUIC 等开源项目一致，**推荐监听 UDP 443**——443 是 HTTP/3 的标准端口，防火墙和运营商对其有正常流量预期，而 8080 等非常规 UDP 端口容易被重点盯防。注意 Linux 上绑定 443 需要 root 或 `setcap cap_net_bind_service=+ep`。

### 4. 启动客户端

```bash
export HYDRA_AUTH_KEY="a1b2c3d4..."          # 与节点一致
export HYDRA_NODE_CERT=/path/to/hydra-node-cert.der  # 节点证书文件
./target/release/hydra-client 1.2.3.4:443 [更多节点...]
# 本地监听端口也可自选：
./target/release/hydra-client --listen 127.0.0.1:2080 1.2.3.4:443
# 或：HYDRA_LISTEN=127.0.0.1:2080 ./target/release/hydra-client 1.2.3.4:443
```

### 5. 浏览器配置

- SOCKS5: `127.0.0.1:1080`（SOCKS v5）
- 或 HTTP 代理: `127.0.0.1:1080`

### 6. 验证

```bash
curl -x socks5h://127.0.0.1:1080 https://www.baidu.com
curl -x http://127.0.0.1:1080 https://www.google.com
```

### GUI 客户端

```bash
./target/release/hydra-client-gui
```

启动前同样需要设置 `HYDRA_AUTH_KEY` 与 `HYDRA_NODE_CERT` 环境变量；未设置时代理启动会给出明确错误提示。

## 协议（v2，客户端 ↔ 节点）

每条 QUIC 双向流的字节序列：

```
[64 字节认证 token]          AuthToken: 时间戳(8) + HMAC-SHA256(32) + nonce(16) + reserved(8)
[2 字节地址长度（大端）]
[目标地址 "host:port"]        域名或 IP
[节点应答 2 字节]             0x00 成功 / 0x01 连接目标失败 / 0x02 节点侧 DNS 失败
[双向裸转发]                  直至任一方关闭
```

认证失败的流被静默关闭（零字节关流）；应答码只出现在**已认证**的流上，探测者无法据此区分节点行为。

## 环境变量

| 变量 | 端 | 说明 |
|---|---|---|
| `HYDRA_AUTH_KEY` | 双端 | 预共享密钥（hex，解码后 ≥16 字节），**必填** |
| `HYDRA_NODE_CERT` | 客户端 | 节点证书 .der 文件路径，**必填** |
| `HYDRA_SNI` | 客户端 | SNI 伪装域名覆盖（默认 `hydra.node`；须与节点证书 SAN 匹配） |
| `HYDRA_LISTEN` | 双端 | 监听地址（节点默认 `0.0.0.0:8080`，客户端默认 `127.0.0.1:1080`；也可用命令行参数覆盖） |
| `HYDRA_CERT_FILE` / `HYDRA_KEY_FILE` | 节点 | 证书/私钥保存路径（默认 `hydra-node-cert.der` / `hydra-node-key.der`） |
| `HYDRA_CERT_DOMAINS` | 节点 | 证书 SAN，逗号分隔（默认 `hydra.node,localhost`） |
| `HYDRA_MAX_CONNECTIONS` | 节点 | 最大并发连接数（默认 1000） |

## 项目结构

```
Hydra-Multipath-Proxy/
├── hydra-protocol/          # 协议定义：认证 token、节点状态、错误类型
├── hydra-node/              # 代理节点：QUIC 服务、认证、证书持久化、连接数上限
├── hydra-client/            # 客户端库：SOCKS5/HTTP、连接池、故障切换调度
├── hydra-client-gui/        # 桌面 GUI（egui）
├── docs/
│   ├── review/              # 技术团队审查报告（稳定性/安全性/防追踪性）与改进路线图
│   ├── archive/             # 历史审查文档
│   └── Hydra-Multipath-Proxy-RFC-v1.md   # 协议设计 RFC
└── config/                  # （占位，配置系统尚未实现）
```

## 测试

```bash
cargo test --workspace
```

测试覆盖：端到端 SOCKS5 → 认证 → 节点 → 回显服务器；**节点故障自动切换**（杀掉节点1 后请求经节点2 成功）；64KB 大块数据完整往返；分片/重组单元逻辑；连接池与缓冲池。

## 开发路线

- [x] **Phase A（2026-10）**：认证接线、证书固定、故障切换、资源上限、防追踪特征正常化、DNS 隐私、过时测试修复
- [x] **Phase A 复审（2026-10-04）**：两评审组交叉复审，修复认证宽限看门狗（防未认证连接占满配额的 DoS）、时钟偏移容差、超时不对称、连接池锁竞争等 11 项（见 [docs/review/04](docs/review/04-PhaseA代码复审报告.md)）
- [ ] **Phase B**：测速重写（结果写回调度器）、协议错误显式传播（替代静默 FIN）、nonce 防重放表、SSRF 目标过滤、依赖升级 rustls 0.23
- [ ] **Phase C**：真多路径聚合（单连接多 stream 架构）、流量整形、BBR

详细依据见 [docs/review/00-审查总览与改进目标.md](docs/review/00-审查总览与改进目标.md)。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

## 联系方式

- 项目: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)
