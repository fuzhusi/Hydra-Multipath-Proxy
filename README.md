# Hydra Multipath Proxy

基于 Rust 的多链路聚合代理协议实现，通过多节点并行传输实现带宽聚合和故障恢复。

## 项目简介

Hydra 是一个用户态多链路聚合代理协议，旨在解决传统单点代理的带宽限制和单点故障问题。通过将数据分片并通过多个节点并行传输，Hydra 能够实现：

- **桌面GUI客户端**：基于egui的跨平台桌面应用程序，支持中文界面
- **带宽聚合**：多个节点的带宽叠加，提升传输速度
- **故障自动恢复**：节点故障时自动切换到健康节点
- **智能调度**：基于网络质量动态选择最优节点
- **加密通信**：基于 QUIC 的端到端加密

## 核心功能

### 已实现功能 (Phase 1-4)

#### Phase 1: 基础通信
- ✅ QUIC 加密传输（基于 quinn）
- ✅ 自定义二进制协议
- ✅ 数据包校验和验证
- ✅ 基本代理框架

#### Phase 2: 多节点传输
- ✅ 多节点并行连接
- ✅ 数据分片（Splitter）
- ✅ 数据重组（Assembler）
- ✅ 节点评分调度算法

#### Phase 3: 智能调度
- ✅ 动态节点选择（基于带宽、延迟、丢包率）
- ✅ 自动测速（定期测量节点性能）
- ✅ 故障检测与恢复
- ✅ 节点状态管理（Online/Degraded/Offline）

#### Phase 4: GUI 与系统集成
- ✅ 桌面 GUI 客户端（基于 egui，支持中文界面）
- ✅ 节点连接状态检测与显示
- ✅ 系统全局代理设置（参考 v2rayN 实现）
- ✅ 代理异常退出自动清理
- ✅ 详细连接日志
- ✅ 分享链接功能

### 待实现功能 (Phase 5)

- ⏳ NAT 穿透
- ⏳ 用户认证与管理
- ⏳ Web 管理面板
- ⏳ 流量统计与监控
- ⏳ BBR 拥塞控制
- ⏳ AI 线路预测

## 架构设计

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
│                        │                            │
│              ┌─────────▼─────────┐                  │
│              │  SOCKS5/HTTP Proxy │                  │
│              └─────────┬─────────┘                  │
│                        │                            │
│              ┌─────────▼─────────┐                  │
│              │    Hydra Client    │                  │
│              │  ┌───────────────┐ │                  │
│              │  │   Scheduler   │ │                  │
│              │  └───────┬───────┘ │                  │
│              │  ┌───────▼───────┐ │                  │
│              │  │   Splitter    │ │                  │
│              │  └───────┬───────┘ │                  │
│              │  ┌───────▼───────┐ │                  │
│              │  │  Assembler    │ │                  │
│              │  └───────────────┘ │                  │
│              └─────────┬─────────┘                  │
│                        │                            │
│         ┌──────────────┼──────────────┐             │
│         │              │              │             │
│   ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐     │
│   │  Node A   │  │  Node B   │  │  Node C   │     │
│   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘     │
│         │              │              │             │
│         └──────────────┼──────────────┘             │
│                        │                            │
│                    Internet                         │
└─────────────────────────────────────────────────────┘
```

## 项目结构

```
Hydra-Multipath-Proxy/
├── hydra-protocol/          # 协议定义和共享类型
│   └── src/
│       ├── lib.rs           # 模块导出
│       ├── packet.rs        # 数据包定义
│       ├── session.rs       # 会话管理
│       ├── node.rs          # 节点配置
│       └── error.rs         # 错误类型
├── hydra-node/              # 代理节点服务器
│   └── src/
│       ├── lib.rs           # 模块导出
│       ├── server.rs        # QUIC 服务器
│       ├── handler.rs       # 连接处理
│       ├── config.rs        # 节点配置
│       └── main.rs          # 节点启动入口
├── hydra-client/            # 客户端代理库
│   └── src/
│       ├── lib.rs           # 模块导出
│       ├── proxy.rs         # SOCKS5 代理服务器
│       ├── session.rs       # 会话管理
│       ├── scheduler.rs     # 多路径调度
│       ├── splitter.rs      # 数据分片
│       ├── assembler.rs     # 数据重组
│       ├── transport.rs     # QUIC 传输层
│       ├── crypto.rs        # 加密模块
│       ├── speedtest.rs     # 自动测速
│       ├── share_link.rs    # 分享链接解析
│       └── main.rs          # 客户端启动入口
├── hydra-client-gui/        # 桌面GUI客户端
│   ├── src/
│   │   └── main.rs          # GUI应用程序入口
│   └── fonts/
│       └── NotoSansCJK-Regular.ttc  # 中文字体文件
├── config/                  # 配置文件
│   └── default.toml         # 默认配置
├── Cargo.toml               # 工作空间配置
└── README.md                # 项目说明
```

## 技术栈

- **语言**: Rust 2021 Edition
- **异步运行时**: Tokio
- **网络协议**: QUIC (quinn)
- **加密**: rustls + ring
- **序列化**: serde + serde_json
- **日志**: tracing + tracing-subscriber
- **GUI框架**: egui + eframe (桌面客户端，支持中文界面，使用Noto Sans CJK字体)
- **URL解析**: url crate
- **Base64编码**: base64 crate

## 快速开始

### 环境要求

- Rust 1.70+
- Cargo
- Linux (支持 GNOME/KDE 桌面环境)

### 1. 克隆项目

```bash
git clone https://github.com/fuzhusi/Hydra-Multipath-Proxy.git
cd Hydra-Multipath-Proxy
```

### 2. 编译项目

```bash
# 编译所有组件
cargo build --release

# 或仅编译特定组件
cargo build --release --bin hydra-node
cargo build --release --bin hydra-client
cargo build --release --bin hydra-client-gui
```

### 3. 运行节点服务器

```bash
# 终端 1：启动节点服务器（默认监听 0.0.0.0:8080）
./target/release/hydra-node
```

### 4. 运行客户端代理

#### 方式一：命令行客户端

```bash
# 终端 2：启动客户端代理（默认监听 127.0.0.1:1080）
./target/release/hydra-client

# 指定节点地址
./target/release/hydra-client 43.130.251.236:8080
```

#### 方式二：GUI 客户端（推荐）

```bash
# 运行桌面GUI客户端
./target/release/hydra-client-gui
```

### 5. 配置浏览器

#### Firefox 设置

1. 打开 Firefox → 设置 → 常规 → 网络设置
2. 点击 "设置..."
3. 选择 "手动代理配置"
4. 填写：
   - **SOCKS 主机**: `127.0.0.1`
   - **端口**: `1080`
   - 选择 **SOCKS v5**
   - ✅ 勾选 "为所有协议使用相同代理"
5. 点击 "确定"

#### 或使用系统代理

GUI 客户端会自动设置系统代理，支持：
- GNOME 桌面环境
- KDE 桌面环境
- 环境变量 (http_proxy, https_proxy, all_proxy)

### 6. 测试连接

```bash
# 测试 SOCKS5 代理
curl -x socks5://127.0.0.1:1080 http://google.com

# 测试 HTTPS
curl -x socks5://127.0.0.1:1080 https://google.com
```

## GUI 客户端功能

### 节点管理
- **添加节点**: 输入节点地址并点击"添加"
- **删除节点**: 点击节点列表中的"删除"按钮
- **测试连接**: 点击"测试"按钮验证节点可达性
- **测试所有节点**: 一键测试所有节点的连接状态

### 连接状态显示
- 🟢 **已连接**: 节点可达，显示延迟
- 🔴 **未连接**: 节点不可达
- ⚪ **未测试**: 尚未测试连接状态

### 代理控制
- **启动代理**: 启动 SOCKS5 代理服务
- **停止代理**: 停止代理并清除系统代理设置

### 系统代理设置
参考 v2rayN 实现，支持：
- 设置所有协议的代理（HTTP/HTTPS/FTP/SOCKS）
- 自动添加忽略主机列表（本地地址不走代理）
- 支持 GNOME 和 KDE 桌面环境
- 代理异常退出时自动清除系统代理

### 安全保护
- **正常退出**: 点击"停止代理"或"退出"菜单
- **窗口关闭**: 点击窗口关闭按钮
- **代理崩溃**: 自动检测并清除系统代理
- **程序 panic**: panic hook 自动清除系统代理

### 日志显示
- 实时显示连接日志
- 显示目标地址（域名/IP + 端口）
- 显示 DNS 解析过程
- 显示节点选择和连接过程

## 配置说明

### 配置文件位置

- 默认配置: `config/default.toml`
- 可通过环境变量 `HYDRA_CONFIG` 指定自定义配置路径

### 配置示例

```toml
[server]
listen_addr = "0.0.0.0:8080"  # 节点监听地址
max_connections = 1000         # 最大连接数
buffer_size = 65536            # 缓冲区大小
log_level = "info"             # 日志级别

[client]
proxy_addr = "127.0.0.1:1080"  # 代理监听地址
nodes = [                      # 节点列表
    "127.0.0.1:8080",
    "192.168.1.100:8080",
    "10.0.0.1:8080"
]
```

### 多节点配置

```toml
[client]
proxy_addr = "127.0.0.1:1080"
nodes = [
    "node1.example.com:8080",
    "node2.example.com:8080",
    "node3.example.com:8080"
]
```

## 测试

### 运行所有测试

```bash
cargo test --workspace
```

### 运行特定测试

```bash
# 测试 QUIC 连接
cargo test --test test_client

# 测试多节点传输
cargo test --test test_multipath

# 测试数据分片重组
cargo test --test test_full_multipath

# 测试故障恢复
cargo test --test test_failover

# 测试自动测速
cargo test --test test_speedtest
```

### 测试覆盖率

```bash
# 安装 cargo-tarpaulin
cargo install cargo-tarpaulin

# 生成测试覆盖率报告
cargo tarpaulin --out Html
```

## 性能特性

### 调度算法

节点评分公式：
```
score = bandwidth × 0.5 - latency × 0.3 - loss_rate × 0.2
```

- **带宽权重**: 50% - 优先选择高带宽节点
- **延迟权重**: 30% - 优先选择低延迟节点
- **丢包率权重**: 20% - 优先选择低丢包率节点

### 数据分片

- 默认分片大小: 可配置（测试中使用 10-20 字节）
- 支持乱序接收和重组
- 校验和验证确保数据完整性

### 故障检测

- 连接超时检测（默认 3-5 秒）
- 自动标记故障节点为 Offline
- 自动切换到健康节点
- 定期健康检查（每 30 秒）

## 分享链接

支持节点配置的导入和导出，方便用户分享节点配置。

### 链接格式

```
hydra://address:port?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| address | 节点地址 | - |
| port | 节点端口 | - |
| bandwidth | 带宽 (Mbps) | 100.0 |
| latency | 延迟 (ms) | 10.0 |
| loss_rate | 丢包率 (0-1) | 0.01 |
| load | 负载 (0-1) | 0.5 |
| status | 节点状态 | online |

### 使用示例

```
# 单个节点链接
hydra://192.168.1.100:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online

# 多个节点链接（每行一个）
hydra://192.168.1.100:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online
hydra://192.168.1.101:8080?bandwidth=80&latency=15&loss_rate=0.02&load=0.3&status=online
```

## 故障排除

### 代理无法连接

1. 检查代理是否正在运行：
   ```bash
   ss -tlnp | grep 1080
   ```

2. 测试代理连接：
   ```bash
   curl -v -x socks5://127.0.0.1:1080 http://example.com
   ```

3. 检查节点是否可达：
   - 在 GUI 中点击"测试所有节点"
   - 或查看终端日志

### Firefox 不使用代理

1. 打开 Firefox → 设置 → 常规 → 网络设置
2. 选择 "手动代理配置"
3. 设置 SOCKS 代理：`127.0.0.1:1080`
4. 选择 SOCKS v5

### 代理异常退出后系统代理未清除

手动清除系统代理：
```bash
gsettings set org.gnome.system.proxy mode none
```

或重新启动 GUI 并点击"停止代理"。

## 开发路线

### Phase 1: 基础通信 ✅
- [x] QUIC 加密传输
- [x] 自定义协议定义
- [x] 基本代理框架

### Phase 2: 多节点传输 ✅
- [x] 多节点并行连接
- [x] 数据分片与重组
- [x] 节点调度算法

### Phase 3: 智能调度 ✅
- [x] 动态节点选择
- [x] 自动测速
- [x] 故障检测与恢复

### Phase 4: GUI 与系统集成 ✅
- [x] 桌面 GUI 客户端
- [x] 节点连接状态检测
- [x] 系统全局代理设置
- [x] 代理异常退出自动清理
- [x] 分享链接功能

### Phase 5: 高级功能 ⏳
- [ ] NAT 穿透
- [ ] 用户认证与管理
- [ ] Web 管理面板
- [ ] 流量统计与监控
- [ ] BBR 拥塞控制
- [ ] AI 线路预测

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 代码规范

- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量
- 确保所有测试通过
- 添加必要的注释和文档

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 联系方式

- 项目链接: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)

## 致谢

- [quinn](https://github.com/quinn-rs/quinn) - QUIC 协议实现
- [tokio](https://tokio.rs/) - 异步运行时
- [rustls](https://github.com/ctz/rustls) - TLS 实现
- [serde](https://serde.rs/) - 序列化框架
- [v2rayN](https://github.com/2dust/v2rayN) - 系统代理设置参考
