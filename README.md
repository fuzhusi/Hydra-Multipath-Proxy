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

### 已实现功能 (Phase 1-3)

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

### 待实现功能 (Phase 4)

- ⏳ NAT 穿透
- ⏳ 用户认证与管理
- ✅ 桌面GUI客户端 (基于egui，支持中文界面)
- ⏳ Web 管理面板
- ⏳ 流量统计与监控

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
│       ├── proxy.rs         # 代理服务器
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

### 1. 克隆项目

```bash
git clone <repository-url>
cd Hydra-Multipath-Proxy
```

### 2. 编译项目

```bash
# 编译所有组件
cargo build --release

# 或仅编译特定组件
cargo build --release --bin hydra-node
cargo build --release --bin hydra-client
```

### 3. 运行节点服务器

```bash
# 终端 1：启动节点服务器（默认监听 0.0.0.0:8080）
cargo run --release --bin hydra-node
```

### 4. 运行客户端代理

```bash
# 终端 2：启动客户端代理（默认监听 127.0.0.1:1080）
cargo run --release --bin hydra-client
```

### 5. 运行GUI客户端（可选）

```bash
# 编译并运行桌面GUI客户端
cargo run --release --bin hydra-client-gui
```

**GUI客户端功能**：
- 节点管理：添加、删除、查看节点状态
- 代理控制：启动、停止代理服务
- 配置管理：修改监听地址、节点列表
- 日志显示：实时查看运行日志
- 中文界面：完整中文支持

### 6. 测试连接

```bash
# 终端 3：运行测试
cargo test --workspace
```

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

## GUI客户端

### 功能特性

- **节点管理**：添加、删除、查看节点状态
- **代理控制**：启动、停止代理服务
- **配置管理**：修改监听地址、节点列表
- **日志显示**：实时查看运行日志
- **中文界面**：完整中文支持，使用Noto Sans CJK字体
- **分享链接**：导入/导出节点配置分享链接

### 运行GUI客户端

```bash
# 编译并运行桌面GUI客户端
cargo run --release --bin hydra-client-gui
```

### 界面布局

- **左侧边栏**：节点管理、代理控制、状态信息
- **中央区域**：运行日志显示
- **顶部菜单**：文件、帮助菜单
- **分享链接对话框**：导入/导出节点配置

### 中文支持

- 使用Google Noto Sans CJK字体
- 支持中文界面显示
- 字体文件位于 `hydra-client-gui/fonts/NotoSansCJK-Regular.ttc`

### 分享链接

支持节点配置的导入和导出，方便用户分享节点配置。

#### 链接格式

```
hydra://address:port?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online
```

#### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| address | 节点地址 | - |
| port | 节点端口 | - |
| bandwidth | 带宽 (Mbps) | 100.0 |
| latency | 延迟 (ms) | 10.0 |
| loss_rate | 丢包率 (0-1) | 0.01 |
| load | 负载 (0-1) | 0.5 |
| status | 节点状态 | online |

#### 状态值

- `online`：在线
- `degraded`：降级
- `offline`：离线

#### 使用示例

```
# 单个节点链接
hydra://192.168.1.100:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online

# 多个节点链接（每行一个）
hydra://192.168.1.100:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online
hydra://192.168.1.101:8080?bandwidth=80&latency=15&loss_rate=0.02&load=0.3&status=online
```

#### GUI操作

1. **导出分享链接**：点击"导出分享链接"按钮，复制生成的链接
2. **导入分享链接**：点击"导入分享链接"按钮，粘贴链接并点击"导入"

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

### Phase 4: 高级功能 ⏳
- [ ] NAT 穿透
- [ ] 用户认证与管理
- [x] 桌面GUI客户端 (基于egui，支持中文界面)
- [x] 分享链接功能 (导入/导出节点配置)
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

版权所有 (c) 2024 fuzhusi。保留所有权利。

未经版权所有者书面许可，不得复制、修改、分发或使用本软件的任何部分。

## 联系方式

- 作者: fuzhusi
- 项目链接: [GitHub Repository](https://github.com/fuzhusi/Hydra-Multipath-Proxy)
- 问题反馈: [Issues](https://github.com/fuzhusi/Hydra-Multipath-Proxy/issues)

## 致谢

- [quinn](https://github.com/quinn-rs/quinn) - QUIC 协议实现
- [tokio](https://tokio.rs/) - 异步运行时
- [rustls](https://github.com/ctz/rustls) - TLS 实现
- [serde](https://serde.rs/) - 序列化框架