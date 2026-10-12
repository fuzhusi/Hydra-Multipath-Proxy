# hydra-core 基准（批次 B0）

criterion 基线：UDP 中继链路三面（帧构造/校验和/路由 decide）。后续批次 B
每项优化的前后对比以本表为基线，**数字随代码变化必须同步更新本文件**。

## 运行方法

```bash
# 仅计时（默认，不启用计数分配器）
cargo bench -p hydra-core

# 计时 + 分配计数（bench-alloc feature 门控 #[global_allocator]，
# 输出附 alloc-op 行：allocs/op 与 bytes/op；生产构建零影响）
cargo bench -p hydra-core --features bench-alloc

# 单组
cargo bench -p hydra-core -- udp_frame
```

说明：
- `roundtrip` 基准经 current-thread runtime `block_on` 驱动（`read_udp_frame`
  是 async），对照组 `blockon_overhead_control` 给出 `block_on` 常数开销，
  解读往返数字时请扣除；
- `checksum16` 实现位于 `hydra-client/src/tun.rs`（B0 起 `pub` 导出），
  经 dev-dependency 回环引用（仅基准/测试编译期）。

## 基线数字（Windows 本地实测，2026-10-12）

环境：Windows 11 · rustc 1.99.0 (b940084d7 2026-09-28) · release（criterion 默认
3s 预热 + 100 样本）· `cargo bench -p hydra-core --features bench-alloc`

| 基准 | 中位时间 | allocs/op | bytes/op |
|---|---|---|---|
| `udp_frame/encode_1200B`（会话帧构造，1200B 载荷） | **85.5 ns** | 1.00 | 1219 |
| `udp_frame/encode_64B`（DNS 量级小报文） | **74.4 ns** | — | — |
| `udp_frame/roundtrip_1200B_blockon`（构造→解析往返） | **737.3 ns** | — | — |
| `udp_frame/blockon_overhead_control`（block_on 空转对照） | **189.3 ns** | — | — |
| `checksum16/576B`（RFC 1071，B2 单遍化基线） | **57.8 ns** | 0 | 0 |
| `routing_decide/geoip_cn_hit`（114.114.114.114 命中直连） | **28.0 ns** | — | — |
| `routing_decide/geoip_cn_miss`（8.8.8.8 未命中走节点） | **27.2 ns** | 0 | 0 |

### 批次 B 优化目标对照（方案 §二批次 B）

| 项 | 基线断言 | 目标 |
|---|---|---|
| B1 UDP 回包缓冲复用 | `build_udp_reply` 每包 1 次堆分配 | 稳态分配 0 |
| B2 checksum16 单遍化 | `checksum16/576B` = 57.8 ns（含拼接分配的调用面在 tun.rs 伪首部路径） | 免拼接 Vec + 等价性测试，时间不回退 |
| B3 udp_relay 帧构造复用 | `encode_1200B` = 1.00 allocs/op | 帧构造分配 0 |

## 基准面说明

1. **udp_relay 帧构造**：`hydra_protocol::udp_frame::encode_udp_data`
   （sid + 掩码前 target + 载荷 → 变长会话帧）；往返含 `read_udp_frame` 解析。
2. **checksum16**：TUN TCP/UDP 伪首部校验和（576B 段），当前两遍实现
   （拼接后反码求和）。
3. **路由 decide**：`RuleEngine::builtin_cn().decide(SocketAddr)`——内置
   GeoIP-CN 表命中/未命中（每连接建连一次，热路径零分配已由基线验证）。
