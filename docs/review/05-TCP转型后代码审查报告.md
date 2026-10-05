# Hydra-Multipath-Proxy TCP 转型后代码审查报告

- **日期**：2026-10-05（TCP/TLS 转型完成后）
- **范围**：`hydra-protocol`、`hydra-client`、`hydra-client-gui`、`hydra-node`、workspace 级配置与 `deploy/` 脚本
- **方法**：静态代码审查（多 agent 独立精读后汇总）。五份独立审查（hydra-protocol、hydra-client、hydra-client-gui、hydra-node、workspace 横切面）去重、合并、按严重度与类别整理而成。
- **性质**：纯只读审查，未修改任何仓库文件。

---

## 执行摘要

### 问题总数统计

**总计 36 条**（去重合并后；跨报告重复指出的问题已合并为一条，保留两处位置的以"×"标注）。

| 严重度 | bug | security | performance | maintainability | 小计 |
|--------|-----|----------|-------------|-----------------|------|
| P0 | 2 | 0 | 0 | 0 | **2** |
| P1 | 4 | 2 | 2 | 1 | **9** |
| P2 | 2 | 4 | 7 | 3 | **16** |
| P3 | 3 | 0 | 2 | 4 | **9** |
| **合计** | **11** | **6** | **11** | **8** | **36** |

| 类别 | 数量 |
|------|------|
| bug | 11 |
| performance | 11 |
| maintainability | 8 |
| security | 6 |

### 去重说明

以下问题在多份审查中重复报告，已合并：

- **目标失败误判节点离线**（hydra-client 与横切面均报 P0/P1）→ 合并为 R-01（P0）。
- **SOCKS5 单次 read 假设**（hydra-client 与横切面均报 P1）→ 合并为 R-03（P1），含粘包丢数据与拆段断连两个方向。
- **每连接重建 rustls ClientConfig**（hydra-client 与横切面均报）→ 合并为 R-06（P2/performance）。
- **traffic 全局 Mutex 热路径争用**（两份均报）→ 合并为 R-08（P2/performance）。
- **quinn 0.10 死依赖 / Quinn* 错误变体 / dangerous_configuration**（hydra-protocol 与横切面均报）→ 合并为 R-14（P1/maintainability）。
- **packet/splitter 死代码**（hydra-protocol 报性能，hydra-client 报 maintainability，横切面报死代码清单）→ 合并为 R-15（P2/maintainability）。
- **TCP_NODELAY 缺失**（横切面独有量化）→ R-07（P2/performance）。

### Top 风险（按影响排序）

1. **R-01（P0/bug）目标连接失败被误判为节点故障**：访问死域名/被 SSRF 拒绝的目标会把健康节点（最多连锁 3 个）标记 Offline，多用户场景下级联失去可用节点，故障切换与评分系统被系统性污染。违反 README "节点存活但目标不可达不应触发切换" 的明确声明。
2. **R-02（P0/bug）多节点证书按下标 zip 配对 + CLI 仅支持单证书**：非首节点 Noise 证书指纹通道绑定必败 → 握手必败 → 离线-恢复振荡，多节点容灾静默退化为单节点。
3. **R-03/R-04（P1/bug）SOCKS5 与 HTTP 明文代理解析缺陷**：单次 read 假设导致偶发连接失败与静默数据丢失；keep-alive 第二请求被错误路由；IPv6 Host 解析产生错误目标。
4. **R-10/R-11（P1/security）日志脱敏策略被违反**：客户端与节点侧在 info/error 级输出明文目标地址，默认日志配置下浏览历史明文落盘，且节点侧日志恰是脱敏设计要防的远端泄点。
5. **R-17（P2/bug）节点数据期无任何超时**：合法 PSK 持有者可低成本占满 1000 并发配额，accept 循环停摆。
6. **R-20（P2/bug）配置文件非原子写入**：崩溃/断电可丢失全部配置（含明文密钥）。

整体评价（正面结论）：核心密码学用法正确——NNpsk2 消息顺序无误、confirm 比对走 constant_time、HKDF 域分离合理、节点侧新鲜临时 e 抗重放且有测试；tcp_frame 帧解析无 DoS 面；GUI 后台任务模式与安全细节（密钥掩码、0600 权限）到位；deploy 的 systemd/Docker 加固整体质量高；未发现凭据泄漏到 debug 之外的脱敏系统性失效（日志类问题见 R-10~R-12）。

---

## P0 问题详单

### R-01 [P0/bug] 目标连接失败（应答码 0x01/0x02）被误判为节点故障，健康节点被错误标记 Offline

- **位置**：`hydra-client/src/proxy.rs` `open_target()` L289-328 × `hydra-protocol/src/tcp_frame.rs` `read_reply()` L107-135
- **机理**：`read_reply` 把节点应用层应答码 0x01（目标连接失败，含 SSRF 拒绝）与 0x02（节点侧 DNS 失败）都折叠为 `HydraError::ConnectionError`，与 TCP/TLS/握手传输失败共用同一错误类型、无字段区分。`open_target` 对 `connect_target` 的任何 `Err` 一律执行 `scheduler.mark_node_offline(&node.address)` 并切换下一节点重试同一目标。用户访问一个拒绝连接/不存在的目标时，当前健康节点被标 Offline，failover 循环连锁把候选前 3 个全部健康节点标 Offline（横切面审查确认此连锁上限）。节点恢复依赖后台探测（默认 30s ± 抖动，`speedtest.rs` L34），期间新连接全部失去 Online 节点；评分系统与调度被污染。README 明确声明"节点存活但目标不可达"不应触发切换。
- **影响**：批量访问失效目标（网页内多个死链、端口扫描器、多用户共享节点）时形成级联不可用；故障切换机制对最常见的故障形态（目标侧故障）系统性误动作。
- **修复方案**：让目标失败可分类——在 `HydraError` 增加变体（如 `TargetRejected(u8)` / `DnsFailure`），`tcp_frame::read_reply` 对 0x01/0x02 返回该变体（或返回 `enum Reply`）；`open_target` 的 `Err` 分支匹配到这两类时不调用 `mark_node_offline`、不切换节点，直接向上游返回失败（客户端回 SOCKS5 0x01 / HTTP 502）；仅对真正的传输类错误（TCP connect/TLS/Noise/超时/静默关流）执行离线标记与 failover。

### R-02 [P0/bug] 多节点证书映射按下标配对 + CLI 仅支持单证书文件，非首节点必然握手失败并被反复误判离线

- **位置**：`hydra-client/src/proxy.rs` `start()` L127-133（`cert_by_node` 按下标 zip 配对）、L131-133/L280-288（fallback 首证书分支）；`hydra-client/src/lib.rs` `node_certs_from_env()` L43-49；`hydra-client/src/main.rs` L87-90
- **机理**：`proxy.rs:128` 用 `nodes.iter().zip(node_certs.iter())` 按"注入顺序恰好一致"建立映射，`ProxyServer` 无任何 API 表达"某节点用哪张证书"。而 `node_certs_from_env()` 只读 `HYDRA_NODE_CERT` 一个文件、返回 `vec![der]`，故 CLI 多节点模式下除首节点外全部落入 fallback（回退 `trust_certs.first()`）。README:156 与 `tcp_transport.rs:99-100` 自己写明：Noise confirm 的证书指纹通道绑定必须用目标节点自己的证书，指纹取错 = 对端 confirm 必败 = 静默关流。后果链：节点 B 证书 ≠ 节点 A 证书 → 连 B 用 A 的证书算指纹 → 握手必败 → B 被 mark_node_offline → 探测恢复 TLS 后下次业务连接再次失败再次离线，形成离线-恢复振荡。
- **影响**：多节点容灾静默退化为单节点（仅 zip 恰好配对的首节点可用），且无任何显式报错，用户无从发现。
- **修复方案**：① 引入显式 per-node 绑定的 `NodeConfig { addr, cert_der }` 列表；至少 `with_nodes`/`with_node_certs` 在 `nodes.len() != node_certs.len()` 时拒绝启动（fail-fast），而非告警后带病运行；② `node_certs_from_env` 支持 `HYDRA_NODE_CERT` 多路径（路径分隔符）或 `HYDRA_NODE_CERT_<idx>`，保证 CLI 多节点每节点有对应证书；③ 运行期自愈：`connect_target` 收到 Noise 握手失败时（证书映射错位的确定性信号），遍历 `trust_certs` 其余证书重试握手一次，成功则回写 `cert_by_node`。

---

## P1 问题详单

### R-03 [P1/bug] SOCKS5 握手与请求假设单次 read 读全：拆段即解析失败断连；粘连即数据丢失

- **位置**：`hydra-client/src/proxy.rs` `handle_socks5()` L611-626（单次 read）、L588-598（`initial_len < 2` 判定）、`handle_connection` L216（首读）；另 L359（HTTP 头）见 R-28
- **机理**：两个方向的缺陷：
  1. **拆段**：读 SOCKS5 请求只调用一次 `stream.read(&mut buf)`（320B 栈缓冲）后按 n 做长度校验（L618、L651、L677、L709）。TCP 是字节流，CONNECT 请求（域名 255 字节时共 262 字节）可能被拆成两段，首读不足 → 回 0x01 错误码断连，表现为偶发难复现的"第一个网站打不开，重试就好"。greeting 首读只收到 0x05 单字节时同理被 `initial_len < 2` 拒绝。
  2. **粘连（数据丢失）**：客户端把 CONNECT 请求与首批上行数据合并发送时，超出请求长度的字节被静默丢弃，转发数据从此错位。HTTP 路径已有 raw 缓冲 + `find_header_end` 的正确做法，SOCKS5 未对齐。
- **影响**：代理链、慢网络、Nagle 延迟、低延迟本地客户端下偶发断连或静默数据错位。
- **修复方案**：改为按协议状态机循环凑齐：greeting 先 `read_exact` 2 字节（VER+NMETHODS），再按 NMETHODS `read_exact` 读 methods；请求先 `read_exact` 4 字节（VER/CMD/RSV/ATYP），再按 ATYP `read_exact` 补齐地址+端口；解析后保留缓冲中剩余字节，在 relay 建立后作为初始上行数据先写入 `NodeLink.send`。可复用一个 `fill_buf` 辅助函数（读满所需字节数、保留多读字节）。

### R-04 [P1/bug] HTTP 明文代理：keep-alive 第二个请求被字节泵发往首个 target；IPv6 Host 解析产生错误目标

- **位置**：`hydra-client/src/proxy.rs` `handle_http()` L430-530（非 CONNECT 路径）、L460-468（端口解析）
- **机理**：① 非 CONNECT 请求转发到一个 target 后进入 `relay_bidirectional` 纯字节泵；浏览器对普通 HTTP 代理默认复用连接（HTTP/1.1 keep-alive），同一连接上的第二个请求可能指向不同 Host，但会被原样发给第一个 target 的源服务器——多数服务器容错返回错误内容或 400，属静默错误路由。② 端口解析 L463-465 对裸 IPv6 Host（如 `2001:db8::1`，无括号无端口）执行 `splitn(2, ':')` 得 `("2001", "db8::1")`，端口 parse 失败静默取 80，目标变成 `2001:80`——连接到错误主机名。
- **影响**：经明文 HTTP 代理模式的流量被错误路由到错误主机/错误内容。
- **修复方案**：① 普通 HTTP 请求完成一次响应后检测连接语义：响应含 `Connection: close` 或 HTTP/1.0 按现状；否则在转发响应结束后主动关闭客户端连接（禁用该连接上的多请求），或在转发前改写/追加 `Connection: close` 头并转发后即关。② IPv6 解析改用 `rsplit_once(':')` 并检查 host 部分是否含多个 `:`，含则视为裸 IPv6（默认端口 80、目标格式化补方括号），无法解析时返回 400 而非静默拼错目标。

### R-05 [P1/bug] PSK 长度域三方不一致：16–31 字节密钥通过启动校验但每次握手必失败

- **位置**：`hydra-protocol/src/handshake.rs` `build()` L128-129；`hydra-node/src/config.rs` L306；`hydra-client` 的 `decode_auth_key` 路径
- **机理**：`handshake.rs:128` 校验 `psk.len()` 为 `1..=32`，但 snow NNpsk2 要求恰好 32 字节（build 阶段返回 `ValidatePskLengths`）；而 node 侧 `config.rs:306` 与 README 只要求 ≥16 字节。用户按文档生成 16–31 字节密钥时两端启动正常，之后每条连接握手都在 `build_initiator`/`build_responder` 失败并静默关流，错误仅在 debug 日志可见，极难排障。
- **影响**：文档允许的合法配置导致全部连接静默失败。
- **修复方案**：`build()` 改为强制 `psk.len() == 32` 并在错误信息中说明；node/client 两侧 `decode_auth_key` 在启动期做 `== 32` 校验 fail-fast。若确要支持短密钥，需两端统一用 HKDF 拉伸到 32 字节（属协议变更，需谨慎）。

### R-06 [P1/performance] GUI 渲染循环内每帧执行 block_in_place + block_on 读取流量统计

- **位置**：`hydra-client-gui/src/main.rs` `ui_overview` 约 L2084-2086（配合 `main()` L3206 的 `#[tokio::main]`）
- **机理**：流量卡片在代理运行期间每 UI 帧执行 `tokio::task::block_in_place(|| Handle::current().block_on(monitor.get_stats()))`。整个 GUI 事件循环跑在多线程 runtime 的一个 worker 上；`block_in_place` 每帧触发一次 worker 降级与任务迁移 + 一次 block_on 唤醒（≥2 次 futex/epoll 级系统调用与队列操作）。repaint 周期 500ms（L1807），交互时可达 60fps，开销放大 120 倍；其他 worker 被 proxy 任务占满时 `get_stats` 排队，直接表现为 UI 卡顿。而 `get_stats` 只是读计数器/瞬时速率，完全无需进 runtime。
- **影响**：交互期间 UI 卡顿、拖拽掉帧。
- **修复方案**：速率采样移出渲染路径——启动代理时 spawn 后台 `std::thread`（内含小 runtime 或直接同步读 AtomicU64），每 500ms 算好 `TrafficStats` 放入 `Arc<RwLock>`/mpsc，UI 帧只读缓存；建议同时把 `main` 从 `#[tokio::main]` 改为普通 fn（GUI 进程不需要常驻 runtime，代理线程已自建）。

### R-07 [P1/performance] 二维码图片识别在 UI 线程同步执行，大图必然冻结界面且内存峰值高

- **位置**：`hydra-client-gui/src/main.rs` `import_from_qr_image` 约 L1209-1243；`qr.rs` `decode_qr_from_bytes` L49-65
- **机理**：点击"从二维码图片导入"后，`std::fs::read` → `image::load_from_memory` → `to_luma8` → `rqrr::PreparedImage::prepare + detect_grids` 全部在 egui update 调用栈上同步执行。量化：一张 4000×3000 JPEG 解码约 150-400ms，`to_luma8` 额外分配 12MB 灰度缓冲并全图转换一次，rqrr 的 prepare（积分图）+ detect_grids 是全图多尺度扫描，大图需数百 ms 到数秒——期间 UI 完全冻结；内存峰值约 60MB（原始字节 + RGBA 48MB + 灰度 12MB 同时存活）。
- **影响**：常见操作（手机截图导入）导致界面秒级无响应。
- **修复方案**：① 解码前用 `image::imageops::resize`（或 thumbnails）把长边缩到 ≤1000px 再 `to_luma8` 喂给 rqrr——二维码定位对降采样非常鲁棒，像素工作量从 ~12MP 降到 ~1MP（约 12 倍）；② 整段 decode+parse 移入 `std::thread::spawn`，经既有 mpsc 模式回投 UI（仓库 `node_test_receiver` 已是同款范式）。

### R-08 [P1/security] 客户端 info 级日志输出明文目标地址，违反"info 一律脱敏"承诺

- **位置**：`hydra-client/src/tcp_transport.rs` `connect_target` L214
- **机理**：`info!("✓ TCP/TLS target {} opened via node {}", target, node_addr)`——target 是完整明文域名:端口，每条成功连接必打。README 与 log.rs/协议注释均承诺"访问目标一律 SHA-256 短哈希，明文仅 RUST_LOG=debug 可见"；客户端默认 `RUST_LOG=info` 即把全部浏览历史明文落盘。同文件 `open_target`/relay 路径都正确使用了 `mask_target`，唯独此处遗漏。
- **影响**：客户端日志（本地磁盘）泄漏完整浏览历史。
- **修复方案**：改为 `mask_target(target)`；建议加 CI grep 门禁（禁止 info 及以上级别直接输出 target/first_line 等明文变量）。

### R-09 [P1/security] 节点侧 error 级日志输出目标明文，与同函数内脱敏注释自相矛盾

- **位置**：`hydra-node/src/handler.rs` `resolve_and_connect` L261、L274、L333-336、L349-352（对照 L239-241）
- **机理**：函数开头 L239 注释声明"info 级一律短哈希，完整明文仅 debug 级可见"，L240-241 也确实分了 info(mask)/debug(plaintext)；但后续 DNS 失败（L261/L274 `error!` target_addr_str）、目标连接失败（L333-336）、连接超时（L349-352）全部在 error!（默认 info 过滤器下必然开启）输出明文。节点侧日志恰是"远端节点"泄点，是脱敏设计明确要防的对象。
- **影响**：用户访问的任何连不上的域名都明文进远端节点日志。
- **修复方案**：四处 error! 统一改为 `mask_target(&target_addr_str)`（或 `&target_addr.to_string()`），明文版本以 debug! 并行保留。

### R-10 [P1/maintainability] QUIC 死依赖 quinn 0.10 仍被全 workspace 编译；dangerous_configuration feature 声明未使用

- **位置**：`hydra-protocol/Cargo.toml` L5（quinn）、L7（dangerous_configuration）；`hydra-protocol/src/error.rs` L26-36
- **机理**：QUIC 路径删除后，quinn 在源码里只剩 error.rs 的 Quinn* 错误变体（生产代码零构造）与 handshake.rs 的注释；但因是 path 依赖，hydra-node、hydra-client 连同 GUI 全都要编译 quinn + quinn-proto 及其依赖树（Cargo.lock 可证），纯增构建时间与供应链面（release 二进制约 +1MB 量级）。另外 rustls 的 `dangerous_configuration` feature 全仓 grep 无任何 `danger::` 使用（pinning 走 RootCertStore 标准校验），属误留的高危 feature 开关，扩大供应链审计面。
- **影响**：全 workspace 的构建时间、二进制体积与供应链审计面无谓扩大。
- **修复方案**：删除 quinn 依赖与 error.rs 全部 Quinn* 变体（及同检无引用的 serde_bytes 等）；删除 `dangerous_configuration` feature。预计减少 10+ 个 crate 的编译（含 node 发布构建）。

---

## 性能提升方案

以下整合全部 performance 类问题（11 条），按优先级组织为短期/中期路线。短期项改动小、收益确定；中期项需要结构性改动。

### 短期（一天内可完成，收益/成本比最高）

| 优先级 | 编号 | 措施 | 预期收益 |
|--------|------|------|----------|
| ★★★ | R-11 | 全仓三处 `TcpStream` 拿到后立即 `set_nodelay(true)`（客户端→节点 `tcp_transport.rs` L138、节点 accept 后 `tcp_server.rs` L57、节点→目标 `handler.rs` L317） | 消除 Nagle+delayed ACK 造成的每连接 40-200ms 级延迟毛刺；本项目无连接复用、每 HTTPS 请求新建连接，握手 4 往返即可能累计 +160ms 首连延迟。一行/处，收益最确定 |
| ★★★ | R-12 | 启动时构建一次 `TlsConnector`（`Arc<rustls::ClientConfig>`）存入 `TcpCreds`（或按 trust_certs 内容键的 OnceLock 缓存），`connect_target` 与 `speedtest::probe_connect` 复用，删除两处重复的 ~30 行配置代码 | 每连接省 0.5-2ms CPU 与数次 KB 级堆分配；100 conn/s 浏览负载即每秒省 50-200ms CPU；同时消除探测与主链路配置漂移的风险（SNI 每节点不同不影响复用，ServerName 在 connect 时传入） |
| ★★☆ | R-13 | `TcpCreds.cert_by_node` 改为 `Arc<HashMap<SocketAddr, Arc<[u8]>>>`，`open_target` 中 `get()` 后直接传 `&cert`/Arc clone，去掉 `.cloned()` | `TcpCreds::clone` 退化为 4 个 Arc 计数递增；消除每连接整张证书表的深拷贝（100 并发 = 100 份完整证书副本） |
| ★★☆ | R-14 | relay 缓冲从 2×64KB 降到 16KB（与 TLS 1.3 记录上限对齐）或 32KB | 1000 并发下常驻内存从 128MB 降到 32-64MB；64KB 缓冲超出单条 TLS 记录实际读出量（≤16KB），无收益 |
| ★★☆ | R-15 | GUI 二维码导入：解码前缩图至长边 ≤1000px + 移入后台线程（R-07 修复） | 像素工作量降 ~12 倍，UI 不再冻结 |
| ★★☆ | R-16 | GUI 流量统计移出渲染帧：后台线程 500ms 采样 → 缓存，UI 只读（R-06 修复）；建议同步去掉 `#[tokio::main]` | 消除交互期每帧 block_in_place/block_on 开销与 UI 卡顿 |

### 中期（需要结构性改动，按序推进）

| 优先级 | 编号 | 措施 | 预期收益 |
|--------|------|------|----------|
| ★★★ | R-17 | traffic 热路径去锁：① `CountingStream` 先在本地 u64 累加（per-connection 实例加 `pending: u64`），达阈值（每 64KB 或 100ms）才调一次 `record_*_sync`；② `SpeedHistory` 改固定槽位时间片桶（如 10 个 500ms 桶，`AtomicU64[10]` + 周期轮转）替代 `Vec<(Instant,u64)>` + O(n) retain，写入 O(1)、读取 O(10)，彻底去掉 Mutex | 锁竞争次数降 1-2 个数量级；消除所有连接唯一全局串行点（1Gbps ÷ 64KB ≈ 每方向 2000 lock/s）；窗口内 ~8000 条样本的每次全表 retain 也一并消除。此数据仅服务 GUI 速度显示，精度需求极低 |
| ★★☆ | R-18 | GUI 健康检查复用进程级探测 runtime（`OnceLock<Runtime>` 或专用探测线程 + 通道），删除 `test_node_connection` 未使用的 `node_certs` 参数与逐节点 `certs.clone()` | 消除每 30s 一次的多线程 runtime 冷启动/销毁（num_cpus 个 worker + epoll 实例 + 线程创建毛刺）；三个触发源（启动、周期、手动）全部受益 |
| ★★☆ | R-19 | 节点列表渲染：在 config 变更点构建一次 addr→source 的 HashMap 缓存，渲染期 O(1) 查表；heading 统计用缓存计数一次；每帧整表克隆改为索引迭代/标量克隆（R-24 修复） | 消除每帧 O(节点数×订阅节点数)×3 的 String 比较与数千次 String 分配（300×300 订阅场景交互期 ~1600 万次比较/秒） |
| ★☆☆ | R-20 | 分享对话框 URL：`to_share_url()` 仅在 share_link/share_compact 变化时调用一次并缓存（R-25 修复） | 消除打开期间每帧 1.5-2.5KB URL 的重生成、base64/hex 编码与整串 clone（60fps 下 ~300KB/s 无谓分配） |

### 依赖层面的性能/体积项（与 maintainability 交叉，详见 R-30/R-31）

- 删除 quinn 0.10 死依赖（R-10，P1）：预计减少 10+ crate 编译，release 二进制 -1MB 量级。
- 收敛 ring 0.16/0.17 双栈与 rustls 0.21 EOL（R-31，P2）：消除两份 SHA-256/AES 汇编同时编入产物。
- tokio 从 `features=["full"]` 收敛到实际所需（rt-multi-thread/net/io-util/time/sync/macros）：缩短 node 交叉编译时间（归入 R-31）。
- 删除 packet.rs/splitter.rs 死代码（R-15/R-32）：若启用，`calculate_checksum` 为逐位软件 CRC32（每字节 8 次内层迭代，比查表 crc32fast 慢 8 倍以上），且 TCP+TLS AEAD 已保证完整性，校验纯冗余；每 chunk 还有两次冗余拷贝（同一数据 3 份内存）。

---

## P2 问题详单

### R-21 [P2/bug] hex_decode 对含多字节 UTF-8 的输入 panic（字节切片越字符边界）

- **位置**：`hydra-protocol/src/auth.rs` `hex_decode` L169-180
- **机理**：`hex.len()` 为字节长度，循环内 `&hex[i..i+2]` 按字节切片；含多字节字符且总字节长为偶数的输入（如 `"a密"`）会在字符内部切片，触发 `byte index not a char boundary` panic。该函数是节点（config.rs:305）与客户端（lib.rs:35）读取密钥的必经路径。
- **影响**：一次误粘贴即让节点进程启动即崩而非报错。
- **修复方案**：先拒绝非 ASCII（`!hex.is_ascii()` 返回 Err），再用 `hex.as_bytes()` + 手写 hex 值表或 base16ct/hex crate 按字节解码。

### R-22 [P2/security] legacy AuthToken 仍公开导出且窗口内可重放、依赖系统时钟

- **位置**：`hydra-protocol/src/auth.rs` `AuthToken::verify` L61-97；`lib.rs:10` 导出
- **机理**：QUIC 路径已删，AuthToken 无任何调用方但仍经 `pub use auth::*` 导出。verify 无 nonce 重放表，max_age 窗口内同一 token 可无限重放，且依赖 SystemTime（与 v3 握手"全程不读系统时间"的设计相悖）。留存风险是未来代码误用静默回退到弱方案。
- **修复方案**：删除 AuthToken（及无调用方的 AuthConfig/PBKDF2 函数）；或加 `#[deprecated]` 并文档标注"仅 QUIC legacy，窗口内可重放"。

### R-23 [P2/security] error 级 dump 原始请求字节/请求行，含目标域名明文

- **位置**：`hydra-client/src/proxy.rs` L394、L592、L619
- **机理**：L619 `error!("Invalid SOCKS5 request: {:?}", &buf[..n])` 把含目标域名/IP 的原始 SOCKS 请求字节打进 error 日志；L592 同理 dump greeting 字节；L394 输出完整 HTTP 请求行（含 URL）。虽只在畸形请求时触发，但与"info 及以上一律脱敏"冲突，且恶意方可用畸形请求把任意"明文目标+时间戳"写入日志。
- **修复方案**：只记录长度/atyp/首字节等结构信息（脱敏后），字节 dump 降到 debug!。

### R-24 [P2/security] 运行期在 UI 线程调用 std::env::set_var/remove_var，与后台线程的 env 读取构成数据竞争（UB）

- **位置**：`hydra-client-gui/src/main.rs` `set_system_proxy` L801-806、`remove_system_proxy_static` L911-916、`start_proxy` L626（`config::apply_env_overrides`，config.rs L326-330）
- **机理**：`set_var`/`remove_var` 在进程存活期任意时刻对 6 个 env var 写入。Rust std 明确文档：多线程进程并发读写 env 是 UB（2024 edition 已把 set_var 标为 unsafe）。而进程内确定存在并发读者：代理线程、健康检查线程、订阅线程都可能调用 `std::env::var`。`apply_env_overrides` 虽设计为"spawn 前"调用，但 `start_proxy` L626 在代理停止后、其他后台线程可能仍存活时再次调用，"不会并发"的前提不成立。
- **修复方案**：彻底去掉运行期 env 写入：① set_system_proxy 的 6 个 env var 对 GUI 自身进程无实际收益（子进程才继承），直接删除；② probe_interval_secs 不经 env 中转——给 ProxyServer/Scheduler 增加显式 `with_probe_interval_secs()` 构造参数（hydra-client 是自有 crate）；若暂不能改，则只在 `HydraApp::new`（确认尚无线程）时调用一次 set_var，start_proxy 中的重复调用删除。

### R-25 [P2/security] Dockerfile COPY . . 且仓库无 .dockerignore：构建上下文吸入 target/ 与本地未忽略的密钥文件

- **位置**：`deploy/docker/Dockerfile` L11（仓库根无 .dockerignore，已验证）
- **机理**：.gitignore 只对 git 生效，docker build 的 COPY . . 会把整个构建上下文发进 daemon：target/（GB 级，上下文传输极慢）以及真实存在于工作区的敏感文件——`.probe/key.hex`（探测密钥）、`.e2e/` 下 cert/key、`hydra-node/hydra-node-key.der`（节点私钥）。这些文件虽未进最终镜像 runtime 层，但全部进入构建上下文与 builder 层缓存，私钥落进镜像层可被 docker history/layer 导出还原。
- **修复方案**：新增 `.dockerignore`：`target/`、`.e2e/`、`.probe/`、`*.der`、`*.pem`、`*.log`、`node.toml`、`.git/`。同时 Dockerfile 改为先 COPY 各 Cargo.toml + 虚 src 做 `cargo fetch` 建依赖缓存层，再 COPY 全源（注释中"无法只拷 manifests"的说法不成立）。

### R-26 [P2/security] 节点侧 DNS 解析无超时，可拖住已认证连接并占用并发配额

- **位置**：`hydra-node/src/handler.rs` `lookup_host` L248（`tcp_server.rs:150` 复用）；15s 超时仅覆盖 L315 的 connect
- **机理**：版本字节/握手/地址帧均有 AUTH_TIMEOUT=10s 包裹，但认证后的 `lookup_host` 无超时。上游 DNS 黑洞时（glibc 重试可拖 40s+）已认证连接远超客户端 20s 超时仍存活并持有 Semaphore permit；持有效 PSK 的攻击者可用大量慢解析域名请求占满 max_connections（默认 1000），饿死正常连接。
- **修复方案**：`lookup_host` 用 `tokio::time::timeout(Duration::from_secs(5), ...)` 包裹，超时归入现有 ERR_DNS_FAIL(0x02) 路径，维持"DNS 5s < connect 15s < 客户端 20s"的层次。

### R-27 [P2/bug] 下行先结束（远端 FIN）时直接 abort 上行任务，客户端未发完的数据被静默丢弃

- **位置**：`hydra-client/src/proxy.rs` `relay_bidirectional()` 分支 `(false, None)` L983-988
- **机理**：远端先 FIN（down 返回 Ok）时 `up.abort()` 直接杀掉上行任务。与浏览器半关闭路径（up 结束 → `up_sink.shutdown()` 优雅排水 30s）相比，该方向没有任何排水：up 任务中已读出、正在 write_all 途中的数据块被丢弃；写端经 drop 关闭，TLS 流不发送 close_notify。注释（L982）声称"drop → FIN 传给远端"，但语义上是 abort 而非 shutdown，与 README 宣称的对称半关闭语义不符。
- **影响**：对"服务器推完响应、客户端还有尾巴数据"的协议造成尾部数据静默丢失。
- **修复方案**：down 干净结束后不立即 abort up：对 up 施加有限排水窗口（较短的超时值如 5s，或直接等待 up 完成——up 侧客户端 EOF 逻辑已会 shutdown 远端写端），超时再 abort，保留现有超时告警。

### R-28 [P2/bug] 全局 speed_history 互斥锁在每 64KB 数据块上竞争，且样本 Vec 每次写入做 O(n) retain

- **位置**：`hydra-client/src/traffic.rs` `record_sent_sync/record_received_sync` L312-331、`SpeedHistory::add_sent_sample` L70-85；调用点 `ByteCounter::record` → poll_read/poll_write L245-285（另见横切面 L312-331）
- **机理**：每次 `CountingStream::poll_write/poll_read`（64KB 块粒度）获取全局 `std::sync::Mutex`，push 一条样本后 retain 全量扫描 5 秒窗口。量化：64KB 块、单连接 100MB/s 双向 ≈ 每方向 ~1600 次/秒 lock+push+O(n) retain；窗口内样本 ~8000 条，所有连接所有方向在唯一一把锁上串行化，poll 上下文内的同步临界区还拉长任务调度延迟。此数据仅服务 GUI 速度显示，精度需求极低。
- **修复方案**：见"性能提升方案" R-17（本地累加 + 时间片桶两步走）。

### R-29 [P2/bug] 配置文件非原子写入：崩溃/断电可截断 config.json，导致全部配置（含密钥）丢失

- **位置**：`hydra-client-gui/src/config.rs` `save_to_file` L249-275（非 unix 分支 `std::fs::write`；unix 分支 truncate(true) 直写）
- **机理**：直接对 config.json 以 create+truncate 打开写入。进程在写入中途崩溃/断电（GUI 代理崩溃路径并不少见）会留下半截 JSON；下次启动 `load_from_file` 返回 Err，代码降级为默认配置——auth_key、全部节点、订阅列表一次性丢失，且下次编辑任何字段后即被覆盖写，无法恢复。对存有明文密钥和全部节点配置的唯一持久化文件，这是真实数据丢失路径。
- **修复方案**：原子写：序列化后先写同目录临时文件 `config.json.tmp`（Unix 对 tmp 同样 mode 0600），`f.sync_all()` 后 rename/replace 到 config.json（同文件系统内 rename 原子；Windows 用 `std::fs::rename`，必要时先 remove 旧文件）。可选：load 失败时尝试读取 .tmp/备份而非直接丢弃。

### R-30 [P2/maintainability] QUIC 时代死代码残留：session/packet/auth(v2)/node/splitter 整模块零生产引用；HYDRA_TRANSPORT 告警未接线导致 README 行为失实

- **位置**：`hydra-protocol/src/{packet,session,auth,node}.rs`；`hydra-client/src/splitter.rs`；`tcp_transport.rs` L66-79
- **机理**：grep 证实：splitter 仅被 lib.rs mod/re-export 和 test_split.rs 引用；packet 仅被 splitter 引用；session.rs 中 client 实际使用的只有 NodeInfo，Session/Stream 零引用；auth.rs（v2 HMAC token）、node.rs（NodeConfig）均无生产调用。`tcp_transport.rs` 的 `transport_from_env`（README 声称 `HYDRA_TRANSPORT=quic` 会告警回退 tcp）在 main.rs/gui 生产代码零调用——用户设该变量实际不会有任何告警，README L113 描述的行为不存在。
- **修复方案**：删除 splitter.rs、session.rs、packet.rs、auth.rs、node.rs 及 test_split/test_tcp_ssrf 中对 v2 的引用；`transport_from_env` 要么在 client main.rs 启动时调用一次（兑现 README），要么连同 HYDRA_TRANSPORT 文档一并删除。

### R-31 [P2/maintainability] 无 [workspace.dependencies] 统一版本；tokio 全 feature；rustls 0.21/tokio-rustls 0.24 已 EOL；ring 0.16+0.17 双份编译

- **位置**：workspace 根 Cargo.toml 与 4 个 crate 的 Cargo.toml
- **机理**：tokio/rustls/bytes/serde/tracing 在 4 个 crate 各自声明版本字符串，已有漂移土壤（lock 里 rustls 0.21.x、ring 0.16 与 0.17 并存——两份 ring 静态编进每个二进制）。rustls 0.21/tokio-rustls 0.24 官方已停止维护（当前线 0.23/0.26），安全修复不再回移，对安全产品是实质风险。tokio 各 crate 均开 `features=["full"]`（含 fs/process/signal 等未用模块），拉长 node 交叉编译时间。
- **修复方案**：短期：加 `[workspace.dependencies]` 统一版本、tokio 收敛到实际所需 feature（rt-multi-thread/net/io-util/time/sync/macros）；中期：规划升级 rustls 0.23 + tokio-rustls 0.26 + ring 0.17 单栈（snow 的 ring-resolver 随之自然去重，或暂只留 default-resolver 消除双 ring）。

### R-32 [P2/maintainability] packet.rs / splitter.rs 死代码，且存在可量化的性能缺陷

- **位置**：`hydra-protocol/src/packet.rs` `Packet::new` L17-52；`hydra-client/src/splitter.rs`
- **机理**：全仓无调用点（Splitter 仅定义未引用）。若启用：每 chunk 两次冗余拷贝（splitter.rs:22 `copy_from_slice` + packet.rs:33 `to_vec`，同一数据 3 份内存）；`calculate_checksum` 为逐位软件 CRC32（每字节 8 次内层迭代），比查表 crc32fast 慢约 8 倍以上（10MB 流约 8000 万次内层循环），且 TCP+TLS1.3 AEAD 已保证完整性，校验纯冗余。属 TCP 转型 Wave 3 删 QUIC 死路径的遗漏项。
- **修复方案**：删除 packet.rs、splitter.rs 及 lib.rs 的 re-export。

### R-33 [P2/bug] 节点数据期无任何超时，Semaphore permit 全程占用：1000 条空闲/慢连接即令 accept 循环停摆

- **位置**：`hydra-node/src/tcp_server.rs` L55-75、L87-184
- **机理**：`handle_tls_stream` 进入双向 pump 后没有任何 idle/生命周期上限；permit 在 accept 循环 `acquire_owned().await` 后贯穿整条连接。恶意或异常客户端（建立 TLS+Noise 后不发不收）每条永久占 1 个 permit；1000 条即满，accept 循环阻塞在 acquire，新 TCP 连接只能在内核 backlog 排队直至超时。对公网 443 节点是低成本的资源耗尽面（错 PSK 在握手期即被 10s AUTH_TIMEOUT 关闭，合法 PSK 持有者可无限挂起）。
- **修复方案**：数据期为 pump 包 `tokio::time::timeout` 或用 interval 做写侧 idle 检测（如 300s 无字节即关）；或把 permit 拆为握手期短持有 + 数据期长持有两档额度。

### R-34 [P2/performance] 每次节点健康检查（每 30s）新建并销毁一个多线程 tokio Runtime；certs 逐节点克隆且参数实际未用

- **位置**：`hydra-client-gui/src/main.rs` `test_all_nodes` 约 L515-534（触发点：start_proxy L655、周期检查 L1586-1594、手动按钮 L2128/L2289）
- **机理**：每次调用都在新 std::thread 里 `Runtime::new()`（多线程 runtime = num_cpus 个 worker 线程 + epoll/kqueue 实例 + 若干 SYSCALL），用完即丢。长期运行每 30 秒一次完整 runtime 冷启动/销毁，并有线程瞬时创建的调度毛刺。循环里 `certs.clone()`（L522）对每节点克隆整份证书 Vec，而 `test_node_connection`（L403-423）转型后只做 `TcpStream::connect`，certs 参数完全未使用。
- **修复方案**：进程级创建一次探测 runtime（OnceLock 或专用探测线程 + 通道），所有健康检查复用；删除 node_certs 参数与逐节点 clone。若后续恢复"TLS 握手时延探测"，在共享 runtime 内加即可。

### R-35 [P2/performance] stop_proxy 在 UI 线程阻塞 join 代理线程

- **位置**：`hydra-client-gui/src/main.rs` `stop_proxy` 约 L973-975（触发点含托盘退出 L1991、on_exit L1539）
- **机理**：设置 stop_flag 后立刻在 UI 线程 join 代理线程。停止信号靠代理线程内 `while !stop_flag { sleep(100ms) }` 轮询（L747-750），join 至少阻塞 UI ≥100ms；且 `tokio::select!` 无法打断不在 yield 点的 future——若 `proxy.start()` 正处于"节点预热（可能数十秒）"的阻塞/长 await 链，UI 将冻结同样长时间，托盘、按钮、窗口全部无响应。已有 `proxy_exit_receiver`（L697/763）这条非阻塞退出通知通道，join 完全多余。
- **修复方案**：删除 `handle.join()`：stop_proxy 只置 stop_flag 并立即返回，退出确认交给 update 里已有的 proxy_exit_receiver 轮询分支（L1553-1583），UI 状态先置"停止中"；若必须同步等待，用带超时的 `exit_rx.try_recv()` 轮询。

### R-36 [P2/performance] 节点列表每帧 O(节点数×订阅节点数) 的来源扫描 + 整表克隆，交互期 60fps 下放大数十倍

- **位置**：`hydra-client-gui/src/main.rs` `ui_nodes` 约 L2295-2310（heading 双重 filter）、L2355（每行 node_source_label）、L2319（node_addrs.clone()）；`ui_subscriptions` L2587 与 `ui_subscription_section` L2505（subs_clone.clone()）
- **机理**：每帧对每节点调用 `config.node_source_label(a)`（内部线性扫描所有订阅的 nodes Vec 做 String 比较），heading 又调用两轮 filter（L2300-2308），同一行 L2355 再调一次。总量 = 每帧约 (节点数 × 订阅节点总数) × 3 次字符串比较 + 数千次 String 分配。量化：300 节点 × 300 行 = 每帧约 27 万次 String 比较；交互期 60fps 即 ~1600 万次比较/秒。另有每帧 `node_addrs.clone()`、`subscriptions.clone()`（每帧多次堆分配，节点多时数十 KB/帧）。`apply_subscription_update` 的 `contains`（L1447、L1488）也是 O(n²)，但为低频路径。
- **修复方案**：在 config 变更点（add/delete/订阅更新/另存为手动/rename 后）构建一次 addr→source 的 HashMap 存入 HydraApp 缓存字段，渲染期 O(1) 查表；heading 统计用缓存计数一次；每帧克隆改为索引迭代或仅克隆标量。

---

## P3 附录

### R-37 [P3/bug] start_proxy 同步读取 test_all_nodes 的异步结果，"有 N 个节点可用"统计恒为过期值

- **位置**：`hydra-client-gui/src/main.rs` `start_proxy` 约 L655-663
- **机理**：test_all_nodes 是异步的（结果经 mpsc 在后续帧返回），下一行立即统计 node_status 里 connected 的数量打日志。本次探测结果此刻必然不在，online_count 反映上一次状态；首启恒为 0，用户每次启动都看到"警告: 没有可用的节点连接"与"代理已就绪"并存，日志自相矛盾。
- **修复方案**：删掉该即时统计（探测结果由 poll_health_check_results 落地后自然更新 UI），或改为中性提示"正在后台检测节点连通性…"。

### R-38 [P3/bug] 监听地址为 IPv6 时 set_system_proxy 的字符串切分产出错误端口（Linux 分支）

- **位置**：`hydra-client-gui/src/main.rs` `set_system_proxy` 约 L808-813（gsettings/KDE 分支）
- **机理**：手工 `split(':')` 解析 proxy_url。IPv6 监听（GUI 明确支持 `[::1]:4433`）时 `"socks5://[::1]:1080"` 得 `addr_parts=["[", ":", "1]", "1080"]`，proxy_port 取到空或错误段——gsettings/kwriteconfig 写入空端口，桌面代理配置损坏；Windows 分支用整个 addr_port 字符串，不受影响。
- **修复方案**：不要手写字符串切分：由调用方直接传入已解析的 SocketAddr（start_proxy 本就有 proxy_addr: SocketAddr），按平台惯例生成 host/port；或用 url::Url 解析。env var（http_proxy 等）惯例要求 IPv6 带方括号，注意区分。

### R-39 [P3/bug] 本地代理入口三处初始读无超时、accept 后任务无并发上限

- **位置**：`hydra-client/src/proxy.rs` L216（协议探测读）、L359（HTTP 头循环读）、L611（SOCKS5 请求读）
- **机理**：三处初始读都不包 timeout：客户端连上后不发数据，任务与缓冲无限期挂起；`loop + tokio::spawn` 无并发上限。默认监听 127.0.0.1 风险低，但 README 支持 `--listen 0.0.0.0`，此时构成慢连接资源泄漏面。
- **修复方案**：三处初始读包 `tokio::time::timeout`（如 30s，与节点侧 AUTH_TIMEOUT 语义对齐）；可选加全局 Semaphore 限并发（节点侧已有同款模式可复制）。

### R-40 [P3/performance] 每连接克隆整张 cert_by_node 证书 HashMap（Vec<u8> 深拷贝）

- **位置**：`hydra-client/src/proxy.rs` TcpCreds 定义 L31-37；`start()` L134-139 与 L182 `creds.clone()`；`open_target` L281-285
- **机理**：每条连接 `creds.clone()` 深拷贝 `cert_by_node: HashMap<SocketAddr, Vec<u8>>`——含全部节点证书 DER 的 Vec 拷贝（每张 ~500-800B），100 并发 = 100 份完整证书表副本；`open_target` 命中后再 `.cloned()` 拷贝一次传入 connect_target。相比每连接重建 TLS config 是小头，但同属无谓分配。
- **修复方案**：见性能路线 R-13（`Arc<HashMap<.., Arc<[u8]>>>`，get 后传引用/Arc clone）。

### R-41 [P3/performance] 分享对话框打开期间每帧重生成含证书 base64 的完整 URL 字符串

- **位置**：`hydra-client-gui/src/main.rs` share 对话框约 L1630-1634 与 L1660-1665
- **机理**：open_share_dialog 已把链接存入 self.share_link，但 Window 闭包内每帧调用 `l.to_share_url()` 重新生成完整 URL（完整模式含 base64(DER) 与 hex 密钥，约 1.5-2.5KB，每帧 1-2 次堆分配 + 编码计算），随后 L1660 又 clone 一次整串。拖动窗口（60fps）时 ~300KB/s 无谓分配。
- **修复方案**：见性能路线 R-20（变化时生成一次并缓存；当前缓存被用作"上次渲染值"，语义反了）。

### R-42 [P3/maintainability] TCP 转型后测试缺口：HTTP 代理路径、SOCKS5 畸形输入、故障切换 E2E 三大块零覆盖

- **位置**：`hydra-client/tests/`、`hydra-node/tests/`
- **机理**：现有集成测试仅覆盖 SOCKS5 大块回显/错 PSK/半关闭/SSRF/分流/配置。缺口：① handle_http/handle_http_connect 约 240 行零测试（CONNECT、明文 GET/POST 字节保真、64KB 头上限、Host 解析）——A6 刚修过 lossy 转码数据损坏 bug，回归风险最高处恰无测试；② SOCKS5 畸形/粘包/拆段零测试（R-03 一测即红）；③ 故障切换 E2E 缺失（节点宕→切下一候选、target-fail 不应标 Offline——正好覆盖 R-01、A2 恢复探测）；④ 客户端 TLS 证书校验失败（MITM 拒绝）无测试——防中间人是核心卖点；⑤ 远端先 FIN、relay 排水超时分支；⑥ 节点 max_connections Semaphore 生效性。
- **修复方案**：优先补 ①②③；①② 可用 tests/common 的进程内 spawn + 本地 echo/HTTP 目标服务器覆盖，无需外网。

### R-43 [P3/maintainability] 错误处理与脱敏基础设施的一致性问题

- **位置**：`hydra-client/src/traffic.rs` L339、L346-348、L367；`tcp_transport.rs` L74；`speedtest.rs` L134
- **机理**：traffic.rs 三处 `lock().expect("poisoned")`（node_entry/node_traffic_snapshot/get_stats）在持锁线程 panic 后会让 GUI 刷新或测速任务连锁 panic，而同文件热路径 L317 用 if let Ok 容忍式——策略不一致。tcp_transport.rs L74 用 `eprintln!` 输出 HYDRA_TRANSPORT 告警（绕过 tracing，GUI 场景不可见）。`probe_connect` 返回 `Result<_, String>`，与全仓 HydraError 风格割裂；错误文案中英混杂。
- **修复方案**：三处 expect 改 `unwrap_or_else(|p| p.into_inner())`；eprintln 改 `tracing::warn!`；probe_connect 返回 HydraError 并统一文案语言。

### R-44 [P3/bug] Host 头提取按字节偏移切片，obs-fold/大小写混合多 Host 头时取值脆弱

- **位置**：`hydra-client/src/proxy.rs` `handle_http()` L440-446
- **机理**：非 CONNECT 请求从 Host 头提取用 `line[5..].trim()`，依赖 `starts_with("host:")` 恰好 5 字节前缀；未处理 RFC 7230 obs-fold（续行以空格开头），多 Host 头时取首个。取第一个匹配行是安全方向（多 Host 头本身非法），风险有限，列为提示级。
- **修复方案**：如需更稳健可跳过以空白开头的续行再匹配；低优先级改进。

### R-45 [P3/maintainability] splitter.split 每 chunk Bytes::copy_from_slice 全量深拷贝（QUIC 遗留死代码）

- **位置**：`hydra-client/src/splitter.rs` `split()` L22
- **机理**：对每个 chunk 执行 `Bytes::copy_from_slice` 深拷贝，而入参已是 Bytes（`slice()` 零拷贝引用计数+1 即可）。该模块只被 QUIC 时代测试引用，业务路径无调用者。
- **修复方案**：若保留公共 API 改用 `Bytes::slice` 零拷贝；若确认为死路径，随 QUIC 清理一并删除（并入 R-30/R-32）。

### R-46 [P3/maintainability] deploy/install.sh：env 文件属主与注释不符；生成密钥明文回显终端

- **位置**：`deploy/install.sh` chown 段与脚本头注释
- **机理**：整体评价正面：systemd unit 的 User=hydra+CAP_NET_BIND_SERVICE、ProtectSystem=strict+ReadWritePaths、NoNewPrivileges、RestrictAddressFamilies、Docker 非 root+cap_drop ALL+no-new-privileges 都正确；env.example 密钥防泄漏指引准确。瑕疵：① 脚本头注释声称 env 文件"root:600，不进 history"，实际 `chown hydra:hydra`——hydra 用户可篡改自己的 EnvironmentFile（与 ProtectSystem 重叠后风险低，但注释应如实）；② 自动生成密钥时 echo 明文到终端（脚本自己注明会留滚动缓冲）。
- **修复方案**：注释改为如实描述（hydra:hydra 0600），或改 chown root:hydra 并让 unit 以组读；密钥回显改为提示用户 grep 查看（删掉 echo 明文段即可）。

---

## 覆盖范围与方法说明

### 审查方法

本报告由四份独立静态代码审查结果合并而成：

1. **hydra-protocol**：逐文件精读，并核对 node/client 接线与 snow（NNpsk2）上游行为。
2. **hydra-client**：逐文件精读（README→tcp_transport/proxy/scheduler/speedtest/traffic/share_link/subscription/splitter/routing/main），交叉验证 hydra-protocol 的应答码实现。
3. **hydra-client-gui**：精读 README、main.rs（全 3236 行）、config.rs、qr.rs，复核 subscription.rs 与 tray.rs。
4. **workspace 横切面**：4 个 crate 的 Cargo.toml、hydra-protocol/hydra-node/hydra-client 全部 src、hydra-client tests、deploy 全部脚本；GUI 仅做凭据存储抽查。

合并时对多份审查重复指出的问题做了去重（见执行摘要的去重说明），统计数字与详单一一对应。

### 未覆盖方面（如实声明）

- **纯静态审查**：所有结论来自源码阅读与推理，未运行动态测试、模糊测试、压测或性能 profile；文中性能数字（如每连接 0.5-2ms、27 万次比较/秒）为基于代码路径的量化估算，非实测值。
- **未实际构建验证**：Cargo.lock 中的依赖并存（ring 双版本等）为审查声明，未逐一重新求解验证。
- **运行时/并发行为**：数据竞争（R-24）、锁竞争（R-28）、调度毛刺（R-34）等问题的实际触发频率与严重度依赖运行时负载，需动态验证确认。
- **网络与部署环境**：未在真实公网节点、真实 DNS 故障（黑洞/慢解析）、真实移动网络条件下验证故障切换与超时层次。
- **密码学实现正确性**：只审查了用法层面（消息顺序、域分离、常量时间比较、重放防护），未对 snow/ring/rustls 库内部做密码学审计。
- **GUI 视觉/可用性**：不在范围内。
- **hydra-node**：未做与 protocol/client 同深度的逐文件精读，相关条目（R-09、R-26、R-33）来自横切面审查与交叉引用。**（已于第二轮补齐，见文末附录 A）**
- **测试**：审查中未新增或运行任何测试；R-42 列出的缺口未经实际执行确认（"一测即红"为代码路径推理）。

### 与统计的一致性声明

执行摘要统计表（P0×2、P1×9、P2×16、P3×9，共 36 条）与 P0/P1 详单、性能方案引用、P2 详单、P3 附录中的编号条目一一对应：R-01~R-02（P0）、R-03~R-10（P1）、R-11~R-36（P2，其中 R-11~R-20 为性能路线引用的条目编号，R-21~R-36 为 P2 详单）、R-37~R-46（P3）。多份审查对同一问题的重复报告已合并计一次。

---

## 附录 A：hydra-node 专项审查（第二轮补齐，2026-10-05）

第一轮 hydra-node 专项 agent 失败，本轮以同规格补齐。对 tcp_server.rs、handler.rs、server.rs、config.rs、cert.rs、health.rs、main.rs、tests/ 逐文件精读。

**总评**：协议状态机清晰、认证前静默关流语义一致、SSRF 过滤覆盖 IPv4-mapped/NAT64 内嵌绕过、toml 配置显式报错设计到位。但存在**两条真实的资源耗尽路径**（下 N-1/N-2）。核对无问题项：DNS 无 TOCTOU（解析结果过 SSRF 后按已检 SocketAddr 建连，不重解析）、pump 背压由分块读写天然形成、防探测静默语义各错误路径一致。

| 编号 | 级别/类别 | 位置 | 问题与修复 |
|---|---|---|---|
| N-01 | P1/security | tcp_server.rs accept 循环 | **TLS 握手无超时 + 信号量握手前预占 → 认证前 slowloris 耗尽连接额度**（慢速 ClientHello 每连接无限期占 1 permit，默认 1000 条即全节点拒绝服务）。修复：TLS accept 包 10s 超时。**【已修复，见附录 B】** |
| N-02 | P1/security | tcp_server.rs 转发阶段 | **无 idle 超时**：已认证零流量连接可无限期占用 permit/fd（与 N-01 叠加成两级耗尽）。修复：idle watchdog（默认 300s，`HYDRA_IDLE_TIMEOUT_SECS` 可调）。**【已修复，见附录 B】** |
| N-03 | P2/security | tcp_server.rs accept 循环 | 信号量满时 `acquire_owned().await` 无界排队，节点假死。修复：`try_acquire` 快速失败。**【已修复，见附录 B】** |
| N-04 | P2/security | handler.rs resolve_and_connect | 4 处 `error!` 打印目标明文（与 R-09 同源，节点侧）。**【已修复，见附录 B】** |
| N-05 | P2/security | main.rs parse_args | `--auth-key` 把 PSK 暴露进 /proc/<pid>/cmdline，与 config.rs "CLI 不暴露密钥"自相矛盾。**【已修复：参数移除，显式报错提示改用 env/密钥文件】** |
| N-06 | P3/security | handler.rs classify_blocked_ip | SSRF 黑名单缺 CGNAT 100.64/10、198.18/15、multicast 224/4、reserved 240/4（纵深不足，非可利用洞）。**【待修复】** |
| N-07 | P3/bug | cert.rs load_or_generate | 新私钥先 0644 创建后 chmod 0600，毫秒级可读竞态窗口。修复：`OpenOptions::create_new(true).mode(0o600)`。**【待修复】** |
| N-08 | P3/bug | config.rs parse_u32_field | 空白 env 值导致启动失败，违反"空白视为未设置"约定。**【待修复】** |
| N-09 | P3/maintainability | Cargo.toml | rustls 0.21 / tokio-rustls 0.24 / ring 0.16 已 EOL，TLS 栈新漏洞不回移；规划升级 0.23/0.26/0.17。**【技术债，与 R-46 同源】** |

## 附录 B：报告发布当轮已直接修复项（2026-10-05）

以下问题在报告产出后随即修复（`cargo test --workspace` 全绿后合入）：

| 对应编号 | 修复内容 |
|---|---|
| R-01 / N 附带 | **新增 `HydraError::TargetUnreachable` 错误变体**：节点侧目标失败（连接失败/超时/DNS）改用该变体 → 客户端 `read_reply` 保留错误类型 → proxy `open_target` 对 TargetUnreachable **立即报错且不计节点故障**（原实现把健康节点连锁标记 Offline，污染评分） |
| R-05 | **PSK 长度 fail-fast**：handshake build() 强制 32 字节；node `decode_auth_key` / client `auth_key_from_hex` / GUI `resolve_auth_key` 启动期校验 `== 32` 并给出 openssl rand -hex 32 提示；相关测试同步更新 |
| R-08 | 客户端 `connect_target` info 级目标明文改 `mask_target` |
| R-09 / N-04 | 节点 `resolve_and_connect` 4 处 error 级明文改 `mask_target`（明文降为 debug） |
| R-10 | hydra-protocol 移除 quinn 依赖与 Quinn* 错误变体、移除 rustls `dangerous_configuration` feature、移除未用的 serde_bytes（全 workspace 构建通过） |
| R-11 | 三处 TCP 连接建立后 `set_nodelay(true)`（客户端→节点、节点 accept、节点→目标） |
| N-01 / N-03 | TLS accept 包 10s 超时；额度满 `try_acquire` 快速失败 |
| N-02 | 转发阶段 idle 看门狗（默认 300s，`HYDRA_IDLE_TIMEOUT_SECS` 30..86400 可调），泵改分块读写实现，缓冲 16KB（顺带落实 R-14） |
| N-05 | `--auth-key` CLI 参数移除（显式报错提示替代路径），`CliOverrides.auth_key` 字段删除，测试同步更新 |

**仍未修复（按优先级待排期）**：R-02（CLI 多节点证书配对）、R-03~R-07、R-12~R-20 中期性能项、N-06/N-07/N-08、R-46（rustls 0.23 升级）。建议下一轮按「P0 → P1/security、performance → 性能短期路线」顺序清账。
