# TCP 传输协议优化评估（被迫走 TCP 前提下的增强路线）

- 日期：2026-10-05 ｜ 性质：调研评估报告（只读代码 + 2024-2025 公开实践检索）
- 前提约束：部署网络（广东移动→境外 VPS）UDP 回程 QoS 丢包，QUIC/UDP 路线不可用，一切方案限定在 **TCP** 生态内。
- 标注约定：【实测共识】= 社区/学术界有实测或广泛验证的结论；【推测】= 依据原理与有限来源的推断。

---

## TL;DR 推荐

**当前方案（TLS 1.3 自签 pinning + Noise-PSK + 私有帧）方向正确，不需要推倒重来。** 逐项结论：

| 项 | 结论 | 优先级 |
|---|---|---|
| TLS 指纹伪装（rustls CH 指纹） | **是现方案最大可识别短板，但非最大风险**——真正的最大风险是自签证书 + TLS-in-TLS 内层指纹（见 §1/§7）。值得做，且有现成 Rust 轮子 | **P1** |
| ACME 真证书（DNS-01 + wildcard） | **性价比最高的单点增强**：消除自签证书固有指纹，成本低于任何伪装方案 | **P0** |
| 回退页 / REALITY 式借站 | 回退静态页值得做（伪代码级简单）；REALITY 式借站**明确不做**（需 hack TLS 库 + 借站目标运维，数月级，个人自用收益不成比例） | 回退页 **P1**；REALITY **不做** |
| 连接内多路复用（yamux/H2 类） | **不做内层多路复用**（与 TLS-in-TLS 指纹检测研究冲突）；用「连接池 + 连接级并发」替代 | **P0（负向决策，写明理由）** |
| 拥塞控制 | 节点侧开 **内核 BBR + fq**（一条 sysctl 命令，人日级）；**brutal 不做**（UDP 已弃，TCP 版 brutal 内核模块维护差且个人链路收益不明） | **P0** |
| XTLS Vision / ShadowTLS v3 / Restls / CDN 中转 | Vision（splice）需私有 TLS 形态、与自实现架构冲突，不做；ShadowTLS v3 生态（Rust 原生 crate）可作为**备选逃生舱**记录不实施；CDN 中转作为**被封后的 Plan B** 记录 | 均不做 / 记录 |

一句话：**P0 = ACME 真证书 + 节点 BBR + 明确拒绝内层 mux；P1 = rustls ClientHello 指纹模仿 + 认证前回退静态页；P2 = 逃生舱预案（ShadowTLS v3 / CDN WebSocket）。**

---

## 现状基线

来自 README 与《TCP转型与加密选型方案》：

- 链路：浏览器 → 本地 SOCKS5/HTTP → **单条 TCP 443 + TLS 1.3（tokio-rustls）** → VPS 节点 → 目标。
- TLS 细节：自签证书 + 客户端 pinning（SHA-256 指纹）；SNI 伪装 `hydra.node`；**无 ALPN**；禁会话恢复。
- 应用层：Noise-PSK（snow NNpsk2）握手，confirm 绑定「证书指纹 + TLS exporter」双通道，抗重放/抗跨连接转发；私有地址帧 `[u16 BE len][target]` + 2B 应答码；认证失败零字节静默关流。
- 已知限制（README 自述）：单连接单流；**客户端 TLS 指纹与浏览器有差异**；ACME 真证书与非认证 IP 反代静态页为规划项。
- 运维形态：个人自用、节点为自有 VPS（可 root、可装内核模块、可跑 systemd），这是所有工作量估计的前提。

---

## 逐项评估

### 1. TLS 指纹伪装（rustls ClientHello 指纹）

**原理**：DPI 可从 ClientHello 的 cipher 套件列表/扩展顺序/椭圆曲线/GREASE 等计算 JA3/JA4 指纹。Go 生态用 uTLS 一键模仿 Chrome；Rust 生态 rustls 不暴露 ClientHello 组装细节，所以本项目 README 如实承认「Rust 生态无 uTLS 等价物」。

**2024-2025 现状盘点**：
- [craftls](https://github.com/Charles-Johnson/craftls)（fork rustls，可定制 ClientHello 指纹，[docs.rs 有 0.0.2+rustls.0.22.0 版本](https://docs.rs/crate/craftls/latest)）——原理可行的直接证据，但版本冻结在旧 rustls，跟进成本高。【实测：存在；推测：维护不活跃，fork 长期跟随 rustls 升级是负担】
- [ja-tools（XOR-op）](https://github.com/XOR-op/ja-tools)——在**不 fork rustls** 的前提下 parrot JA3/JA4 指纹的库，是 Rust 生态目前最实用的路线。【实测：库存在并有明确设计目标】
- [meow-rs](https://deepwiki.com/madeye/meow-rs/5.1-tls-layer)（shadowsocks 作者 madeye 的 Rust 客户端）中也有 ECH + uTLS 层的探索（[DeepWiki 摘要](https://deepwiki.com/madeye/meow-rs/5.3-ech-and-utls)），说明社区在推进但尚无 crates.io 上的标准件。【实测：项目存在；推测：无成熟标准件】

**与现方案对比**：
- 抗探测：现方案 ClientHello 是 rustls 默认指纹（JA3 固定、无 GREASE），与真实浏览器差异显著——但注意 SNI `hydra.node` 本身就不是真实域名，指纹伪装的价值要和真证书（§2）配套才有意义。**指纹是短板但不是单点短板**。【推测，有依据：README 自述 + 指纹原理共识】
- 另一个 2024 关键发现：[USENIX Security 2024 的 TLS-in-TLS 指纹检测论文（Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes*）](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf) 证明：即使外层完美伪装，**浏览器在隧道内发起的内层 TLS 握手**（HTTPS 网站流量）会形成可检测的嵌套特征。这直接冲击「只做外层指纹伪装」的思路——单连接单流裸转发恰好是此论文的攻击模型。【实测：学术论文 + 实测】对个人自用、流量未被重点盯防的场景，实际被针对的概率低，但应如实认知。

**工作量**：接入 ja-tools 类方案做 ClientHello 模仿 ≈ **2-4 人日**（客户端单点改动 + 测试）；走 craftls fork 路线 ≈ **1-2 人周**并引入长期维护债。

**结论**：**P1，做**。用非 fork 方案（ja-tools 思路）模仿 Chrome 指纹；前置条件是先做 §2 真证书（否则 SNI 与证书都不真实，指纹再像也矛盾）。同时在文档中如实记录 TLS-in-TLS 内层指纹风险为已知限制。

### 2. 真证书路线：ACME + Let's Encrypt vs 自签 pinning

**原理**：自签证书有两个固有可识别特征：①证书链不指向公共根，censor 可被动识别「TLS 443 + 非受信 CA」；②SNI 与证书 SAN 的组合（`hydra.node` 不存在 DNS 记录）。真证书 + 真域名后，外层 100% 等价于普通 HTTPS 站点，被动指纹面只剩 ClientHello（§1）。

**现状盘点**：Let's Encrypt 免费证书、90 天有效期、[DNS-01 挑战支持 wildcard 证书](https://www.ctyun.cn/developer/article/830442843357253)（HTTP-01 需 80 端口暴露，DNS-01 只需域名 API token，且 wildcard 一次覆盖 `*.example.com`）。Rust 生态有 [ACME 库（instant-acme，rustls 官方同门）]；最省事的实现是节点侧用 certbot/acme.sh 外部进程续期、Hydra 节点只加载证书文件——**零 Rust 代码**路径存在。

**与现方案对比**：
- 抗探测：质变。自签 → 真证书后，「非受信 CA 的 443」这一最廉价的批量筛查规则直接失效。【实测共识：GFW 及各类中间盒长期将非受信证书作为低成本低误伤的筛查信号；个人自用被主动批量封 IP 的前提也大幅弱化】
- 代价：需要一个真实域名（约 ¥10-60/年）+ DNS API token；失去 pinning 的「自带信任」——改为 pin **Let's Encrypt 中间证书指纹或公钥（SPKI pin）**，Noise-PSK 的证书指纹通道绑定逻辑不变，只是 pin 的对象换成真证书的 SPKI，防中间人能力不降级。【推测：安全等价，原理同 current pinning】
- 生态成熟度：ACME 是互联网基础设施级标准，无风险。

**工作量**：
- 外部 certbot/acme.sh + systemd timer + 节点读文件：**0.5-1 人日**（部署脚本 + 文档 + 客户端 pin 值更新到分享链接）。
- 内置 instant-acme 自动续期（`HYDRA_ACME_DOMAIN`）：**3-5 人日**。

**结论**：**P0，强烈建议做外部 certbot 版**（人日级、零代码风险）。这是全表性价比最高的一项。

### 3. 回退页 / 站点伪装（Trojan fallback 与 REALITY 借站）

**原理**：
- Trojan fallback：认证失败的连接不关闭，反代到本机 nginx/静态页 → 主动探测者看到正常网站。
- [REALITY 借站](https://xtls.github.io/config/transports/reality.html)：更进一步——服务端不持有证书，把**未认证的 TLS 握手原样转发给真实目标站**（target），由真站完成握手并回真证书；认证通过的流量才进代理。官方文档明确：认证失败流量「直接转发至 target」，配合 uTLS 指纹（文档要求 `fingerprint` 必填），是「目前最安全的传输安全方案之一」。代价：客户端必须 hack TLS 库（utls 级别操作握手参数）、服务端要做真实回落的转发与限速治理（文档花了大量篇幅讲回落限速与 Cloudflare 端口转发滥用风险）。

**与现方案对比**：现方案认证失败 = 零字节静默关流。对「连上就断」式主动探测有一定迷惑性但**行为可区分**（真站会回证书+页面，现节点什么都不回）。回退页把行为补齐到「看起来像个站」，是标准且廉价的增强。【实测共识：Trojan/Xray 社区多年实践】
- REALITY 式借站需要：解析并转发原始 ClientHello、劫持回程流、处理证书与 SNI 一致性——等于自实现半个 MITM TLS 代理，且 Rust 侧无现成组件（§1 的库都不覆盖 REALITY 协议）。原转型方案已评估为「数月级」，2025 年现状未变。【推测，与方案原文一致】

**工作量**：回退页 = 节点在 Noise 握手失败路径上改连本地静态文件服务或反代 nginx ≈ **1-2 人日**。REALITY = **2-3 人月起**，不做。

**结论**：回退页 **P1，做**（前置：先上真证书，否则回退页与自签证书并存的组合本身矛盾——探测者拿到真站证书才闭环）。REALITY **明确不做**：个人自用无对抗国家级定向探测的现实需求，收益与成本严重不成比例。

### 4. 多路复用：单连接每请求 vs 连接内 mux（yamux/H2 类）

**收益侧（为什么想做）**：浏览器打开一个页面并发 50-300+ 连接；每条连接独立过 TCP 三次握手 + TLS 1.3 握手（1-RTT，跨境 RTT 200ms+ 时每连接首字节延迟 ~600ms+）+ TCP 慢启动。单流 mux 后只有一次握手，慢启动只经历一次。【实测共识：这是 mux 的经典动机，Clash/sing-box/Xray mux 文档均如此表述】

**反对侧（为什么不做）**：
1. **TLS-in-TLS 指纹**：内层 mux 使隧道内流量呈现「多条内层流封装在单条外层流」的强特征，正是 [USENIX 2024 论文](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf)检测模型的放大器——嵌套协议栈越规整越易被指纹化。【实测：学术实证；实际被针对概率：推测，低】
2. **队头阻塞**：TCP 单流内多路复用把 N 条逻辑流绑进一条物理流，一条流丢包重传阻塞全部流；跨境高丢包链路（本项目正是因丢包被迫转 TCP）下这是负优化。Xray 社区 mux 长期争议的结论也是「默认关闭 mux，浏览场景收益小」。【实测共识：sing-box/Xray 文档均建议浏览场景不开 mux】
3. **实现成本**：yamux（Rust 有 crates：yamux，ipfs 系）或 H2 流复用 + 背压 + 生命周期管理 ≈ **1-2 人周**，还要改分享链接兼容。

**替代方案（推荐）**：客户端做**小连接池（如每节点预热 2-4 条已建连 + 新请求直接新建并发连接）**。浏览器自身对同代理的并发连接天然并行，代理层只需控制 TLS 握手风暴；配合 TCP_NODELAY + TLS 1.3 session resumption 的**同源替代**——注意现方案「禁会话恢复」是为抗重放/可链接性，若要降低握手成本，可评估**仅客户端侧 0-RTT 关闭保持不变、TLS session ticket 仅用于省 1-RTT 且 ticket 绑定 PSK** 的折中，但收益（每次省 1-RTT）与复杂度相比不划算，**维持禁用**。【推测：折中得不偿失】

**结论**：**明确不做内层 mux**（写进已知限制的理由栏）；P0 级负向决策。若日后实测建连风暴成为瓶颈，先做连接池预热（**2-3 人日**，P2）。

### 5. 拥塞控制与调优：内核 BBR vs 用户态 brutal

**原理与现状**：
- 内核 BBR：Google 拥塞控制算法，基于带宽-RTT 模型而非丢包回退，在高丢包长肥管道（正是跨境链路）上对 cubic 常见 2-10 倍吞吐提升；Linux `net.ipv4.tcp_congestion_control=bbr` + `net.core.default_qdisc=fq` 即开，4.x+ 内核自带。2025 年中文 VPS 教程已将其列为跨境 VPS 标配（[vpscost BBR 教程 2025](https://vpscost.com/blog/post/vps-bbr-acceleration-guide-2025)、[Margrop：一条 sysctl 让国际链路 20×](https://blog.margrop.net/en/post/bbr-fix-china-us-vps-slow-network/)）。【实测共识：大量部署案例；倍数因链路而异】
- brutal：Hysteria 团队的固定速率拥塞控制，在持续丢包链路上无视丢包硬打满带宽；TCP 版 [tcp-brutal 内核模块](https://github.com/mzh741/tcp-brutal) 存在但需自编译内核模块、维护人力单薄（另有社区 fork [nb-tcp-brutal](https://github.com/nebulabox/nb-tcp-brutal)）。【实测：项目存在且有效；推测：长期维护与内核升级兼容风险高】
- 调优项：`TCP_NODELAY`（tokio 默认已设，确认即可）；收发缓冲 `tcp_rmem/tcp_wmem` 上限调大；BBR 搭配 fq qdisc。社区现成脚本如 [TCP-Optimize](https://github.com/Madhatter2099/TCP-Optimize) 可参考参数集。【实测：脚本存在；参数需自测】

**与现方案对比**：README 明言「TCP 拥塞控制与缓冲由内核栈管理」——即现方案完全依赖节点侧内核默认（多半是 cubic）。这是**零代码、纯运维**就能拿到的最大性能增益点，且与「广东移动高丢包」痛点直接对应。用户态 brutal 与本项目架构（tokio 用户态转发）契合度差（需内核模块 + 手动带宽设定，带宽估计错了适得其反），且 brutal 的价值场景是「QoS 限速而非拥塞丢包」——本项目实测问题是回程丢包，BBR 已针对性解决。【推测：先 BBR 后按实测数据决定是否进一步】

**工作量**：BBR + sysctl = **0.5 人日**（改 deploy 脚本 + systemd/sysctl.d 文件 + 部署指南）。tcp-brutal = 2-3 人日 + 长期运维债。

**结论**：**P0：节点侧 BBR+fq + 缓冲调优写进部署套件**。brutal **不做**，理由：内核模块维护成本、带宽需手动设定易劣化、与个人自用定位不符。

### 6. 其他 TCP 生态方案盘点

| 方案 | 原理 | 与现方案关系 | 结论 |
|---|---|---|---|
| **XTLS Vision（splice 零拷贝）** | 对 TLS-in-TLS 流量中的内层 TLS record「原样透传」不再二次加密，配合 Linux splice 零拷贝转发，官方称性能数倍提升（[REALITY 文档](https://xtls.github.io/config/transports/reality.html)提及 Vision 联动收益） | 需要 Xray 私有的 VLESS 流控与对 record 边界的感知；Rust 自实现 = 深度 hack rustls + splice 管线，数周-数月级；且「内层 TLS 明透传」恰恰**降低**了内层混淆——在 GFW 研究 TLS-in-TLS 指纹（§1 论文）的 2024+ 环境是双刃剑 | **不做**。性能瓶颈大概率不在此；个人带宽场景二次加密 CPU 开销可忽略【推测】 |
| **ShadowTLS v3** | 客户端把真实 TLS 握手打到借站目标，PSK 校验通过后再切换到数据流，数据帧带 4B HMAC 流式校验，抗劫持/重放/切片（[官方 v3 协议文档](https://docs.rs/crate/shadow-tls/latest/source/docs/protocol-v3-en.md)）；Rust 原生实现成熟（[shadow-tls crate 0.2.20](https://docs.rs/crate/shadow-tls/latest)） | 抗探测上限高于「真证书+回退页」，因为借的是别人的真站且无需自己持有证书。但其定位是独立协议栈，与本项目私有帧 + Noise-PSK + 多节点调度体系不兼容，接入等于维护两套协议 | **不实施，记录为逃生舱**：若主方案域名/证书被针对性封锁，ShadowTLS v3 是 Rust 生态现成的 Plan B【实测：crate 成熟；推测：触发条件概率低】 |
| **Restls** | ShadowTLS v3 的思想来源（v3 文档明确致谢）：在 TLS 握手上做完美伪装的通用化设计（[restls 仓库](https://github.com/3andne/restls)） | 学术性强、实现生态极小，ShadowTLS v3 已吸收其精华 | **不做** |
| **CDN 中转（WebSocket+TLS 过 CDN）** | 节点藏在 Cloudflare 等 CDN 后，censor 只见 CDN IP；Xray 生态 WebSocket/HTTPUpgrade/XHTTP 传输皆是此路线（[REALITY 文档传输列表](https://xtls.github.io/config/transports/reality.html)） | 防封 IP 能力最强，但延迟 +100ms 级、CDN 免费档限速、2025 年 XHTTP 演进剧烈（[XHTTP 概述](https://habr.com/en/articles/990208/)）——生态在 Go 侧，Rust 自实现 WebSocket+TLS 反代 ≈ 1 人周且性能劣化明显 | **不做，记录为 Plan C**：仅当 VPS IP 被封且换 IP 无效时启用【推测：个人自用 IP 被封概率低，被封后换 IP 更便宜】 |

---

## 推荐路线图

### P0（立即可做，合计 ≈ 2 人日，零/低代码风险）
1. **ACME 真证书**：申请真实域名 → 节点侧 acme.sh/certbot DNS-01 wildcard 自动续期 → 节点加载真证书 → 客户端 pin 改为真证书 SPKI 指纹（Noise confirm 绑定逻辑不变，更新分享链接字段）。SNI 改为真域名。
2. **节点侧 BBR + fq + 缓冲 sysctl**：写入 `deploy/`（sysctl.d 文件 + install.sh 检测内核支持）+ 部署指南章节 + 部署后 iperf3/网页实测留档。
3. **负向决策落档**：README「已知限制」补两条——不做内层 mux（TLS-in-TLS 指纹 + 队头阻塞理由）、TLS-in-TLS 内层指纹为已知残余风险（引 USENIX 2024）。

### P1（真证书落地后跟进，合计 ≈ 3-5 人日）
4. **ClientHello 指纹模仿**：调研 ja-tools 类非 fork 方案接入客户端，目标 JA4 ≈ Chrome；验收 = 第三方指纹检测（如 tls.peet.ws 类服务）自测比对。若依赖库不达标则降级为「记录风险、不做」，**不引入 rustls fork**。
5. **认证前回退静态页**：节点 Noise 握手失败路径改为反代本地 nginx 静态站（与真域名内容一致）；验收 = curl 主动探测返回正常页面 + 原有静默关流测试改写。

### P2（仅实测触发）
6. **客户端连接池预热**（仅当实测建连风暴/首字节延迟成为痛点）：每节点维持 2 条预热连接，2-3 人日。
7. **逃生舱预案文档**：记录 ShadowTLS v3（Plan B）与 CDN WebSocket（Plan C）的启用条件与切换成本，不写代码。

### 明确不做（理由存档）
- **REALITY 式借站**：自实现数月级 + 借站运维负担，个人自用无此对抗需求。
- **内层 mux（yamux/H2）**：高丢包链路队头阻塞负优化 + TLS-in-TLS 指纹放大。
- **tcp-brutal**：内核模块维护债 + 需手动带宽设定 + brutal 解决的是限速场景而非本项目实测的回程丢包。
- **XTLS Vision/Restls**：需 hack TLS 库或生态过小，与私有协议架构冲突。

---

## 参考来源

- [REALITY 官方文档（Xray）](https://xtls.github.io/config/transports/reality.html) —— 借站原理、回落转发/限速、fingerprint 强制 uTLS、Vision 联动表述
- [ShadowTLS v3 协议文档（docs.rs 镜像）](https://docs.rs/crate/shadow-tls/latest/source/docs/protocol-v3-en.md) —— v3 抗劫持/重放设计、Restls 致谢
- [Xue et al., Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes, USENIX Security 2024](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf) —— TLS-in-TLS 内层握手指纹检测实证
- [craftls：可定制 ClientHello 指纹的 rustls fork](https://github.com/Charles-Johnson/craftls) 及其 [docs.rs 版本页](https://docs.rs/crate/craftls/latest)
- [ja-tools：rustls 上 parrot JA3/JA4 指纹（非 fork 路线）](https://github.com/XOR-op/ja-tools)
- [meow-rs TLS/ECH/uTLS 层探索（DeepWiki 摘要）](https://deepwiki.com/madeye/meow-rs/5.3-ech-and-utls) · [其 TLS 层设计](https://deepwiki.com/madeye/meow-rs/5.1-tls-layer)
- [HTTP-01 与 DNS-01 挑战选型（wildcard/安全权衡）](https://www.ctyun.cn/developer/article/830442843357253)
- [VPS BBR 加速教程 2025（跨境带宽、BBR2、排错）](https://vpscost.com/blog/post/vps-bbr-acceleration-guide-2025)
- [一条 sysctl 优化国际链路（Margrop）](https://blog.margrop.net/en/post/bbr-fix-china-us-vps-slow-network/)
- [tcp-brutal（TCP 版 brutal 内核模块）](https://github.com/mzh741/tcp-brutal) · 社区 fork [nb-tcp-brutal](https://github.com/nebulabox/nb-tcp-brutal)
- [TCP-Optimize：BBR/FQ/缓冲跨境调优脚本（参数集参考）](https://github.com/Madhatter2099/TCP-Optimize)
- [XHTTP for VLESS 概述（CDN 路线 2025 演进）](https://habr.com/en/articles/990208/)
