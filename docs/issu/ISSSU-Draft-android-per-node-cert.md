# [安卓端] 多节点场景下每节点独立证书缺失：全局单证书导致握手失败 BadSignature

## 问题概述

安卓客户端（v0.2.8，versionCode 9）在多节点场景下**只支持一张全局证书**，导致：

1. **后导入的节点会覆盖先前节点的证书** —— `ShareImporter` 直接写 `certDerB64`，多节点共存的证书只剩最后导入的那张
2. **证书错配时握手直接失败** —— 用 A 节点的证书去连 B 节点，TLS 校验报 `invalid peer certificate: BadSignature`
3. **节点不可达与证书错配的错误无法区分** —— 用户只看到 TLS 报错，不知道是证书配错还是网络问题

核心层、桌面 GUI、CLI 均已支持多节点独立证书，**仅安卓端仍停留在"v1 单证书"**。

## 复现步骤

### 场景一：多节点导入互相覆盖（必现）

1. 部署节点 A（自签证书 A），生成分享链接 `hydra://<A>:11534?...&cc=<certA>`
2. 部署节点 B（自签证书 B），生成分享链接 `hydra://<B>:11534?...&cc=<certB>`
3. 在安卓端依次导入 A 的链接、再导入 B 的链接
4. 启动引擎，连接节点 A

**预期**：节点 A 用证书 A 校验成功
**实际**：握手失败，报 `invalid peer certificate: BadSignature`

### 场景二：单节点证书过期/被替换（必现）

1. 节点重装或更换自签证书（证书指纹变化）
2. 客户端仍持有旧证书，未重新导入链接
3. 连接该节点

**实际**：同上，报 `BadSignature`

> 注：所有自签证书的 Subject/Issuer 均为 `CN = rcgen self signed cert`（完全相同），因此 rustls/webpki 在校验时会匹配到同名的信任根，然后签名比对失败 —— 表现为 `BadSignature` 而非更明确的"证书不匹配"。这使问题更难被用户自行定位。

## 根因分析

### 1. 安卓端存储层：全局单证书字段

`android/app/src/main/kotlin/dev/hydra/vpn/SecureStore.kt:20-21`

```kotlin
* - cert_der_b64：pin 模式证书 DER（base64；多节点共用同一自签证书是当前
*   部署惯例，v1 单证书）
```

`SecureStore` 只有一个 `KEY_CERT_B64 = "cert_der_b64"` 字段，**没有按节点地址索引的证书表**。

### 2. 导入层：新证书无条件覆盖旧证书

`android/app/src/main/kotlin/dev/hydra/vpn/ui/import/ShareImporter.kt:34-38`

```kotlin
val merged = cur.copy(
    nodesText = mergedNodes,
    authKeyHex = p.authKeyHex.ifEmpty { cur.authKeyHex },
    certDerB64 = p.certDerB64.ifEmpty { cur.certDerB64 },   // ← 覆盖式写入
)
```

节点列表是**合并**的（`mergedNodes` 追加去重），但证书是**覆盖**的。两者语义不一致：节点越多，留下的证书越少且必然对不上其中大多数节点。

### 3. 引擎层：永远只传一张证书

`android/app/src/main/kotlin/dev/hydra/vpn/EngineService.kt:198-206`

```kotlin
val trust = if (cfg.trustMode == SecureStore.TRUST_CA) {
    TrustMode.PublicCa
} else {
    val der = android.util.Base64.decode(
        cfg.certDerB64.ifEmpty { throw IllegalStateException("pin 模式必须提供节点证书") },
        android.util.Base64.DEFAULT,
    )
    TrustMode.Pinned(listOf(der))    // ← 恒为单元素列表
}
```

`MainActivity.kt:182-187`（节点连通性测试）同样是 `TrustMode.Pinned(listOf(...))`。

### 4. Rust FFI 层：能力已经具备，但被调用方浪费

`hydra-android/src/lib.rs:36-41`

```rust
pub enum TrustMode {
    /// 自签证书 pin：Kotlin 从 EncryptedSharedPreferences/Assets 读 der 传入
    Pinned { cert_der: Vec<Vec<u8>> },   // ← 本身已是 Vec，支持多张
    PublicCa,
}
```

`hydra-android/src/lib.rs:1337-1344` 直接透传给 `TlsTrust::pinned(cert_der)`，`hydra-core/src/tcp_transport.rs:177-183` 的 `pinned_certs: Arc<Vec<Vec<u8>>>` 也是多张的信任根池（`build_client_config` L293-297 逐张加入 rustls RootCertStore）。

**即：Rust 侧完全支持一次传入多张证书，安卓端只是永远只传一张。** 修复不需要改 Rust 内核。

## 与既有审查结论的对应

本问题在 `docs/review/05-TCP转型后代码审查报告.md` 中已作为 **R-02 [P0/bug]** 记录：

> **R-02（P0/bug）多节点证书按下标 zip 配对 + CLI 仅支持单证书**：非首节点 Noise 证书指纹通道绑定必败 → 握手必败 → 离线-恢复振荡，多节点容灾静默退化为单节点。

该报告指出根因在 `hydra-client`（CLI）的按下标 zip 配对与单证书文件，**Rust 核心层已根治**（`hydra-core/src/lib.rs:67-69` 注释：*"Noise 指纹取对端叶证书，配对错误不再导致握手失败——审查 R-02 的根治补全"*）。

但 **R-02 的修复未覆盖安卓客户端** —— 安卓端从一开始就是"全局单证书"设计，从未接入多证书能力。

## 各端能力对比

| 组件 | 多节点独立证书 | 实现位置 |
|---|---|---|
| Rust 核心 | ✅ 支持（信任根池 + 取对端叶证书） | `hydra-core/src/tcp_transport.rs:177-183, 293-297` |
| 桌面 GUI | ✅ 支持（`node_cert_paths: HashMap<String, String>` 按节点独立保存，缺项回落全局） | `hydra-client-gui/src/config.rs:121, 504-520` |
| CLI | ⚠️ 部分支持（`HYDRA_NODE_CERTS` 逗号分隔多张；`HYDRA_NODE_CERT` 仅单张） | `hydra-client/src/main.rs:315-320` |
| **安卓客户端** | ❌ **不支持**（全局单 `certDerB64`，导入即覆盖） | `android/.../SecureStore.kt:20-21`、`ui/import/ShareImporter.kt:37` |

`docs/design/UI重设计方案-v2.md:120-121` 也已记录 GUI 侧当时存在同样的全局单值问题，并已修复；安卓端沿用了同一套早期设计。

## 影响

- **多节点容灾在安卓端静默退化为单节点**（与 R-02 描述的失效模式一致）
- 节点切换时用错证书，握手必败，节点被误判 Offline
- 证书更新后客户端无感知，只能靠用户手动重新导入链接
- 错误信息不可辨识（`BadSignature` 未指向证书不匹配）

## 建议修复方向

参照桌面 GUI 的 `node_cert_paths` 实现，安卓端补齐按节点独立证书：

1. **存储层**（`SecureStore`）：新增按节点地址索引的证书表（如 `node_cert_b64: Map<String, String>`），保留现有 `cert_der_b64` 作为全局回落项（兼容旧配置迁移）
2. **导入层**（`ShareImporter`）：新节点的证书写入其**自身地址对应的条目**，不再覆盖全局字段；不同节点携带不同证书时互不影响
3. **引擎层**（`EngineService` / `MainActivity`）：构造 `TrustMode.Pinned(...)` 时传入**所有相关节点的证书集合**（Rust 侧已支持多张，无需改内核）；节点连通性测试应传入**被测节点自己的那张证书**
4. **UI**（`NodesScreen` / `SettingsScreen`）：提供按节点查看/更新证书的入口，节点行可显示证书指纹（取链接中的 `cf` 字段），便于用户识别证书漂移
5. **证书漂移提示**：连接报 `BadSignature` 时明确提示"证书不匹配，请重新导入该节点的分享链接"，而非泛化的 TLS 错误

> 实现提示：`TrustMode.Pinned { cert_der: Vec<Vec<u8>> }` 已是多张语义，**本次修复不需要修改 Rust 内核与 FFI 签名**，改动集中在 Kotlin 侧存储/导入/引擎三层。

## 复现环境

- 节点：`hydra-node` v0.2.8，TCP/TLS 传输，自签证书（`CN = rcgen self signed cert`）
- 客户端：Hydra Android v0.2.8（versionCode 9）
- 实际故障节点：118.193.33.251:11534
- 报错原文：`Connection error: TLS handshake with 118.193.33.251:11534 failed: invalid peer certificate: BadSignature`

## 补充说明

同批排查中还确认了一个**非代码问题的独立故障**（已解决，记录备查）：UCloud 云主机上自建防火墙策略的「绑定资源数量」为 0，导致安全组规则未生效、11534 端口公网不可达（表现为连接超时而非 refused）。绑定实例后端口即恢复。此项与本 Issue 的证书问题无关。
