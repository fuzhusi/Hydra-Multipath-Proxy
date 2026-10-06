//! Hydra 跨平台核心库：桌面 CLI/GUI 与 Android 共用的全部平台无关逻辑。
//!
//! 从 hydra-client 抽取（docs/design/移动端Android方案-v2.md §3）：
//! - 协议/握手/帧：hydra-protocol（独立 crate）
//! - TCP/TLS 传输：rustls 0.23 + ring + ClientHello 指纹 + 信任双路线（pinned der / 公共 CA）
//! - SOCKS 代理服务实体、多节点调度/故障切换/测速、订阅与分享链接、流量统计
//! - UDP-over-proxy 客户端通道、NAT 会话逻辑
//! - 代理通道开启器抽象（`channel`，TUN 设备层反向依赖）
//!
//! 本 crate 刻意**零 env 读取、零平台专有代码**：凭据与证书一律显式参数传入
//! （Android 侧经 uniffi 由 Kotlin 传 bytes，桌面侧 env/文件路径封装留在
//! hydra-client）。TUN 设备与系统路由等平台代码不在本 crate（桌面 tun.rs 留
//! hydra-client；Android 将按评审 R1-R4 增强 tun_core）。

pub mod channel;
pub mod connections;
pub mod nat;
pub mod proxy;
pub mod routing;
pub mod scheduler;
pub mod share_link;
pub mod speedtest;
pub mod subscription;
pub mod tcp_transport;
pub mod traffic;
pub mod transport;
// UDP-over-proxy 客户端通道（同一条 TCP/TLS 流上的 UDP 多路复用）
pub mod udp_relay;

pub use channel::*;
pub use connections::*;
pub use nat::*;
pub use proxy::*;
pub use routing::*;
pub use scheduler::*;
pub use share_link::*;
pub use speedtest::*;
pub use subscription::*;
pub use tcp_transport::*;
pub use traffic::*;
pub use transport::*;

/// 从 hex 字符串解析认证密钥（必须恰好 32 字节——snow NNpsk2 的 PSK 长度约束，
/// 提前 fail-fast 而非让每条连接在握手期静默失败）
pub fn auth_key_from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let key = hydra_protocol::hex_decode(hex_str)?;
    if key.len() != 32 {
        return Err(format!(
            "认证密钥长度非法：解码后 {} 字节（必须恰好 32 字节，即 64 个 hex 字符；生成：openssl rand -hex 32）",
            key.len()
        ));
    }
    Ok(key)
}

/// 从逗号分隔的证书文件路径列表读取多节点证书（`HYDRA_NODE_CERTS`）。
/// 顺序必须与节点地址顺序一一对应（仅用于 pin 模式信任根；Noise 指纹取对端
/// 叶证书，配对错误不再导致握手失败——审查 R-02 的根治补全）。
pub fn node_certs_from_paths(paths: &str) -> Result<Vec<Vec<u8>>, String> {
    paths
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| std::fs::read(p).map_err(|e| format!("读取节点证书 {} 失败: {}", p, e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_hex_roundtrip() {
        let hex = "ab".repeat(32);
        assert!(auth_key_from_hex(&hex).is_ok());
        // 31 字节（62 hex）必须被拒
        assert!(auth_key_from_hex(&"ab".repeat(31)).is_err());
        assert!(auth_key_from_hex("zz").is_err());
    }
}
