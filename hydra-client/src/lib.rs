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
// TUN 透明代理模式（feature = "tun"，见 tun.rs 模块文档）
#[cfg(feature = "tun")]
pub mod tun;

pub use nat::*;
pub use proxy::*;
pub use routing::*;
pub use scheduler::*;
pub use share_link::*;
pub use speedtest::*;
pub use subscription::*;
pub use tcp_transport::*;
pub use traffic::*;
#[cfg(feature = "tun")]
pub use tun::*;

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";

/// 从 HYDRA_AUTH_KEY 环境变量解析节点预共享认证密钥
pub fn auth_key_from_env() -> Result<Vec<u8>, String> {
    let hex_str = std::env::var("HYDRA_AUTH_KEY").map_err(|_| {
        "未设置 HYDRA_AUTH_KEY 环境变量（节点预共享密钥，hex 编码，解码后恰好 32 字节）".to_string()
    })?;
    auth_key_from_hex(&hex_str)
}

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

/// 从 HYDRA_NODE_CERT 环境变量读取节点证书文件
pub fn node_certs_from_env() -> Result<Vec<Vec<u8>>, String> {
    let path = std::env::var("HYDRA_NODE_CERT").map_err(|_| {
        "未设置 HYDRA_NODE_CERT 环境变量（指向节点生成的 hydra-node-cert.der 证书文件，用于防止中间人）"
            .to_string()
    })?;
    let der = std::fs::read(&path).map_err(|e| format!("读取节点证书 {} 失败: {}", path, e))?;
    Ok(vec![der])
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
