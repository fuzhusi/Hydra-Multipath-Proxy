pub mod aggregate;
pub mod assembler;
pub mod buf_pool;
pub mod crypto;
pub mod nat_traversal;
pub mod pool;
pub mod proxy;
pub mod routing;
pub mod scheduler;
pub mod session;
pub mod share_link;
pub mod speedtest;
pub mod splitter;
pub mod subscription;
pub mod traffic;
pub mod transport;

pub use aggregate::*;
pub use assembler::*;
pub use buf_pool::*;
pub use crypto::*;
pub use nat_traversal::*;
pub use pool::*;
pub use proxy::*;
pub use routing::*;
pub use scheduler::*;
pub use session::*;
pub use share_link::*;
pub use speedtest::*;
pub use splitter::*;
pub use subscription::*;
pub use traffic::*;
pub use transport::*;

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";

/// 从 HYDRA_AUTH_KEY 环境变量解析节点预共享认证密钥
pub fn auth_key_from_env() -> Result<Vec<u8>, String> {
    let hex_str = std::env::var("HYDRA_AUTH_KEY").map_err(|_| {
        "未设置 HYDRA_AUTH_KEY 环境变量（节点预共享密钥，hex 编码，解码后至少 16 字节）".to_string()
    })?;
    auth_key_from_hex(&hex_str)
}

/// 从 hex 字符串解析认证密钥
pub fn auth_key_from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let key = hydra_protocol::hex_decode(hex_str)?;
    if key.len() < 16 {
        return Err("认证密钥太短（解码后至少 16 字节）".to_string());
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
