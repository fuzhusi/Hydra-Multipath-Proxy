pub mod cert;
pub mod config;
// DNS AAAA 查询本地过滤（v4-only 节点降噪，见模块文档）
pub mod dns_aaaa;
pub mod fallback;
pub mod handler;
pub mod health;
pub mod server;
pub mod signal;
pub mod tcp_server;
// UDP-over-proxy 中继（协议层能力，TUN 模式 UDP 转发的地基）
pub mod udp_relay;

pub use config::*;
pub use fallback::*;
pub use handler::*;
pub use health::*;
pub use server::*;
pub use tcp_server::*;
