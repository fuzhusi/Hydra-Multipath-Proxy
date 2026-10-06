//! 代理通道开启器抽象（平台无关）。
//!
//! TUN 透明代理模式（桌面 `hydra-client/src/tun.rs`，未来 Android `tun_core`）
//! 每接到一条新流，都需要一条「目标地址 → 节点代理链路」的双工通道。本模块
//! 只定义该接口的数据类型（零平台依赖），实现由 [`crate::proxy::
//! ProxyServer::tun_channel_opener`] 提供，消费方（tun.rs）反向依赖本模块，
//! 从而 proxy ↔ tun 无循环、且核心库不携带任何 TUN/平台代码。

use hydra_protocol::Result;
use std::future::Future;
use std::pin::Pin;

/// 已建成的代理双工链路（既有 NodeLink 的读/写端，含流量统计）
pub struct ProxyDuplex {
    pub reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
}

/// 通道开启返回 future
pub type OpenFuture = Pin<Box<dyn Future<Output = Result<ProxyDuplex>> + Send>>;

/// TUN 新流 → 代理通道（target 形如 "ip:port"；复用 open_target 的故障切换 /
/// TargetUnreachable 判定 / mark_node_offline / 流量统计语义，零分叉）
pub type ChannelOpener = std::sync::Arc<dyn Fn(String) -> OpenFuture + Send + Sync>;
