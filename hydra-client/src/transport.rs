//! 传输层公共常量（TCP 转型 Wave 3 后）。
//!
//! QUIC/quinn Endpoint、obfs 双模式接线、流控窗口调优（B1）与拥塞控制
//! （HYDRA_CC / Brutal / BBR）均随 QUIC/UDP 死路径一并移除：
//! TCP/TLS 传输由内核 TCP 栈管理拥塞控制与缓冲，客户端无需（也无法）
//! 做 QUIC 传输参数调优。本文件仅保留伪装域名常量供 TCP/TLS 路径使用。

/// 默认 SNI（伪装域名，同时是节点证书的默认 SAN）
pub const DEFAULT_SNI: &str = "hydra.node";
