//! hydra-fetch：多节点并行下载器（HTTP Range 分块 + 评分加权 + 断点续传）。
//!
//! 用法（CLI）：
//! ```text
//! export HYDRA_AUTH_KEY=<64 hex>      # 与节点一致的认证密钥
//! export HYDRA_NODE_CERT=cert.der     # 节点证书（pin 模式，默认）
//! export HYDRA_NODES=1.2.3.4:443,5.6.7.8:443   # 或用位置参数逐个列出
//! hydra-fetch [-o 输出文件] [--workers 16] [--chunk-mb 16] [--sha256 <hex>] \
//!             <https://目标> [更多节点...]
//! ```
//!
//! 仅支持 https 目标（隧道内端到端 TLS，webpki 公共 CA + 主机名校验）。
//!
//! 内部模块图：
//! - [`http`]：最小 HTTP/1.1（请求构造/响应解析/三种 body 帧式统一读取器）
//! - [`target_tls`]：目标站 TLS 连接器（webpki 公共 CA + ALPN 锁定 http/1.1）
//! - [`probe`]：HEAD→Range-GET 探测、重定向跟随、元信息提取
//! - [`engine`]：隧道工厂（评分加权选节点/故障记账）+ 单块取回（隧道复用）
//! - [`download`]：编排（分块计划/worker 池/多轮重试/断点续传/校验/就位）
//! - [`state`]：断点续传状态文件（强校验 + 原子写）
//! - [`sha256`]：流式完整性校验

pub mod download;
pub mod engine;
pub mod http;
pub mod probe;
pub mod sha256;
pub mod state;
pub mod target_tls;
