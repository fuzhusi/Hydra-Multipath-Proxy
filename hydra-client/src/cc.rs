//! 拥塞控制（Brutal / BBR / CUBIC 三选，env `HYDRA_CC`/`HYDRA_BRUTAL_MBPS`）。
//!
//! 实现已迁入 [`hydra_obfs::cc`]（client 与 node 的公共依赖——节点侧下行主方向
//! 需接同一实现，而 node 不依赖 hydra-client，迁移先例同 `tuning`）。
//! 此处整体 re-export 保持既有公开 API、调用点（transport.rs）与测试路径不变。
//! 全部实现与单测随迁移位于 hydra-obfs/src/cc.rs。

pub use hydra_obfs::cc::*;
