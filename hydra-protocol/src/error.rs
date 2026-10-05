use thiserror::Error;
#[derive(Error, Debug)]
pub enum HydraError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// 目标不可达（节点存活但目标连不上/SSRF 拒绝/DNS 失败）。
    /// 与 ConnectionError 的语义区分：故障切换层不得把此类错误计为节点故障
    /// （目标在任意节点都不可达，换节点无意义，更不能污染节点评分）。
    #[error("Target unreachable: {0}")]
    TargetUnreachable(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Node error: {0}")]
    NodeError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),

    #[error("Address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
}

pub type Result<T> = std::result::Result<T, HydraError>;
