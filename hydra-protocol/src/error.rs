use thiserror::Error;

#[derive(Error, Debug)]
pub enum HydraError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
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
    
    #[error("QUIC connection error: {0}")]
    QuinnConnectionError(#[from] quinn::ConnectionError),
    
    #[error("QUIC connect error: {0}")]
    QuinnConnectError(#[from] quinn::ConnectError),
    
    #[error("QUIC write error: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),
    
    #[error("QUIC read error: {0}")]
    QuinnReadError(#[from] quinn::ReadToEndError),
    
    #[error("Address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
}

pub type Result<T> = std::result::Result<T, HydraError>;