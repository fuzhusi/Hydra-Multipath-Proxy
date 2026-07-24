use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use tracing::{info, warn, error};
use hydra_protocol::{Result, HydraError};

/// STUN 服务器地址
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// NAT 类型
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    /// 无 NAT（公网 IP）
    Open,
    /// 完全锥形 NAT（最容易穿透）
    FullCone,
    /// 受限锥形 NAT（需要先发送数据给对方）
    RestrictedCone,
    /// 端口受限锥形 NAT
    PortRestrictedCone,
    /// 对称 NAT（最难穿透）
    Symmetric,
    /// 未知
    Unknown,
}

/// NAT 穿透结果
#[derive(Debug, Clone)]
pub struct NatTraversalResult {
    /// 本地地址
    pub local_addr: SocketAddr,
    /// 公网地址（通过 STUN 获取）
    pub public_addr: Option<SocketAddr>,
    /// NAT 类型
    pub nat_type: NatType,
    /// 穿透是否成功
    pub success: bool,
}

/// NAT 穿透管理器
pub struct NatTraversal {
    /// 本地绑定地址
    local_addr: SocketAddr,
    /// STUN 服务器列表
    stun_servers: Vec<String>,
}

impl NatTraversal {
    /// 创建新的 NAT 穿透管理器
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            stun_servers: STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 使用自定义 STUN 服务器
    pub fn with_stun_servers(mut self, servers: Vec<String>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// 执行 NAT 穿透
    pub fn traverse(&self) -> Result<NatTraversalResult> {
        info!("Starting NAT traversal on {}", self.local_addr);

        // 绑定本地 UDP 端口
        let socket = UdpSocket::bind(self.local_addr)
            .map_err(|e| HydraError::ConnectionError(format!("Failed to bind UDP socket: {}", e)))?;

        socket.set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| HydraError::ConnectionError(format!("Failed to set timeout: {}", e)))?;

        // 尝试通过 STUN 获取公网地址
        let public_addr = self.discover_public_address(&socket);

        // 检测 NAT 类型
        let nat_type = self.detect_nat_type(&socket, public_addr);

        let result = NatTraversalResult {
            local_addr: self.local_addr,
            public_addr,
            nat_type: nat_type.clone(),
            success: public_addr.is_some(),
        };

        info!("NAT traversal result: {:?}", result);
        Ok(result)
    }

    /// 通过 STUN 服务器发现公网地址
    fn discover_public_address(&self, socket: &UdpSocket) -> Option<SocketAddr> {
        for server in &self.stun_servers {
            match self.query_stun_server(socket, server) {
                Ok(addr) => {
                    info!("Discovered public address via {}: {}", server, addr);
                    return Some(addr);
                }
                Err(e) => {
                    warn!("Failed to query STUN server {}: {}", server, e);
                }
            }
        }
        error!("Failed to discover public address from any STUN server");
        None
    }

    /// 查询 STUN 服务器
    fn query_stun_server(&self, socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
        let server_addr: SocketAddr = server.parse()
            .map_err(|_| HydraError::ConnectionError(format!("Invalid STUN server address: {}", server)))?;

        // 构建 STUN Binding Request
        let request = self.build_stun_request();
        
        // 发送请求
        socket.send_to(&request, server_addr)
            .map_err(|e| HydraError::ConnectionError(format!("Failed to send STUN request: {}", e)))?;

        // 接收响应
        let mut buf = [0u8; 1024];
        let (len, _) = socket.recv_from(&mut buf)
            .map_err(|e| HydraError::ConnectionError(format!("Failed to receive STUN response: {}", e)))?;

        // 解析响应
        self.parse_stun_response(&buf[..len])
    }

    /// 构建 STUN Binding Request
    fn build_stun_request(&self) -> Vec<u8> {
        // STUN Binding Request 格式
        // Message Type: 0x0001 (Binding Request)
        // Message Length: 0x0000 (no attributes)
        // Magic Cookie: 0x2112A442
        // Transaction ID: 12 bytes random
        let mut request = vec![
            0x00, 0x01, // Message Type
            0x00, 0x00, // Message Length
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        ];

        // Transaction ID (12 bytes)
        for _ in 0..12 {
            request.push(rand::random());
        }

        request
    }

    /// 解析 STUN Binding Response
    fn parse_stun_response(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 20 {
            return Err(HydraError::ProtocolError("STUN response too short".to_string()));
        }

        // 检查消息类型 (0x0101 = Binding Response)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != 0x0101 {
            return Err(HydraError::ProtocolError(format!("Unexpected STUN message type: 0x{:04x}", msg_type)));
        }

        // 检查 Magic Cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != 0x2112A442 {
            return Err(HydraError::ProtocolError("Invalid STUN magic cookie".to_string()));
        }

        // 解析属性
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut offset = 20;

        while offset + 4 <= 20 + msg_len {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if offset + 4 + attr_len > data.len() {
                break;
            }

            // MAPPED-ADDRESS (0x0001) 或 XOR-MAPPED-ADDRESS (0x0020)
            if attr_type == 0x0001 || attr_type == 0x0020 {
                return self.parse_mapped_address(&data[offset + 4..offset + 4 + attr_len], attr_type == 0x0020);
            }

            offset += 4 + attr_len;
            // 对齐到 4 字节边界
            offset = (offset + 3) & !3;
        }

        Err(HydraError::ProtocolError("No MAPPED-ADDRESS attribute found".to_string()))
    }

    /// 解析 MAPPED-ADDRESS 属性
    fn parse_mapped_address(&self, data: &[u8], is_xor: bool) -> Result<SocketAddr> {
        if data.len() < 8 {
            return Err(HydraError::ProtocolError("MAPPED-ADDRESS too short".to_string()));
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);
        let port = if is_xor { port ^ 0x2112 } else { port };

        match family {
            0x01 => {
                // IPv4
                let ip = if is_xor {
                    [
                        data[4] ^ 0x21,
                        data[5] ^ 0x12,
                        data[6] ^ 0xA4,
                        data[7] ^ 0x42,
                    ]
                } else {
                    [data[4], data[5], data[6], data[7]]
                };
                Ok(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(HydraError::ProtocolError("IPv6 MAPPED-ADDRESS too short".to_string()));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[4..20]);
                if is_xor {
                    for i in 0..16 {
                        ip[i] ^= 0x21;
                    }
                }
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => Err(HydraError::ProtocolError(format!("Unknown address family: {}", family)))
        }
    }

    /// 检测 NAT 类型
    fn detect_nat_type(&self, socket: &UdpSocket, public_addr: Option<SocketAddr>) -> NatType {
        if public_addr.is_none() {
            return NatType::Unknown;
        }

        let public_addr = public_addr.unwrap();
        let local_addr = socket.local_addr().unwrap();

        // 如果公网地址和本地地址相同，说明没有 NAT
        if public_addr.ip() == local_addr.ip() {
            return NatType::Open;
        }

        // 简单的 NAT 类型检测（实际实现需要更复杂的逻辑）
        // 这里简化处理，返回 FullCone 作为默认值
        NatType::FullCone
    }
}

/// UDP 打洞器
pub struct UdpHolePuncher {
    /// 本地地址
    local_addr: SocketAddr,
    /// 目标地址
    target_addr: SocketAddr,
}

impl UdpHolePuncher {
    /// 创建新的 UDP 打洞器
    pub fn new(local_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            target_addr,
        }
    }

    /// 执行 UDP 打洞
    pub fn punch(&self) -> Result<UdpSocket> {
        info!("Starting UDP hole punching from {} to {}", self.local_addr, self.target_addr);

        let socket = UdpSocket::bind(self.local_addr)
            .map_err(|e| HydraError::ConnectionError(format!("Failed to bind UDP socket: {}", e)))?;

        socket.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| HydraError::ConnectionError(format!("Failed to set timeout: {}", e)))?;

        // 发送打洞包
        let punch_packet = b"HYDRA_PUNCH";
        for _ in 0..5 {
            socket.send_to(punch_packet, self.target_addr)
                .map_err(|e| HydraError::ConnectionError(format!("Failed to send punch packet: {}", e)))?;
            
            // 短暂等待
            std::thread::sleep(Duration::from_millis(100));
        }

        // 尝试接收响应
        let mut buf = [0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if addr == self.target_addr && &buf[..len] == b"HYDRA_PUNCH" {
                    info!("UDP hole punching successful!");
                    return Ok(socket);
                }
            }
            Err(e) => {
                warn!("No response received: {}", e);
            }
        }

        Err(HydraError::ConnectionError("UDP hole punching failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_request() {
        let traversal = NatTraversal::new("0.0.0.0:0".parse().unwrap());
        let request = traversal.build_stun_request();
        
        assert_eq!(request.len(), 20);
        assert_eq!(request[0], 0x00); // Message Type high byte
        assert_eq!(request[1], 0x01); // Message Type low byte
        assert_eq!(request[4], 0x21); // Magic Cookie
        assert_eq!(request[5], 0x12);
        assert_eq!(request[6], 0xA4);
        assert_eq!(request[7], 0x42);
    }
}
