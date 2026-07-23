use serde::{Deserialize, Serialize};
use bytes::Bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub magic: u32,
    pub session_id: u64,
    pub stream_id: u32,
    pub chunk_id: u32,
    pub offset: u64,
    pub length: u32,
    pub payload: Vec<u8>,
    pub checksum: u32,
}

impl Packet {
    pub fn new(session_id: u64, stream_id: u32, chunk_id: u32, offset: u64, payload: Bytes) -> Self {
        let length = payload.len() as u32;
        let checksum = Self::calculate_checksum(&payload);
        Self {
            magic: 0x48594452, // "HYDR"
            session_id,
            stream_id,
            chunk_id,
            offset,
            length,
            payload: payload.to_vec(),
            checksum,
        }
    }

    fn calculate_checksum(data: &[u8]) -> u32 {
        // Simple CRC32-like checksum
        let mut crc: u32 = 0xFFFFFFFF;
        for byte in data {
            crc ^= *byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^ 0xFFFFFFFF
    }

    pub fn verify_checksum(&self) -> bool {
        let calculated = Self::calculate_checksum(&self.payload);
        self.checksum == calculated
    }
}