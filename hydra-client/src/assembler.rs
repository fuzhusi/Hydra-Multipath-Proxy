use bytes::{Bytes, BytesMut};
use hydra_protocol::Packet;
use std::collections::HashMap;

pub struct Assembler {
    chunks: HashMap<u32, Packet>,
    expected_offset: u64,
    buffer: BytesMut,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            expected_offset: 0,
            buffer: BytesMut::new(),
        }
    }

    pub fn add_packet(&mut self, packet: Packet) -> Option<Bytes> {
        if !packet.verify_checksum() {
            return None;
        }

        self.chunks.insert(packet.chunk_id, packet);
        self.try_assemble()
    }

    fn try_assemble(&mut self) -> Option<Bytes> {
        let mut assembled = BytesMut::new();
        let mut current_offset = self.expected_offset;

        loop {
            let found = self.chunks.values()
                .find(|p| p.offset == current_offset)
                .cloned();

            if let Some(packet) = found {
                assembled.extend_from_slice(&packet.payload);
                current_offset += packet.length as u64;
                self.chunks.remove(&packet.chunk_id);
            } else {
                break;
            }
        }

        if !assembled.is_empty() {
            self.expected_offset = current_offset;
            Some(assembled.freeze())
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        self.chunks.clear();
        self.expected_offset = 0;
        self.buffer.clear();
    }
}