use bytes::Bytes;
use hydra_protocol::Packet;

pub struct Splitter {
    chunk_size: usize,
    next_chunk_id: u32,
}

impl Splitter {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            next_chunk_id: 0,
        }
    }

    pub fn split(&mut self, data: Bytes, session_id: u64, stream_id: u32) -> Vec<Packet> {
        let mut packets = Vec::new();
        let mut offset = 0;

        for chunk in data.chunks(self.chunk_size) {
            let chunk_bytes = Bytes::copy_from_slice(chunk);
            let packet = Packet::new(
                session_id,
                stream_id,
                self.next_chunk_id,
                offset as u64,
                chunk_bytes,
            );
            packets.push(packet);
            offset += chunk.len();
            self.next_chunk_id += 1;
        }

        packets
    }

    pub fn set_chunk_size(&mut self, size: usize) {
        self.chunk_size = size;
    }

    pub fn get_chunk_size(&self) -> usize {
        self.chunk_size
    }
}