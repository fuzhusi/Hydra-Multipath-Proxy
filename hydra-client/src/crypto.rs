use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use hydra_protocol::{HydraError, Result};

pub struct Crypto {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl Default for Crypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Crypto {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; 32];
        rng.fill(&mut key_bytes).unwrap();
        
        let key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
        let key = LessSafeKey::new(key);
        
        Self { key, rng }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        let mut in_out = data.to_vec();
        let tag = self.key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| HydraError::ProtocolError(format!("Encryption error: {}", e)))?;
        
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag.as_ref());
        
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 + 16 {
            return Err(HydraError::ProtocolError("Invalid encrypted data".to_string()));
        }
        
        let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        let mut in_out = data[12..].to_vec();
        let plaintext = self.key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| HydraError::ProtocolError(format!("Decryption error: {}", e)))?;
        
        Ok(plaintext.to_vec())
    }
}