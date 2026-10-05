use ring::hmac;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 认证配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// 预共享密钥（hex 编码）
    pub psk: Option<String>,
    /// 用户名/密码认证
    pub users: HashMap<String, StoredCredential>,
}

/// 存储的凭据（PBKDF2 哈希）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

/// 认证令牌
pub struct AuthToken;

/// 所有客户端使用的固定 client_id（单租户自用场景）
pub const CLIENT_ID: &str = "hydra";

impl AuthToken {
    pub const TOKEN_LEN: usize = 64;
    // [8 bytes: timestamp] [32 bytes: HMAC] [16 bytes: nonce] [8 bytes: reserved]

    /// 生成认证令牌
    pub fn generate(key: &[u8], client_id: &str) -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let rng = ring::rand::SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce).unwrap();

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut message = Vec::new();
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(client_id.as_bytes());
        message.extend_from_slice(&nonce);

        let tag = hmac::sign(&hmac_key, &message);

        let mut token = Vec::with_capacity(Self::TOKEN_LEN);
        token.extend_from_slice(&timestamp.to_be_bytes());
        token.extend_from_slice(tag.as_ref()); // 32 bytes
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&[0u8; 8]); // reserved
        token
    }

    /// 验证认证令牌
    pub fn verify(
        key: &[u8],
        token: &[u8],
        client_id: &str,
        max_age_secs: u64,
    ) -> Result<(), AuthError> {
        if token.len() < Self::TOKEN_LEN {
            return Err(AuthError::InvalidToken);
        }

        let timestamp = u64::from_be_bytes(token[0..8].try_into().unwrap());
        let received_hmac = &token[8..40];
        let nonce = &token[40..56];

        // 检查时间戳有效性
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 允许 ±5s 时钟偏移：客户端与节点跨机部署时时钟差会把健康节点误判为故障
        const CLOCK_SKEW_TOLERANCE: u64 = 5;
        if timestamp > now + CLOCK_SKEW_TOLERANCE || now.saturating_sub(timestamp) > max_age_secs {
            return Err(AuthError::TokenExpired);
        }

        // 重新计算并比较 HMAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut message = Vec::new();
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(client_id.as_bytes());
        message.extend_from_slice(nonce);

        let expected = hmac::sign(&hmac_key, &message);
        ring::constant_time::verify_slices_are_equal(expected.as_ref(), received_hmac)
            .map_err(|_| AuthError::InvalidToken)
    }
}

/// 认证错误
#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    TokenExpired,
    InvalidCredentials,
    AuthRequired,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidToken => write!(f, "Invalid authentication token"),
            AuthError::TokenExpired => write!(f, "Authentication token expired"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::AuthRequired => write!(f, "Authentication required"),
        }
    }
}

/// PBKDF2 密码哈希
pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    use ring::pbkdf2;
    use std::num::NonZeroU32;

    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    const CREDENTIAL_LEN: usize = 32;
    const ITERATIONS: u32 = 100_000;

    let mut hash = vec![0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut hash,
    );
    hash
}

/// 验证密码
pub fn verify_password(password: &str, stored: &StoredCredential) -> bool {
    use ring::pbkdf2;
    use std::num::NonZeroU32;

    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    const ITERATIONS: u32 = 100_000;

    pbkdf2::verify(
        PBKDF2_ALG,
        NonZeroU32::new(ITERATIONS).unwrap(),
        &stored.salt,
        password.as_bytes(),
        &stored.hash,
    )
    .is_ok()
}

/// 创建新的凭据
pub fn create_credential(password: &str) -> StoredCredential {
    let rng = ring::rand::SystemRandom::new();
    let mut salt = vec![0u8; 16];
    rng.fill(&mut salt).unwrap();

    let hash = hash_password(password, &salt);
    StoredCredential { salt, hash }
}

/// Hex 解码（非法输入返回错误而不是 panic）
pub fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, String> {
    // 按字节处理并拒绝非 ASCII：多字节 UTF-8 字符（如 "a中"、emoji）按字节长度
    // 做偶数检查会通过，但 str 切片落在 char boundary 内会 panic（此前 fail-fast
    // 链路上 GUI/CLI 输入非法密钥即整个进程 abort）——改为返回 Err。
    if !hex.is_ascii() {
        return Err("hex 字符串包含非 ASCII 字符".to_string());
    }
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("hex 字符串长度必须为偶数".to_string());
    }
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            // 已确认全 ASCII，切片边界安全
            let pair = std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("");
            u8::from_str_radix(pair, 16)
                .map_err(|e| format!("第 {} 个字节不是合法的 hex: {}", i / 2, e))
        })
        .collect()
}

/// Hex 编码
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_合法输入() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(hex_decode("AbCd").unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn hex_decode_非法输入返回err不panic() {
        assert!(hex_decode("abc").is_err()); // 奇数长度
        assert!(hex_decode("zz").is_err()); // 非 hex 字符
    }

    #[test]
    fn hex_decode_多字节utf8输入返回err不panic() {
        // 此前实现按字节长度切片，"a中"（4 字节）通过偶数检查后切片跨 char
        // boundary 直接 panic；修复后必须返回 Err。
        assert!(hex_decode("a中").is_err());
        assert!(hex_decode("中").is_err());
        assert!(hex_decode("😀").is_err());
        assert!(hex_decode("616263中").is_err());
    }
}
