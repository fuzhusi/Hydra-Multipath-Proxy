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

impl AuthToken {
    const TOKEN_LEN: usize = 64;
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

        if now < timestamp || now - timestamp > max_age_secs {
            return Err(AuthError::TokenExpired);
        }

        // 重新计算并比较 HMAC
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut message = Vec::new();
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(client_id.as_bytes());
        message.extend_from_slice(nonce);

        let expected = hmac::sign(&hmac_key, &message);
        ring::constant_time::verify_slices_are_equal(
            expected.as_ref(), received_hmac
        ).map_err(|_| AuthError::InvalidToken)
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

/// 速率限制器
pub struct AuthRateLimiter {
    attempts: std::sync::Mutex<HashMap<std::net::IpAddr, Vec<std::time::Instant>>>,
    max_attempts: usize,
    window: std::time::Duration,
}

impl AuthRateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: std::sync::Mutex::new(HashMap::new()),
            max_attempts,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// 检查是否允许请求，返回 true 表示允许
    pub fn check(&self, addr: std::net::IpAddr) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = std::time::Instant::now();

        let entry = attempts.entry(addr).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);

        if entry.len() >= self.max_attempts {
            return false; // 速率限制
        }

        entry.push(now);
        true
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
    ).is_ok()
}

/// 创建新的凭据
pub fn create_credential(password: &str) -> StoredCredential {
    let rng = ring::rand::SystemRandom::new();
    let mut salt = vec![0u8; 16];
    rng.fill(&mut salt).unwrap();

    let hash = hash_password(password, &salt);
    StoredCredential { salt, hash }
}

/// Hex 解码
pub fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Hex 编码
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
