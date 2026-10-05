use ring::hmac;

// R-22（2026-10-05 Wave 2）：QUIC 时代的 legacy AuthToken / AuthConfig / PBKDF2
// 凭据模块已整体删除——该路径零调用方，且 verify 无重放防护、依赖系统时钟，
// 留存只会构成"未来误用回退到弱方案"的风险。本文件现仅保留：hex 编解码、
// P2P 信令 peer_id 属主证明。

/// 所有客户端使用的固定 client_id（单租户自用场景）
pub const CLIENT_ID: &str = "hydra";

/// Hex 解码（非法输入返回错误而不是 panic）
pub fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, String> {
    // 按字节处理并拒绝非 ASCII：多字节 UTF-8 字符（如 "a中"、emoji）按字节长度
    // 做偶数检查会通过，但 str 切片落在 char boundary 内会 panic（此前 fail-fast
    // 链路上 GUI/CLI 输入非法密钥即整个进程 abort）——改为返回 Err。
    if !hex.is_ascii() {
        return Err("hex 字符串包含非 ASCII 字符".to_string());
    }
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("hex 字符串长度必须为偶数".to_string());
    }
    // 07-P3-5 零成本顺修：显式校验字符集——from_str_radix 接受可选前导 '+'，
    // "+f"/"+0f" 会被静默解码成功，违背密钥入口 fail-fast 目标
    if !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err("hex 字符串包含非 hex 字符".to_string());
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

// ── P2P 信令 peer_id 属主证明（评审-专家团队-安全与协议：信令 peer_id 属主）──

/// 属主证明域分离标签：HMAC 消息 = `"hydra-p2p-owner" || peer_id`
pub const P2P_OWNER_PROOF_LABEL: &[u8] = b"hydra-p2p-owner";

/// 派生 peer_id 属主证明：`hex(HMAC-SHA256(psk, "hydra-p2p-owner" || peer_id))`。
/// 客户端注册时提交、节点校验（同一 PSK 双方天然可验）；同 peer_id 二次注册
/// 必须携带相同 proof，否则按顶替攻击拒绝——防止已认证连接冒用他人 peer_id。
pub fn p2p_owner_proof(psk: &[u8], peer_id: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, psk);
    let mut msg = Vec::with_capacity(P2P_OWNER_PROOF_LABEL.len() + peer_id.len());
    msg.extend_from_slice(P2P_OWNER_PROOF_LABEL);
    msg.extend_from_slice(peer_id.as_bytes());
    let tag = hmac::sign(&key, &msg);
    hex_encode(tag.as_ref())
}

/// 校验属主证明（常量时间比较，不泄漏 HMAC 部分匹配信息）
pub fn verify_p2p_owner_proof(psk: &[u8], peer_id: &str, proof_hex: &str) -> bool {
    let expected = p2p_owner_proof(psk, peer_id);
    // hex 大小写不敏感：比较统一小写化后的字符串（Proof 由 hex_encode 产出为小写）
    // ring 0.17 将 constant_time 移入 deprecated_constant_time（Wave 3 升级触发）；
    // 常量时间比较语义正是所需（不泄漏部分匹配），无等价替代 API，显式豁免弃用告警
    #[allow(deprecated)]
    ring::constant_time::verify_slices_are_equal(
        expected.as_bytes(),
        proof_hex.trim().to_ascii_lowercase().as_bytes(),
    )
    .is_ok()
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

    #[test]
    fn 属主证明派生与校验() {
        let psk = [7u8; 32];
        let proof = p2p_owner_proof(&psk, "abcd1234");
        assert_eq!(proof.len(), 64, "HMAC-SHA256 hex = 64 字符");
        assert!(verify_p2p_owner_proof(&psk, "abcd1234", &proof));
        // 大写 hex 也接受（客户端兼容），错误 proof / 错误 peer / 错误 PSK 拒绝
        assert!(verify_p2p_owner_proof(
            &psk,
            "abcd1234",
            &proof.to_uppercase()
        ));
        assert!(!verify_p2p_owner_proof(&psk, "abcd1234", &"00".repeat(32)));
        assert!(!verify_p2p_owner_proof(&psk, "other", &proof));
        assert!(!verify_p2p_owner_proof(&[8u8; 32], "abcd1234", &proof));
        // 域分离：proof 确实绑定标签 + peer_id（不同 peer_id 的证明不同）
        assert_ne!(proof, p2p_owner_proof(&psk, "other"));
    }
}
