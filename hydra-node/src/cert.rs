use std::fs;
use std::path::Path;
use ring::digest::{digest, SHA256};
use tracing::info;
use hydra_protocol::{hex_encode, Result, HydraError};

/// 加载或生成节点证书。
///
/// 证书持久化到磁盘：客户端通过把该证书加入本地信任根（RootCertStore）实现
/// 标准 webpki 校验，杜绝 SkipVerification 带来的中间人风险。
pub fn load_or_generate(
    cert_file: &Path,
    key_file: &Path,
    domains: &[String],
) -> Result<(rustls::Certificate, rustls::PrivateKey)> {
    if cert_file.exists() && key_file.exists() {
        let cert_der = fs::read(cert_file)?;
        let key_der = fs::read(key_file)?;
        info!(
            "已加载持久化节点证书: {} (SHA-256 指纹: {})",
            cert_file.display(),
            fingerprint_hex(&cert_der)
        );
        Ok((rustls::Certificate(cert_der), rustls::PrivateKey(key_der)))
    } else {
        let cert = rcgen::generate_simple_self_signed(domains.to_vec()).map_err(|e| {
            HydraError::NodeError(format!("生成自签证书失败: {}", e))
        })?;
        let cert_der = cert.serialize_der().map_err(|e| {
            HydraError::NodeError(format!("证书序列化失败: {}", e))
        })?;
        let key_der = cert.serialize_private_key_der();

        fs::write(cert_file, &cert_der)?;
        fs::write(key_file, &key_der)?;
        info!(
            "已生成新节点证书并保存到 {} (SHA-256 指纹: {})。请将证书文件分发给客户端用于校验。",
            cert_file.display(),
            fingerprint_hex(&cert_der)
        );
        Ok((rustls::Certificate(cert_der), rustls::PrivateKey(key_der)))
    }
}

/// 证书 DER 的 SHA-256 指纹（hex）
pub fn fingerprint_hex(cert_der: &[u8]) -> String {
    hex_encode(digest(&SHA256, cert_der).as_ref())
}
