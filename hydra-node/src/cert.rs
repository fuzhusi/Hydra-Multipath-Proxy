use hydra_protocol::{hex_encode, HydraError, Result};
use ring::digest::{digest, SHA256};
use std::fs;
use std::path::Path;
use tracing::info;
#[cfg(unix)]
use tracing::warn;

/// 加载或生成节点证书。
///
/// 证书持久化到磁盘：客户端通过把该证书加入本地信任根（RootCertStore）实现
/// 标准 webpki 校验，杜绝 SkipVerification 带来的中间人风险。
pub fn load_or_generate(
    cert_file: &Path,
    key_file: &Path,
    domains: &[String],
) -> Result<(rustls::Certificate, rustls::PrivateKey)> {
    if cert_file.exists() || key_file.exists() {
        // 只剩其一时拒绝启动：静默重新生成会让客户端 pin 的证书指纹失效
        if !(cert_file.exists() && key_file.exists()) {
            return Err(HydraError::NodeError(format!(
                "证书/私钥不完整（{}: {}，{}: {}），拒绝重新生成以免客户端证书固定失效。请补齐或同时删除两者。",
                cert_file.display(),
                cert_file.exists(),
                key_file.display(),
                key_file.exists()
            )));
        }
        warn_if_key_permissions_too_open(key_file);
        let cert_der = fs::read(cert_file)?;
        let key_der = fs::read(key_file)?;
        info!(
            "已加载持久化节点证书: {} (SHA-256 指纹: {})",
            cert_file.display(),
            fingerprint_hex(&cert_der)
        );
        Ok((rustls::Certificate(cert_der), rustls::PrivateKey(key_der)))
    } else {
        let cert = rcgen::generate_simple_self_signed(domains.to_vec())
            .map_err(|e| HydraError::NodeError(format!("生成自签证书失败: {}", e)))?;
        let cert_der = cert
            .serialize_der()
            .map_err(|e| HydraError::NodeError(format!("证书序列化失败: {}", e)))?;
        let key_der = cert.serialize_private_key_der();

        fs::write(cert_file, &cert_der)?;
        fs::write(key_file, &key_der)?;
        set_unix_file_permissions(cert_file, key_file);
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

/// Unix 下收紧落盘权限（遗留 G）：私钥 0600，证书 0644（需分发给客户端）。
/// 收紧失败只告警不阻断启动（证书功能不受影响，但运维须关注）。
#[cfg(unix)]
fn set_unix_file_permissions(cert_file: &Path, key_file: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for (path, mode, what) in [(key_file, 0o600, "私钥"), (cert_file, 0o644, "证书")] {
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
            warn!(
                "{}权限收紧失败（目标 {:o}）: {}: {}——请手动 chmod",
                what,
                mode,
                path.display(),
                e
            );
        }
    }
}

#[cfg(not(unix))]
fn set_unix_file_permissions(_cert_file: &Path, _key_file: &Path) {}

/// Unix 下加载既有私钥时，权限宽于 0600（group/other 任一可访问）则告警
#[cfg(unix)]
fn warn_if_key_permissions_too_open(key_file: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(key_file) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            warn!(
                "私钥权限过宽（{:o}，应 0600）: {}——本机其他用户可能读取私钥",
                mode,
                key_file.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_key_permissions_too_open(_key_file: &Path) {}
