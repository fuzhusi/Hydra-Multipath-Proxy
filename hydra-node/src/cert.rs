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
        let cert_raw = fs::read(cert_file)?;
        let key_raw = fs::read(key_file)?;
        // 真证书部署（ACME/Let's Encrypt，审查报告协议评估 P0）：检测 PEM 并解析。
        // cert_file 可为 fullchain（leaf + 中间链），key 支持 PKCS8/RSA/EC。
        if cert_raw.starts_with(b"-----BEGIN") {
            let (certs, key) = parse_pem_pair(&cert_raw, &key_raw)?;
            info!(
                "已加载 PEM 真证书（{} 证书，含链）: {} (leaf SHA-256 指纹: {})",
                certs.len(),
                cert_file.display(),
                fingerprint_hex(&certs[0].0)
            );
            return Ok((certs[0].clone(), key));
        }
        let cert_der = cert_raw;
        let key_der = key_raw;
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

/// 解析 PEM 证书链 + 私钥（真证书部署路径：HYDRA_CERT_FILE/HYDRA_KEY_FILE 指向
/// acme.sh/certbot 产出的 fullchain 与 key）。key 依次尝试 PKCS8 → RSA → EC。
fn parse_pem_pair(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    use std::io::BufRead;

    let mut rd = std::io::BufReader::new(cert_pem);
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut rd)
        .map_err(|e| HydraError::NodeError(format!("PEM 证书解析失败: {e}")))?;
    if certs.is_empty() {
        return Err(HydraError::NodeError(
            "PEM 证书文件中未找到任何证书（-----BEGIN CERTIFICATE-----）".to_string(),
        ));
    }

    let mut rd = std::io::BufReader::new(key_pem);
    let key_der = rustls_pemfile::pkcs8_private_keys(&mut rd)
        .map_err(|e| HydraError::NodeError(format!("PEM 私钥（PKCS8）解析失败: {e}")))?;
    let key_der = if !key_der.is_empty() {
        key_der
    } else {
        let mut rd = std::io::BufReader::new(key_pem);
        rustls_pemfile::rsa_private_keys(&mut rd)
            .map_err(|e| HydraError::NodeError(format!("PEM 私钥（RSA）解析失败: {e}")))?
    };
    let key_der = if !key_der.is_empty() {
        key_der
    } else {
        let mut rd = std::io::BufReader::new(key_pem);
        rustls_pemfile::ec_private_keys(&mut rd)
            .map_err(|e| HydraError::NodeError(format!("PEM 私钥（EC）解析失败: {e}")))?
    };
    let key = key_der
        .into_iter()
        .next()
        .ok_or_else(|| HydraError::NodeError("PEM 私钥文件中未找到私钥".to_string()))?;
    Ok((
        certs.into_iter().map(rustls::Certificate).collect(),
        rustls::PrivateKey(key),
    ))
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
