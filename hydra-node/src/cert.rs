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
/// rustls 0.23（Wave 3）：返回 pki-types 的 CertificateDer / PrivateKeyDer。
/// 07-P1-1 修复：返回**整条证书链**（`Vec<CertificateDer>`，叶在前）——真证书
/// 部署（ACME fullchain）下服务端必须向对端发送中间链，否则公共 CA 客户端
/// 无法构链到根，TLS 握手必败；自签/DER 路径链长为 1，行为不变。
/// 指纹/通道绑定仍取 `chain[0]`（叶证书），语义不变。
pub fn load_or_generate(
    cert_file: &Path,
    key_file: &Path,
    domains: &[String],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
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
                fingerprint_hex(certs[0].as_ref())
            );
            // 07-P1-1：整链返回（叶在前），由 spawn_tcp_listener with_single_cert 下发
            return Ok((certs, key));
        }
        let cert_der = cert_raw;
        let key_der = key_raw;
        info!(
            "已加载持久化节点证书: {} (SHA-256 指纹: {})",
            cert_file.display(),
            fingerprint_hex(&cert_der)
        );
        // 单张 DER 证书 → 链长 1（与真证书整链路径同一返回形态）
        Ok((
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        ))
    } else {
        let cert = rcgen::generate_simple_self_signed(domains.to_vec())
            .map_err(|e| HydraError::NodeError(format!("生成自签证书失败: {}", e)))?;
        // rcgen 0.13（Wave 3）：CertifiedKey { cert, key_pair }；cert.der() 取 DER
        let cert_der = cert.cert.der().as_ref().to_vec();
        let key_der = cert.key_pair.serialize_der();

        // 私钥先建后写（审查 N-07）：`create_new(true)` + unix `mode(0o600)` 使文件
        // 以最终权限原子创建，消除"先 0644 创建后 chmod"的毫秒级可读竞态窗口。
        // Windows 权限模型不同（ACL 继承，无 POSIX mode）：mode 扩展属性仅 unix
        // 生效，Windows 保持默认 ACL（当前用户私有目录下为用户私有），行为不变。
        // 失败时清理半成品，保持"证书+私钥要么同时存在要么都不存在"的加载不变量。
        write_key_file_secure(key_file, &key_der)?;
        if let Err(e) = fs::write(cert_file, &cert_der) {
            let _ = fs::remove_file(key_file);
            return Err(HydraError::NodeError(format!(
                "证书写入失败（已回滚私钥半成品）: {}",
                e
            )));
        }
        info!(
            "已生成新节点证书并保存到 {} (SHA-256 指纹: {})。请将证书文件分发给客户端用于校验。",
            cert_file.display(),
            fingerprint_hex(&cert_der)
        );
        // rcgen 0.10 KeyPair：serialize_private_key_der 产 PKCS#8 DER，
        // 与 rustls 0.23 的 PrivateKeyDer::Pkcs8 直接兼容（Wave 3 核查项）
        Ok((
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        ))
    }
}

/// 以独占创建（create_new）+ unix 0600 权限写入私钥。
/// create_new 失败（AlreadyExists）→ 保持"存在即加载"语义：转由上层下一次启动
/// 走加载路径；此处直接报错并提示删除或检查（并发首次生成属异常场景）。
fn write_key_file_secure(key_file: &Path, key_der: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    // Windows：无 POSIX mode，ACL 由目录继承决定（注释见调用点）
    let mut f = opts.open(key_file).map_err(|e| {
        HydraError::NodeError(format!(
            "私钥文件独占创建失败（{}）: {}（已存在则删除后重试或走加载路径）",
            key_file.display(),
            e
        ))
    })?;
    // 07-P2-2：write/flush/sync_all 任一失败都必须回滚半成品 key 文件——否则
    // 下次启动走"存在即加载"分支并命中"证书/私钥不完整"检查，无人值守节点
    // 从此无法自愈（启动死锁）。sync_all 保证掉电不留下"存在但截断"的密钥。
    let write_res = (|| -> std::io::Result<()> {
        f.write_all(key_der)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(key_file);
        return Err(HydraError::NodeError(format!(
            "私钥写入失败（已回滚半成品文件）: {}",
            e
        )));
    }
    Ok(())
}

/// 证书 DER 的 SHA-256 指纹（hex）
pub fn fingerprint_hex(cert_der: &[u8]) -> String {
    hex_encode(digest(&SHA256, cert_der).as_ref())
}

/// 解析 PEM 证书链 + 私钥（真证书部署路径：HYDRA_CERT_FILE/HYDRA_KEY_FILE 指向
/// acme.sh/certbot 产出的 fullchain 与 key）。key 依次尝试 PKCS8 → RSA → EC。
/// rustls-pemfile 2.x（Wave 3）：迭代器产出 CertificateDer / 各类 key DER 新类型。
fn parse_pem_pair(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let mut rd = std::io::BufReader::new(cert_pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| HydraError::NodeError(format!("PEM 证书解析失败: {e}")))?;
    if certs.is_empty() {
        return Err(HydraError::NodeError(
            "PEM 证书文件中未找到任何证书（-----BEGIN CERTIFICATE-----）".to_string(),
        ));
    }

    let mut rd = std::io::BufReader::new(key_pem);
    let key_der = rustls_pemfile::pkcs8_private_keys(&mut rd)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| HydraError::NodeError(format!("PEM 私钥（PKCS8）解析失败: {e}")))?;
    let key_der = if !key_der.is_empty() {
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into_iter().next().unwrap())
    } else {
        let mut rd = std::io::BufReader::new(key_pem);
        let keys = rustls_pemfile::rsa_private_keys(&mut rd)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| HydraError::NodeError(format!("PEM 私钥（RSA）解析失败: {e}")))?;
        if !keys.is_empty() {
            rustls::pki_types::PrivateKeyDer::Pkcs1(keys.into_iter().next().unwrap())
        } else {
            let mut rd = std::io::BufReader::new(key_pem);
            let keys = rustls_pemfile::ec_private_keys(&mut rd)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| HydraError::NodeError(format!("PEM 私钥（EC）解析失败: {e}")))?;
            rustls::pki_types::PrivateKeyDer::Sec1(
                keys.into_iter()
                    .next()
                    .ok_or_else(|| HydraError::NodeError("PEM 私钥文件中未找到私钥".to_string()))?,
            )
        }
    };
    Ok((certs, key_der))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 09 审查补测（此前 cert.rs 零测试）：rcgen 生成真自签 PEM 对 →
    /// parse_pem_pair 应产出可被 rustls 消费的证书链与私钥；
    /// 坏输入有清晰错误而非 panic。
    #[test]
    fn pem_对解析_rcgen自签往返() {
        let certified = rcgen::generate_simple_self_signed(vec!["hydra.node".into()])
            .expect("rcgen 生成自签证书失败");
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();

        let (chain, key_der) =
            parse_pem_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("合法 PEM 对应解析成功");
        assert!(!chain.is_empty(), "证书链至少含叶证书");
        // 叶证书 DER 与 PEM 内容一致（指纹可复算）
        assert_eq!(fingerprint_hex(chain[0].as_ref()).len(), 64);
        assert!(!key_der.secret_der().is_empty(), "私钥 DER 非空");
    }

    #[test]
    fn pem_空证书与坏输入_显式报错不panic() {
        // 空证书文件
        let err = parse_pem_pair(b"", b"").expect_err("空输入必须报错");
        assert!(
            err.to_string().contains("未找到任何证书"),
            "错误信息应指明原因: {err}"
        );
        // 有证书无合法私钥
        let certified = rcgen::generate_simple_self_signed(vec!["hydra.node".into()]).unwrap();
        let err = parse_pem_pair(certified.cert.pem().as_bytes(), b"not a key")
            .expect_err("坏私钥必须报错");
        assert!(!err.to_string().is_empty());
    }
}
