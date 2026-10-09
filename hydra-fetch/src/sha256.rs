//! 流式 SHA-256（ring）：完成后整文件回读校验（`--sha256` 可选）。
//! 注：SHA-256 无法乱序合并分块，故校验在拼装完成后一次性回读（一次额外读盘，
//! 如实写入 --help）。流式读取（1MB 缓冲）——不支持大文件整读进内存。

use std::path::Path;

/// 计算文件 SHA-256（hex 小写；流式，内存占用 O(1MB)）
pub async fn file_sha256_hex(path: &Path) -> std::io::Result<String> {
    use ring::digest::{Context, SHA256};
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex_lower(ctx.finish().as_ref()))
}

/// 计算内存字节序列 SHA-256（hex 小写；测试用）
pub fn bytes_sha256_hex(data: &[u8]) -> String {
    use ring::digest::{digest, SHA256};
    hex_lower(digest(&SHA256, data).as_ref())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 空输入已知摘要() {
        assert_eq!(
            bytes_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc已知摘要() {
        assert_eq!(
            bytes_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn 文件流式摘要与内存一致() {
        let dir = std::env::temp_dir().join(format!("hydra-fetch-sha-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("data.bin");
        tokio::fs::write(&p, b"abc").await.unwrap();
        assert_eq!(file_sha256_hex(&p).await.unwrap(), bytes_sha256_hex(b"abc"));
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
