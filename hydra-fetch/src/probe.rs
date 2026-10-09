//! 目标探测：HEAD →（405/501 回退）Range-GET bytes=0-0；重定向跟随（≤5 次）。
//! 提取 Content-Length / Accept-Ranges / ETag / Last-Modified。
//!
//! 仅支持 **https** 目标：隧道对字节透明，下载器在隧道内对目标做端到端 TLS
//! （webpki 公共 CA + 主机名校验）；明文 http 目标显式拒绝（分发场景没有走
//! 明文的理由）。探测隧道每次新建（元信息阶段，复用收益为零）。

use hydra_core::tcp_transport::TcpNodeStream;

use crate::engine::TunnelFactory;
use crate::http::{self, header};

/// 探测结果（决定分块并行 or 单流回落）
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// 最终（重定向后）主机名（目标站 TLS SNI/Host/隧道目标用）
    pub host: String,
    pub port: u16,
    /// 最终路径（含 query）
    pub path: String,
    pub total_len: Option<u64>,
    pub accept_ranges: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// 解析 https URL（path 默认 /）
pub fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("仅支持 https URL: {url}"))?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("端口非法: {hostport}"))?,
        ),
        None => (hostport.to_string(), 443),
    };
    if host.is_empty() {
        return Err(format!("URL 缺主机名: {url}"));
    }
    if path.contains(['\r', '\n', '\0']) || host.contains(['\r', '\n', '\0']) {
        return Err("URL 含非法控制字符（CRLF 注入防御）".to_string());
    }
    Ok((host, port, path))
}

/// 探测（重定向 ≤5 次；每次重定向后重建隧道——目标站可能变化）
pub async fn probe(
    tls_connector: &crate::target_tls::TargetTlsConnector,
    factory: &TunnelFactory,
    url: &str,
) -> Result<ProbeResult, String> {
    let mut current = url.to_string();
    for _ in 0..=5 {
        let (host, port, path) = parse_https_url(&current)?;
        // 重建探测隧道（重定向可能换目标站，旧隧道已指向旧地址）
        let (_node, tunnel) = factory.open(&host, port).await?;
        let mut tls_stream = tls_connector.connect(&host, tunnel).await?;

        // 先 HEAD；405/501 → Range-GET bytes=0-0（从 Content-Range 取总长）
        let head = match issue(&mut tls_stream, &host, &path, "HEAD", None, None).await {
            Ok((h, _)) if h.status == 405 || h.status == 501 => {
                let (h2, _) = issue(
                    &mut tls_stream,
                    &host,
                    &path,
                    "GET",
                    Some((0, Some(0))),
                    None,
                )
                .await?;
                match h2.status {
                    206 => {
                        let total = header(&h2, "content-range")
                            .and_then(|v| v.rsplit('/').next().and_then(|t| t.parse::<u64>().ok()));
                        (h2, total, true)
                    }
                    200 => {
                        // 服务器不支持 Range：Content-Length 即总长
                        let total =
                            header(&h2, "content-length").and_then(|v| v.parse::<u64>().ok());
                        (h2, total, false)
                    }
                    code => return Err(format!("Range 探测失败（HTTP {code}）: {current}")),
                }
            }
            Ok((h, _)) => {
                let total = header(&h, "content-length").and_then(|v| v.parse::<u64>().ok());
                let ar = header(&h, "accept-ranges")
                    .map(|v| v.to_ascii_lowercase().contains("bytes"))
                    .unwrap_or(false);
                (h, total, ar)
            }
            Err(e) => return Err(format!("探测请求失败: {e}")),
        };

        match head.0.status {
            200 | 206 => {
                return Ok(ProbeResult {
                    host,
                    port,
                    path,
                    total_len: head.1,
                    accept_ranges: head.2,
                    etag: header(&head.0, "etag")
                        .filter(|v| !v.contains(['\r', '\n']))
                        .map(|s| s.to_string()),
                    last_modified: header(&head.0, "last-modified")
                        .filter(|v| !v.contains(['\r', '\n']))
                        .map(|s| s.to_string()),
                });
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = header(&head.0, "location")
                    .ok_or_else(|| format!("重定向缺 Location: {current}"))?
                    .to_string();
                // Location 规范化：协议相对 //host/path、缺前导 / 的相对路径；
                // CRLF 注入防御（恶意 Location 拼请求头——防御纵深）
                if loc.contains(['\r', '\n', '\0']) {
                    return Err("Location 含非法控制字符".to_string());
                }
                current = if loc.starts_with("https://") {
                    loc
                } else if loc.starts_with("http://") {
                    return Err("重定向到明文 http——仅支持 https 目标".to_string());
                } else if let Some(rest) = loc.strip_prefix("//") {
                    format!("https://{rest}")
                } else if loc.starts_with('/') {
                    format!("https://{host}:{port}{loc}")
                } else {
                    // 相对路径：基于当前 path 的目录（简单拼接已满足分发场景）
                    let base = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                    format!("https://{host}:{port}{base}/{loc}")
                };
                continue;
            }
            code => return Err(format!("探测失败（HTTP {code}）: {current}")),
        }
    }
    Err("重定向次数超限（>5）".to_string())
}

/// 发请求并读响应头（返回头 + 未消费的 body 前缀——探测不读 body，随隧道丢弃）
async fn issue(
    stream: &mut tokio_rustls::client::TlsStream<TcpNodeStream>,
    host: &str,
    path: &str,
    method: &str,
    range: Option<(u64, Option<u64>)>,
    if_range: Option<&str>,
) -> Result<(http::ResponseHead, Vec<u8>), String> {
    use tokio::io::AsyncWriteExt;
    let req = http::build_request(method, host, path, range, if_range);
    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("请求写入失败: {e}"))?;
    http::read_response_head(stream)
        .await
        .map_err(|e| format!("响应读取失败: {e}"))
}
