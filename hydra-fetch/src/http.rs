//! 最小 HTTP/1.1 客户端（跑在 hydra 隧道流上）：仅覆盖下载器需要的子集。
//!
//! # 范围与边界（如实）
//! - 请求：GET（含 Range/If-Range 头）、HEAD；固定 `Connection: close`？**否**——
//!   worker 持久隧道依赖 keep-alive（同连接 Content-Length 界定完整 body 后可
//!   发下一请求），故默认不主动关闭，由响应帧式决定 body 边界；
//! - 响应：状态行 + 大小写不敏感头解析（头部区上限 64KB，防恶意超大头部）；
//!   body 三种帧式：Content-Length / chunked（RFC 7230 §4.1）/ 连接关闭读至 EOF
//!   （EOF 帧式下无法复用隧道——读取后即弃）；
//! - 不支持：压缩（不发 Accept-Encoding，服务器不应压缩响应）、100-continue、
//!   trailer、HTTP/2（隧道目标 TLS 已锁定 ALPN=http/1.1，见 target_tls.rs）。
//!
//! 解析为纯函数（`parse_response_head`）可单测，I/O 与解析分离。

use std::collections::HashMap;
use tokio::io::AsyncReadExt;

/// 解析后的响应头（body 由调用方按帧式读取）
#[derive(Debug)]
pub struct ResponseHead {
    pub status: u16,
    /// 头名称统一小写
    pub headers: HashMap<String, String>,
    /// 帧式（None = 连接关闭读至 EOF）
    pub body_kind: BodyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// 按 Content-Length 界定（keep-alive 可复用）
    Length(u64),
    /// chunked 传输编码（可复用）
    Chunked,
    /// 读至连接关闭（不可复用；对 Range 请求即"服务器不支持分块"信号）
    Eof,
}

/// 构造 GET/HEAD 请求报文（\r\n 结尾，含 Host）
pub fn build_request(
    method: &str,
    host: &str,
    path: &str,
    range: Option<(u64, Option<u64>)>,
    if_range: Option<&str>,
) -> Vec<u8> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: hydra-fetch/{}\r\nAccept: */*\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Some((start, end)) = range {
        match end {
            Some(e) => req.push_str(&format!("Range: bytes={start}-{e}\r\n")),
            None => req.push_str(&format!("Range: bytes={start}-\r\n")),
        }
        // If-Range：仅当校验器匹配时才按 Range 响应，否则服务器回 200 全量
        // （防下载中途内容变更拼出脏文件——服务器端校验优于客户端比对）
        if let Some(validator) = if_range {
            req.push_str(&format!("If-Range: {validator}\r\n"));
        }
    }
    req.push_str("Connection: keep-alive\r\n\r\n");
    req.into_bytes()
}

/// 读取并解析响应头（从流上读至 \r\n\r；流式读取避免一次性吞掉 body 前缀）。
/// 返回 (解析头, 头部之后已读入缓冲区的 body 前缀)。
pub async fn read_response_head<S>(
    stream: &mut S,
) -> std::io::Result<(ResponseHead, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];
    // 头部区上限 64KB（与 hydra 客户端 HTTP 入站同款防御）
    loop {
        if let Some(pos) = find_head_end(&buf) {
            let head_bytes = buf[..pos].to_vec();
            let body_prefix = buf[pos + 4..].to_vec(); // 跳过 \r\n\r\n
            let head = parse_response_head(&head_bytes)?;
            return Ok((head, body_prefix));
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP 响应头部超过 64KB 上限",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "连接在响应头完成前关闭",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// 头部结束标记（\r\n\r\n）位置
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析响应头（纯函数）。status 非法/缺 Host 结构 → 错误。
pub fn parse_response_head(head: &[u8]) -> std::io::Result<ResponseHead> {
    let text = std::str::from_utf8(head)
        .map_err(|_| invalid("响应头非 UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| invalid("空响应"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(invalid(format!("非 HTTP/1.x 响应: {version}")));
    }
    let status: u16 = parts
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| invalid(format!("状态码非法: {status_line}")))?;
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            // 头名称大小写不敏感（统一小写）；重复头取首个（下载器关心的
            // Content-Length/ETag/Transfer-Encoding 不应重复）
            headers
                .entry(k.trim().to_ascii_lowercase())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    let body_kind = if let Some(te) = headers.get("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            BodyKind::Chunked
        } else {
            BodyKind::Eof
        }
    } else if let Some(cl) = headers.get("content-length") {
        let len: u64 = cl
            .trim()
            .parse()
            .map_err(|_| invalid(format!("Content-Length 非法: {cl}")))?;
        BodyKind::Length(len)
    } else {
        BodyKind::Eof
    };
    Ok(ResponseHead {
        status,
        headers,
        body_kind,
    })
}

pub fn header<'a>(h: &'a ResponseHead, name: &str) -> Option<&'a str> {
    h.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
}

pub fn invalid(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

/// 统一 body 读取器：三种帧式的流式读取（`read` 返回 0 = body 结束）。
/// - `Length`：读满 remaining 即结束——**连接可复用**（keep-alive 下一请求）；
/// - `Chunked`：逐块解码（块长行 + 数据 + CRLF），0 尺寸终止块即结束——可复用；
/// - `Eof`：读到连接关闭即结束——**连接不可复用**（读完置 `dead = true`）。
///
/// `prefix` = [`read_response_head`] 带出的 body 前缀字节：读取器先吐前缀、
/// 再读流；`Length` 的 remaining 构造时已扣除前缀长度——调用方**不要**重复
/// 写入 prefix（前缀经读取器统一交付）。
pub struct BodyReader<S> {
    stream: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
    kind: BodyKind,
    remaining: u64,
    /// chunked 解码状态机：Some(块内剩余) = 正在读块数据；None = 需要读块长行
    chunk_remaining: u64,
    chunk_done: bool,
    /// Eof 帧式读完后的连接死亡标记
    pub dead: bool,
}

impl<S: tokio::io::AsyncRead + Unpin> BodyReader<S> {
    pub fn new(stream: S, head: &ResponseHead, prefix: Vec<u8>) -> Self {
        let plen = prefix.len() as u64;
        let remaining = match head.body_kind {
            BodyKind::Length(n) => n.saturating_sub(plen),
            _ => 0,
        };
        Self {
            stream,
            prefix,
            prefix_pos: 0,
            kind: head.body_kind,
            remaining,
            chunk_remaining: 0,
            chunk_done: false,
            dead: false,
        }
    }

    /// 底层字节源：先吐前缀，前缀耗尽后读流。
    /// `cap` 限制**流**读取量（Length 帧式的 remaining 限幅）；前缀不受 cap
    /// 限制（其长度本身即上限）。每次调用只从一个源返回。
    async fn raw_read(&mut self, buf: &mut [u8], cap: Option<usize>) -> std::io::Result<usize> {
        if self.prefix_pos < self.prefix.len() {
            let avail = self.prefix.len() - self.prefix_pos;
            let want = buf.len().min(avail).min(cap.unwrap_or(buf.len()));
            buf[..want].copy_from_slice(&self.prefix[self.prefix_pos..self.prefix_pos + want]);
            self.prefix_pos += want;
            return Ok(want);
        }
        let want = buf.len().min(cap.unwrap_or(buf.len()));
        let n = self.stream.read(&mut buf[..want]).await?;
        Ok(n)
    }

    /// 读一段 body 到 buf（≤buf.len()），返回实际读取数；Ok(0) = body 结束
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.kind {
            BodyKind::Length(_) => {
                let from_prefix = self.prefix_pos < self.prefix.len();
                if !from_prefix && self.remaining == 0 {
                    return Ok(0);
                }
                // 流读取按 remaining 限幅（前缀字节已从 remaining 扣除）
                let cap = (!from_prefix).then_some(self.remaining as usize);
                let n = self.raw_read(buf, cap).await?;
                if n == 0 {
                    return Err(invalid("Content-Length 未读满连接即关闭"));
                }
                if !from_prefix {
                    self.remaining -= n as u64;
                }
                Ok(n)
            }
            BodyKind::Chunked => self.read_chunked(buf).await,
            BodyKind::Eof => {
                let n = self.raw_read(buf, None).await?;
                if n == 0 {
                    self.dead = true;
                }
                Ok(n)
            }
        }
    }

    /// 读满 `buf.len()` 字节（下载路径：块边界必须读满，少一字节即错误）
    pub async fn read_exact_body(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(invalid("body 提前结束（Range 块未读满）"));
            }
            filled += n;
        }
        Ok(())
    }

    async fn read_chunked(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // 每次调用推进一段：块长行 → 块数据 → 块尾 CRLF → … → 0 终止块。
        // 读行/读数据统一走 raw_read（前缀与流的边界对解析器透明）
        if self.chunk_done {
            return Ok(0);
        }
        if self.chunk_remaining == 0 {
            // 读块长行（十六进制 + 可选扩展，CRLF 结尾）
            let line = self.read_line().await?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_str, 16)
                .map_err(|_| invalid(format!("chunked 块长非法: {line}")))?;
            if size == 0 {
                // 终止块：随后是尾注头直到空行（读掉一行即可——本客户端
                // 不发送 trailer 相关头，服务器通常直接空行收尾）
                let _ = self.read_line().await?;
                self.chunk_done = true;
                return Ok(0);
            }
            self.chunk_remaining = size;
        }
        let want = buf.len().min(self.chunk_remaining as usize);
        let n = self.raw_read(&mut buf[..want], None).await?;
        if n == 0 {
            return Err(invalid("chunked 数据未读完连接即关闭"));
        }
        self.chunk_remaining -= n as u64;
        if self.chunk_remaining == 0 {
            // 块数据后的 CRLF
            let crlf = self.read_line().await?;
            if crlf != "\r\n" && !crlf.is_empty() {
                return Err(invalid(format!("chunked 块尾非 CRLF: {crlf:?}")));
            }
        }
        Ok(n)
    }

    /// 读一行（\r\n 或 \n 结尾；行上限 8KB）
    async fn read_line(&mut self) -> std::io::Result<String> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = self.raw_read(&mut b, None).await?;
            if n == 0 {
                return Err(invalid("行读取中连接关闭"));
            }
            if b[0] == b'\n' {
                break;
            }
            if b[0] != b'\r' {
                line.push(b[0]);
            }
            if line.len() > 8 * 1024 {
                return Err(invalid("行超长（8KB 上限）"));
            }
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 解析_206_带_content_length() {
        let raw = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 16MB-32MB-1/100MB\r\nContent-Length: 10485760\r\nETag: \"abc\"\r\n\r\n";
        let h = parse_response_head(raw).unwrap();
        assert_eq!(h.status, 206);
        assert_eq!(h.body_kind, BodyKind::Length(10485760));
        assert_eq!(header(&h, "etag"), Some("\"abc\""));
        assert_eq!(header(&h, "CONTENT-RANGE"), Some("bytes 16MB-32MB-1/100MB"));
    }

    #[test]
    fn 解析_chunked_与_eof_帧式() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(parse_response_head(chunked).unwrap().body_kind, BodyKind::Chunked);
        let eof = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(parse_response_head(eof).unwrap().body_kind, BodyKind::Eof);
    }

    #[test]
    fn 恶意头部_超限与非法状态码() {
        assert!(parse_response_head(b"NOT-HTTP\r\n\r\n").is_err());
        assert!(parse_response_head(b"HTTP/1.1 ABC BAD\r\n\r\n").is_err());
        // Content-Length 非法
        let bad = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n";
        assert!(parse_response_head(bad).is_err());
    }

    #[test]
    fn 请求_带_range与if_range() {
        let req = build_request("GET", "example.com", "/f.iso", Some((0, Some(99))), Some("\"e1\""));
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("GET /f.iso HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(s.contains("Range: bytes=0-99\r\n"));
        assert!(s.contains("If-Range: \"e1\"\r\n"));
        assert!(s.ends_with("Connection: keep-alive\r\n\r\n"));
        // 开放区间
        let req2 = build_request("HEAD", "h", "/", Some((5, None)), None);
        assert!(String::from_utf8(req2).unwrap().contains("Range: bytes=5-\r\n"));
    }

    #[tokio::test]
    async fn 流式读取_头与body前缀分离() {
        // 模拟流：头 + body 前缀一次性到达
        let mut stream: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nABCD".to_vec(),
        );
        let (head, prefix) = read_response_head(&mut stream).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(prefix, b"ABCD");
    }

    #[tokio::test]
    async fn body_reader_length_读满即止() {
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 206 Partial Content\r\nContent-Length: 6\r\n\r\nABCDEF".to_vec(),
        );
        let (head, prefix) = read_response_head(&mut stream).await.unwrap();
        assert_eq!(prefix, b"ABCDEF");
        // 前缀经读取器统一交付（remaining 构造时已扣除前缀长度）
        let mut reader = BodyReader::new(&mut stream, &head, prefix);
        assert!(!reader.dead, "Length 帧式可复用");
        let mut all = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, b"ABCDEF");
        assert!(!reader.dead);
    }

    #[tokio::test]
    async fn body_reader_chunked解码() {
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nwor\r\n0\r\n\r\n".to_vec(),
        );
        let (head, prefix) = read_response_head(&mut stream).await.unwrap();
        let mut reader = BodyReader::new(&mut stream, &head, prefix);
        let mut all = Vec::new();
        let mut buf = [0u8; 4];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, b"hellowor");
        assert!(!reader.dead, "chunked 终止块后连接可复用");
    }

    #[tokio::test]
    async fn body_reader_eof_死亡标记() {
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\n\r\nbody-till-eof".to_vec(),
        );
        let (head, prefix) = read_response_head(&mut stream).await.unwrap();
        let mut reader = BodyReader::new(&mut stream, &head, prefix);
        let mut all = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(all, b"body-till-eof");
        assert!(reader.dead, "EOF 帧式读完 = 连接耗尽");
    }
}
