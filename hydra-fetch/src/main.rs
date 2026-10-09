//! hydra-fetch：多节点并行下载器（HTTP Range 分块 + 评分加权 + 断点续传）。
//!
//! 经 hydra 加密隧道下载：分块按节点评分加权分散到多节点并行拉取，单流回落
//! 保底。用法见 [`hydra_fetch`] 模块文档与 --help。

use hydra_fetch::download;

use hydra_core::tcp_transport::TlsTrust;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    // 日志：HYDRA_LOG_LEVEL（默认 info；RUST_LOG 优先）——与 CLI/节点同款
    {
        use tracing_subscriber::EnvFilter;
        let level = std::env::var("HYDRA_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let filter = match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info")),
        };
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("错误: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn usage() -> String {
    "用法: hydra-fetch [-o 输出文件] [--workers N] [--chunk-mb N] [--sha256 <64hex>] <https://URL> [节点 addr:port...]\n\
     环境变量: HYDRA_AUTH_KEY（64 hex，必填）| HYDRA_NODE_CERT(S)（节点证书 DER，pin 模式必填）|\n\
    　　　　　 HYDRA_TRUST=pin|ca | HYDRA_SNI | HYDRA_LOG_LEVEL（默认 info）"
        .to_string()
}

async fn run() -> Result<(), String> {
    let mut url: Option<String> = None;
    let mut nodes: Vec<String> = Vec::new();
    let mut output: Option<PathBuf> = None;
    let mut workers: usize = 0; // 0 = 自动
    let mut chunk_mb: u64 = 16;
    let mut sha256: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" | "--output" => output = Some(PathBuf::from(args.next().ok_or("-o 缺参数")?)),
            "--workers" => {
                workers = args
                    .next()
                    .ok_or("--workers 缺参数")?
                    .parse()
                    .map_err(|_| "--workers 非法")?;
            }
            "--chunk-mb" => {
                chunk_mb = args
                    .next()
                    .ok_or("--chunk-mb 缺参数")?
                    .parse()
                    .map_err(|_| "--chunk-mb 非法")?;
                if chunk_mb == 0 || chunk_mb > 1024 {
                    return Err("--chunk-mb 须在 1..=1024".to_string());
                }
            }
            "--sha256" => {
                let v = args.next().ok_or("--sha256 缺参数")?;
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("--sha256 须为 64 位 hex".to_string());
                }
                sha256 = Some(v.to_ascii_lowercase());
            }
            "-h" | "--help" => return Err(usage()),
            _ if a.starts_with('-') => return Err(format!("未知参数: {a}\n{}", usage())),
            _ if url.is_none() => url = Some(a),
            _ => nodes.push(a),
        }
    }
    let url = url.ok_or_else(usage)?;

    // 凭据（与 hydra-client 同款约定）
    let auth_key_hex =
        std::env::var("HYDRA_AUTH_KEY").map_err(|_| "未设置 HYDRA_AUTH_KEY（64 位 hex）".to_string())?;
    let auth_key = hydra_core::auth_key_from_hex(&auth_key_hex)
        .map_err(|m| format!("HYDRA_AUTH_KEY 非法: {m}"))?;
    let certs = read_certs()?;
    let trust = match std::env::var("HYDRA_TRUST").as_deref() {
        Ok("ca") => TlsTrust::public_ca(None),
        _ => {
            if certs.is_empty() {
                return Err("pin 模式需 HYDRA_NODE_CERT(S)（或 HYDRA_TRUST=ca 信任公共 CA）".to_string());
            }
            TlsTrust::pinned(certs)
        }
    };
    let sni = std::env::var("HYDRA_SNI").unwrap_or_else(|_| hydra_core::DEFAULT_SNI.to_string());

    // 节点：位置参数优先，回落 HYDRA_NODES（逗号分隔）
    let nodes_str = if nodes.is_empty() {
        std::env::var("HYDRA_NODES").map_err(|_| "未配置节点（HYDRA_NODES 或位置参数）".to_string())?
    } else {
        nodes.join(",")
    };
    let nodes: Vec<std::net::SocketAddr> = nodes_str
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("节点地址非法: {e}"))?;

    let output = output.unwrap_or_else(|| {
        // 默认输出名 = URL 路径最后一段
        url.split('?')
            .next()
            .unwrap_or("download")
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("download")
            .to_string()
            .into()
    });

    let cfg = download::FetchConfig {
        nodes,
        sni,
        trust,
        auth_key,
        workers,
        chunk_size: chunk_mb * 1024 * 1024,
        url,
        output,
        expect_sha256: sha256,
    };
    println!("Hydra 多节点下载器 v{}", env!("CARGO_PKG_VERSION"));
    download::run(cfg).await
}

/// 读取节点证书（HYDRA_NODE_CERT 单文件 / HYDRA_NODE_CERTS 逗号分隔多个，DER）
fn read_certs() -> Result<Vec<Vec<u8>>, String> {
    let list = match (
        std::env::var("HYDRA_NODE_CERT"),
        std::env::var("HYDRA_NODE_CERTS"),
    ) {
        (Ok(a), _) if !a.is_empty() => vec![a],
        (_, Ok(b)) if !b.is_empty() => b.split(',').map(|s| s.trim().to_string()).collect(),
        _ => return Ok(Vec::new()),
    };
    list.iter()
        .map(|p| std::fs::read(p).map_err(|e| format!("证书读取失败 {p}: {e}")))
        .collect()
}
