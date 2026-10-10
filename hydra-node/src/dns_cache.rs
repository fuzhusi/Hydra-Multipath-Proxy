//! 节点级 DNS 共享缓存 + 全局解析并发闸（内核优化 #6）。
//!
//! # 动机（量化）
//! TCP 路径每连接冷 `getaddrinfo`（spawn_blocking，5s 超时）：域名透传负载
//! 下每新连接多 10-200ms 首字节延迟；解析器故障时每连接烧满 5s 且可瞬间
//! 打出 512 个 blocking 线程（tokio 默认池）。UDP 路径已有连接内缓存
//! （TTL 60s/128 条），本模块提供**进程级共享缓存 + 全局 Semaphore**，
//! 两条路径单源化。
//!
//! # 语义
//! - 缓存条目存**已过 SSRF 过滤的地址**（过滤位置与现状一致：解析后复查）；
//! - 统一 TTL 60s 上限（getaddrinfo 不暴露记录 TTL；负缓存 10s）；
//! - 容量 1024 条 LRU（超限清最旧）；全局解析并发 64（排队 3s 超时）；
//! - `HYDRA_DNS_CACHE=0` 关闭缓存（回落逐连接解析，并发闸保留）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 正向缓存 TTL（getaddrinfo 无记录 TTL——统一 60s 上限）
const POSITIVE_TTL: Duration = Duration::from_secs(60);
/// 负缓存 TTL（解析失败 short-circuit，防解析器故障期间每连接重打）
const NEGATIVE_TTL: Duration = Duration::from_secs(10);
/// 容量上限（LRU 超限清最旧）
const MAX_ENTRIES: usize = 1024;
/// 全局解析并发闸（封顶 blocking 池占用）
const RESOLVE_CONCURRENCY: usize = 64;
/// 并发闸排队超时
const QUEUE_TIMEOUT: Duration = Duration::from_secs(3);

struct CacheEntry {
    addrs: Vec<SocketAddr>,
    at: Instant,
    negative: bool,
}

struct DnsCacheInner {
    map: HashMap<String, CacheEntry>,
}

fn cache() -> &'static Mutex<DnsCacheInner> {
    static C: OnceLock<Mutex<DnsCacheInner>> = OnceLock::new();
    C.get_or_init(|| {
        Mutex::new(DnsCacheInner {
            map: HashMap::new(),
        })
    })
}

fn cache_enabled() -> bool {
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| std::env::var("HYDRA_DNS_CACHE").as_deref() != Ok("0"))
}

fn resolve_semaphore() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(RESOLVE_CONCURRENCY))
}

/// 查缓存：命中且未过期 → Some(addrs)（negative 命中 = Some(vec![]) 表示
/// 「已知解析失败」——调用方直接返回 DNS 错误不再打上游）
pub(crate) fn lookup_cached(host: &str) -> Option<Vec<SocketAddr>> {
    if !cache_enabled() {
        return None;
    }
    let mut c = cache().lock().unwrap_or_else(|p| p.into_inner());
    let ttl = match c.map.get(host) {
        Some(e) if e.negative => NEGATIVE_TTL,
        Some(_) => POSITIVE_TTL,
        None => return None,
    };
    match c.map.get(host) {
        Some(e) if e.at.elapsed() < ttl => Some(e.addrs.clone()),
        Some(_) => {
            c.map.remove(host);
            None
        }
        None => None,
    }
}

/// 写缓存（LRU 超限清最旧）
fn put_cache(host: &str, addrs: Vec<SocketAddr>, negative: bool) {
    if !cache_enabled() {
        return;
    }
    let mut c = cache().lock().unwrap_or_else(|p| p.into_inner());
    if c.map.len() >= MAX_ENTRIES {
        // 清最旧（O(n) 一次，1024 条可接受）
        if let Some(oldest) = c
            .map
            .iter()
            .min_by_key(|(_, e)| e.at)
            .map(|(k, _)| k.clone())
        {
            c.map.remove(&oldest);
        }
    }
    c.map.insert(
        host.to_string(),
        CacheEntry {
            addrs,
            at: Instant::now(),
            negative,
        },
    );
}

/// 带缓存 + 并发闸的域名解析（DNS 宽松匹配 target 域名；IP 字面量由调用方
/// 在进入本函数前拦截）。返回 None = 负缓存/解析失败（调用方按 DNS 错误处理）。
pub(crate) async fn resolve_host_cached(host: &str) -> Option<Vec<SocketAddr>> {
    if let Some(cached) = lookup_cached(host) {
        if cached.is_empty() {
            return None; // 负缓存命中
        }
        return Some(cached);
    }
    // 全局并发闸（排队 3s 超时——防解析器故障期间排队雪崩）
    let _permit = match tokio::time::timeout(
        QUEUE_TIMEOUT,
        resolve_semaphore().acquire(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            tracing::warn!("DNS 解析并发闸排队超时（{QUEUE_TIMEOUT:?}）: {host}");
            return None;
        }
    };
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(host.to_string()),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let v: Vec<SocketAddr> = addrs.collect();
            if v.is_empty() {
                put_cache(host, Vec::new(), true);
                return None;
            }
            put_cache(host, v.clone(), false);
            Some(v)
        }
        Ok(Err(_)) => {
            put_cache(host, Vec::new(), true); // 负缓存
            None
        }
        Err(_) => {
            put_cache(host, Vec::new(), true); // 5s 超时也负缓存
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 负缓存与过期语义() {
        // 独立 host 避免与其他测试串扰
        let host = format!("neg-{}.invalid", std::process::id());
        assert!(lookup_cached(&host).is_none(), "未缓存应 None");
        put_cache(&host, Vec::new(), true); // 负缓存
        assert_eq!(lookup_cached(&host), Some(Vec::new()), "负缓存命中=空表");
    }

    #[test]
    fn 正向缓存存取与过期() {
        let host = format!("pos-{}.test", std::process::id());
        let addr: SocketAddr = "203.0.113.5:443".parse().unwrap();
        put_cache(&host, vec![addr], false);
        assert_eq!(lookup_cached(&host), Some(vec![addr]));
        // 手动过期
        {
            let mut c = cache().lock().unwrap();
            let e = c.map.get_mut(&host).unwrap();
            e.at = Instant::now() - POSITIVE_TTL - Duration::from_secs(1);
        }
        assert!(lookup_cached(&host).is_none(), "过期后应清除并返回 None");
    }

    #[test]
    fn 容量上限_清最旧() {
        let mut c = cache().lock().unwrap();
        // 灌满（前 1024 条用带序号 key；已有条目共存无碍）
        for i in 0..MAX_ENTRIES {
            let k = format!("cap-{}-{}.test", std::process::id(), i);
            c.map.insert(
                k,
                CacheEntry {
                    addrs: Vec::new(),
                    at: Instant::now(),
                    negative: true,
                },
            );
        }
        // 再放一条更旧的，随后新插入应挤掉它
        let old_key = format!("cap-old-{}.test", std::process::id());
        c.map.insert(
            old_key.clone(),
            CacheEntry {
                addrs: Vec::new(),
                at: Instant::now() - Duration::from_secs(3600),
                negative: true,
            },
        );
        drop(c);
        let probe = format!("cap-new-{}.test", std::process::id());
        put_cache(&probe, Vec::new(), true);
        assert!(
            !cache().lock().unwrap().map.contains_key(&old_key),
            "最旧条目应被清除"
        );
        assert!(cache().lock().unwrap().map.contains_key(&probe));
    }
}
