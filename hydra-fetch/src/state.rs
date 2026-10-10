//! 断点续传状态文件（`.hydra-fetch.json`）：URL/校验器/分块参数/完成位图。
//!
//! # 数据完整性规则（评审 P0）
//! - 恢复前强校验：URL、total_len、chunk_size 三者任一不一致即**失效重下**
//!   （位图按旧分块边界记录，参数漂移继续用 = 静默写花文件，数据损坏级）；
//! - 校验器（ETag 优先，Last-Modified 弱校验）缺失时**不续传**；
//! - 原子写：临时文件 + rename（崩溃不留半截状态文件）。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FetchState {
    pub url: String,
    pub total_len: u64,
    pub chunk_size: u64,
    /// 强校验器：ETag（优先）
    #[serde(default)]
    pub etag: Option<String>,
    /// 弱校验器：Last-Modified（无 ETag 时用，秒级 mtime 碰撞风险已在文档标注）
    #[serde(default)]
    pub last_modified: Option<String>,
    /// 每块完成位图（按块序号）
    pub done: Vec<bool>,
}

impl FetchState {
    pub fn chunk_count(total_len: u64, chunk_size: u64) -> usize {
        total_len.div_ceil(chunk_size.max(1)) as usize
    }

    pub fn new(
        url: &str,
        total_len: u64,
        chunk_size: u64,
        etag: Option<String>,
        last_modified: Option<String>,
    ) -> Self {
        Self {
            url: url.to_string(),
            total_len,
            chunk_size,
            etag,
            last_modified,
            done: vec![false; Self::chunk_count(total_len, chunk_size)],
        }
    }

    /// 恢复校验：全部匹配才返回 Some（可续传）；否则 None（重下）
    pub fn resumable(&self, url: &str, total_len: u64, chunk_size: u64) -> Option<()> {
        if self.url != url || self.total_len != total_len || self.chunk_size != chunk_size {
            return None;
        }
        // 校验器存在性：至少有一个（外部调用方还需保证与服务器当前校验器一致）
        if self.etag.is_none() && self.last_modified.is_none() {
            return None;
        }
        if self.done.len() != Self::chunk_count(total_len, chunk_size) {
            return None;
        }
        Some(())
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.done
            .iter()
            .enumerate()
            .filter(|(_, d)| !**d)
            .map(|(i, _)| {
                let start = i as u64 * self.chunk_size;
                let end = ((i as u64 + 1) * self.chunk_size).min(self.total_len);
                end - start
            })
            .sum()
    }

    /// 原子写（临时文件 + rename）。临时名带进程内唯一序号——多 worker 并发
    /// save 不共写同一 tmp（评审企业级 P1：共享 tmp 会交错写/丢更新）。
    /// 残余边界（如实）：rename 顺序不受限，后完成者的旧快照可能覆盖新快照
    /// ——丢的只是"已完成位"（续传时多重下已完成的块），数据不会错。
    pub async fn save(&self, state_path: &Path) -> std::io::Result<()> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = state_path.with_extension(format!("json.tmp{}", seq));
        let json = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, state_path).await
    }

    /// 读取（不存在 → None；损坏 → Err 调用方决定重下）
    pub async fn load(state_path: &Path) -> std::io::Result<Option<Self>> {
        match tokio::fs::read(state_path).await {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn path_for(output: &Path) -> PathBuf {
        let mut p = output.as_os_str().to_owned();
        p.push(".hydra-fetch.json");
        PathBuf::from(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 块数与剩余字节() {
        let st = FetchState::new("u", 100, 30, None, Some("lm".to_string()));
        assert_eq!(FetchState::chunk_count(100, 30), 4);
        assert_eq!(st.done.len(), 4);
        assert_eq!(st.remaining_bytes(), 100);
        let mut st2 = st.clone();
        st2.done[0] = true;
        st2.done[3] = true; // 尾块 10 字节已完成
                            // 剩余 = 未完成块：idx1(30) + idx2(30)；idx3 已完成不计
        assert_eq!(st2.remaining_bytes(), 60);
    }

    #[test]
    fn 恢复校验_参数漂移即失效() {
        let st = FetchState::new("u1", 100, 30, Some("\"e\"".into()), None);
        assert!(st.resumable("u1", 100, 30).is_some());
        assert!(st.resumable("u2", 100, 30).is_none(), "URL 变化");
        assert!(st.resumable("u1", 101, 30).is_none(), "总长变化");
        assert!(st.resumable("u1", 100, 32).is_none(), "块大小变化");
        // 无校验器：拒绝续传
        let noval = FetchState::new("u1", 100, 30, None, None);
        assert!(noval.resumable("u1", 100, 30).is_none());
    }

    #[tokio::test]
    async fn 原子保存与读取() {
        let dir = std::env::temp_dir().join(format!("hydra-fetch-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("out.bin.hydra-fetch.json");
        let st = FetchState::new("u", 10, 4, Some("\"e\"".into()), None);
        st.save(&path).await.unwrap();
        let loaded = FetchState::load(&path).await.unwrap().unwrap();
        assert_eq!(loaded.total_len, 10);
        assert_eq!(loaded.etag.as_deref(), Some("\"e\""));
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
