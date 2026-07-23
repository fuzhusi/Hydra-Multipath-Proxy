use std::sync::Arc;
use crossbeam_queue::ArrayQueue;

/// 无锁缓冲池
#[derive(Clone)]
pub struct BufPool {
    queue: Arc<ArrayQueue<Vec<u8>>>,
    buf_size: usize,
}

impl BufPool {
    /// 创建新的缓冲池
    ///
    /// - `buf_size`: 每个缓冲区的大小
    /// - `capacity`: 池中最大缓冲区数量
    pub fn new(buf_size: usize, capacity: usize) -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(capacity)),
            buf_size,
        }
    }

    /// 从池中获取一个缓冲区
    ///
    /// 如果池中有空闲缓冲区，复用它；否则分配新的
    pub fn get(&self) -> Vec<u8> {
        let mut buf = self.queue.pop().unwrap_or_else(|| vec![0u8; self.buf_size]);
        buf.resize(self.buf_size, 0);
        buf
    }

    /// 将缓冲区归还到池中
    ///
    /// 如果池已满，缓冲区会被丢弃
    pub fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        let _ = self.queue.push(buf);
    }

    /// 获取池中当前可用的缓冲区数量
    pub fn available(&self) -> usize {
        self.queue.len()
    }

    /// 获取缓冲区大小
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }
}

/// RAII 包装器，drop 时自动归还缓冲区到池中
pub struct PooledBuf {
    buf: Option<Vec<u8>>,
    pool: BufPool,
}

impl PooledBuf {
    /// 从池中获取一个新的缓冲区
    pub fn new(pool: &BufPool) -> Self {
        Self {
            buf: Some(pool.get()),
            pool: pool.clone(),
        }
    }

    /// 获取可变切片引用
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut().unwrap()
    }

    /// 获取切片引用
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref().unwrap()
    }

    /// 获取缓冲区长度
    pub fn len(&self) -> usize {
        self.buf.as_ref().map_or(0, |b| b.len())
    }

    /// 转换为原始 Vec<u8>
    pub fn into_inner(mut self) -> Vec<u8> {
        self.buf.take().unwrap()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf_pool_basic() {
        let pool = BufPool::new(1024, 4);

        // 获取缓冲区
        let buf1 = pool.get();
        assert_eq!(buf1.len(), 1024);

        // 归还缓冲区
        pool.put(buf1);
        assert_eq!(pool.available(), 1);

        // 再次获取，应该复用
        let buf2 = pool.get();
        assert_eq!(buf2.len(), 1024);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_pooled_buf() {
        let pool = BufPool::new(1024, 4);

        {
            let mut buf = PooledBuf::new(&pool);
            let slice = buf.as_mut_slice();
            slice[0] = 42;
            assert_eq!(buf.as_slice()[0], 42);
        }

        // buf 应该被归还到池中
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn test_pool_capacity() {
        let pool = BufPool::new(1024, 2);

        let buf1 = pool.get();
        let buf2 = pool.get();
        let buf3 = pool.get(); // 超出容量

        pool.put(buf1);
        pool.put(buf2);
        pool.put(buf3); // 这个应该被丢弃

        assert_eq!(pool.available(), 2);
    }
}
