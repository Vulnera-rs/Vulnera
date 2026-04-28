//! In-memory L1 cache via Moka

use async_trait::async_trait;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use vulnera_contract::infrastructure::cache::{CacheBackend, CacheError};

/// Moka-based in-memory cache
#[derive(Debug, Clone)]
pub struct MokaCache {
    inner: Arc<Cache<String, Vec<u8>>>,
}

impl MokaCache {
    /// Create a new Moka cache with the given size limit and TTL
    pub fn new(max_size_mb: u64, ttl_seconds: u64) -> Self {
        let max_weight = max_size_mb * 1024 * 1024;
        let ttl = Duration::from_secs(ttl_seconds);

        let cache = Cache::builder()
            .max_capacity(max_weight)
            .weigher(|_key, value: &Vec<u8>| -> u32 {
                let weight = value.len().saturating_add(64);
                weight.min(u32::MAX as usize) as u32
            })
            .time_to_live(ttl)
            .build();

        Self {
            inner: Arc::new(cache),
        }
    }
}

#[async_trait]
impl CacheBackend for MokaCache {
    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(self.inner.get(key).await)
    }

    async fn set_raw(&self, key: &str, value: &[u8], _ttl: Duration) -> Result<(), CacheError> {
        self.inner.insert(key.to_string(), value.to_vec()).await;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.inner.invalidate(key).await;
        Ok(())
    }

    async fn delete_by_pattern(&self, pattern: &str) -> Result<usize, CacheError> {
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|(k, _v)| k.contains(&pattern[..pattern.len().saturating_sub(1)]))
            .map(|(k, _v)| (*k).clone())
            .collect();

        let count = keys.len();
        for key in keys {
            self.inner.invalidate(&key).await;
        }
        Ok(count)
    }
}
