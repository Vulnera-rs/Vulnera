//! No-op cache backend
//!
//! Always misses. Useful for tests and when caching is explicitly disabled.

use async_trait::async_trait;
use std::time::Duration;
use vulnera_contract::infrastructure::cache::{CacheBackend, CacheError};

/// Cache backend that never stores or retrieves anything
#[derive(Debug, Clone)]
pub struct NoOpCache;

impl NoOpCache {
    /// Create a new no-op cache instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoOpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for NoOpCache {
    async fn get_raw(&self, _key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        Ok(None)
    }

    async fn set_raw(&self, _key: &str, _value: &[u8], _ttl: Duration) -> Result<(), CacheError> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<(), CacheError> {
        Ok(())
    }

    async fn delete_by_pattern(&self, _pattern: &str) -> Result<usize, CacheError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_always_misses() {
        let cache = NoOpCache::new();
        let result = cache.get_raw("any_key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_noop_set_is_noop() {
        let cache = NoOpCache::new();
        cache
            .set_raw("key", b"value", Duration::from_secs(60))
            .await
            .unwrap();
        let result = cache.get_raw("key").await.unwrap();
        assert!(result.is_none());
    }
}
