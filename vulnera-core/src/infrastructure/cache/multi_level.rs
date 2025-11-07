//! Multi-level cache implementation (L1 in-memory + L2 filesystem)

use crate::application::errors::ApplicationError;
use crate::application::vulnerability::services::CacheService;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use super::file_cache::FileCacheRepository;
use super::memory_cache::MemoryCache;

/// Multi-level cache that combines L1 (in-memory) and L2 (filesystem) caches
pub struct MultiLevelCache {
    l1: Arc<MemoryCache>,
    l2: Arc<FileCacheRepository>,
}

impl MultiLevelCache {
    /// Create a new multi-level cache
    pub fn new(l1: Arc<MemoryCache>, l2: Arc<FileCacheRepository>) -> Self {
        Self { l1, l2 }
    }

    /// Get the L1 cache
    pub fn l1(&self) -> &MemoryCache {
        &self.l1
    }

    /// Get the L2 cache
    pub fn l2(&self) -> &FileCacheRepository {
        &self.l2
    }
}

#[async_trait]
impl CacheService for MultiLevelCache {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        // Try L1 first (fast path)
        match self.l1.get::<T>(key).await {
            Ok(Some(value)) => {
                tracing::debug!("L1 cache hit for key: {}", key);
                return Ok(Some(value));
            }
            Ok(None) => {
                // L1 miss, try L2
            }
            Err(e) => {
                tracing::warn!("L1 cache error for key {}: {}, falling back to L2", key, e);
            }
        }

        // Try L2 cache
        match self.l2.get::<T>(key).await {
            Ok(Some(value)) => {
                tracing::debug!("L2 cache hit for key: {}", key);
                // Note: Promotion to L1 would require Serialize bound, so we skip it here
                // Promotion happens naturally when items are set in the cache
                Ok(Some(value))
            }
            Ok(None) => {
                tracing::debug!("Cache miss for key: {}", key);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        // Write to both levels concurrently
        let l1_fut = self.l1.set(key, value);
        let l2_fut = self.l2.set(key, value, ttl);

        // Wait for both, but don't fail if L1 fails (L2 is more important)
        let (l1_result, l2_result) = tokio::join!(l1_fut, l2_fut);

        if let Err(e) = l1_result {
            tracing::warn!("Failed to write to L1 cache for key {}: {}", key, e);
        }

        // L2 write is critical
        l2_result
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        // Invalidate in both levels
        let l1_fut = self.l1.invalidate(key);
        let l2_fut = self.l2.invalidate(key);

        let (_l1_result, l2_result) = tokio::join!(l1_fut, l2_fut);
        // L2 invalidation is critical
        l2_result
    }
}
