//! Tiered cache: L1 (Moka in-memory) + L2 (Dragonfly/Redis)
//!
//! Read path: L1 → L2 → source → write L2 → write L1
//! Write path: write L2 → write L1
//! Delete path: delete L1 → delete L2

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
use vulnera_contract::infrastructure::cache::{CacheBackend, CacheError};

use super::{DragonflyCache, MokaCache};

/// Two-tier cache combining in-memory and distributed backends
#[derive(Debug, Clone)]
pub struct TieredCache {
    l1: MokaCache,
    l2: Option<Arc<DragonflyCache>>,
}

impl TieredCache {
    /// Create a new tiered cache
    ///
    /// If `dragonfly_url` is empty, only the L1 Moka cache is used.
    pub async fn new(
        l1_size_mb: u64,
        l1_ttl_seconds: u64,
        dragonfly_url: &str,
        enable_compression: bool,
        compression_threshold: usize,
    ) -> Result<Self, CacheError> {
        let l1 = MokaCache::new(l1_size_mb, l1_ttl_seconds);

        let l2 = if dragonfly_url.is_empty() {
            None
        } else {
            match DragonflyCache::new(dragonfly_url, enable_compression, compression_threshold)
                .await
            {
                Ok(cache) => {
                    debug!(url = %dragonfly_url, "L2 Dragonfly cache initialized");
                    Some(Arc::new(cache))
                }
                Err(e) => {
                    warn!(error = %e, "Failed to connect to Dragonfly; falling back to L1 only");
                    None
                }
            }
        };

        Ok(Self { l1, l2 })
    }

    /// Create a tiered cache from the standard application config
    pub async fn from_config(config: &crate::config::CacheConfig) -> Result<Self, CacheError> {
        Self::new(
            config.l1_cache_size_mb,
            config.l1_cache_ttl_seconds,
            &config.dragonfly_url,
            config.enable_cache_compression,
            config.compression_threshold_bytes,
        )
        .await
    }
}

#[async_trait]
impl CacheBackend for TieredCache {
    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        // Try L1 first
        if let Some(value) = self.l1.get_raw(key).await? {
            return Ok(Some(value));
        }

        // Fall through to L2
        if let Some(ref l2) = self.l2
            && let Some(value) = l2.get_raw(key).await?
        {
            // Backfill L1
            if let Err(e) = self.l1.set_raw(key, &value, Duration::from_secs(300)).await {
                debug!(error = %e, "Failed to backfill L1 cache");
            }
            return Ok(Some(value));
        }

        Ok(None)
    }

    async fn set_raw(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        // Write L2 first (source of truth)
        if let Some(ref l2) = self.l2 {
            l2.set_raw(key, value, ttl).await?;
        }

        // Then write L1
        self.l1.set_raw(key, value, ttl).await?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.l1.delete(key).await?;
        if let Some(ref l2) = self.l2 {
            l2.delete(key).await?;
        }
        Ok(())
    }

    async fn delete_by_pattern(&self, pattern: &str) -> Result<usize, CacheError> {
        let l1_count = self.l1.delete_by_pattern(pattern).await?;
        let l2_count = if let Some(ref l2) = self.l2 {
            l2.delete_by_pattern(pattern).await?
        } else {
            0
        };
        Ok(l1_count + l2_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tiered_l1_only() {
        let cache = TieredCache::new(10, 60, "", false, 1024).await.unwrap();

        cache
            .set_raw("key", b"value", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get_raw("key").await.unwrap();
        assert_eq!(result, Some(b"value".to_vec()));
    }

    #[tokio::test]
    async fn test_tiered_delete() {
        let cache = TieredCache::new(10, 60, "", false, 1024).await.unwrap();

        cache
            .set_raw("key", b"value", Duration::from_secs(60))
            .await
            .unwrap();
        cache.delete("key").await.unwrap();

        let result = cache.get_raw("key").await.unwrap();
        assert!(result.is_none());
    }
}
