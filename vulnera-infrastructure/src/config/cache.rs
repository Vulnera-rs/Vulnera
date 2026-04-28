//! Cache configuration

use serde::Deserialize;

/// Two-tier cache configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// L1 in-memory cache size in megabytes
    pub l1_cache_size_mb: u64,
    /// L1 cache entry TTL in seconds
    pub l1_cache_ttl_seconds: u64,
    /// Enable gzip compression for large values
    pub enable_cache_compression: bool,
    /// Minimum value size (bytes) before compression is applied
    pub compression_threshold_bytes: usize,
    /// Dragonfly/Redis connection URL. Empty string disables L2.
    pub dragonfly_url: String,
    /// Connection timeout for Dragonfly in seconds
    pub dragonfly_connection_timeout_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_cache_size_mb: 100,
            l1_cache_ttl_seconds: 300,
            enable_cache_compression: true,
            compression_threshold_bytes: 10_240,
            dragonfly_url: "redis://127.0.0.1:6379".to_string(),
            dragonfly_connection_timeout_seconds: 5,
        }
    }
}
