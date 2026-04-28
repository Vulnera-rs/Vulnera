//! Cache backend trait

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur during cache operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CacheError {
    #[error("Cache connection error: {0}")]
    Connection(String),
    #[error("Cache serialization error: {0}")]
    Serialization(String),
    #[error("Cache operation error: {0}")]
    Operation(String),
}

/// Low-level cache backend trait for binary operations
#[async_trait]
pub trait CacheBackend: Send + Sync {
    /// Retrieve raw bytes for the given key
    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError>;

    /// Store raw bytes with a time-to-live
    async fn set_raw(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError>;

    /// Delete a single key
    async fn delete(&self, key: &str) -> Result<(), CacheError>;

    /// Delete all keys matching a pattern (e.g., "prefix:*")
    async fn delete_by_pattern(&self, pattern: &str) -> Result<usize, CacheError>;
}
