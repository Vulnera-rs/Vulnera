//! Dragonfly database cache implementation
//!
//! This module provides a Redis-compatible cache implementation using the Dragonfly database.
//! Dragonfly is a high-performance, multi-threaded in-memory data store that
// cspell:ignore Dragonfly GzEncoder GzDecoder flate

use async_trait::async_trait;
use redis::Client;
use redis::aio::ConnectionManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, warn};

use crate::application::errors::{ApplicationError, CacheError};
use crate::application::vulnerability::services::CacheService;

const COMPRESSION_MARKER: &[u8; 4] = b"GZIP";

/// Cache entry metadata wrapper
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry<T> {
    data: T,
    created_at: u64,
    expires_at: u64,
    access_count: u64,
    compressed: bool,
}

/// Dragonfly database cache implementation
pub struct DragonflyCache {
    connection_manager: Arc<ConnectionManager>,
    enable_compression: bool,
    compression_threshold_bytes: u64,
}

impl DragonflyCache {
    /// Create a new Dragonfly cache instance
    ///
    /// # Arguments
    /// * `url` - Connection URL (e.g., "redis://127.0.0.1:6379")
    /// * `enable_compression` - Whether to enable compression for large entries
    /// * `compression_threshold_bytes` - Minimum size in bytes to trigger compression
    ///
    /// # Errors
    /// Returns an error if the connection to the Dragonfly database cannot be established
    pub async fn new(
        url: &str,
        enable_compression: bool,
        compression_threshold_bytes: u64,
    ) -> Result<Self, ApplicationError> {
        let client = Client::open(url).map_err(|e| {
            error!("Failed to create Redis client: {}", e);
            ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to the Dragonfly database: {}", e),
            )))
        })?;

        let connection_manager = ConnectionManager::new(client.clone()).await.map_err(|e| {
            error!("Failed to create connection manager: {}", e);
            ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!(
                    "Failed to establish connection to the Dragonfly database: {}",
                    e
                ),
            )))
        })?;

        // Test the connection
        let mut conn = connection_manager.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to ping the Dragonfly database: {}", e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("Failed to ping the Dragonfly database: {}", e),
                )))
            })?;

        debug!(
            "Successfully connected to the Dragonfly database at {}",
            url
        );

        Ok(Self {
            connection_manager: Arc::new(connection_manager),
            enable_compression,
            compression_threshold_bytes,
        })
    }

    /// Compress data using gzip
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, ApplicationError> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|e| {
            ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Compression error: {}", e),
            )))
        })?;
        encoder.finish().map_err(|e| {
            ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Compression finish error: {}", e),
            )))
        })
    }

    /// Decompress data using gzip
    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, ApplicationError> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|e| {
            ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Decompression error: {}", e),
            )))
        })?;
        Ok(decompressed)
    }

    /// Get current timestamp in seconds since Unix epoch
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    /// Push a value to the head of a list
    pub async fn lpush<T>(&self, key: &str, value: &T) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        let mut conn = (*self.connection_manager).clone();
        let json_value = serde_json::to_string(value).map_err(ApplicationError::Json)?;

        redis::cmd("LPUSH")
            .arg(key)
            .arg(json_value)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to LPUSH to key {}: {}", key, e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Redis LPUSH error: {}", e),
                )))
            })?;

        Ok(())
    }

    /// Pop a value from the tail of a list, blocking until available
    pub async fn brpop<T>(
        &self,
        key: &str,
        timeout_seconds: f64,
    ) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let mut conn = (*self.connection_manager).clone();

        // BRPOP returns [key, value] or nil if timeout
        let result: Option<(String, String)> = redis::cmd("BRPOP")
            .arg(key)
            .arg(timeout_seconds)
            .query_async::<Option<(String, String)>>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to BRPOP from key {}: {}", key, e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Redis BRPOP error: {}", e),
                )))
            })?;

        match result {
            Some((_, value_str)) => {
                let value: T = serde_json::from_str(&value_str).map_err(ApplicationError::Json)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl CacheService for DragonflyCache {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let mut conn = (*self.connection_manager).clone();

        // Get the value from Redis
        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
            .map_err(|e| {
                if e.kind() == redis::ErrorKind::TypeError {
                    // Key doesn't exist, not an error
                    debug!("Cache key not found: {}", key);
                    return ApplicationError::Cache(CacheError::KeyNotFound {
                        key: key.to_string(),
                    });
                }
                error!("Failed to get cache key {}: {}", key, e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Redis GET error: {}", e),
                )))
            })?;

        let value = match value {
            Some(v) => v,
            None => {
                debug!("Cache miss for key: {}", key);
                return Ok(None);
            }
        };

        // Check if data is compressed (starts with COMPRESSION_MARKER marker)
        let decompressed = if value.len() > COMPRESSION_MARKER.len()
            && &value[0..COMPRESSION_MARKER.len()] == COMPRESSION_MARKER.as_slice()
        {
            self.decompress_data(&value[COMPRESSION_MARKER.len()..])?
        } else {
            value
        };

        // Deserialize the cache entry
        let entry: CacheEntry<serde_json::Value> =
            serde_json::from_slice(&decompressed).map_err(ApplicationError::Json)?;

        // Check if entry is expired
        let now = Self::current_timestamp();
        if now > entry.expires_at {
            // Entry expired, delete it
            let _: i64 = redis::cmd("DEL")
                .arg(key)
                .query_async::<i64>(&mut conn)
                .await
                .map_err(|e| {
                    warn!("Failed to delete expired key {}: {}", key, e);
                    ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Redis DEL error: {}", e),
                    )))
                })?;
            debug!("Cache entry expired for key: {}", key);
            return Ok(None);
        }

        // Deserialize the actual data
        let result: T = serde_json::from_value(entry.data).map_err(ApplicationError::Json)?;
        debug!("Cache hit for key: {}", key);
        Ok(Some(result))
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        let mut conn = (*self.connection_manager).clone();

        // Serialize the value to JSON
        let json_value = serde_json::to_value(value).map_err(ApplicationError::Json)?;

        // Create cache entry metadata
        let now = Self::current_timestamp();
        let expires_at = now + ttl.as_secs();

        // Determine if this entry should be compressed
        let serialized_json = serde_json::to_string(&json_value).map_err(ApplicationError::Json)?;
        let should_compress = self.enable_compression
            && serialized_json.len() as u64 > self.compression_threshold_bytes;

        let entry = CacheEntry {
            data: json_value,
            created_at: now,
            expires_at,
            access_count: 0,
            compressed: should_compress,
        };

        // Serialize the entry
        let serialized_entry = serde_json::to_vec(&entry).map_err(ApplicationError::Json)?;

        // Compress if needed
        let final_data = if should_compress {
            let compressed = self.compress_data(&serialized_entry)?;
            let mut result = COMPRESSION_MARKER.to_vec();
            result.extend_from_slice(&compressed);
            result
        } else {
            serialized_entry
        };

        // Set the value in Redis with TTL
        let ttl_seconds = ttl.as_secs() as usize;
        redis::cmd("SET")
            .arg(key)
            .arg(final_data)
            .arg("EX")
            .arg(ttl_seconds)
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to set cache key {}: {}", key, e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Redis SET error: {}", e),
                )))
            })?;

        debug!(
            "Successfully cached entry for key: {} with TTL: {}s",
            key, ttl_seconds
        );
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        let mut conn = (*self.connection_manager).clone();

        let deleted: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to invalidate cache key {}: {}", key, e);
                ApplicationError::Cache(CacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Redis DEL error: {}", e),
                )))
            })?;

        if deleted > 0 {
            debug!("Invalidated cache key: {}", key);
        } else {
            debug!("Cache key not found for invalidation: {}", key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Note: These tests require a running Dragonfly database instance
    // They should be run as integration tests with a test container

    #[tokio::test]
    #[ignore] // Ignore by default, requires Dragonfly database instance
    async fn test_dragonfly_cache_set_get() {
        let cache = DragonflyCache::new("redis://127.0.0.1:6379", false, 0)
            .await
            .expect("Failed to create cache");

        let test_key = "test:set_get";
        let test_value = serde_json::json!({"foo": "bar", "baz": 42});

        // Set value
        cache
            .set(test_key, &test_value, Duration::from_secs(60))
            .await
            .expect("Failed to set value");

        // Get value
        let result: Option<serde_json::Value> =
            cache.get(test_key).await.expect("Failed to get value");

        assert!(result.is_some());
        assert_eq!(result.unwrap(), test_value);
    }

    #[tokio::test]
    #[ignore]
    async fn test_dragonfly_cache_invalidate() {
        let cache = DragonflyCache::new("redis://127.0.0.1:6379", false, 0)
            .await
            .expect("Failed to create cache");

        let test_key = "test:invalidate";
        let test_value = serde_json::json!({"test": "data"});

        // Set value
        cache
            .set(test_key, &test_value, Duration::from_secs(60))
            .await
            .expect("Failed to set value");

        // Invalidate
        cache
            .invalidate(test_key)
            .await
            .expect("Failed to invalidate");

        // Verify it's gone
        let result: Option<serde_json::Value> =
            cache.get(test_key).await.expect("Failed to get value");

        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_dragonfly_cache_ttl() {
        let cache = DragonflyCache::new("redis://127.0.0.1:6379", false, 0)
            .await
            .expect("Failed to create cache");

        let test_key = "test:ttl";
        let test_value = serde_json::json!({"test": "ttl"});

        // Set value with short TTL
        cache
            .set(test_key, &test_value, Duration::from_secs(1))
            .await
            .expect("Failed to set value");

        // Should be available immediately
        let result: Option<serde_json::Value> =
            cache.get(test_key).await.expect("Failed to get value");
        assert!(result.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be expired
        let result: Option<serde_json::Value> =
            cache.get(test_key).await.expect("Failed to get value");
        assert!(result.is_none());
    }
}
