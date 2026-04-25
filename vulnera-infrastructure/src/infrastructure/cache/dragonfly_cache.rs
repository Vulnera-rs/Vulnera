//! Dragonfly/Redis cache backend
//!
//! Uses the `redis` crate with `ConnectionManager` for multiplexed
//! async connections. Supports optional gzip compression for large values.

use async_trait::async_trait;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::io::{Read, Write};
use std::time::Duration;
use tracing::info;
use vulnera_contract::infrastructure::cache::{CacheBackend, CacheError};

/// 4-byte marker prefix for compressed entries
const COMPRESSION_MARKER: &[u8] = b"GZP_";

/// Dragonfly-compatible Redis cache backend
#[derive(Clone)]
pub struct DragonflyCache {
    conn: ConnectionManager,
    enable_compression: bool,
    compression_threshold: usize,
}

impl std::fmt::Debug for DragonflyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DragonflyCache")
            .field("enable_compression", &self.enable_compression)
            .field("compression_threshold", &self.compression_threshold)
            .finish_non_exhaustive()
    }
}

impl DragonflyCache {
    /// Connect to a Dragonfly/Redis instance
    pub async fn new(
        url: &str,
        enable_compression: bool,
        compression_threshold: usize,
    ) -> Result<Self, CacheError> {
        if url.is_empty() {
            return Err(CacheError::Connection("Dragonfly URL is empty".to_string()));
        }

        let client = redis::Client::open(url)
            .map_err(|e| CacheError::Connection(format!("Failed to parse Redis URL: {e}")))?;

        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| CacheError::Connection(format!("Failed to connect to Dragonfly: {e}")))?;

        info!(url = %url, "Connected to Dragonfly cache");

        Ok(Self {
            conn,
            enable_compression,
            compression_threshold,
        })
    }

    /// Store a typed value with automatic JSON serialization
    pub async fn set<T: serde::Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| CacheError::Serialization(format!("JSON serialization failed: {e}")))?;
        self.set_raw(key, &bytes, ttl).await
    }

    /// Retrieve and deserialize a typed value
    pub async fn get<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        let bytes = self.get_raw(key).await?;
        match bytes {
            Some(b) => {
                let value = serde_json::from_slice(&b).map_err(|e| {
                    CacheError::Serialization(format!("JSON deserialization failed: {e}"))
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Left-push a value onto a Redis list (used by job queue)
    pub async fn lpush<T: serde::Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), CacheError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| CacheError::Serialization(format!("JSON serialization failed: {e}")))?;

        let mut conn = self.conn.clone();
        let _: () = redis::cmd("LPUSH")
            .arg(key)
            .arg(&bytes)
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Operation(format!("LPUSH failed: {e}")))?;

        Ok(())
    }

    /// Blocking right-pop from a Redis list with timeout (used by job queue)
    pub async fn brpop<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        timeout: Duration,
    ) -> Result<Option<T>, CacheError> {
        let mut conn = self.conn.clone();
        let result: Option<(String, Vec<u8>)> = redis::cmd("BRPOP")
            .arg(key)
            .arg(timeout.as_secs() as usize)
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Operation(format!("BRPOP failed: {e}")))?;

        match result {
            Some((_key, bytes)) => {
                let value = serde_json::from_slice(&bytes).map_err(|e| {
                    CacheError::Serialization(format!("JSON deserialization failed: {e}"))
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Delete all keys matching a pattern using SCAN + DEL
    async fn delete_by_pattern_impl(&self, pattern: &str) -> Result<usize, CacheError> {
        let mut conn = self.conn.clone();
        let mut count = 0usize;
        let mut cursor = 0u64;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|e| CacheError::Operation(format!("SCAN failed: {e}")))?;

            if !keys.is_empty() {
                let deleted: usize = conn
                    .del(&keys)
                    .await
                    .map_err(|e| CacheError::Operation(format!("DEL failed: {e}")))?;
                count += deleted;
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(count)
    }

    fn maybe_compress(&self, data: &[u8]) -> Result<Vec<u8>, CacheError> {
        if !self.enable_compression || data.len() < self.compression_threshold {
            return Ok(data.to_vec());
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(data)
            .map_err(|e| CacheError::Operation(format!("Compression failed: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| CacheError::Operation(format!("Compression finish failed: {e}")))?;

        let mut result = COMPRESSION_MARKER.to_vec();
        result.extend_from_slice(&compressed);
        Ok(result)
    }

    fn maybe_decompress(&self, data: &[u8]) -> Result<Vec<u8>, CacheError> {
        if data.starts_with(COMPRESSION_MARKER) {
            let compressed = &data[COMPRESSION_MARKER.len()..];
            let mut decoder = GzDecoder::new(compressed);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| CacheError::Operation(format!("Decompression failed: {e}")))?;
            Ok(decompressed)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Ping the Dragonfly server to verify connectivity
    pub async fn ping(&self) -> Result<(), CacheError> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Operation(format!("PING failed: {e}")))?;
        Ok(())
    }

    /// Get cache statistics from the Dragonfly server
    pub async fn get_statistics(&self) -> Result<super::CacheStatistics, CacheError> {
        let mut conn = self.conn.clone();

        let hits: u64 = conn.get("stats:hits").await.unwrap_or(0);
        let misses: u64 = conn.get("stats:misses").await.unwrap_or(0);

        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        Ok(super::CacheStatistics {
            hits,
            misses,
            hit_rate,
            total_entries: 0,
            total_size_bytes: 0,
        })
    }
}

#[async_trait]
impl CacheBackend for DragonflyCache {
    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let mut conn = self.conn.clone();
        let result: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| CacheError::Operation(format!("GET failed: {e}")))?;

        match result {
            Some(data) => {
                let decompressed = self.maybe_decompress(&data)?;
                Ok(Some(decompressed))
            }
            None => Ok(None),
        }
    }

    async fn set_raw(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        let compressed = self.maybe_compress(value)?;
        let mut conn = self.conn.clone();
        let _: () = conn
            .set_ex(key, compressed, ttl.as_secs())
            .await
            .map_err(|e| CacheError::Operation(format!("SETEX failed: {e}")))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .del(key)
            .await
            .map_err(|e| CacheError::Operation(format!("DEL failed: {e}")))?;
        Ok(())
    }

    async fn delete_by_pattern(&self, pattern: &str) -> Result<usize, CacheError> {
        self.delete_by_pattern_impl(pattern).await
    }
}
