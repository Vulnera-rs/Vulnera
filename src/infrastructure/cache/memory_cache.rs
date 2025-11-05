//! In-memory L1 cache implementation using moka

use crate::application::errors::ApplicationError;
use moka::future::Cache;
use std::time::Duration;

/// In-memory L1 cache for fast access to frequently used data
pub struct MemoryCache {
    cache: Cache<String, Vec<u8>>,
    enable_compression: bool,
    compression_threshold_bytes: u64,
}

impl MemoryCache {
    /// Create a new in-memory cache with specified size and TTL
    pub fn new(max_size_mb: u64, ttl_seconds: u64) -> Self {
        Self::new_with_compression(max_size_mb, ttl_seconds, false, 0)
    }

    /// Create a new in-memory cache with compression support
    pub fn new_with_compression(
        max_size_mb: u64,
        ttl_seconds: u64,
        enable_compression: bool,
        compression_threshold_bytes: u64,
    ) -> Self {
        let max_capacity = max_size_mb * 1024 * 1024; // Convert MB to bytes
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_seconds))
            .build();

        Self {
            cache,
            enable_compression,
            compression_threshold_bytes,
        }
    }

    /// Get an entry from the cache
    pub async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.cache.get(key).await {
            Some(data) => {
                // Decompress if needed (check for compression marker)
                let decompressed = if self.enable_compression
                    && data.len() > 4
                    && &data[0..4] == b"CMP\0"
                {
                    use flate2::read::GzDecoder;
                    use std::io::Read;
                    let mut decoder = GzDecoder::new(&data[4..]);
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).map_err(|e| {
                        ApplicationError::Cache(crate::application::errors::CacheError::Io(
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                        ))
                    })?;
                    decompressed
                } else {
                    data
                };

                serde_json::from_slice(&decompressed)
                    .map(Some)
                    .map_err(ApplicationError::Json)
            }
            None => Ok(None),
        }
    }

    /// Set an entry in the cache
    pub async fn set<T>(&self, key: &str, value: &T) -> Result<(), ApplicationError>
    where
        T: serde::Serialize,
    {
        let serialized = serde_json::to_vec(value).map_err(ApplicationError::Json)?;

        // Compress if enabled and larger than threshold
        let data = if self.enable_compression
            && serialized.len() as u64 > self.compression_threshold_bytes
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&serialized).map_err(|e| {
                ApplicationError::Cache(crate::application::errors::CacheError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e),
                ))
            })?;
            let compressed = encoder.finish().map_err(|e| {
                ApplicationError::Cache(crate::application::errors::CacheError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e),
                ))
            })?;

            // Prepend compression marker
            let mut result = b"CMP\0".to_vec();
            result.extend_from_slice(&compressed);
            result
        } else {
            serialized
        };

        self.cache.insert(key.to_string(), data).await;
        Ok(())
    }

    /// Invalidate an entry
    pub async fn invalidate(&self, key: &str) {
        self.cache.invalidate(key).await;
    }

    /// Clear all entries
    pub async fn clear(&self) {
        self.cache.invalidate_all();
    }

    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64) {
        let weighted_size = self.cache.weighted_size();
        let entry_count = self.cache.entry_count();
        (entry_count, weighted_size)
    }
}

