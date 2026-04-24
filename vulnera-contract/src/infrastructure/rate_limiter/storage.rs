//! Rate Limit Storage Backends
//!
//! Provides storage implementations for rate limiting state:
//! - Dragonfly/Redis for distributed, production use
//! - In-memory for development and single-instance deployments

use super::types::{SlidingWindowState, TokenBucketState};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Trait for rate limit storage backends
#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    /// Get token bucket state
    async fn get_token_bucket(&self, key: &str) -> Result<Option<TokenBucketState>, String>;

    /// Set token bucket state with TTL
    async fn set_token_bucket(
        &self,
        key: &str,
        state: &TokenBucketState,
        ttl_secs: u64,
    ) -> Result<(), String>;

    /// Get sliding window state
    async fn get_sliding_window(&self, key: &str) -> Result<Option<SlidingWindowState>, String>;

    /// Set sliding window state with TTL
    async fn set_sliding_window(
        &self,
        key: &str,
        state: &SlidingWindowState,
        ttl_secs: u64,
    ) -> Result<(), String>;

    /// Get lockout expiration time
    async fn get_lockout(&self, key: &str) -> Result<Option<u64>, String>;

    /// Set lockout with TTL
    async fn set_lockout(&self, key: &str, until: u64, ttl_secs: u64) -> Result<(), String>;

    /// Delete a key
    async fn delete(&self, key: &str) -> Result<(), String>;

    /// Cleanup expired entries (for in-memory storage)
    async fn cleanup(&self);
}

/// Dragonfly/Redis storage backend
pub struct DragonflyRateLimitStorage {
    connection_manager: Arc<ConnectionManager>,
}

impl DragonflyRateLimitStorage {
    /// Create a new Dragonfly storage backend
    pub async fn new(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| {
            warn!("Failed to create Redis client for rate limiting: {}", e);
            format!("Failed to create Redis client: {}", e)
        })?;

        let connection_manager = ConnectionManager::new(client).await.map_err(|e| {
            warn!(
                "Failed to create connection manager for rate limiting: {}",
                e
            );
            format!("Failed to create connection manager: {}", e)
        })?;

        // Test connection
        let mut conn = connection_manager.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| {
                warn!("Failed to ping Redis for rate limiting: {}", e);
                format!("Failed to ping Redis: {}", e)
            })?;

        debug!("Successfully connected to Dragonfly for rate limiting");

        Ok(Self {
            connection_manager: Arc::new(connection_manager),
        })
    }
}

#[async_trait]
impl RateLimitStorage for DragonflyRateLimitStorage {
    async fn get_token_bucket(&self, key: &str) -> Result<Option<TokenBucketState>, String> {
        let mut conn = (*self.connection_manager).clone();

        let value: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Redis GET error: {}", e))?;

        match value {
            Some(json) => {
                let state: TokenBucketState =
                    serde_json::from_str(&json).map_err(|e| format!("JSON parse error: {}", e))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn set_token_bucket(
        &self,
        key: &str,
        state: &TokenBucketState,
        ttl_secs: u64,
    ) -> Result<(), String> {
        let mut conn = (*self.connection_manager).clone();
        let json =
            serde_json::to_string(state).map_err(|e| format!("JSON serialize error: {}", e))?;

        redis::cmd("SET")
            .arg(key)
            .arg(json)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| format!("Redis SET error: {}", e))?;

        Ok(())
    }

    async fn get_sliding_window(&self, key: &str) -> Result<Option<SlidingWindowState>, String> {
        let mut conn = (*self.connection_manager).clone();

        let value: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Redis GET error: {}", e))?;

        match value {
            Some(json) => {
                let state: SlidingWindowState =
                    serde_json::from_str(&json).map_err(|e| format!("JSON parse error: {}", e))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn set_sliding_window(
        &self,
        key: &str,
        state: &SlidingWindowState,
        ttl_secs: u64,
    ) -> Result<(), String> {
        let mut conn = (*self.connection_manager).clone();
        let json =
            serde_json::to_string(state).map_err(|e| format!("JSON serialize error: {}", e))?;

        redis::cmd("SET")
            .arg(key)
            .arg(json)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| format!("Redis SET error: {}", e))?;

        Ok(())
    }

    async fn get_lockout(&self, key: &str) -> Result<Option<u64>, String> {
        let lockout_key = format!("{}:lockout", key);
        let mut conn = (*self.connection_manager).clone();

        let value: Option<u64> = redis::cmd("GET")
            .arg(&lockout_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Redis GET error: {}", e))?;

        Ok(value)
    }

    async fn set_lockout(&self, key: &str, until: u64, ttl_secs: u64) -> Result<(), String> {
        let lockout_key = format!("{}:lockout", key);
        let mut conn = (*self.connection_manager).clone();

        redis::cmd("SET")
            .arg(&lockout_key)
            .arg(until)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| format!("Redis SET error: {}", e))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut conn = (*self.connection_manager).clone();

        redis::cmd("DEL")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .map_err(|e| format!("Redis DEL error: {}", e))?;

        Ok(())
    }

    async fn cleanup(&self) {
        // Redis handles TTL-based cleanup automatically
    }
}

/// In-memory storage entry with expiration
#[derive(Clone)]
struct MemoryEntry<T: Clone> {
    value: T,
    expires_at: u64,
}

/// In-memory storage backend for development/single instance
pub struct InMemoryRateLimitStorage {
    token_buckets: Arc<RwLock<HashMap<String, MemoryEntry<TokenBucketState>>>>,
    sliding_windows: Arc<RwLock<HashMap<String, MemoryEntry<SlidingWindowState>>>>,
    lockouts: Arc<RwLock<HashMap<String, MemoryEntry<u64>>>>,
}

impl InMemoryRateLimitStorage {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        Self {
            token_buckets: Arc::new(RwLock::new(HashMap::new())),
            sliding_windows: Arc::new(RwLock::new(HashMap::new())),
            lockouts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for InMemoryRateLimitStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RateLimitStorage for InMemoryRateLimitStorage {
    async fn get_token_bucket(&self, key: &str) -> Result<Option<TokenBucketState>, String> {
        let buckets = self.token_buckets.read().await;
        if let Some(entry) = buckets.get(key)
            && Self::current_time() < entry.expires_at
        {
            return Ok(Some(entry.value.clone()));
        }
        Ok(None)
    }

    async fn set_token_bucket(
        &self,
        key: &str,
        state: &TokenBucketState,
        ttl_secs: u64,
    ) -> Result<(), String> {
        let mut buckets = self.token_buckets.write().await;
        buckets.insert(
            key.to_string(),
            MemoryEntry {
                value: state.clone(),
                expires_at: Self::current_time() + ttl_secs,
            },
        );
        Ok(())
    }

    async fn get_sliding_window(&self, key: &str) -> Result<Option<SlidingWindowState>, String> {
        let windows = self.sliding_windows.read().await;
        if let Some(entry) = windows.get(key)
            && Self::current_time() < entry.expires_at
        {
            return Ok(Some(entry.value.clone()));
        }
        Ok(None)
    }

    async fn set_sliding_window(
        &self,
        key: &str,
        state: &SlidingWindowState,
        ttl_secs: u64,
    ) -> Result<(), String> {
        let mut windows = self.sliding_windows.write().await;
        windows.insert(
            key.to_string(),
            MemoryEntry {
                value: state.clone(),
                expires_at: Self::current_time() + ttl_secs,
            },
        );
        Ok(())
    }

    async fn get_lockout(&self, key: &str) -> Result<Option<u64>, String> {
        let lockout_key = format!("{}:lockout", key);
        let lockouts = self.lockouts.read().await;
        if let Some(entry) = lockouts.get(&lockout_key)
            && Self::current_time() < entry.expires_at
        {
            return Ok(Some(entry.value));
        }
        Ok(None)
    }

    async fn set_lockout(&self, key: &str, until: u64, ttl_secs: u64) -> Result<(), String> {
        let lockout_key = format!("{}:lockout", key);
        let mut lockouts = self.lockouts.write().await;
        lockouts.insert(
            lockout_key,
            MemoryEntry {
                value: until,
                expires_at: Self::current_time() + ttl_secs,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        let mut buckets = self.token_buckets.write().await;
        let mut windows = self.sliding_windows.write().await;
        let mut lockouts = self.lockouts.write().await;

        buckets.remove(key);
        windows.remove(key);
        lockouts.remove(&format!("{}:lockout", key));

        Ok(())
    }

    async fn cleanup(&self) {
        let now = Self::current_time();

        // Cleanup token buckets
        {
            let mut buckets = self.token_buckets.write().await;
            buckets.retain(|_, entry| entry.expires_at > now);
        }

        // Cleanup sliding windows
        {
            let mut windows = self.sliding_windows.write().await;
            windows.retain(|_, entry| entry.expires_at > now);
        }

        // Cleanup lockouts
        {
            let mut lockouts = self.lockouts.write().await;
            lockouts.retain(|_, entry| entry.expires_at > now);
        }

        debug!("Completed rate limit storage cleanup");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_token_bucket() {
        let storage = InMemoryRateLimitStorage::new();

        // Initially empty
        let result = storage.get_token_bucket("test:key").await.unwrap();
        assert!(result.is_none());

        // Set a value
        let state = TokenBucketState {
            tokens: 50.0,
            last_refill: 1234567890,
        };
        storage
            .set_token_bucket("test:key", &state, 60)
            .await
            .unwrap();

        // Get the value back
        let result = storage.get_token_bucket("test:key").await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.tokens, 50.0);
    }

    #[tokio::test]
    async fn test_in_memory_sliding_window() {
        let storage = InMemoryRateLimitStorage::new();

        let state = SlidingWindowState {
            current_count: 5,
            previous_count: 10,
            window_start: 1234567890,
        };
        storage
            .set_sliding_window("test:window", &state, 60)
            .await
            .unwrap();

        let result = storage.get_sliding_window("test:window").await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.current_count, 5);
        assert_eq!(retrieved.previous_count, 10);
    }

    #[tokio::test]
    async fn test_in_memory_lockout() {
        let storage = InMemoryRateLimitStorage::new();

        // Set lockout
        storage
            .set_lockout("test:auth", 1234567890, 60)
            .await
            .unwrap();

        // Get lockout
        let result = storage.get_lockout("test:auth").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1234567890);
    }

    #[tokio::test]
    async fn test_in_memory_delete() {
        let storage = InMemoryRateLimitStorage::new();

        let state = TokenBucketState {
            tokens: 100.0,
            last_refill: 1234567890,
        };
        storage
            .set_token_bucket("test:delete", &state, 60)
            .await
            .unwrap();

        // Verify it exists
        assert!(
            storage
                .get_token_bucket("test:delete")
                .await
                .unwrap()
                .is_some()
        );

        // Delete
        storage.delete("test:delete").await.unwrap();

        // Verify it's gone
        assert!(
            storage
                .get_token_bucket("test:delete")
                .await
                .unwrap()
                .is_none()
        );
    }
}
