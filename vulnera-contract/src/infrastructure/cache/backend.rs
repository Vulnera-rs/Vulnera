use async_trait::async_trait;
use std::time::Duration;

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn set_raw(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
    async fn delete_by_pattern(&self, pattern: &str) -> Result<usize, String>;
}
