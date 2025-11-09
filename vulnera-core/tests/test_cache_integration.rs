//! Integration tests for cache system

use std::sync::Arc;
use std::time::Duration;
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::infrastructure::cache::{FileCacheRepository, MemoryCache, MultiLevelCache};

#[tokio::test]
async fn test_file_cache_integration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache = FileCacheRepository::new(temp_dir.path().to_path_buf(), Duration::from_secs(3600));

    // Test write and read
    let key = "test_key";
    let value: i32 = 42;

    cache
        .set(key, &value, Duration::from_secs(60))
        .await
        .unwrap();

    let retrieved: Option<i32> = cache.get(key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}

#[tokio::test]
async fn test_memory_cache_integration() {
    let cache = MemoryCache::new(100, 3600);

    let key = "test_key";
    let value: String = "test_value".to_string();

    cache.set(key, &value).await.unwrap();

    let retrieved: Option<String> = cache.get(key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}

#[tokio::test]
async fn test_multi_level_cache_integration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let l1 = Arc::new(MemoryCache::new(100, 3600));
    let l2 = Arc::new(FileCacheRepository::new(
        temp_dir.path().to_path_buf(),
        Duration::from_secs(3600),
    ));

    let cache = MultiLevelCache::new(l1.clone(), l2);

    let key = "test_key";
    let value: i32 = 42;

    // Write to cache
    cache
        .set(key, &value, Duration::from_secs(60))
        .await
        .unwrap();

    // Read from cache (should hit L1)
    let retrieved: Option<i32> = cache.get(key).await.unwrap();
    assert_eq!(retrieved, Some(value));

    // Invalidate L1 cache directly
    l1.invalidate(key).await;

    // Read again (should hit L2)
    let retrieved: Option<i32> = cache.get(key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}
