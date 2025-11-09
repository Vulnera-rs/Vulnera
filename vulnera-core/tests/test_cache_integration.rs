//! Integration tests for cache system

use std::sync::Arc;
use std::time::Duration;
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::infrastructure::cache::{
    DragonflyCache, FileCacheRepository, MemoryCache, MultiLevelCache,
};

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

/// Integration test for DragonflyCache
/// Requires a running Dragonfly DB instance at redis://127.0.0.1:6379
#[tokio::test]
#[ignore] // Ignore by default, requires Dragonfly DB instance
async fn test_dragonfly_cache_integration() {
    let cache = DragonflyCache::new("redis://127.0.0.1:6379", false, 0)
        .await
        .expect("Failed to create DragonflyCache");

    let key = "integration_test_key";
    let value: i32 = 42;

    // Test write
    cache
        .set(key, &value, Duration::from_secs(60))
        .await
        .expect("Failed to set value");

    // Test read
    let retrieved: Option<i32> = cache.get(key).await.expect("Failed to get value");
    assert_eq!(retrieved, Some(value));

    // Test invalidation
    cache.invalidate(key).await.expect("Failed to invalidate");

    // Verify it's gone
    let retrieved: Option<i32> = cache.get(key).await.expect("Failed to get value");
    assert!(retrieved.is_none());
}

/// Integration test for DragonflyCache with compression
#[tokio::test]
#[ignore]
async fn test_dragonfly_cache_compression_integration() {
    let cache = DragonflyCache::new("redis://127.0.0.1:6379", true, 100)
        .await
        .expect("Failed to create DragonflyCache");

    let key = "integration_test_compression";
    // Create a large value that will trigger compression
    let large_data = "x".repeat(1000);
    let value = serde_json::json!({
        "large_field": large_data,
        "small_field": "value"
    });

    // Test write with compression
    cache
        .set(key, &value, Duration::from_secs(60))
        .await
        .expect("Failed to set value");

    // Test read (should decompress automatically)
    let retrieved: Option<serde_json::Value> = cache.get(key).await.expect("Failed to get value");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), value);
}

/// Integration test for DragonflyCache TTL expiration
#[tokio::test]
#[ignore]
async fn test_dragonfly_cache_ttl_integration() {
    let cache = DragonflyCache::new("redis://127.0.0.1:6379", false, 0)
        .await
        .expect("Failed to create DragonflyCache");

    let key = "integration_test_ttl";
    let value: i32 = 42;

    // Set with short TTL
    cache
        .set(key, &value, Duration::from_secs(1))
        .await
        .expect("Failed to set value");

    // Should be available immediately
    let retrieved: Option<i32> = cache.get(key).await.expect("Failed to get value");
    assert_eq!(retrieved, Some(value));

    // Wait for expiration
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Should be expired
    let retrieved: Option<i32> = cache.get(key).await.expect("Failed to get value");
    assert!(retrieved.is_none());
}
