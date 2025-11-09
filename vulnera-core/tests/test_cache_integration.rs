//! Integration tests for cache system

use std::time::Duration;
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::infrastructure::cache::DragonflyCache;

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
