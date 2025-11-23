//! Integration tests for cache system

use std::time::Duration;
use testcontainers::{GenericImage, core::WaitFor, runners::AsyncRunner};
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::infrastructure::cache::DragonflyCache;

async fn start_redis() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new("redis", "7-alpine")
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
        .expect("Failed to start Redis container");

    let port = container
        .get_host_port_ipv4(6379)
        .await
        .expect("Failed to get port");
    let url = format!("redis://127.0.0.1:{}", port);

    (container, url)
}

/// Integration test for DragonflyCache
#[tokio::test]
async fn test_dragonfly_cache_integration() {
    let (_container, url) = start_redis().await;

    let cache = DragonflyCache::new(&url, false, 0)
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
async fn test_dragonfly_cache_compression_integration() {
    let (_container, url) = start_redis().await;

    let cache = DragonflyCache::new(&url, true, 100)
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
async fn test_dragonfly_cache_ttl_integration() {
    let (_container, url) = start_redis().await;

    let cache = DragonflyCache::new(&url, false, 0)
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
