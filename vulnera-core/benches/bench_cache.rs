//! Benchmarks for cache operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, async_executor::FuturesExecutor};
use std::sync::Arc;
use std::time::Duration;
use vulnera_core::infrastructure::cache::memory_cache::MemoryCacheRepository;

fn bench_cache_set(c: &mut Criterion) {
    let cache = Arc::new(MemoryCacheRepository::new(1000, Duration::from_secs(3600)));
    let key = "test_key";
    let value: i32 = 42;
    
    c.bench_function("cache_set", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let _ = cache
                .set(black_box(key), black_box(&value), Duration::from_secs(60))
                .await;
        });
    });
}

fn bench_cache_get(c: &mut Criterion) {
    let cache = Arc::new(MemoryCacheRepository::new(1000, Duration::from_secs(3600)));
    let key = "test_key";
    let value: i32 = 42;
    
    // Pre-populate cache
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        cache
            .set(key, &value, Duration::from_secs(60))
            .await
            .unwrap();
    });
    
    c.bench_function("cache_get", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let _: Option<i32> = cache.get(black_box(key)).await.unwrap();
        });
    });
}

criterion_group!(benches, bench_cache_set, bench_cache_get);
criterion_main!(benches);

