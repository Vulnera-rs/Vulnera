//! Benchmarks for cache operations

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use vulnera_core::infrastructure::cache::MemoryCache;

fn bench_cache_set(c: &mut Criterion) {
    let cache = Arc::new(MemoryCache::new(1000, 3600));
    let key = "test_key";
    let value: i32 = 42;

    c.bench_function("cache_set", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let _ = cache.set(black_box(key), black_box(&value)).await;
            });
        });
    });
}

fn bench_cache_get(c: &mut Criterion) {
    let cache = Arc::new(MemoryCache::new(1000, 3600));
    let key = "test_key";
    let value: i32 = 42;

    // Pre-populate cache
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        cache.set(key, &value).await.unwrap();
    });

    c.bench_function("cache_get", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let _: Option<i32> = cache.get(black_box(key)).await.unwrap();
            });
        });
    });
}

criterion_group!(benches, bench_cache_set, bench_cache_get);
criterion_main!(benches);
