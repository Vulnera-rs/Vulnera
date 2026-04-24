//! Benchmarks for cache operations

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct SimpleCache {
    inner: Mutex<HashMap<String, i32>>,
}

impl SimpleCache {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn set(&self, key: &str, value: &i32) {
        let mut guard = self.inner.lock().await;
        guard.insert(key.to_string(), *value);
    }

    async fn get(&self, key: &str) -> Option<i32> {
        let guard = self.inner.lock().await;
        guard.get(key).copied()
    }
}

fn bench_cache_set(c: &mut Criterion) {
    let cache = Arc::new(SimpleCache::new());
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
    let cache = Arc::new(SimpleCache::new());
    let key = "test_key";
    let value: i32 = 42;

    // Pre-populate cache
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        cache.set(key, &value).await;
    });

    c.bench_function("cache_get", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let _: Option<i32> = cache.get(black_box(key)).await;
            });
        });
    });
}

criterion_group!(benches, bench_cache_set, bench_cache_get);
criterion_main!(benches);
