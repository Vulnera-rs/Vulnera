//! Benchmarks for dependency resolution

use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_version_parsing(c: &mut Criterion) {
    let version = "1.2.3";

    c.bench_function("version_parsing", |b| {
        b.iter(|| {
            let _ = black_box(version).parse::<semver::Version>();
        });
    });
}

criterion_group!(benches, bench_version_parsing);
criterion_main!(benches);
