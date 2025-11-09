//! Benchmarks for parsers

use criterion::{black_box, criterion_group, criterion_main, Criterion, async_executor::FuturesExecutor};
use vulnera_core::infrastructure::parsers::traits::ParserFactory;

fn bench_npm_parser(c: &mut Criterion) {
    let factory = ParserFactory::new();
    let parser = factory.create_parser("package.json").unwrap();
    let content = r#"{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21"
  }
}"#;
    
    c.bench_function("npm_parser", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let _ = parser.parse_file(black_box(content)).await;
        });
    });
}

fn bench_python_parser(c: &mut Criterion) {
    let factory = ParserFactory::new();
    let parser = factory.create_parser("requirements.txt").unwrap();
    let content = "requests==2.28.0\nflask>=2.0.0,<3.0.0\npytest~=7.0.0";
    
    c.bench_function("python_parser", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let _ = parser.parse_file(black_box(content)).await;
        });
    });
}

fn bench_rust_parser(c: &mut Criterion) {
    let factory = ParserFactory::new();
    let parser = factory.create_parser("Cargo.toml").unwrap();
    let content = r#"[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;
    
    c.bench_function("rust_parser", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let _ = parser.parse_file(black_box(content)).await;
        });
    });
}

criterion_group!(benches, bench_npm_parser, bench_python_parser, bench_rust_parser);
criterion_main!(benches);

