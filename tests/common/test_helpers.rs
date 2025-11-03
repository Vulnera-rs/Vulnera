//! Common test helper functions and utilities
//!
//! This module provides utility functions that are commonly needed
//! across different test modules.

use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use vulnera_rust::{Config, create_app};
use axum_test::TestServer;

/// Test configuration builder for creating consistent test configurations
pub struct TestConfigBuilder {
    config: Config,
}

impl TestConfigBuilder {
    /// Create a new test configuration builder with defaults
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Set a temporary cache directory
    pub fn with_temp_cache(mut self) -> Result<(Self, TempDir), std::io::Error> {
        let temp_dir = TempDir::new()?;
        self.config.cache.directory = temp_dir.path().to_string_lossy().to_string();
        Ok((self, temp_dir))
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.cache.default_ttl = ttl;
        self
    }

    /// Set analysis concurrency
    pub fn with_concurrency(mut self, max_concurrent: usize) -> Self {
        self.config.analysis.max_concurrent_packages = max_concurrent;
        self
    }

    /// Enable debug mode
    pub fn with_debug(mut self) -> Self {
        self.config.debug = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Config {
        self.config
    }
}

impl Default for TestConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper for creating test servers with consistent configuration
pub struct TestServerBuilder;

impl TestServerBuilder {
    /// Create a test server with default configuration
    pub async fn new() -> Result<TestServer, Box<dyn std::error::Error>> {
        let (config, _temp_dir) = TestConfigBuilder::new().with_temp_cache()?;
        let app = create_app(config).await?;
        Ok(TestServer::new(app)?)
    }

    /// Create a test server with custom configuration
    pub async fn with_config(config: Config) -> Result<TestServer, Box<dyn std::error::Error>> {
        let app = create_app(config).await?;
        Ok(TestServer::new(app)?)
    }

    /// Create a test server with debug mode enabled
    pub async fn debug() -> Result<TestServer, Box<dyn std::error::Error>> {
        let (config, _temp_dir) = TestConfigBuilder::new().with_temp_cache()?.with_debug();
        let app = create_app(config).await?;
        Ok(TestServer::new(app)?)
    }
}

/// Async test timeout utilities
pub struct AsyncTestUtils;

impl AsyncTestUtils {
    /// Run a test with a timeout
    pub async fn with_timeout<F, T>(
        duration: Duration,
        future: F,
    ) -> Result<T, tokio::time::error::Elapsed>
    where
        F: std::future::Future<Output = T>,
    {
        timeout(duration, future).await
    }

    /// Run a test with a default 30-second timeout
    pub async fn with_default_timeout<F, T>(
        future: F,
    ) -> Result<T, tokio::time::error::Elapsed>
    where
        F: std::future::Future<Output = T>,
    {
        Self::with_timeout(Duration::from_secs(30), future).await
    }

    /// Run a test with a short 5-second timeout (for quick tests)
    pub async fn with_short_timeout<F, T>(
        future: F,
    ) -> Result<T, tokio::time::error::Elapsed>
    where
        F: std::future::Future<Output = T>,
    {
        Self::with_timeout(Duration::from_secs(5), future).await
    }
}

/// Performance testing utilities
pub struct PerformanceTestUtils;

impl PerformanceTestUtils {
    /// Measure execution time of an async function
    pub async fn measure_async<F, T, E>(future: F) -> Result<(T, Duration), E>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        let start = std::time::Instant::now();
        let result = future.await?;
        let duration = start.elapsed();
        Ok((result, duration))
    }

    /// Measure execution time of a sync function
    pub fn measure_sync<F, T, E>(func: F) -> Result<(T, Duration), E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let start = std::time::Instant::now();
        let result = func()?;
        let duration = start.elapsed();
        Ok((result, duration))
    }

    /// Assert that execution completes within the specified duration
    pub async fn assert_under_duration<F, T, E>(
        max_duration: Duration,
        future: F,
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let (result, duration) = Self::measure_async(future).await?;

        if duration > max_duration {
            return Err(format!(
                "Operation took {:?}, which exceeds the maximum allowed duration of {:?}",
                duration, max_duration
            ).into());
        }

        Ok(result)
    }

    /// Benchmark a function with multiple iterations
    pub async fn benchmark_async<F, T, E>(
        iterations: usize,
        future_factory: impl Fn() -> F,
    ) -> Result<Vec<Duration>, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        let mut durations = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let (_, duration) = Self::measure_async(future_factory()).await?;
            durations.push(duration);
        }

        Ok(durations)
    }
}

/// Concurrency testing utilities
pub struct ConcurrencyTestUtils;

impl ConcurrencyTestUtils {
    /// Run multiple instances of the same async function concurrently
    pub async fn run_concurrent<F, T, E>(
        count: usize,
        task_factory: impl Fn(usize) -> F,
    ) -> Vec<Result<T, E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        let handles: Vec<_> = (0..count)
            .map(|i| tokio::spawn(task_factory(i)))
            .collect();

        let mut results = Vec::with_capacity(count);
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => panic!("Task panicked: {:?}", e),
            }
        }

        results
    }

    /// Test that a function can handle concurrent access safely
    pub async fn test_concurrent_safety<F, T, E>(
        count: usize,
        task_factory: impl Fn(usize) -> F,
    ) -> ConcurrencyTestResult<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        T: Clone + PartialEq + std::fmt::Debug,
        E: std::fmt::Debug,
    {
        let results = Self::run_concurrent(count, task_factory).await;

        let successful_results: Vec<T> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .cloned()
            .collect();

        let errors: Vec<&E> = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .collect();

        let all_same = successful_results
            .windows(2)
            .all(|w| w[0] == w[1]);

        ConcurrencyTestResult {
            total_tasks: count,
            successful: successful_results.len(),
            failed: errors.len(),
            results_are_consistent: all_same,
            unique_results: {
                let mut unique = std::collections::HashSet::new();
                for result in &successful_results {
                    unique.insert(result);
                }
                unique.len()
            },
        }
    }
}

/// Result of concurrency testing
#[derive(Debug)]
pub struct ConcurrencyTestResult<T, E> {
    pub total_tasks: usize,
    pub successful: usize,
    pub failed: usize,
    pub results_are_consistent: bool,
    pub unique_results: usize,
}

impl<T, E> std::fmt::Display for ConcurrencyTestResult<T, E>
where
    T: std::fmt::Debug,
    E: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Concurrency test results: {}/{} successful, {}/{} failed, consistent: {}, unique results: {}",
            self.successful, self.total_tasks, self.failed, self.total_tasks, self.results_are_consistent, self.unique_results
        )
    }
}

/// Memory testing utilities
pub struct MemoryTestUtils;

impl MemoryTestUtils {
    /// Get current memory usage (approximate)
    pub fn get_memory_usage() -> usize {
        // This is a simplified implementation
        // In a real scenario, you might use platform-specific APIs
        std::mem::size_of::<usize>() * 1000 // Placeholder
    }

    /// Test for memory leaks by running a function multiple times
    pub async fn test_memory_leak<F, T, E>(
        iterations: usize,
        task_factory: impl Fn() -> F,
    ) -> MemoryLeakTestResult
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        let initial_memory = Self::get_memory_usage();
        let mut peak_memory = initial_memory;

        for i in 0..iterations {
            let _ = task_factory().await; // Run the task
            let current_memory = Self::get_memory_usage();
            peak_memory = peak_memory.max(current_memory);

            // Force garbage collection hint
            if i % 10 == 0 {
                std::hint::black_box(i);
            }
        }

        let final_memory = Self::get_memory_usage();

        MemoryLeakTestResult {
            iterations,
            initial_memory,
            peak_memory,
            final_memory,
            memory_growth: final_memory.saturating_sub(initial_memory),
            potential_leak: final_memory > initial_memory * 2, // Heuristic
        }
    }
}

/// Result of memory leak testing
#[derive(Debug)]
pub struct MemoryLeakTestResult {
    pub iterations: usize,
    pub initial_memory: usize,
    pub peak_memory: usize,
    pub final_memory: usize,
    pub memory_growth: usize,
    pub potential_leak: bool,
}

impl std::fmt::Display for MemoryLeakTestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Memory test over {} iterations: initial: {}, peak: {}, final: {}, growth: {}, potential leak: {}",
            self.iterations, self.initial_memory, self.peak_memory, self.final_memory, self.memory_growth, self.potential_leak
        )
    }
}

/// Test data generation utilities
pub struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate random package names
    pub fn random_package_names(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("package-{}", i))
            .collect()
    }

    /// Generate random versions
    pub fn random_versions(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("{}.{}.{}", (i % 10) + 1, (i % 20) + 1, (i % 100)))
            .collect()
    }

    /// Generate random vulnerability IDs
    pub fn random_vulnerability_ids(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("TEST-{:04}", i + 1000))
            .collect()
    }

    /// Generate large text for testing
    pub fn large_text(size_bytes: usize) -> String {
        "x".repeat(size_bytes)
    }

    /// Generate random JSON-like structure
    pub fn random_json_structure(depth: usize, breadth: usize) -> String {
        if depth == 0 {
            "\"value\"".to_string()
        } else {
            let mut result = "{".to_string();
            for i in 0..breadth {
                if i > 0 {
                    result.push_str(", ");
                }
                result.push_str(&format!("\"key{}\": {}", i, Self::random_json_structure(depth - 1, breadth)));
            }
            result.push('}');
            result
        }
    }
}

/// Utility macros for testing

/// Macro to assert that an async operation completes within a timeout
#[macro_export]
macro_rules! assert_async_under_duration {
    ($max_duration:expr, $future:expr) => {
        match $crate::common::test_helpers::AsyncTestUtils::with_timeout($max_duration, $future).await {
            Ok(result) => result,
            Err(_) => panic!("Operation timed out after {:?}", $max_duration),
        }
    };
}

/// Macro to run a test function with different parameter sets
#[macro_export]
macro_rules! test_with_params {
    ($test_name:ident, $param_type:ty, [$($param:expr),*]) => {
        $(
            #[tokio::test]
            async fn $test_name() {
                $test_name::<$param_type>($param).await;
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::factories::*;

    #[tokio::test]
    async fn test_test_config_builder() {
        let (config, _temp_dir) = TestConfigBuilder::new()
            .with_temp_cache()
            .expect("Failed to create temp cache")
            .with_cache_ttl(Duration::from_secs(60))
            .with_concurrency(5)
            .with_debug()
            .build();

        assert_eq!(config.analysis.max_concurrent_packages, 5);
        assert!(config.debug);
    }

    #[tokio::test]
    async fn test_async_test_utils() {
        let quick_future = async { 42 };
        let result = AsyncTestUtils::with_short_timeout(quick_future)
            .await
            .expect("Future should complete quickly");
        assert_eq!(result, 42);

        let slow_future = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            42
        };

        let result = AsyncTestUtils::with_timeout(Duration::from_millis(200), slow_future)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_performance_utils() {
        let test_func = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<(), ()>(())
        };

        let (_, duration) = PerformanceTestUtils::measure_async(test_func).await.unwrap();
        assert!(duration >= Duration::from_millis(10));
        assert!(duration < Duration::from_millis(50));

        let result = PerformanceTestUtils::assert_under_duration(
            Duration::from_millis(20),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<(), ()>(())
            }
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_concurrency_utils() {
        let result = ConcurrencyTestUtils::test_concurrent_safety(
            10,
            |i| async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok::<usize, ()>(i * 2)
            },
        ).await;

        assert_eq!(result.successful, 10);
        assert_eq!(result.failed, 0);
        assert!(!result.results_are_consistent); // Each task returns different values
        assert_eq!(result.unique_results, 10);
    }

    #[tokio::test]
    async fn test_memory_utils() {
        let result = MemoryTestUtils::test_memory_leak(5, || async {
            let _data = vec![0u8; 1000]; // Allocate some memory
            Ok::<(), ()>(())
        }).await;

        assert_eq!(result.iterations, 5);
        println!("{}", result);
    }

    #[test]
    fn test_test_data_generator() {
        let names = TestDataGenerator::random_package_names(5);
        assert_eq!(names.len(), 5);
        assert!(names.iter().all(|n| n.starts_with("package-")));

        let versions = TestDataGenerator::random_versions(3);
        assert_eq!(versions.len(), 3);
        assert!(versions.iter().all(|v| v.contains('.')));

        let vuln_ids = TestDataGenerator::random_vulnerability_ids(4);
        assert_eq!(vuln_ids.len(), 4);
        assert!(vuln_ids.iter().all(|id| id.starts_with("TEST-")));
    }
}