//! Cache service implementation
//!
//! This module provides the concrete implementation of the CacheService trait
//! using the file-based cache repository.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::application::errors::ApplicationError;
use crate::application::vulnerability::services::CacheService;
use crate::domain::vulnerability::entities::Package;
use crate::domain::vulnerability::repositories::IVulnerabilityRepository;
use crate::domain::vulnerability::value_objects::Ecosystem;
use crate::infrastructure::cache::file_cache::FileCacheRepository;
use crate::infrastructure::cache::multi_level::MultiLevelCache;

/// Cache service implementation with advanced features
/// Uses an enum to support different cache implementations (FileCache or MultiLevelCache)
pub struct CacheServiceImpl {
    cache_repository: CacheBackend,
}

/// Internal cache backend enum to support different implementations
#[derive(Clone)]
enum CacheBackend {
    File(Arc<FileCacheRepository>),
    MultiLevel(Arc<MultiLevelCache>),
}

impl CacheServiceImpl {
    /// Create a new cache service implementation with FileCacheRepository
    pub fn new(cache_repository: Arc<FileCacheRepository>) -> Self {
        Self {
            cache_repository: CacheBackend::File(cache_repository),
        }
    }

    /// Create a new cache service implementation with MultiLevelCache
    pub fn new_with_cache(cache_repository: Arc<MultiLevelCache>) -> Self {
        Self {
            cache_repository: CacheBackend::MultiLevel(cache_repository),
        }
    }

    /// Get the underlying file cache repository if available (for stats)
    pub fn get_file_cache(&self) -> Option<&FileCacheRepository> {
        match &self.cache_repository {
            CacheBackend::File(fc) => Some(fc.as_ref()),
            CacheBackend::MultiLevel(_ml) => {
                // Try to get L2 cache (FileCacheRepository) from MultiLevelCache
                // This is a bit hacky but needed for stats
                None // We'll handle stats differently
            }
        }
    }

    /// Generate cache key for package vulnerabilities
    /// Optimized with capacity hint to avoid reallocations
    pub fn package_vulnerabilities_key(package: &Package) -> String {
        let ecosystem_name = package.ecosystem.canonical_name();
        let version_str = package.version.to_string();
        let estimated_capacity = 5 + ecosystem_name.len() + package.name.len() + version_str.len();
        let mut key = String::with_capacity(estimated_capacity);
        key.push_str("vuln:");
        key.push_str(ecosystem_name);
        key.push(':');
        key.push_str(&package.name);
        key.push(':');
        key.push_str(&version_str);
        key
    }

    /// Generate cache key for vulnerability details
    pub fn vulnerability_details_key(
        vulnerability_id: &crate::domain::vulnerability::value_objects::VulnerabilityId,
    ) -> String {
        format!("vuln_details:{}", vulnerability_id.as_str())
    }

    /// Generate cache key for analysis reports
    pub fn analysis_report_key(content_hash: &str, ecosystem: &Ecosystem) -> String {
        format!("analysis:{}:{}", ecosystem.canonical_name(), content_hash)
    }

    /// Generate cache key for parsed packages
    pub fn parsed_packages_key(content_hash: &str, ecosystem: &Ecosystem) -> String {
        format!("packages:{}:{}", ecosystem.canonical_name(), content_hash)
    }

    /// Generate cache key for registry versions for a package (used by VersionResolutionService)
    /// Example: registry_versions:npm:express
    pub fn registry_versions_key(ecosystem: &Ecosystem, package_name: &str) -> String {
        format!(
            "registry_versions:{}:{}",
            ecosystem.canonical_name(),
            package_name
        )
    }

    /// Generate a hash for file content to use as cache key component
    pub fn content_hash(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Cache warming: preload commonly accessed data
    pub async fn warm_cache(
        &self,
        packages: &[Package],
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    ) -> Result<(), ApplicationError> {
        info!("Starting cache warming for {} packages", packages.len());

        let mut successful_warms = 0;
        let mut failed_warms = 0;

        for package in packages {
            let cache_key = Self::package_vulnerabilities_key(package);

            // Check if already cached
            if self.exists(&cache_key).await? {
                debug!("Package {} already cached, skipping", package.identifier());
                continue;
            }

            // Fetch vulnerabilities and cache them
            match vulnerability_repository.find_vulnerabilities(package).await {
                Ok(vulnerabilities) => {
                    let cache_ttl = Duration::from_secs(24 * 3600); // 24 hours
                    if let Err(e) = self.set(&cache_key, &vulnerabilities, cache_ttl).await {
                        warn!(
                            "Failed to cache vulnerabilities for {}: {}",
                            package.identifier(),
                            e
                        );
                        failed_warms += 1;
                    } else {
                        debug!("Warmed cache for package: {}", package.identifier());
                        successful_warms += 1;
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to fetch vulnerabilities for {} during warm-up: {}",
                        package.identifier(),
                        e
                    );
                    failed_warms += 1;
                }
            }
        }

        info!(
            "Cache warming completed: {} successful, {} failed",
            successful_warms, failed_warms
        );

        Ok(())
    }

    /// Preload cache with vulnerability data for a list of packages
    pub async fn preload_vulnerabilities(
        &self,
        packages: &[Package],
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    ) -> Result<(), ApplicationError> {
        info!(
            "Preloading vulnerability cache for {} packages",
            packages.len()
        );

        let mut join_set = JoinSet::new();
        let max_concurrent = 5; // Limit concurrent preloading

        for chunk in packages.chunks(max_concurrent) {
            for package in chunk {
                let package_clone = package.clone();
                let cache_service_backend = self.cache_repository.clone();
                let repo_clone = vulnerability_repository.clone();

                join_set.spawn(async move {
                    let cache_key = Self::package_vulnerabilities_key(&package_clone);

                    // Skip if already cached
                    let exists = match &cache_service_backend {
                        CacheBackend::File(fc) => fc.exists(&cache_key).await.unwrap_or(false),
                        CacheBackend::MultiLevel(ml) => {
                            // Check L1 first, then L2
                            if let Ok(Some(_)) = ml.l1().get::<serde_json::Value>(&cache_key).await
                            {
                                true
                            } else {
                                ml.l2().exists(&cache_key).await.unwrap_or(false)
                            }
                        }
                    };
                    if exists {
                        return Ok::<_, ApplicationError>(());
                    }

                    // Try to find and cache vulnerabilities for this package
                    match repo_clone.find_vulnerabilities(&package_clone).await {
                        Ok(vulnerabilities) => {
                            debug!(
                                "Preloaded {} vulnerabilities for: {}",
                                vulnerabilities.len(),
                                package_clone.identifier()
                            );
                            // Cache the vulnerabilities
                            let cache_result = match &cache_service_backend {
                                CacheBackend::File(fc) => {
                                    fc.set(&cache_key, &vulnerabilities, Duration::from_secs(3600))
                                        .await
                                }
                                CacheBackend::MultiLevel(ml) => {
                                    ml.set(&cache_key, &vulnerabilities, Duration::from_secs(3600))
                                        .await
                                }
                            };
                            if let Err(e) = cache_result {
                                warn!(
                                    "Failed to cache vulnerabilities for {}: {}",
                                    package_clone.identifier(),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                "Failed to preload vulnerabilities for {}: {}",
                                package_clone.identifier(),
                                e
                            );
                        }
                    }
                    Ok(())
                });
            }

            // Wait for current chunk to complete
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    warn!("Preload task failed: {}", e);
                }
            }
        }

        info!("Vulnerability cache preloading completed");
        Ok(())
    }

    /// Invalidate cache entries for updated vulnerability data
    pub async fn invalidate_vulnerability_data(
        &self,
        package: &Package,
    ) -> Result<(), ApplicationError> {
        let cache_key = Self::package_vulnerabilities_key(package);
        self.invalidate(&cache_key).await?;

        debug!(
            "Invalidated vulnerability cache for package: {}",
            package.identifier()
        );
        Ok(())
    }

    /// Invalidate all cache entries for a specific ecosystem
    pub async fn invalidate_ecosystem_cache(
        &self,
        ecosystem: &Ecosystem,
    ) -> Result<u64, ApplicationError> {
        info!(
            "Invalidating all cache entries for ecosystem: {}",
            ecosystem
        );

        let mut invalidated_count = 0u64;

        // Read cache directory and find files matching ecosystem prefix
        let cache_dir = match &self.cache_repository {
            CacheBackend::File(fc) => fc.cache_dir(),
            CacheBackend::MultiLevel(ml) => ml.l2().cache_dir(),
        };
        if let Ok(mut entries) = tokio::fs::read_dir(cache_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(file_type) = entry.file_type().await {
                    if file_type.is_file() {
                        let file_name = entry.file_name();
                        let file_name_str = file_name.to_string_lossy();

                        // Check if filename contains ecosystem-specific cache keys
                        let ecosystem_str = ecosystem.to_string().to_lowercase();
                        if file_name_str
                            .contains(&format!("package_vulnerabilities:{}:", ecosystem_str))
                            || file_name_str
                                .contains(&format!("version_recommendations:{}:", ecosystem_str))
                            || file_name_str
                                .contains(&format!("registry_versions:{}:", ecosystem_str))
                        {
                            if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                                warn!("Failed to remove cache file {}: {}", file_name_str, e);
                            } else {
                                invalidated_count += 1;
                                debug!("Removed cache file: {}", file_name_str);
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Invalidated {} cache entries for ecosystem: {}",
            invalidated_count, ecosystem
        );
        Ok(invalidated_count)
    }

    /// Get cache statistics
    pub async fn get_cache_statistics(&self) -> Result<CacheStatistics, ApplicationError> {
        match &self.cache_repository {
            CacheBackend::File(fc) => {
                let stats = fc.get_stats().await;
                let (total_size, entry_count) = fc.get_cache_info().await?;

                Ok(CacheStatistics {
                    hits: stats.hits,
                    misses: stats.misses,
                    hit_rate: if stats.hits + stats.misses > 0 {
                        stats.hits as f64 / (stats.hits + stats.misses) as f64
                    } else {
                        0.0
                    },
                    total_entries: entry_count,
                    total_size_bytes: total_size,
                    expired_entries: stats.expired_entries,
                    cleanup_runs: stats.cleanup_runs,
                })
            }
            CacheBackend::MultiLevel(ml) => {
                // Get stats from L2 (FileCacheRepository)
                let l2 = ml.l2();
                let stats = l2.get_stats().await;
                let (total_size, entry_count) = l2.get_cache_info().await?;
                let (l1_entries, l1_size) = ml.l1().stats();

                Ok(CacheStatistics {
                    hits: stats.hits,
                    misses: stats.misses,
                    hit_rate: if stats.hits + stats.misses > 0 {
                        stats.hits as f64 / (stats.hits + stats.misses) as f64
                    } else {
                        0.0
                    },
                    total_entries: entry_count + l1_entries,
                    total_size_bytes: total_size + l1_size,
                    expired_entries: stats.expired_entries,
                    cleanup_runs: stats.cleanup_runs,
                })
            }
        }
    }

    /// Check if a cache entry exists and is not expired
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        match &self.cache_repository {
            CacheBackend::File(fc) => fc.exists(key).await,
            CacheBackend::MultiLevel(ml) => {
                // Check L1 first, then L2
                if let Ok(Some(_)) = ml.l1().get::<serde_json::Value>(key).await {
                    Ok(true)
                } else {
                    ml.l2().exists(key).await
                }
            }
        }
    }

    /// Manually trigger cache cleanup
    pub async fn cleanup_expired_entries(&self) -> Result<u64, ApplicationError> {
        match &self.cache_repository {
            CacheBackend::File(fc) => fc.cleanup_expired().await,
            CacheBackend::MultiLevel(ml) => {
                // Cleanup L2 (L1 is automatically cleaned via TTL)
                ml.l2().cleanup_expired().await
            }
        }
    }
}

/// Cache statistics for monitoring and debugging
#[derive(Debug, Clone)]
pub struct CacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub total_entries: u64,
    pub total_size_bytes: u64,
    pub expired_entries: u64,
    pub cleanup_runs: u64,
}

#[async_trait]
impl CacheService for CacheServiceImpl {
    async fn get<T>(&self, key: &str) -> Result<Option<T>, ApplicationError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        match &self.cache_repository {
            CacheBackend::File(fc) => fc.get(key).await,
            CacheBackend::MultiLevel(ml) => ml.get(key).await,
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        match &self.cache_repository {
            CacheBackend::File(fc) => fc.set(key, value, ttl).await,
            CacheBackend::MultiLevel(ml) => ml.set(key, value, ttl).await,
        }
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        match &self.cache_repository {
            CacheBackend::File(fc) => fc.invalidate(key).await,
            CacheBackend::MultiLevel(ml) => ml.invalidate(key).await,
        }
    }
}
