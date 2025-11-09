//! Cache service implementation
//!
//! This module provides the concrete implementation of the CacheService trait
//! using Dragonfly DB cache.

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
use crate::infrastructure::cache::dragonfly_cache::DragonflyCache;

/// Cache service implementation with advanced features
/// Uses Dragonfly DB as the cache backend
pub struct CacheServiceImpl {
    cache_repository: Arc<DragonflyCache>,
}

impl CacheServiceImpl {
    /// Create a new cache service implementation with DragonflyCache
    pub fn new_with_dragonfly(cache_repository: Arc<DragonflyCache>) -> Self {
        Self { cache_repository }
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
                let cache_service = self.cache_repository.clone();
                let repo_clone = vulnerability_repository.clone();

                join_set.spawn(async move {
                    let cache_key = Self::package_vulnerabilities_key(&package_clone);

                    // Skip if already cached
                    let exists = cache_service
                        .get::<serde_json::Value>(&cache_key)
                        .await
                        .unwrap_or(None)
                        .is_some();
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
                            if let Err(e) = cache_service
                                .set(&cache_key, &vulnerabilities, Duration::from_secs(3600))
                                .await
                            {
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

        // Dragonfly cache doesn't support filesystem-based invalidation
        // This would require SCAN operations which are expensive
        // For now, return 0 and log a warning
        warn!(
            "Ecosystem cache invalidation not fully supported for Dragonfly cache. Use individual key invalidation instead."
        );
        Ok(0)
    }

    /// Get cache statistics
    pub async fn get_cache_statistics(&self) -> Result<CacheStatistics, ApplicationError> {
        // Dragonfly cache doesn't provide detailed statistics in the same way
        // Return default statistics
        Ok(CacheStatistics {
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
            total_entries: 0,
            total_size_bytes: 0,
            expired_entries: 0,
            cleanup_runs: 0,
        })
    }

    /// Check if a cache entry exists and is not expired
    pub async fn exists(&self, key: &str) -> Result<bool, ApplicationError> {
        // Check if key exists by trying to get it
        Ok(self
            .cache_repository
            .get::<serde_json::Value>(key)
            .await?
            .is_some())
    }

    /// Manually trigger cache cleanup
    pub async fn cleanup_expired_entries(&self) -> Result<u64, ApplicationError> {
        // Dragonfly DB automatically handles TTL expiration
        // No manual cleanup needed
        Ok(0)
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
        self.cache_repository.get(key).await
    }

    async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), ApplicationError>
    where
        T: serde::Serialize + Send + Sync,
    {
        self.cache_repository.set(key, value, ttl).await
    }

    async fn invalidate(&self, key: &str) -> Result<(), ApplicationError> {
        self.cache_repository.invalidate(key).await
    }
}
