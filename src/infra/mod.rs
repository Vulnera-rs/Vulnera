//! Infrastructure initialization for the Vulnera application
//!
//! This module handles the setup of core infrastructure components like
//! database pools, cache backends, and external service clients.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use tracing::info;

use vulnera_core::Config;
use vulnera_core::infrastructure::cache::DragonflyCache;
use vulnera_orchestrator::infrastructure::{GitService, GitServiceConfig, S3Service};

/// Infrastructure components initialized at startup
pub struct Infrastructure {
    pub db_pool: Arc<PgPool>,
    pub dragonfly_cache: Arc<DragonflyCache>,
    pub git_service: Arc<GitService>,
    pub s3_service: Arc<S3Service>,
}

impl Infrastructure {
    /// Initialize all infrastructure components from configuration
    pub async fn init(config: &Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize database pool
        info!("Initializing PostgreSQL database pool");
        let db_pool = Arc::new(
            PgPoolOptions::new()
                .max_connections(config.database.max_connections)
                .min_connections(config.database.min_idle.unwrap_or(0))
                .acquire_timeout(std::time::Duration::from_secs(
                    config.database.connect_timeout_seconds,
                ))
                .max_lifetime(
                    config
                        .database
                        .max_lifetime_seconds
                        .map(std::time::Duration::from_secs),
                )
                .idle_timeout(
                    config
                        .database
                        .idle_timeout_seconds
                        .map(std::time::Duration::from_secs),
                )
                .test_before_acquire(config.database.enable_health_checks)
                .connect(&config.database.url)
                .await?,
        );

        // Initialize cache - Dragonfly DB is the default and only cache backend
        info!(
            "Initializing Dragonfly DB cache at {}",
            config.cache.dragonfly_url
        );
        let dragonfly_cache = Arc::new(
            DragonflyCache::new(
                &config.cache.dragonfly_url,
                config.cache.enable_cache_compression,
                config.cache.compression_threshold_bytes,
            )
            .await?,
        );

        // Initialize Git service for repository cloning
        let git_service = Arc::new(GitService::new(GitServiceConfig::default())?);

        // Initialize S3 service for bucket analysis
        let s3_service = Arc::new(S3Service::new());

        Ok(Self {
            db_pool,
            dragonfly_cache,
            git_service,
            s3_service,
        })
    }
}
