//! CLI Context - Lightweight service context for CLI operations
//!
//! This module provides a minimal service context that initializes only the
//! services needed for CLI operations, avoiding the full HTTP server infrastructure.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use vulnera_core::config::Config;
use vulnera_core::infrastructure::cache::DragonflyCache;

use crate::cli::Cli;
use crate::cli::credentials::CredentialManager;
use crate::cli::output::OutputWriter;
use crate::cli::quota_tracker::QuotaTracker;

/// Lightweight context for CLI operations
///
/// Unlike the full `OrchestratorState` used by the HTTP server, this context
/// only initializes services needed for local CLI analysis operations.
pub struct CliContext {
    /// Application configuration
    pub config: Arc<Config>,

    /// Credential manager for API key storage
    pub credentials: CredentialManager,

    /// Quota tracker with local persistence and remote sync
    pub quota: QuotaTracker,

    /// Cache service for vulnerability data (optional, may be offline)
    pub cache: Option<Arc<DragonflyCache>>,

    /// Output writer configured based on CLI flags
    pub output: OutputWriter,

    /// Whether we're running in CI mode
    pub ci_mode: bool,

    /// Whether we're in offline mode
    pub offline_mode: bool,

    /// Working directory for analysis
    pub working_dir: PathBuf,
}

impl CliContext {
    /// Create a new CLI context from parsed CLI arguments
    pub async fn new(cli: &Cli) -> Result<Self> {
        // Load configuration
        let config = Self::load_config(cli.config.as_ref())?;
        let config = Arc::new(config);

        // Initialize credential manager
        let credentials = CredentialManager::new()?;

        // Determine if we're authenticated
        let api_key = Self::resolve_api_key(cli, &credentials)?;

        // Initialize quota tracker
        let quota = QuotaTracker::new(api_key.is_some())?;

        // Try to connect to cache if not offline
        let cache = if !cli.offline {
            Self::try_connect_cache(&config).await.ok()
        } else {
            None
        };

        // Determine offline mode based on flag or cache availability
        let offline_mode = cli.offline || cache.is_none();

        // Create output writer
        let output = OutputWriter::new(cli.format, cli.quiet, cli.verbose);

        // Determine working directory
        let working_dir =
            std::env::current_dir().context("Failed to determine current working directory")?;

        Ok(Self {
            config,
            credentials,
            quota,
            cache,
            output,
            ci_mode: cli.ci,
            offline_mode,
            working_dir,
        })
    }

    /// Load configuration from file or defaults
    fn load_config(_config_path: Option<&PathBuf>) -> Result<Config> {
        // TODO: Support loading from specific path when Config::load_from is available
        // For now, always use default config loading
        Config::load().or_else(|_| {
            tracing::debug!("No config file found, using defaults");
            Ok(Config::default())
        })
    }

    /// Resolve API key from CLI args, environment, or stored credentials
    fn resolve_api_key(cli: &Cli, credentials: &CredentialManager) -> Result<Option<String>> {
        // Priority: env var > stored credential
        if cli.ci {
            // In CI mode, only use environment variable
            if let Ok(key) = std::env::var("VULNERA_API_KEY") {
                return Ok(Some(key));
            }
        } else {
            // Try environment variable first
            if let Ok(key) = std::env::var("VULNERA_API_KEY") {
                return Ok(Some(key));
            }

            // Try stored credential
            if let Ok(Some(key)) = credentials.get_api_key() {
                return Ok(Some(key));
            }
        }

        Ok(None)
    }

    /// Try to connect to Dragonfly cache
    async fn try_connect_cache(config: &Config) -> Result<Arc<DragonflyCache>> {
        let cache = DragonflyCache::new(
            &config.cache.dragonfly_url,
            config.cache.enable_cache_compression,
            config.cache.compression_threshold_bytes,
        )
        .await
        .context("Failed to connect to cache")?;

        Ok(Arc::new(cache))
    }

    /// Check if we have a valid API key
    pub fn is_authenticated(&self) -> bool {
        self.resolve_current_api_key().is_ok_and(|k| k.is_some())
    }

    /// Get the current API key (from env or stored)
    pub fn resolve_current_api_key(&self) -> Result<Option<String>> {
        // Check env first
        if let Ok(key) = std::env::var("VULNERA_API_KEY") {
            return Ok(Some(key));
        }

        // Check stored credentials
        self.credentials.get_api_key()
    }

    /// Check if we're online (cache is available)
    pub fn is_online(&self) -> bool {
        self.cache.is_some()
    }

    /// Sync quota with remote if online
    pub async fn sync_quota(&mut self) -> Result<()> {
        if let Some(cache) = &self.cache {
            self.quota.sync_with_remote(cache).await?;
        }
        Ok(())
    }

    /// Consume a quota request
    pub async fn consume_quota(&mut self) -> Result<bool> {
        let allowed = self.quota.try_consume().await?;

        // Sync to remote if online
        if let Some(cache) = &self.cache {
            if let Err(e) = self.quota.sync_with_remote(cache).await {
                tracing::warn!("Failed to sync quota with remote: {}", e);
            }
        }

        Ok(allowed)
    }

    /// Get remaining quota
    pub fn remaining_quota(&self) -> u32 {
        self.quota.remaining()
    }

    /// Get daily quota limit
    pub fn daily_limit(&self) -> u32 {
        self.quota.daily_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_load_defaults() {
        let config = CliContext::load_config(None);
        assert!(config.is_ok());
    }
}
