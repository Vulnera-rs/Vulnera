//! CLI Context - Lightweight service context for CLI operations
//!
//! This module provides a minimal service context that initializes only the
//! services needed for CLI operations, avoiding the full HTTP server infrastructure.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use vulnera_core::config::Config;

use crate::Cli;
use crate::api_client::VulneraClient;
use crate::constants::DEFAULT_SERVER_URL;
use crate::credentials::CredentialManager;
use crate::executor::AnalysisExecutor;
use crate::output::OutputWriter;
use crate::quota_tracker::QuotaTracker;

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

    /// Analysis executor for running scans
    pub executor: AnalysisExecutor,

    /// Output writer configured based on CLI flags
    pub output: OutputWriter,

    /// Server URL for API calls
    pub server_url: String,

    /// Whether we're running in CI mode
    pub ci_mode: bool,

    /// Whether we're in offline mode
    pub offline_mode: bool,

    /// Working directory for analysis
    pub working_dir: PathBuf,

    /// API client for server communication (None if offline)
    api_client: Option<VulneraClient>,
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

        // Determine server URL (from CLI flag or config)
        let server_url = cli
            .server
            .clone()
            .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());

        // Create API client if not offline (use resolved server URL)
        let api_client = if !cli.offline {
            let mut client = VulneraClient::with_url(server_url.clone(), None)?;
            if let Some(key) = &api_key {
                client = client.with_api_key(key.clone());
            }
            Some(client)
        } else {
            None
        };

        // Determine offline mode
        let offline_mode = cli.offline;

        // Create analysis executor
        let executor = AnalysisExecutor::new(&config, api_client.clone(), offline_mode);

        // Create output writer
        let output = OutputWriter::new(cli.format, cli.quiet, cli.verbose);

        // Determine working directory
        let working_dir =
            std::env::current_dir().context("Failed to determine current working directory")?;

        Ok(Self {
            config,
            credentials,
            quota,
            executor,
            output,
            server_url,
            ci_mode: cli.ci,
            offline_mode,
            working_dir,
            api_client,
        })
    }

    /// Load configuration from file or defaults
    fn load_config(config_path: Option<&PathBuf>) -> Result<Config> {
        if let Some(path) = config_path {
            // Load from specified path
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read configuration from {:?}", path))?;
            let config: Config = toml::from_str(&content)
                .with_context(|| format!("Failed to parse configuration from {:?}", path))?;
            Ok(config)
        } else {
            // Try default loading, fall back to defaults
            Config::load().or_else(|_| {
                tracing::debug!("No config file found, using defaults");
                Ok(Config::default())
            })
        }
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
            if let Ok(key_opt) = credentials.get_api_key() {
                if let Some(key) = key_opt {
                    return Ok(Some(key));
                }
            }
        }

        Ok(None)
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

    /// Check if we're online (not in offline mode)
    pub fn is_online(&self) -> bool {
        !self.offline_mode
    }

    /// Get the API client (returns None if offline)
    pub fn api_client(&self) -> Option<&VulneraClient> {
        self.api_client.as_ref()
    }

    /// Consume a quota request
    pub async fn consume_quota(&mut self) -> Result<bool> {
        self.quota.try_consume().await
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

    #[test]
    fn test_config_load_defaults() {
        let config = CliContext::load_config(None);
        assert!(config.is_ok());
    }
}
