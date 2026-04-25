//! Sync configuration

use serde::Deserialize;

/// Background sync settings for vulnerability data
#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    /// Enable background sync
    pub enabled: bool,
    /// Sync interval in hours
    pub interval_hours: u64,
    /// Run sync on startup
    pub on_startup: bool,
    /// Shutdown timeout for sync workers in seconds
    pub shutdown_timeout_seconds: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 8,
            on_startup: true,
            shutdown_timeout_seconds: 30,
        }
    }
}
