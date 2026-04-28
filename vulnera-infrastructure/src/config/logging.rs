//! Logging configuration

use serde::Deserialize;

/// Logging output format
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Logging level and format settings
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,
    /// Output format
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
        }
    }
}
