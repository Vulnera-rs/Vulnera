//! Configuration system

use serde::Deserialize;

mod analysis;
mod api_security;
mod cache;
mod database;
mod llm;
mod logging;
mod sast;
mod secret_detection;
mod server;
pub mod sync;
pub mod validation;

pub use analysis::AnalysisConfig;
pub use api_security::ApiSecurityConfig;
pub use cache::CacheConfig;
pub use database::DatabaseConfig;
pub use llm::LlmConfig;
pub use logging::{LogFormat, LoggingConfig};
pub use sast::SastConfig;
pub use secret_detection::SecretDetectionConfig;
pub use server::ServerConfig;
pub use sync::SyncConfig;
pub use validation::Validate;

/// Top-level application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub sync: SyncConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub sast: SastConfig,
    #[serde(default)]
    pub secret_detection: SecretDetectionConfig,
    #[serde(default)]
    pub api_security: ApiSecurityConfig,
    #[serde(default)]
    pub llm: LlmConfig,
}

impl Config {
    /// Load configuration from files and environment variables
    pub fn load() -> Result<Self, config::ConfigError> {
        let env =
            std::env::var("VULNERA_ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        let builder = config::Config::builder()
            .add_source(config::File::with_name("config/default.toml").required(false))
            .add_source(config::File::with_name(&format!("config/{}", env)).required(false))
            .add_source(config::Environment::with_prefix("VULNERA").separator("__"));

        let mut cfg: Self = builder.build()?.try_deserialize()?;

        if let Ok(url) = std::env::var("DATABASE_URL") {
            cfg.database.url = url;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_default() {
        if std::path::Path::new("config/default.toml").exists() {
            let cfg = Config::load().expect("Failed to load config");
            assert!(!cfg.database.url.is_empty());
            assert!(cfg.server.port > 0);
        }
    }
}
