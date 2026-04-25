//! Database configuration

use serde::Deserialize;

/// PostgreSQL connection pool settings
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Connection URL (overridden by `DATABASE_URL` env var)
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum idle connections to maintain
    pub min_idle: Option<u32>,
    /// Timeout for acquiring a connection from the pool (seconds)
    pub connect_timeout_seconds: u64,
    /// Maximum lifetime of a connection (seconds, None = unlimited)
    pub max_lifetime_seconds: Option<u64>,
    /// Idle timeout before a connection is closed (seconds, None = unlimited)
    pub idle_timeout_seconds: Option<u64>,
    /// Test connections before returning them from the pool
    pub enable_health_checks: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://postgres:postgres@localhost/vulnera".to_string(),
            max_connections: 10,
            min_idle: Some(2),
            connect_timeout_seconds: 30,
            max_lifetime_seconds: Some(1800),
            idle_timeout_seconds: Some(600),
            enable_health_checks: true,
        }
    }
}
