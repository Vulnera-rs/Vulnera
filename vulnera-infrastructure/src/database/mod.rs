//! Database infrastructure

use sqlx::postgres::PgPool;
use std::time::Duration;
use tracing::info;

use crate::config::DatabaseConfig;

/// Initialize a PostgreSQL connection pool from configuration
pub async fn init_pool(config: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    info!(url = %redact_url(&config.url), "Initializing PostgreSQL connection pool");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_idle.unwrap_or(0))
        .acquire_timeout(Duration::from_secs(config.connect_timeout_seconds))
        .max_lifetime(config.max_lifetime_seconds.map(Duration::from_secs))
        .idle_timeout(config.idle_timeout_seconds.map(Duration::from_secs))
        .test_before_acquire(config.enable_health_checks)
        .connect(&config.url)
        .await?;

    info!(
        max_connections = config.max_connections,
        min_idle = config.min_idle.unwrap_or(0),
        "PostgreSQL pool initialized"
    );

    Ok(pool)
}

/// Run pending SQLx migrations
///
/// NOTE: Migrations are expected at the workspace root `migrations/` directory.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    info!("Running database migrations");
    sqlx::migrate!("../migrations").run(pool).await?;
    info!("Database migrations complete");
    Ok(())
}

/// Redact password from a database URL for safe logging
fn redact_url(url: &str) -> String {
    match url.rfind('@') {
        Some(at) => {
            let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
            format!("{}***@{}", &url[..scheme_end], &url[at + 1..])
        }
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_url() {
        let url = "postgres://user:secret@localhost/db";
        assert_eq!(redact_url(url), "postgres://***@localhost/db");
    }

    #[test]
    fn test_redact_url_no_password() {
        let url = "postgres://localhost/db";
        assert_eq!(redact_url(url), "postgres://localhost/db");
    }
}
