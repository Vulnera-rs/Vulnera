//! Logging infrastructure
//!
//! Initializes the `tracing` subscriber with configurable format and level.

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::LoggingConfig;

/// Errors that can occur during logging initialization
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("Failed to initialize tracing: {0}")]
    Initialization(String),
}

/// Initialize the global tracing subscriber
///
/// # Arguments
/// * `config` - Logging configuration (level and format)
///
/// # Errors
/// Returns an error if the subscriber cannot be initialized.
pub fn init_tracing(config: &LoggingConfig) -> Result<(), LoggingError> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    let fmt_layer = match config.format {
        crate::config::LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        crate::config::LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .pretty()
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .try_init()
        .map_err(|e| LoggingError::Initialization(e.to_string()))?;

    Ok(())
}
