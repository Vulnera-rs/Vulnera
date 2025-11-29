//! Vulnera CLI - Main entry point
//!
//! Standalone vulnerability analysis tool with offline SAST, secrets, and API
//! security scanning, plus server-based dependency vulnerability analysis.

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    init_tracing();

    // Run the CLI
    let app = vulnera_cli::CliApp::new().await?;
    let exit_code = app.run().await?;

    // Exit with the appropriate code for CI integration
    std::process::exit(exit_code);
}

/// Initialize tracing/logging for the CLI
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,vulnera_cli=info"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).without_time())
        .with(filter)
        .init();
}
