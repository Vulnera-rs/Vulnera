//! Vulnera Rust - Main application entry point
//!
//! This application starts the HTTP API server.
//! For CLI functionality, use the `vulnera-cli` crate instead.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::{net::TcpListener, signal};
use tokio_util::sync::CancellationToken;

use vulnera_rust::{Config, create_app, init_tracing};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_server().await
}

/// Run the HTTP server
async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = dotenvy::dotenv() {
        // Only warn if it's not a "file not found" error
        if !e.not_found() {
            eprintln!("Warning: Failed to load .env file: {}", e);
        }
    }

    // Load configuration
    let config = Config::load().unwrap_or_else(|e| {
        eprintln!("Failed to load configuration: {}", e);
        eprintln!("Using default configuration");
        Config::default()
    });

    // Initialize tracing (after config is loaded so we can use logging config)
    init_tracing(&config.logging)?;

    tracing::info!("Starting Vulnera Rust server...");
    tracing::info!(
        "Configuration loaded: server={}:{}",
        config.server.host,
        config.server.port
    );

    // Create application router using shared initialization logic
    let server_host = config.server.host.clone();
    let server_port = config.server.port;
    let enable_docs = config.server.enable_docs;
    let shutdown_timeout = Duration::from_secs(config.sync.shutdown_timeout_seconds);

    let app_handle = create_app(config).await.map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create application: {}", e),
        ))
    })?;

    // Create server address
    let addr = SocketAddr::new(server_host.parse()?, server_port);

    tracing::info!("Server listening on {}", addr);
    if enable_docs {
        tracing::info!("API documentation available at http://{}/docs", addr);
    } else {
        tracing::info!("API documentation disabled");
    }

    // Start server with graceful shutdown
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app_handle.router)
        .with_graceful_shutdown(shutdown_signal(app_handle.shutdown_token, shutdown_timeout))
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals and cancel background tasks
async fn shutdown_signal(shutdown_token: CancellationToken, timeout: Duration) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }

    // Cancel background tasks and wait for them to complete
    tracing::info!("Cancelling background tasks...");
    shutdown_token.cancel();

    // Give background tasks time to finish gracefully
    tokio::time::sleep(timeout).await;
    tracing::info!("Background tasks shutdown timeout reached");
}
