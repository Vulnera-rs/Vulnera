//! Vulnera Rust - Main application entry point

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};

use vulnera_rust::infrastructure::resilience::CircuitBreakerConfig;
use vulnera_rust::{
    Config,
    application::{
        AnalysisServiceImpl, CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
        VersionResolutionServiceImpl,
    },
    infrastructure::{
        api_clients::{
            circuit_breaker_wrapper::CircuitBreakerApiClient, ghsa::GhsaClient, nvd::NvdClient,
            osv::OsvClient,
        },
        cache::file_cache::FileCacheRepository,
        parsers::ParserFactory,
        registries::MultiplexRegistryClient,
        repositories::AggregatingVulnerabilityRepository,
        repository_source::GitHubRepositoryClient,
        resilience::CircuitBreaker,
    },
    init_tracing,
    presentation::{AppState, create_router},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::load().unwrap_or_else(|e| {
        eprintln!("Failed to load configuration: {}", e);
        eprintln!("Using default configuration");
        Config::default()
    });

    // Initialize tracing
    init_tracing(&config.logging)?;

    tracing::info!("Starting Vulnera Rust server...");
    tracing::info!(
        "Configuration loaded: server={}:{}",
        config.server.host,
        config.server.port
    );

    // Initialize infrastructure services
    let cache_repository = Arc::new(FileCacheRepository::new(
        config.cache.directory.clone(),
        Duration::from_secs(config.cache.ttl_hours * 3600),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repository));
    let parser_factory = Arc::new(ParserFactory::new());

    // Create circuit breakers for each API service
    let osv_circuit_breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 5,
        recovery_timeout: std::time::Duration::from_secs(60),
        half_open_max_requests: 3,
        request_timeout: std::time::Duration::from_secs(30),
    }));
    let nvd_circuit_breaker = Arc::new(CircuitBreaker::new(
        config.apis.nvd.circuit_breaker.to_circuit_breaker_config(),
    ));
    let ghsa_circuit_breaker = Arc::new(CircuitBreaker::new(
        config.apis.ghsa.circuit_breaker.to_circuit_breaker_config(),
    ));

    // Create API clients
    let osv_client_inner = Arc::new(OsvClient);
    let nvd_client_inner = Arc::new(NvdClient::new(
        config.apis.nvd.base_url.clone(),
        config.apis.nvd.api_key.clone(),
    ));
    let ghsa_token_opt = config.apis.ghsa.token.clone().filter(|t| !t.is_empty());
    if ghsa_token_opt.is_none() {
        tracing::info!(
            "GHSA token not provided; GitHub advisories lookups will be skipped unless provided via environment."
        );
    }
    let ghsa_client_inner = Arc::new(
        GhsaClient::new(
            ghsa_token_opt.unwrap_or_default(),
            config.apis.ghsa.graphql_url.clone(),
        )
        .map_err(|e| {
            eprintln!("Failed to create GHSA client: {}", e);
            e
        })?,
    );

    // Wrap clients with circuit breakers
    let osv_client = Arc::new(CircuitBreakerApiClient::new(
        osv_client_inner,
        osv_circuit_breaker,
    ));
    let nvd_client = Arc::new(CircuitBreakerApiClient::new(
        nvd_client_inner,
        nvd_circuit_breaker,
    ));
    let ghsa_client = Arc::new(CircuitBreakerApiClient::new(
        ghsa_client_inner,
        ghsa_circuit_breaker,
    ));

    let vulnerability_repository = Arc::new(AggregatingVulnerabilityRepository::new(
        osv_client,
        nvd_client,
        ghsa_client,
    ));

    let analysis_service = Arc::new(AnalysisServiceImpl::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        &config,
    ));
    let report_service = Arc::new(ReportServiceImpl::new());
    // GitHub repository analysis components (stub wiring)
    let github_client = Arc::new(
        GitHubRepositoryClient::from_token(
            config.apis.github.token.clone(),
            Some(config.apis.github.base_url.clone()),
            config.apis.github.timeout_seconds,
            config.apis.github.reuse_ghsa_token,
        ).await.unwrap_or_else(|e| {
            tracing::warn!(error=?e, "Failed to init GitHubRepositoryClient, attempting fallback");
            // Fallback: try to create client without token
            match octocrab::Octocrab::builder().build() {
                Ok(octo) => GitHubRepositoryClient::new(
                    octo,
                    "https://api.github.com".into(),
                    false,
                    10,
                ),
                Err(err) => {
                    tracing::error!(error=?err, "Failed to create fallback GitHubRepositoryClient, repository analysis disabled");
                    // Create a client that will fail gracefully when used
                    // This is a workaround for now - ideally we'd handle None in the service layer
                    GitHubRepositoryClient::new(
                        octocrab::Octocrab::default(),
                        "https://api.github.com".into(),
                        false,
                        10,
                    )
                }
            }
        })
    );
    let repository_analysis_service: Option<
        Arc<dyn vulnera_rust::application::RepositoryAnalysisService>,
    > = Some(Arc::new(
        vulnera_rust::application::RepositoryAnalysisServiceImpl::new(
            github_client.clone(),
            vulnerability_repository.clone(),
            parser_factory.clone(),
            Arc::new(config.clone()),
        ),
    ));

    // Create popular package service with config
    let config_arc = Arc::new(config.clone());
    let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
        vulnerability_repository.clone(),
        cache_service.clone(),
        config_arc,
    ));

    // Create version resolution service (with cache for registry versions)
    let registry_client = Arc::new(MultiplexRegistryClient::new());
    let version_resolution_service = Arc::new(VersionResolutionServiceImpl::new_with_cache(
        registry_client,
        cache_service.clone(),
    ));

    // Create application state
    let app_state = AppState {
        analysis_service,
        cache_service,
        report_service,
        vulnerability_repository,
        popular_package_service,
        repository_analysis_service,
        version_resolution_service,
        startup_time: std::time::Instant::now(),
    };

    // Create router
    let app = create_router(app_state, &config);

    // Create server address
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    tracing::info!("Server listening on {}", addr);
    if config.server.enable_docs {
        tracing::info!("API documentation available at http://{}/docs", addr);
    } else {
        tracing::info!("API documentation disabled");
    }

    // Start server with graceful shutdown
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
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
}
