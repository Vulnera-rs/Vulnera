//! Vulnera Rust - Main application entry point

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};

use vulnera_rust::infrastructure::resilience::CircuitBreakerConfig;
use vulnera_rust::{
    Config,
    application::{
        CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
        VersionResolutionServiceImpl,
        auth::use_cases::{
            LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
            ValidateTokenUseCase,
        },
    },
    infrastructure::{
        api_clients::{
            circuit_breaker_wrapper::CircuitBreakerApiClient, ghsa::GhsaClient, nvd::NvdClient,
            osv::OsvClient,
        },
        auth::{
            ApiKeyGenerator, JwtService, PasswordHasher, SqlxApiKeyRepository, SqlxUserRepository,
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
    // Determine GHSA token: reuse GitHub token if enabled, otherwise use GHSA-specific token
    let ghsa_token = if config.apis.github.reuse_ghsa_token {
        // Token sharing optimization: use GitHub token for GHSA when enabled
        config
            .apis
            .github
            .token
            .clone()
            .filter(|t| !t.is_empty())
            .or_else(|| config.apis.ghsa.token.clone().filter(|t| !t.is_empty()))
            .unwrap_or_default()
    } else {
        // Use GHSA-specific token when not sharing
        config
            .apis
            .ghsa
            .token
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_default()
    };

    if ghsa_token.is_empty() {
        tracing::info!(
            "GHSA token not provided; GitHub advisories lookups will be skipped unless provided via environment."
        );
    } else if config.apis.github.reuse_ghsa_token && config.apis.github.token.is_some() {
    }

    let ghsa_client_inner = Arc::new(
        GhsaClient::new(ghsa_token, config.apis.ghsa.graphql_url.clone()).map_err(|e| {
            eprintln!("Failed to create GHSA client: {}", e);
            e
        })?,
    );

    use vulnera_rust::infrastructure::resilience::RetryConfig;
    let osv_retry_config = RetryConfig {
        max_attempts: 3,
        initial_delay: std::time::Duration::from_secs(1), // OSV: 1s initial delay
        max_delay: std::time::Duration::from_secs(30),
        backoff_multiplier: 2.0,
    };
    let nvd_retry_config = config.apis.nvd.retry.to_retry_config();
    let ghsa_retry_config = config.apis.ghsa.retry.to_retry_config();

    // Wrap clients with circuit breakers and retry logic
    let osv_client = Arc::new(CircuitBreakerApiClient::new(
        osv_client_inner,
        osv_circuit_breaker,
        osv_retry_config,
    ));
    let nvd_client = Arc::new(CircuitBreakerApiClient::new(
        nvd_client_inner,
        nvd_circuit_breaker,
        nvd_retry_config,
    ));
    let ghsa_client = Arc::new(CircuitBreakerApiClient::new(
        ghsa_client_inner,
        ghsa_circuit_breaker,
        ghsa_retry_config,
    ));

    let vulnerability_repository = Arc::new(AggregatingVulnerabilityRepository::new(
        osv_client,
        nvd_client,
        ghsa_client,
    ));

    // Create vulnerability analysis use cases
    let analyze_dependencies_use_case = Arc::new(
        vulnera_rust::application::vulnerability::AnalyzeDependenciesUseCase::new(
            parser_factory.clone(),
            vulnerability_repository.clone(),
            cache_service.clone(),
            config.analysis.max_concurrent_packages,
        ),
    );
    let get_vulnerability_details_use_case = Arc::new(
        vulnera_rust::application::vulnerability::GetVulnerabilityDetailsUseCase::new(
            vulnerability_repository.clone(),
            cache_service.clone(),
        ),
    );
    let report_service = Arc::new(ReportServiceImpl::new());
    // Initialize GitHub repository client for repository analysis feature
    let github_client: Option<Arc<GitHubRepositoryClient>> =
        match GitHubRepositoryClient::from_token(
            config.apis.github.token.clone(),
            Some(config.apis.github.base_url.clone()),
            config.apis.github.timeout_seconds,
            config.apis.github.reuse_ghsa_token,
        )
        .await
        {
            Ok(client) => Some(Arc::new(client)),
            Err(e) => {
                tracing::warn!(error=?e, "Failed to initialize GitHubRepositoryClient, repository analysis will be disabled");
                // Gracefully disable repository analysis feature when client initialization fails
                None
            }
        };

    // Create repository analysis service only if GitHub client is available
    let repository_analysis_service: Option<
        Arc<dyn vulnera_rust::application::RepositoryAnalysisService>,
    > = if let Some(client) = github_client {
        Some(Arc::new(
            vulnera_rust::application::RepositoryAnalysisServiceImpl::new(
                client,
                vulnerability_repository.clone(),
                parser_factory.clone(),
                Arc::new(config.clone()),
            ),
        ))
    } else {
        None
    };

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

    // Initialize database pool for authentication
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("\n❌ ERROR: DATABASE_URL environment variable is required");
        std::process::exit(1);
    });

    tracing::info!("Connecting to database for authentication services");

    let db_pool = Arc::new(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .unwrap_or_else(|e| {
                eprintln!("\n❌ ERROR: Failed to connect to database");
                eprintln!("   {}", e);
                eprintln!();
                eprintln!("   Please check:");
                eprintln!("   - DATABASE_URL is correct");
                eprintln!("   - PostgreSQL server is running");
                eprintln!("   - Database exists and is accessible");
                eprintln!("   - Network connectivity to database");
                eprintln!();
                std::process::exit(1);
            }),
    );

    // Initialize auth infrastructure
    let user_repository = Arc::new(SqlxUserRepository::new(db_pool.clone()))
        as Arc<dyn vulnera_rust::domain::auth::repositories::IUserRepository>;
    let api_key_repository = Arc::new(SqlxApiKeyRepository::new(db_pool.clone()))
        as Arc<dyn vulnera_rust::domain::auth::repositories::IApiKeyRepository>;

    let jwt_service = Arc::new(JwtService::new(
        config.auth.jwt_secret.clone(),
        config.auth.token_ttl_hours,
        config.auth.refresh_token_ttl_hours,
    ));

    let password_hasher = Arc::new(PasswordHasher::new());
    let api_key_generator = Arc::new(ApiKeyGenerator::new());

    // Initialize auth use cases
    let login_use_case = Arc::new(LoginUseCase::new(
        user_repository.clone(),
        password_hasher.clone(),
        jwt_service.clone(),
    ));

    let register_use_case = Arc::new(RegisterUserUseCase::new(
        user_repository.clone(),
        password_hasher.clone(),
        jwt_service.clone(),
    ));

    let validate_token_use_case = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));

    let refresh_token_use_case = Arc::new(RefreshTokenUseCase::new(
        jwt_service.clone(),
        user_repository.clone(),
    ));

    let validate_api_key_use_case = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repository.clone(),
        api_key_generator.clone(),
    ));

    // Create vulnerability use cases
    let list_vulnerabilities_use_case = Arc::new(
        vulnera_rust::application::vulnerability::ListVulnerabilitiesUseCase::new(
            popular_package_service.clone(),
        ),
    );

    // Create application state
    let config_arc = Arc::new(config.clone());
    let app_state = AppState {
        analyze_dependencies_use_case,
        get_vulnerability_details_use_case,
        list_vulnerabilities_use_case,
        cache_service,
        report_service,
        vulnerability_repository,
        popular_package_service,
        repository_analysis_service,
        version_resolution_service,
        config: config_arc.clone(),
        startup_time: std::time::Instant::now(),
        db_pool,
        user_repository,
        api_key_repository,
        jwt_service,
        password_hasher,
        api_key_generator,
        login_use_case,
        register_use_case,
        validate_token_use_case,
        refresh_token_use_case,
        validate_api_key_use_case,
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
