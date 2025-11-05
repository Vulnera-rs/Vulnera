//! Vulnera Rust - A comprehensive vulnerability analysis API
//!
//! This crate provides a Domain-Driven Design (DDD) architecture for analyzing
//! software dependencies across multiple programming language ecosystems.

use std::{sync::Arc, time::Duration};

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod logging;
pub mod presentation;

pub use config::Config;
pub use logging::init_tracing;

use application::{
    CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
    VersionResolutionServiceImpl,
    auth::use_cases::{
        LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
        ValidateTokenUseCase,
    },
};
use infrastructure::{
    api_clients::{
        circuit_breaker_wrapper::CircuitBreakerApiClient, ghsa::GhsaClient, nvd::NvdClient,
        osv::OsvClient,
    },
    auth::{ApiKeyGenerator, JwtService, PasswordHasher, SqlxApiKeyRepository, SqlxUserRepository},
    cache::file_cache::FileCacheRepository,
    parsers::ParserFactory,
    registries::MultiplexRegistryClient,
    repositories::AggregatingVulnerabilityRepository,
    repository_source::GitHubRepositoryClient,
    resilience::{CircuitBreaker, CircuitBreakerConfig},
};
use presentation::{AppState, create_router};
use sqlx::postgres::PgPoolOptions;

/// Create the application with the given configuration
pub async fn create_app(
    config: Config,
) -> Result<axum::Router, Box<dyn std::error::Error + Send + Sync>> {
    // Initialize database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to database: {}", e),
            ))
        })?;

    tracing::info!("Database connection pool initialized");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await.map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to run migrations: {}", e),
            ))
        },
    )?;

    tracing::info!("Database migrations completed");

    let db_pool = Arc::new(db_pool);

    // Initialize auth services
    let jwt_service = Arc::new(JwtService::new(
        config.auth.jwt_secret.clone(),
        config.auth.token_ttl_hours,
        config.auth.refresh_token_ttl_hours,
    ));

    let password_hasher = Arc::new(PasswordHasher::new());
    let api_key_generator = Arc::new(ApiKeyGenerator::with_length(config.auth.api_key_length));

    // Initialize auth repositories
    let user_repository: Arc<dyn domain::auth::repositories::IUserRepository> =
        Arc::new(SqlxUserRepository::new(db_pool.clone()));
    let api_key_repository: Arc<dyn domain::auth::repositories::IApiKeyRepository> =
        Arc::new(SqlxApiKeyRepository::new(db_pool.clone()));

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
        tracing::info!("GHSA client configured to reuse GitHub token for authentication");
    }

    let ghsa_client_inner = Arc::new(
        GhsaClient::new(ghsa_token, config.apis.ghsa.graphql_url.clone()).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                tracing::error!(error=%e, "Failed to create GHSA client");
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create GHSA client: {}", e),
                ))
            },
        )?,
    );

    // Create retry configs (OSV uses default, NVD and GHSA from config)
    use infrastructure::resilience::RetryConfig;
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
        application::vulnerability::AnalyzeDependenciesUseCase::new(
            parser_factory.clone(),
            vulnerability_repository.clone(),
            cache_service.clone(),
            config.analysis.max_concurrent_packages,
        ),
    );
    let get_vulnerability_details_use_case = Arc::new(
        application::vulnerability::GetVulnerabilityDetailsUseCase::new(
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
    let repository_analysis_service: Option<Arc<dyn application::RepositoryAnalysisService>> =
        if let Some(client) = github_client {
            Some(Arc::new(application::RepositoryAnalysisServiceImpl::new(
                client,
                vulnerability_repository.clone(),
                parser_factory.clone(),
                Arc::new(config.clone()),
            )))
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

    // Create version resolution service
    let registry_client = Arc::new(MultiplexRegistryClient::new());
    let version_resolution_service = Arc::new(VersionResolutionServiceImpl::new_with_cache(
        registry_client,
        cache_service.clone(),
    ));

    // Create vulnerability use cases
    let list_vulnerabilities_use_case = Arc::new(
        application::vulnerability::ListVulnerabilitiesUseCase::new(
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
        // Auth-related state
        db_pool: db_pool.clone(),
        user_repository: user_repository.clone(),
        api_key_repository: api_key_repository.clone(),
        jwt_service: jwt_service.clone(),
        password_hasher: password_hasher.clone(),
        api_key_generator: api_key_generator.clone(),
        login_use_case: login_use_case.clone(),
        register_use_case: register_use_case.clone(),
        validate_token_use_case: validate_token_use_case.clone(),
        refresh_token_use_case: refresh_token_use_case.clone(),
        validate_api_key_use_case: validate_api_key_use_case.clone(),
    };

    // Create router
    Ok(create_router(app_state, &config))
}
