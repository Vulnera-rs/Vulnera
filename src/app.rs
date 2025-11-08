//! Application setup and wiring

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use vulnera_api::ApiSecurityModule;
use vulnera_core::Config;
use vulnera_deps::DependencyAnalyzerModule;
use vulnera_orchestrator::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use vulnera_orchestrator::infrastructure::{
    FileSystemProjectDetector, ModuleRegistry, RuleBasedModuleSelector,
};
use vulnera_orchestrator::presentation::controllers::OrchestratorState;
use vulnera_orchestrator::presentation::routes::create_router;
use vulnera_sast::SastModule;
use vulnera_secrets::SecretDetectionModule;

use vulnera_core::application::auth::use_cases::{
    LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
    ValidateTokenUseCase,
};
use vulnera_core::application::reporting::ReportServiceImpl;
use vulnera_core::infrastructure::{
    api_clients::{circuit_breaker_wrapper::CircuitBreakerApiClient, osv::OsvClient},
    auth::{ApiKeyGenerator, JwtService, PasswordHasher, SqlxApiKeyRepository, SqlxUserRepository},
    cache::{CacheServiceImpl, FileCacheRepository, MemoryCache, MultiLevelCache},
    parsers::ParserFactory,
    registries::MultiplexRegistryClient,
    repositories::AggregatingVulnerabilityRepository,
    resilience::{CircuitBreaker, CircuitBreakerConfig},
};
use vulnera_deps::{
    AnalyzeDependenciesUseCase, services::version_resolution::VersionResolutionServiceImpl,
    types::VersionResolutionService,
};

/// Create the application router
pub async fn create_app(
    config: Config,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let startup_time = Instant::now();
    let config_arc = Arc::new(config.clone());

    // Initialize database pool
    let db_pool = Arc::new(
        PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .min_connections(config.database.min_idle.unwrap_or(0))
            .acquire_timeout(std::time::Duration::from_secs(
                config.database.connect_timeout_seconds,
            ))
            .max_lifetime(
                config
                    .database
                    .max_lifetime_seconds
                    .map(std::time::Duration::from_secs),
            )
            .idle_timeout(
                config
                    .database
                    .idle_timeout_seconds
                    .map(std::time::Duration::from_secs),
            )
            .test_before_acquire(config.database.enable_health_checks)
            .connect(&config.database.url)
            .await?,
    );

    // Initialize cache
    let l2_cache = Arc::new(FileCacheRepository::new_with_compression(
        config.cache.directory.clone(),
        std::time::Duration::from_secs(config.cache.ttl_hours * 3600),
        config.cache.enable_cache_compression,
        config.cache.compression_threshold_bytes,
    ));

    let l1_cache = Arc::new(MemoryCache::new_with_compression(
        config.cache.l1_cache_size_mb,
        config.cache.l1_cache_ttl_seconds,
        config.cache.enable_cache_compression,
        config.cache.compression_threshold_bytes,
    ));

    let multi_level_cache = Arc::new(MultiLevelCache::new(l1_cache, l2_cache.clone()));
    let cache_service = Arc::new(CacheServiceImpl::new_with_cache(multi_level_cache));

    // Initialize API clients
    let osv_circuit_breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
        failure_threshold: 5,
        recovery_timeout: std::time::Duration::from_secs(60),
        half_open_max_requests: 3,
        request_timeout: std::time::Duration::from_secs(30),
    }));

    let osv_client_inner = Arc::new(OsvClient);
    let osv_retry_config = vulnera_core::infrastructure::resilience::RetryConfig {
        max_attempts: 3,
        initial_delay: std::time::Duration::from_secs(1),
        max_delay: std::time::Duration::from_secs(30),
        backoff_multiplier: 2.0,
    };

    let osv_client = Arc::new(CircuitBreakerApiClient::new(
        osv_client_inner,
        osv_circuit_breaker,
        osv_retry_config,
    ));

    // Create vulnerability repository (simplified - you'd add NVD and GHSA clients too)
    let vulnerability_repository =
        Arc::new(AggregatingVulnerabilityRepository::new_with_concurrency(
            osv_client.clone(),
            osv_client.clone(), // Placeholder
            osv_client.clone(), // Placeholder
            config.analysis.max_concurrent_api_calls,
        ));

    // Initialize parser factory
    let parser_factory = Arc::new(ParserFactory::new());

    // Initialize report service
    let report_service = Arc::new(ReportServiceImpl::new());

    // Initialize registry client and version resolution service
    let registry_client = Arc::new(MultiplexRegistryClient::new());
    let version_resolution_service: Arc<dyn VersionResolutionService> =
        Arc::new(VersionResolutionServiceImpl::new_with_cache(
            registry_client.clone(),
            cache_service.clone(),
        ));

    // Create dependency analysis use case
    let dependency_analysis_use_case = Arc::new(AnalyzeDependenciesUseCase::new_with_config(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        config.analysis.max_concurrent_packages,
        config.analysis.max_concurrent_registry_queries,
    ));

    // Create dependency analyzer module
    let deps_module = Arc::new(DependencyAnalyzerModule::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        config.analysis.max_concurrent_packages,
        config.analysis.max_concurrent_registry_queries,
    ));

    // Create SAST module
    let sast_module = Arc::new(SastModule::with_config(&config.sast));

    // Create secret detection module
    let secrets_module = Arc::new(SecretDetectionModule::with_config(&config.secret_detection));

    // Create API security module
    let api_module = Arc::new(ApiSecurityModule::with_config(&config.api_security));

    // Register modules
    let mut module_registry = ModuleRegistry::new();
    module_registry.register(deps_module);
    module_registry.register(sast_module);
    module_registry.register(secrets_module);
    module_registry.register(api_module);

    // Create orchestrator use cases
    let project_detector = Arc::new(FileSystemProjectDetector);
    let module_selector = Arc::new(RuleBasedModuleSelector);
    let create_job_use_case = Arc::new(CreateAnalysisJobUseCase::new(
        project_detector,
        module_selector,
    ));
    let execute_job_use_case = Arc::new(ExecuteAnalysisJobUseCase::new(Arc::new(module_registry)));
    let aggregate_results_use_case = Arc::new(AggregateResultsUseCase::new());

    // Initialize auth repositories
    let user_repository: Arc<dyn vulnera_core::domain::auth::repositories::IUserRepository> =
        Arc::new(SqlxUserRepository::new(db_pool.clone()));
    let api_key_repository: Arc<dyn vulnera_core::domain::auth::repositories::IApiKeyRepository> =
        Arc::new(SqlxApiKeyRepository::new(db_pool.clone()));

    // Initialize auth services
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

    // Create auth state for extractors
    let auth_state = vulnera_orchestrator::presentation::auth::extractors::AuthState {
        validate_token: validate_token_use_case.clone(),
        validate_api_key: validate_api_key_use_case.clone(),
        user_repository: user_repository.clone(),
        api_key_repository: api_key_repository.clone(),
        api_key_generator: api_key_generator.clone(),
    };

    // Create orchestrator state
    let orchestrator_state = OrchestratorState {
        create_job_use_case,
        execute_job_use_case,
        aggregate_results_use_case,
        cache_service,
        report_service,
        vulnerability_repository,
        dependency_analysis_use_case,
        version_resolution_service,
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
        auth_state,
        config: config_arc.clone(),
        startup_time,
    };

    // Create router using orchestrator's router builder
    let router = create_router(orchestrator_state, config_arc);

    Ok(router)
}
