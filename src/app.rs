//! Application setup and wiring

use std::sync::Arc;

use axum::Router;
use vulnera_core::Config;
use vulnera_deps::DependencyAnalyzerModule;
use vulnera_orchestrator::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use vulnera_orchestrator::domain::module::AnalysisModule;
use vulnera_orchestrator::infrastructure::{
    FileSystemProjectDetector, ModuleRegistry, RuleBasedModuleSelector,
};
use vulnera_orchestrator::presentation::controllers::{OrchestratorState, analyze};
use vulnera_sast::SastModule;

use vulnera_core::infrastructure::{
    api_clients::{
        circuit_breaker_wrapper::CircuitBreakerApiClient, ghsa::GhsaClient, nvd::NvdClient,
        osv::OsvClient,
    },
    cache::{CacheServiceImpl, FileCacheRepository, MemoryCache, MultiLevelCache},
    parsers::ParserFactory,
    registries::MultiplexRegistryClient,
    repositories::AggregatingVulnerabilityRepository,
    resilience::{CircuitBreaker, CircuitBreakerConfig},
};

/// Create the application router
pub async fn create_app(
    config: Config,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
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

    // Create dependency analyzer module
    let deps_module = Arc::new(DependencyAnalyzerModule::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        config.analysis.max_concurrent_packages,
        config.analysis.max_concurrent_registry_queries,
    ));

    // Create SAST module
    let sast_module = Arc::new(SastModule::new());

    // Register modules
    let mut module_registry = ModuleRegistry::new();
    module_registry.register(deps_module);
    module_registry.register(sast_module);

    // Create orchestrator use cases
    let project_detector = Arc::new(FileSystemProjectDetector);
    let module_selector = Arc::new(RuleBasedModuleSelector);
    let create_job_use_case = Arc::new(CreateAnalysisJobUseCase::new(
        project_detector,
        module_selector,
    ));
    let execute_job_use_case = Arc::new(ExecuteAnalysisJobUseCase::new(Arc::new(module_registry)));
    let aggregate_results_use_case = Arc::new(AggregateResultsUseCase::new());

    // Create orchestrator state
    let orchestrator_state = OrchestratorState {
        create_job_use_case,
        execute_job_use_case,
        aggregate_results_use_case,
    };

    // Create router
    let router = Router::new()
        .route("/api/v1/analyze", axum::routing::post(analyze))
        .with_state(orchestrator_state);

    Ok(router)
}
