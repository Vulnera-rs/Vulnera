//! Application setup and wiring

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;
use vulnera_api::ApiSecurityModule;
use vulnera_core::Config;
use vulnera_deps::DependencyAnalyzerModule;
use vulnera_orchestrator::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use vulnera_orchestrator::infrastructure::{
    DragonflyJobStore, FileSystemProjectDetector, GitService, GitServiceConfig, JobQueueHandle,
    JobWorkerContext, ModuleRegistry, RuleBasedModuleSelector, spawn_job_worker_pool,
};
use vulnera_orchestrator::presentation::controllers::OrchestratorState;
use vulnera_orchestrator::presentation::routes::create_router;
use vulnera_secrets::SecretDetectionModule;

use vulnera_core::application::analytics::AnalyticsAggregationService;
use vulnera_core::application::analytics::use_cases::{
    CheckQuotaUseCase, GetDashboardOverviewUseCase, GetMonthlyAnalyticsUseCase,
};
use vulnera_core::application::auth::use_cases::{
    LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
    ValidateTokenUseCase,
};
use vulnera_core::application::organization::use_cases::{
    CreateOrganizationUseCase, DeleteOrganizationUseCase, GetOrganizationUseCase,
    InviteMemberUseCase, LeaveOrganizationUseCase, ListUserOrganizationsUseCase,
    RemoveMemberUseCase, TransferOwnershipUseCase, UpdateOrganizationNameUseCase,
};
use vulnera_core::application::reporting::ReportServiceImpl;
use vulnera_core::domain::organization::repositories::{
    IAnalysisEventRepository, IOrganizationMemberRepository, IOrganizationRepository,
    IPersistedJobResultRepository, IPersonalStatsMonthlyRepository, ISubscriptionLimitsRepository,
    IUserStatsMonthlyRepository,
};
use vulnera_core::infrastructure::{
    VulneraAdvisorRepository,
    auth::{
        ApiKeyGenerator, JwtService, PasswordHasher, SqlxAnalysisEventRepository,
        SqlxApiKeyRepository, SqlxOrganizationMemberRepository, SqlxOrganizationRepository,
        SqlxPersistedJobResultRepository, SqlxPersonalStatsMonthlyRepository,
        SqlxSubscriptionLimitsRepository, SqlxUserRepository, SqlxUserStatsMonthlyRepository,
    },
    cache::CacheServiceImpl,
    parsers::ParserFactory,
    rate_limiter::RateLimiterService,
    registries::MultiplexRegistryClient,
    repository_source::github_client::GitHubRepositoryClient,
};
use vulnera_deps::{
    AnalyzeDependenciesUseCase,
    services::{
        repository_analysis::{RepositoryAnalysisService, RepositoryAnalysisServiceImpl},
        version_resolution::VersionResolutionServiceImpl,
    },
    types::VersionResolutionService,
};
use vulnera_llm::{
    EnrichFindingsUseCase, ExplainVulnerabilityUseCase, GenerateCodeFixUseCase, HuaweiLlmProvider,
    NaturalLanguageQueryUseCase,
};

/// Handle returned from create_app for graceful shutdown coordination
pub struct AppHandle {
    pub router: Router,
    pub shutdown_token: CancellationToken,
}

/// Spawns a background worker that periodically syncs vulnerability sources.
/// Respects the cancellation token for graceful shutdown.
fn spawn_sync_worker(
    vulnerability_repository: Arc<VulneraAdvisorRepository>,
    config: &Config,
    shutdown_token: CancellationToken,
) {
    let sync_config = config.sync.clone();
    let is_syncing = Arc::new(AtomicBool::new(false));

    // Perform initial sync if configured
    if sync_config.on_startup {
        let vuln_repo = vulnerability_repository.clone();
        let is_syncing_startup = is_syncing.clone();
        let token = shutdown_token.clone();

        tokio::spawn(async move {
            // Skip if already cancelled
            if token.is_cancelled() {
                return;
            }

            is_syncing_startup.store(true, Ordering::SeqCst);
            tracing::info!("Starting initial vulnerability source sync...");

            tokio::select! {
                result = vuln_repo.sync_all() => {
                    match result {
                        Ok(()) => {
                            tracing::info!("Initial vulnerability source sync completed successfully");
                        }
                        Err(e) => {
                            tracing::warn!("Initial vulnerability sync failed (non-fatal): {}", e);
                        }
                    }
                }
                _ = token.cancelled() => {
                    tracing::info!("Initial sync cancelled due to shutdown");
                }
            }

            is_syncing_startup.store(false, Ordering::SeqCst);
        });
    }

    // Spawn periodic sync worker
    if sync_config.enabled && sync_config.interval_hours > 0 {
        let interval = Duration::from_secs(sync_config.interval_hours * 3600);
        let token = shutdown_token.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            // Skip the first immediate tick since we handle startup sync separately
            interval_timer.tick().await;

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Skip if already syncing
                        if is_syncing.swap(true, Ordering::SeqCst) {
                            tracing::debug!("Skipping periodic sync - already in progress");
                            continue;
                        }

                        tracing::info!("Starting periodic vulnerability source sync...");

                        tokio::select! {
                            result = vulnerability_repository.sync_all() => {
                                match result {
                                    Ok(()) => {
                                        tracing::info!("Periodic vulnerability source sync completed successfully");
                                    }
                                    Err(e) => {
                                        tracing::warn!("Periodic vulnerability sync failed (non-fatal): {}", e);
                                    }
                                }
                            }
                            _ = token.cancelled() => {
                                tracing::info!("Periodic sync cancelled due to shutdown");
                                is_syncing.store(false, Ordering::SeqCst);
                                return;
                            }
                        }

                        is_syncing.store(false, Ordering::SeqCst);
                    }
                    _ = token.cancelled() => {
                        tracing::info!("Sync worker shutting down gracefully");
                        return;
                    }
                }
            }
        });
    }
}

/// Spawns a background worker that periodically cleans up old analytics events.
/// Uses the analytics config for retention period and cleanup interval.
fn spawn_analytics_cleanup_worker(
    analytics_service: Arc<AnalyticsAggregationService>,
    config: &Config,
    shutdown_token: CancellationToken,
) {
    let retention_days = config.analytics.event_retention_days;
    let interval_hours = config.analytics.cleanup_interval_hours;

    // Convert retention days to months (approximate, 30 days per month)
    let retention_months = ((retention_days / 30).max(1)) as u32;

    let interval = Duration::from_secs(interval_hours * 3600);
    let token = shutdown_token.clone();

    tokio::spawn(async move {
        let mut interval_timer = tokio::time::interval(interval);
        // Skip the first immediate tick to avoid cleanup right at startup
        interval_timer.tick().await;

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    tracing::info!("Starting analytics event cleanup (retention: {} months)...", retention_months);

                    tokio::select! {
                        result = analytics_service.cleanup_old_events(retention_months) => {
                            match result {
                                Ok(deleted) => {
                                    if deleted > 0 {
                                        tracing::info!("Analytics cleanup completed: {} old events deleted", deleted);
                                    } else {
                                        tracing::debug!("Analytics cleanup completed: no old events to delete");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Analytics cleanup failed (non-fatal): {}", e);
                                }
                            }
                        }
                        _ = token.cancelled() => {
                            tracing::info!("Analytics cleanup cancelled due to shutdown");
                            return;
                        }
                    }
                }
                _ = token.cancelled() => {
                    tracing::info!("Analytics cleanup worker shutting down gracefully");
                    return;
                }
            }
        }
    });
}

/// Create the application router and return an AppHandle for shutdown coordination
pub async fn create_app(
    config: Config,
) -> Result<AppHandle, Box<dyn std::error::Error + Send + Sync>> {
    let startup_time = Instant::now();
    let config_arc = Arc::new(config.clone());
    let shutdown_token = CancellationToken::new();

    // Initialize master API key (development/extension use)
    vulnera_core::infrastructure::auth::initialize_master_key();

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

    // Initialize cache - Dragonfly DB is the default and only cache backend
    tracing::info!(
        "Initializing Dragonfly DB cache at {}",
        config.cache.dragonfly_url
    );
    let dragonfly_cache = Arc::new(
        vulnera_core::infrastructure::cache::DragonflyCache::new(
            &config.cache.dragonfly_url,
            config.cache.enable_cache_compression,
            config.cache.compression_threshold_bytes,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize Dragonfly DB cache: {}", e);
            e
        })?,
    );
    let cache_service = Arc::new(CacheServiceImpl::new_with_dragonfly(
        dragonfly_cache.clone(),
    ));

    let git_service = Arc::new(GitService::new(GitServiceConfig::default())?);

    let job_store: Arc<dyn vulnera_orchestrator::infrastructure::job_store::JobStore> =
        Arc::new(DragonflyJobStore::new(
            dragonfly_cache.clone(),
            std::time::Duration::from_secs(3600), // 1 hour TTL for job replay data
        ));

    // Initialize vulnerability repository using vulnera-advisor
    tracing::info!("Initializing vulnerability intelligence via vulnera-advisor");
    let vulnerability_repository = Arc::new(
        VulneraAdvisorRepository::from_config(&config)
            .await
            .map_err(|e| {
                tracing::error!("Failed to initialize vulnerability repository: {}", e);
                e
            })?,
    );

    // Spawn background sync worker with periodic re-sync and graceful shutdown support
    if config.sync.enabled {
        spawn_sync_worker(
            vulnerability_repository.clone(),
            &config,
            shutdown_token.clone(),
        );
    }

    // Initialize GitHub repository client for repository analysis (reuse GHSA token when configured)
    let github_repo_token = config
        .apis
        .github
        .token
        .clone()
        .or_else(|| {
            if config.apis.github.reuse_ghsa_token {
                config.apis.ghsa.token.clone()
            } else {
                None
            }
        })
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .filter(|token| !token.trim().is_empty());

    let github_repository_client = Arc::new(
        GitHubRepositoryClient::from_token(
            github_repo_token,
            Some(config.apis.github.base_url.clone()),
            config.apis.github.timeout_seconds,
            config.apis.github.reuse_ghsa_token,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize GitHub repository client");
            e
        })?,
    );

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

    // Create repository analysis service
    let repository_analysis_service: Arc<dyn RepositoryAnalysisService> =
        Arc::new(RepositoryAnalysisServiceImpl::new(
            github_repository_client,
            vulnerability_repository.clone(),
            parser_factory.clone(),
            config_arc.clone(),
        ));

    // Create dependency analyzer module
    let deps_module = Arc::new(DependencyAnalyzerModule::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        config.analysis.max_concurrent_packages,
        config.analysis.max_concurrent_registry_queries,
    ));

    // Create SAST module with database rules and AST cache
    let sast_module = {
        use std::time::Duration;
        use vulnera_sast::{
            AnalysisConfig, DragonflyAstCache, PostgresRuleRepository, SastModule,
            ScanProjectUseCase,
        };

        // Create AST cache backed by Dragonfly
        let ast_cache_ttl = Duration::from_secs(config.sast.ast_cache_ttl_hours.unwrap_or(4) * 3600);
        let ast_cache = Arc::new(DragonflyAstCache::with_ttl(
            dragonfly_cache.clone(),
            ast_cache_ttl,
        ));

        // Create PostgreSQL-backed rule repository
        let rule_repository = PostgresRuleRepository::new((*db_pool).clone());

        // Build the use case with database rules and cache
        let analysis_config = AnalysisConfig {
            use_tree_sitter: true,
            use_semgrep: config.sast.enable_semgrep.unwrap_or(true),
            semgrep_path: config.sast.semgrep_path.clone(),
            semgrep_timeout_secs: config.sast.semgrep_timeout_secs.unwrap_or(60),
            enable_ast_cache: config.sast.enable_ast_cache.unwrap_or(true),
            ast_cache_ttl_hours: config.sast.ast_cache_ttl_hours.unwrap_or(4),
            max_concurrent_files: config.sast.max_concurrent_files.unwrap_or(4),
        };

        let use_case = ScanProjectUseCase::with_config(&config.sast, analysis_config);

        // Load database rules if available (non-blocking, fallback to defaults)
        let use_case = match use_case.with_database_rules(&rule_repository).await {
            Ok(uc) => {
                tracing::info!("Loaded SAST rules from database");
                uc
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to load SAST rules from database, using defaults"
                );
                ScanProjectUseCase::with_config(&config.sast, AnalysisConfig::default())
            }
        };

        // Add AST cache if enabled
        let use_case = if config.sast.enable_ast_cache.unwrap_or(true) {
            use_case.with_ast_cache(ast_cache)
        } else {
            use_case
        };

        Arc::new(SastModule::with_use_case(Arc::new(use_case)))
    };

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

    // Create S3 service for bucket analysis
    let s3_service = Arc::new(vulnera_orchestrator::infrastructure::S3Service::new());

    // Create orchestrator use cases
    let project_detector = Arc::new(FileSystemProjectDetector::new(
        git_service.clone(),
        s3_service,
    ));
    let module_selector = Arc::new(RuleBasedModuleSelector);
    let create_job_use_case = Arc::new(CreateAnalysisJobUseCase::new(
        project_detector,
        module_selector,
    ));
    let execute_job_use_case = Arc::new(ExecuteAnalysisJobUseCase::new(Arc::new(module_registry)));
    let aggregate_results_use_case = Arc::new(AggregateResultsUseCase::new());

    // Initialize analytics repositories (needed before job worker)
    let analysis_events_repository: Arc<dyn IAnalysisEventRepository> =
        Arc::new(SqlxAnalysisEventRepository::new(db_pool.clone()));
    let user_stats_repository: Arc<dyn IUserStatsMonthlyRepository> =
        Arc::new(SqlxUserStatsMonthlyRepository::new(db_pool.clone()));
    let personal_stats_repository: Arc<dyn IPersonalStatsMonthlyRepository> =
        Arc::new(SqlxPersonalStatsMonthlyRepository::new(db_pool.clone()));

    // Initialize analytics service
    let analytics_service = Arc::new(AnalyticsAggregationService::new(
        analysis_events_repository.clone(),
        user_stats_repository.clone(),
        personal_stats_repository.clone(),
        config.analytics.enable_user_level_tracking,
    ));

    // Spawn analytics cleanup worker
    spawn_analytics_cleanup_worker(analytics_service.clone(), &config, shutdown_token.clone());

    // Initialize background job queue and worker pool
    let job_queue_handle = JobQueueHandle::new(cache_service.clone());
    let worker_context = JobWorkerContext {
        execute_job_use_case: execute_job_use_case.clone(),
        aggregate_results_use_case: aggregate_results_use_case.clone(),
        job_store: job_store.clone(),
        git_service: git_service.clone(),
        cache_service: cache_service.clone(),
        analytics_recorder: analytics_service.clone(),
    };
    spawn_job_worker_pool(worker_context, config.analysis.max_job_workers);

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

    // Initialize LLM provider and use cases
    let llm_provider = Arc::new(HuaweiLlmProvider::new(config.llm.clone()));
    let generate_code_fix_use_case = Arc::new(GenerateCodeFixUseCase::new(
        llm_provider.clone(),
        config.llm.clone(),
    ));
    let explain_vulnerability_use_case = Arc::new(ExplainVulnerabilityUseCase::new(
        llm_provider.clone(),
        config.llm.clone(),
    ));
    let natural_language_query_use_case = Arc::new(NaturalLanguageQueryUseCase::new(
        llm_provider.clone(),
        config.llm.clone(),
    ));
    let enrich_findings_use_case = Arc::new(EnrichFindingsUseCase::new(
        llm_provider.clone(),
        config.llm.clone(),
    ));

    // Initialize organization repositories
    let organization_repository: Arc<dyn IOrganizationRepository> =
        Arc::new(SqlxOrganizationRepository::new(db_pool.clone()));
    let organization_member_repository: Arc<dyn IOrganizationMemberRepository> =
        Arc::new(SqlxOrganizationMemberRepository::new(db_pool.clone()));
    let subscription_limits_repository: Arc<dyn ISubscriptionLimitsRepository> =
        Arc::new(SqlxSubscriptionLimitsRepository::new(db_pool.clone()));
    let persisted_job_repository: Arc<dyn IPersistedJobResultRepository> =
        Arc::new(SqlxPersistedJobResultRepository::new(db_pool.clone()));

    // Initialize organization use cases
    let create_organization_use_case = Arc::new(CreateOrganizationUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
        subscription_limits_repository.clone(),
    ));
    let get_organization_use_case = Arc::new(GetOrganizationUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let list_user_organizations_use_case = Arc::new(ListUserOrganizationsUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let invite_member_use_case = Arc::new(InviteMemberUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let remove_member_use_case = Arc::new(RemoveMemberUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let leave_organization_use_case = Arc::new(LeaveOrganizationUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let transfer_ownership_use_case = Arc::new(TransferOwnershipUseCase::new(
        organization_repository.clone(),
        organization_member_repository.clone(),
    ));
    let delete_organization_use_case = Arc::new(DeleteOrganizationUseCase::new(
        organization_repository.clone(),
        subscription_limits_repository.clone(),
    ));
    let update_organization_name_use_case = Arc::new(UpdateOrganizationNameUseCase::new(
        organization_repository.clone(),
    ));

    // Initialize analytics use cases
    let get_dashboard_overview_use_case = Arc::new(GetDashboardOverviewUseCase::new(
        organization_repository.clone(),
        user_stats_repository.clone(),
        subscription_limits_repository.clone(),
        persisted_job_repository.clone(),
    ));
    let get_monthly_analytics_use_case = Arc::new(GetMonthlyAnalyticsUseCase::new(
        user_stats_repository.clone(),
    ));
    let check_quota_use_case = Arc::new(CheckQuotaUseCase::new(
        user_stats_repository.clone(),
        subscription_limits_repository.clone(),
    ));

    // Initialize rate limiter service if enabled
    let rate_limiter_service = if config.server.rate_limit.enabled {
        match RateLimiterService::new(config.server.rate_limit.clone()).await {
            Ok(service) => {
                tracing::info!("Rate limiter service initialized");
                Some(Arc::new(service))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize rate limiter service, rate limiting disabled: {}",
                    e
                );
                None
            }
        }
    } else {
        tracing::info!("Rate limiting is disabled");
        None
    };

    // Create orchestrator state
    let orchestrator_state = OrchestratorState {
        create_job_use_case,
        execute_job_use_case,
        aggregate_results_use_case,
        git_service: git_service.clone(),
        job_store,
        job_queue: job_queue_handle.clone(),
        cache_service,
        report_service,
        vulnerability_repository,
        dependency_analysis_use_case,
        repository_analysis_service,
        version_resolution_service,
        generate_code_fix_use_case,
        explain_vulnerability_use_case,
        natural_language_query_use_case,
        enrich_findings_use_case,
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
        // Organization-related
        organization_member_repository,
        create_organization_use_case,
        get_organization_use_case,
        list_user_organizations_use_case,
        invite_member_use_case,
        remove_member_use_case,
        leave_organization_use_case,
        transfer_ownership_use_case,
        delete_organization_use_case,
        update_organization_name_use_case,
        // Analytics-related
        get_dashboard_overview_use_case,
        get_monthly_analytics_use_case,
        check_quota_use_case,
        analytics_service,
        // Rate limiting
        rate_limiter_service,
        // Config and metadata
        config: config_arc.clone(),
        startup_time,
    };

    // Create router using orchestrator's router builder
    let router = create_router(orchestrator_state, config_arc);

    Ok(AppHandle {
        router,
        shutdown_token,
    })
}
