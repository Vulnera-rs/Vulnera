//! Application setup and wiring - Single Composition Root

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use tokio_util::sync::CancellationToken;
use tracing::info;

use vulnera_core::Config;
use vulnera_orchestrator::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use vulnera_orchestrator::infrastructure::{
    DragonflyJobStore, FileSystemProjectDetector, JobQueueHandle, JobWorkerContext,
    RuleBasedModuleSelector, spawn_job_worker_pool,
};
use vulnera_orchestrator::presentation::controllers::OrchestratorState;
use vulnera_orchestrator::presentation::routes::create_router;

use vulnera_core::application::analytics::AnalyticsAggregationService;
use vulnera_core::application::analytics::use_cases::{
    CheckQuotaUseCase, GetDashboardOverviewUseCase, GetMonthlyAnalyticsUseCase,
};
use vulnera_core::application::organization::use_cases::{
    CreateOrganizationUseCase, DeleteOrganizationUseCase, GetOrganizationUseCase,
    InviteMemberUseCase, LeaveOrganizationUseCase, ListUserOrganizationsUseCase,
    RemoveMemberUseCase, TransferOwnershipUseCase, UpdateOrganizationNameUseCase,
};
use vulnera_core::application::reporting::ReportServiceImpl;
use vulnera_core::domain::organization::repositories::{
    IAnalysisEventRepository, IOrganizationRepository, IPersistedJobResultRepository,
    IPersonalStatsMonthlyRepository, ISubscriptionLimitsRepository, IUserStatsMonthlyRepository,
};
use vulnera_core::infrastructure::{
    VulneraAdvisorRepository,
    auth::{
        JwtService, PasswordHasher, SqlxAnalysisEventRepository, SqlxOrganizationRepository,
        SqlxPersistedJobResultRepository, SqlxPersonalStatsMonthlyRepository,
        SqlxSubscriptionLimitsRepository, SqlxUserStatsMonthlyRepository,
    },
    cache::CacheServiceImpl,
    parsers::ParserFactory,
    rate_limiter::RateLimiterService,
    registries::MultiplexRegistryClient,
    repository_source::github_client::GitHubRepositoryClient,
};
use vulnera_deps::AnalyzeDependenciesUseCase;
use vulnera_deps::services::{
    repository_analysis::{RepositoryAnalysisService, RepositoryAnalysisServiceImpl},
    version_resolution::VersionResolutionServiceImpl,
};
use vulnera_deps::types::VersionResolutionService;
use vulnera_llm::{
    EnrichFindingsUseCase, ExplainVulnerabilityUseCase, GeminiLlmProvider, GenerateCodeFixUseCase,
    NaturalLanguageQueryUseCase,
};

use crate::auth::AuthServices;
use crate::infra::Infrastructure;
use crate::modules::AnalysisModules;
use crate::workers::{spawn_analytics_cleanup_worker, spawn_sync_worker};

/// Handle returned from create_app for graceful shutdown coordination
pub struct AppHandle {
    pub router: Router,
    pub shutdown_token: CancellationToken,
}

/// Main application factory - The Single Composition Root
pub async fn create_app(
    config: Config,
) -> Result<AppHandle, Box<dyn std::error::Error + Send + Sync>> {
    let startup_time = Instant::now();
    let config_arc = Arc::new(config.clone());
    let shutdown_token = CancellationToken::new();

    // 1. Initialize Infrastructure (DB, Cache, Git, S3)
    let infra = Infrastructure::init(&config).await?;
    let cache_service = Arc::new(CacheServiceImpl::new_with_dragonfly(
        infra.dragonfly_cache.clone(),
    ));

    // 2. Initialize Vulnerability Intelligence
    info!("Initializing vulnerability intelligence via vulnera-advisor");
    let vulnerability_repository = Arc::new(VulneraAdvisorRepository::from_config(&config).await?);

    // 3. Initialize Auth Services & Repositories
    let auth = AuthServices::init(&config, infra.db_pool.clone(), cache_service.clone());

    // 4. Initialize Analysis Modules
    let parser_factory = Arc::new(ParserFactory::new());
    let modules = AnalysisModules::init(
        &config,
        infra.db_pool.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        parser_factory.clone(),
    )
    .await?;

    // 5. Initialize Orchestrator Components
    let job_store = Arc::new(DragonflyJobStore::new(
        infra.dragonfly_cache.clone(),
        std::time::Duration::from_secs(3600),
    ));

    let project_detector = Arc::new(FileSystemProjectDetector::new(
        infra.git_service.clone(),
        infra.s3_service.clone(),
    ));
    let module_selector = Arc::new(RuleBasedModuleSelector);

    let create_job_use_case = Arc::new(CreateAnalysisJobUseCase::new(
        project_detector,
        module_selector,
    ));
    let execute_job_use_case = Arc::new(ExecuteAnalysisJobUseCase::new(modules.registry.clone()));
    let aggregate_results_use_case = Arc::new(AggregateResultsUseCase::new());

    // 6. Initialize Analytics & Reporting
    let analysis_events_repository: Arc<dyn IAnalysisEventRepository> =
        Arc::new(SqlxAnalysisEventRepository::new(infra.db_pool.clone()));
    let user_stats_repository: Arc<dyn IUserStatsMonthlyRepository> =
        Arc::new(SqlxUserStatsMonthlyRepository::new(infra.db_pool.clone()));
    let personal_stats_repository: Arc<dyn IPersonalStatsMonthlyRepository> = Arc::new(
        SqlxPersonalStatsMonthlyRepository::new(infra.db_pool.clone()),
    );

    let analytics_service = Arc::new(AnalyticsAggregationService::new(
        analysis_events_repository.clone(),
        user_stats_repository.clone(),
        personal_stats_repository.clone(),
        config.analytics.enable_user_level_tracking,
    ));

    // 7. Initialize LLM Services
    let llm_provider = Arc::new(GeminiLlmProvider::new(config.llm.clone()));
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

    // 8. Initialize Organization Use Cases
    let organization_repository: Arc<dyn IOrganizationRepository> =
        Arc::new(SqlxOrganizationRepository::new(infra.db_pool.clone()));
    let subscription_limits_repository: Arc<dyn ISubscriptionLimitsRepository> =
        Arc::new(SqlxSubscriptionLimitsRepository::new(infra.db_pool.clone()));
    let persisted_job_repository: Arc<dyn IPersistedJobResultRepository> =
        Arc::new(SqlxPersistedJobResultRepository::new(infra.db_pool.clone()));

    let create_organization_use_case = Arc::new(CreateOrganizationUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
        subscription_limits_repository.clone(),
    ));
    let get_organization_use_case = Arc::new(GetOrganizationUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));
    let update_organization_use_case = Arc::new(UpdateOrganizationNameUseCase::new(
        organization_repository.clone(),
    ));
    let delete_organization_use_case = Arc::new(DeleteOrganizationUseCase::new(
        organization_repository.clone(),
        subscription_limits_repository.clone(),
    ));
    let list_organizations_use_case = Arc::new(ListUserOrganizationsUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));
    let invite_member_use_case = Arc::new(InviteMemberUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));
    let remove_member_use_case = Arc::new(RemoveMemberUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));
    let leave_organization_use_case = Arc::new(LeaveOrganizationUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));
    let transfer_ownership_use_case = Arc::new(TransferOwnershipUseCase::new(
        organization_repository.clone(),
        auth.auth_state
            .organization_member_repository
            .clone()
            .unwrap(),
    ));

    // 9. Initialize Analytics Use Cases
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

    // 10. Initialize Dependency Analysis Services
    let octocrab_builder = octocrab::OctocrabBuilder::new();
    let octocrab_builder = if let Some(ref token) = config.apis.github.token {
        octocrab_builder.personal_token(token.clone())
    } else {
        octocrab_builder
    };
    let octocrab = octocrab_builder
        .base_uri(&config.apis.github.base_url)
        .unwrap_or_else(|_| octocrab::OctocrabBuilder::new())
        .build()
        .unwrap_or_else(|_| octocrab::Octocrab::default());
    let github_client = Arc::new(GitHubRepositoryClient::new(
        octocrab,
        config.apis.github.base_url.clone(),
        config.apis.github.token.is_some(),
        config.apis.github.timeout_seconds,
    ));
    let registry_client = Arc::new(MultiplexRegistryClient::new());
    let version_resolution_service: Arc<dyn VersionResolutionService> =
        Arc::new(VersionResolutionServiceImpl::new(registry_client));
    let repository_analysis_service: Arc<dyn RepositoryAnalysisService> =
        Arc::new(RepositoryAnalysisServiceImpl::new(
            github_client,
            vulnerability_repository.clone(),
            parser_factory.clone(),
            config_arc.clone(),
        ));

    // 10.5 Initialize Dependency Analysis Use Case
    let dependency_analysis_use_case = Arc::new(AnalyzeDependenciesUseCase::new(
        parser_factory.clone(),
        vulnerability_repository.clone(),
        cache_service.clone(),
        config.analysis.max_concurrent_packages,
    ));

    // 11. Initialize Rate Limiter
    let rate_limiter_service = if config.server.rate_limit.enabled {
        match RateLimiterService::new_with_url(
            config.server.rate_limit.clone(),
            &config.cache.dragonfly_url,
        )
        .await
        {
            Ok(service) => Some(Arc::new(service)),
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize rate limiter: {}, rate limiting disabled",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // 12. Initialize Report Service
    let report_service = Arc::new(ReportServiceImpl::new());

    // 13. Build Orchestrator State
    let job_queue_handle = JobQueueHandle::new(cache_service.clone());
    let orchestrator_state = OrchestratorState {
        // Orchestrator use cases
        create_job_use_case,
        execute_job_use_case,
        aggregate_results_use_case,
        git_service: infra.git_service.clone(),
        job_store: job_store.clone(),
        job_queue: job_queue_handle.clone(),

        // Services
        cache_service: cache_service.clone(),
        report_service,
        vulnerability_repository: vulnerability_repository.clone(),

        // Dependency analysis
        dependency_analysis_use_case,
        repository_analysis_service,
        version_resolution_service,

        // LLM use cases
        generate_code_fix_use_case,
        explain_vulnerability_use_case,
        natural_language_query_use_case,
        enrich_findings_use_case,

        // Auth-related state
        db_pool: infra.db_pool.clone(),
        user_repository: auth.auth_state.user_repository.clone(),
        api_key_repository: auth.auth_state.api_key_repository.clone(),
        jwt_service: Arc::new(JwtService::new(
            config.auth.jwt_secret.clone(),
            config.auth.token_ttl_hours,
            config.auth.refresh_token_ttl_hours,
        )),
        password_hasher: Arc::new(PasswordHasher::new()),
        api_key_generator: auth.auth_state.api_key_generator.clone(),
        login_use_case: auth.login_use_case.clone(),
        register_use_case: auth.register_use_case.clone(),
        validate_token_use_case: auth.validate_token_use_case.clone(),
        refresh_token_use_case: auth.refresh_token_use_case.clone(),
        validate_api_key_use_case: auth.validate_api_key_use_case.clone(),
        token_blacklist: auth.token_blacklist.clone(),
        auth_state: auth.auth_state.clone(),

        // Organization repositories
        organization_member_repository: auth
            .auth_state
            .organization_member_repository
            .clone()
            .unwrap(),

        // Organization use cases
        create_organization_use_case,
        get_organization_use_case,
        list_user_organizations_use_case: list_organizations_use_case,
        invite_member_use_case,
        remove_member_use_case,
        leave_organization_use_case,
        transfer_ownership_use_case,
        delete_organization_use_case,
        update_organization_name_use_case: update_organization_use_case,

        // Analytics use cases
        get_dashboard_overview_use_case,
        get_monthly_analytics_use_case,
        check_quota_use_case,

        // Analytics service
        analytics_service: analytics_service.clone(),

        // Rate limiting
        rate_limiter_service,

        // Config and metadata
        config: config_arc.clone(),
        startup_time: startup_time.clone(),
    };

    // 14. Spawn Background Workers
    if config.sync.enabled {
        spawn_sync_worker(
            vulnerability_repository.clone(),
            &config,
            shutdown_token.clone(),
        );
    }

    spawn_analytics_cleanup_worker(analytics_service.clone(), &config, shutdown_token.clone());

    let worker_context = JobWorkerContext {
        execute_job_use_case: orchestrator_state.execute_job_use_case.clone(),
        aggregate_results_use_case: orchestrator_state.aggregate_results_use_case.clone(),
        job_store: job_store.clone(),
        git_service: infra.git_service.clone(),
        cache_service: cache_service.clone(),
        analytics_recorder: analytics_service.clone(),
    };
    spawn_job_worker_pool(worker_context, config.analysis.max_job_workers);

    // 15. Create Router
    let router = create_router(orchestrator_state, config_arc);

    info!(
        duration_ms = startup_time.elapsed().as_millis(),
        "Vulnera application initialized successfully"
    );

    Ok(AppHandle {
        router,
        shutdown_token,
    })
}
