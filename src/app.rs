//! Application setup and wiring - Single Composition Root
//!
//! This composition root initializes infrastructure, creates the orchestrator
//! services, and wires analysis modules.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use tokio_util::sync::CancellationToken;
use tracing::info;

use vulnera_infrastructure::Config;
use vulnera_infrastructure::database::init_pool;
use vulnera_infrastructure::infrastructure::cache::dragonfly_cache::DragonflyCache;

use vulnera_orchestrator::application::use_cases::{
    AggregateResultsUseCase, CreateAnalysisJobUseCase, ExecuteAnalysisJobUseCase,
};
use vulnera_orchestrator::application::workflow::JobWorkflow;
use vulnera_orchestrator::infrastructure::git::{GitService, GitServiceConfig};
use vulnera_orchestrator::infrastructure::job_queue::{
    JobQueueHandle, JobWorkerContext, spawn_job_worker_pool,
};
use vulnera_orchestrator::infrastructure::job_store::{DragonflyJobStore, JobStore};
use vulnera_orchestrator::infrastructure::module_registry::ModuleRegistry;
use vulnera_orchestrator::infrastructure::module_selector::RuleBasedModuleSelector;
use vulnera_orchestrator::infrastructure::project_detection::FileSystemProjectDetector;
use vulnera_orchestrator::infrastructure::s3::S3Service;
use vulnera_orchestrator::presentation::controllers::{OrchestratorServices, OrchestratorState};
use vulnera_orchestrator::presentation::routes::create_router;

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

    // 1. Initialize database pool
    let db_pool = Arc::new(init_pool(&config.database).await?);
    info!("Database pool initialized");

    // 2. Initialize cache (Dragonfly/Redis)
    let cache_service = Arc::new(
        DragonflyCache::new(
            &config.cache.dragonfly_url,
            config.cache.enable_cache_compression,
            config.cache.compression_threshold_bytes,
        )
        .await?,
    );
    info!("Cache service initialized");

    // 3. Initialize git service
    let git_service = Arc::new(GitService::new(GitServiceConfig::default())?);

    // 4. Initialize S3 service
    let s3_service = Arc::new(S3Service::new());

    // 5. Initialize job store
    let job_store: Arc<dyn JobStore> = Arc::new(DragonflyJobStore::new(
        cache_service.clone(),
        Duration::from_secs(7200),
    ));

    // 6. Initialize job queue
    let job_queue = JobQueueHandle::new(cache_service.clone());

    // 7. Initialize job workflow
    let workflow = Arc::new(JobWorkflow::new(job_store.clone()));

    // 8. Initialize project detector and module selector
    let project_detector: Arc<dyn vulnera_orchestrator::domain::services::ProjectDetector> =
        Arc::new(FileSystemProjectDetector::new(
            git_service.clone(),
            s3_service,
        ));
    let module_selector: Arc<dyn vulnera_orchestrator::domain::services::ModuleSelector> =
        Arc::new(RuleBasedModuleSelector::community());

    // 9. Initialize module registry and register community modules
    let mut module_registry = ModuleRegistry::new();

    // Register SAST module
    module_registry.register(Arc::new(vulnera_sast::module::SastModule::with_config(
        &config.sast,
    )));
    // Register Secret Detection module
    module_registry.register(Arc::new(
        vulnera_secrets::module::SecretDetectionModule::with_config(&config.secret_detection),
    ));
    // Register API Security module
    module_registry.register(Arc::new(
        vulnera_api::module::ApiSecurityModule::with_config(&config.api_security),
    ));

    let available_modules = module_registry.registered_modules();
    info!("Registered {} community modules", available_modules.len());

    let module_registry = Arc::new(module_registry);

    // 10. Initialize use cases
    let create_job_use_case = Arc::new(CreateAnalysisJobUseCase::new(
        project_detector,
        module_selector,
        available_modules,
    ));

    let sandbox_config = vulnera_sandbox::config::SandboxConfig::default();
    let execute_job_use_case = Arc::new(ExecuteAnalysisJobUseCase::new(
        module_registry,
        sandbox_config,
    ));

    let aggregate_results_use_case = Arc::new(AggregateResultsUseCase::new());

    // 11. Build orchestrator services
    let orchestrator_services = Arc::new(OrchestratorServices {
        create_job_use_case,
        execute_job_use_case,
        aggregate_results_use_case,
        git_service: git_service.clone(),
        job_store,
        job_queue: job_queue.clone(),
        workflow,
        db_pool,
        cache_service: cache_service.clone(),
    });

    // 12. Build orchestrator state
    let orchestrator_state = OrchestratorState {
        orchestrator: orchestrator_services.clone(),
        config: config_arc.clone(),
        startup_time,
    };

    // 13. Spawn background job worker pool
    let worker_context = JobWorkerContext {
        execute_job_use_case: orchestrator_services.execute_job_use_case.clone(),
        aggregate_results_use_case: orchestrator_services.aggregate_results_use_case.clone(),
        workflow: orchestrator_services.workflow.clone(),
        job_store: orchestrator_services.job_store.clone(),
        git_service: orchestrator_services.git_service.clone(),
        cache: cache_service,
    };
    spawn_job_worker_pool(worker_context, config.analysis.max_job_workers);

    // 14. Create router with al routes
    let router = create_router(orchestrator_state, config_arc);

    info!(
        duration_ms = startup_time.elapsed().as_millis(),
        "Vulnera CE application initialized successfully"
    );

    Ok(AppHandle {
        router,
        shutdown_token,
    })
}
