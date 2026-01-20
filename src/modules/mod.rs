//! Analysis module initialization for the Vulnera application
//!
//! This module handles the instantiation and registration of all analysis
//! modules (SAST, Dependency Analysis, Secrets, API Security).

use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use vulnera_api::ApiSecurityModule;
use vulnera_core::Config;
use vulnera_core::domain::vulnerability::repositories::IVulnerabilityRepository;
use vulnera_core::infrastructure::cache::CacheServiceImpl;
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_deps::DependencyAnalyzerModule;
use vulnera_orchestrator::infrastructure::ModuleRegistry;
use vulnera_sast::application::use_cases::{AnalysisConfig, ScanProjectUseCase};
use vulnera_sast::infrastructure::rules::PostgresRuleRepository;
use vulnera_sast::{AstCacheService, DragonflyAstCache, SastModule};
use vulnera_secrets::SecretDetectionModule;

/// Collection of initialized analysis modules
pub struct AnalysisModules {
    pub registry: Arc<ModuleRegistry>,
}

impl AnalysisModules {
    /// Initialize all analysis modules from configuration
    pub async fn init(
        config: &Config,
        db_pool: Arc<sqlx::PgPool>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<CacheServiceImpl>,
        parser_factory: Arc<ParserFactory>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing analysis modules");

        // 1. Initialize Dependency Analyzer Module
        let deps_module = Arc::new(DependencyAnalyzerModule::new(
            parser_factory.clone(),
            vulnerability_repository.clone(),
            cache_service.clone(),
            config.analysis.max_concurrent_packages,
            config.analysis.max_concurrent_registry_queries,
        ));

        // 2. Initialize SAST Module
        let sast_module = {
            let rule_repository = PostgresRuleRepository::new((*db_pool).clone());
            let analysis_config = AnalysisConfig {
                enable_data_flow: config.sast.enable_data_flow,
                enable_call_graph: config.sast.enable_call_graph,
                enable_ast_cache: config.sast.enable_ast_cache.unwrap_or(true),
                ast_cache_ttl_hours: config.sast.ast_cache_ttl_hours.unwrap_or(4),
                max_concurrent_files: config.sast.max_concurrent_files.unwrap_or(4),
                analysis_depth: config.sast.analysis_depth,
                dynamic_depth_enabled: config.sast.dynamic_depth_enabled.unwrap_or(false),
                dynamic_depth_file_count_threshold: config.sast.dynamic_depth_file_count_threshold,
                dynamic_depth_total_bytes_threshold: config
                    .sast
                    .dynamic_depth_total_bytes_threshold,
                tree_cache_max_entries: config.sast.tree_cache_max_entries.unwrap_or(1024),
                max_file_size_bytes: config.sast.max_file_size_bytes.unwrap_or(1_048_576),
                per_file_timeout_seconds: config.sast.per_file_timeout_seconds.unwrap_or(30),
                scan_timeout_seconds: config.sast.scan_timeout_seconds,
                max_findings_per_file: config.sast.max_findings_per_file.unwrap_or(100),
                max_total_findings: config.sast.max_total_findings,
            };

            let ast_cache: Option<Arc<dyn AstCacheService>> = if analysis_config.enable_ast_cache {
                Some(Arc::new(DragonflyAstCache::with_ttl(
                    cache_service.dragonfly_cache(),
                    Duration::from_secs(analysis_config.ast_cache_ttl_hours * 3600),
                )))
            } else {
                None
            };

            let use_case = ScanProjectUseCase::with_config(&config.sast, analysis_config);
            let use_case = if let Some(cache) = ast_cache {
                use_case.with_ast_cache(cache)
            } else {
                use_case
            };

            // Load database rules if available
            let use_case = match use_case.with_database_rules(&rule_repository).await {
                Ok(uc) => uc,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load SAST rules from database, using defaults");
                    ScanProjectUseCase::with_config(&config.sast, AnalysisConfig::default())
                }
            };

            Arc::new(SastModule::with_use_case(Arc::new(use_case)))
        };

        // 3. Initialize Secret Detection Module
        let secrets_module = Arc::new(SecretDetectionModule::with_config(&config.secret_detection));

        // 4. Initialize API Security Module
        let api_module = Arc::new(ApiSecurityModule::with_config(&config.api_security));

        // Register all modules in the registry
        let mut registry = ModuleRegistry::new();
        registry.register(deps_module);
        registry.register(sast_module);
        registry.register(secrets_module);
        registry.register(api_module);

        Ok(Self {
            registry: Arc::new(registry),
        })
    }
}
