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
use vulnera_sast::application::use_cases::AnalysisConfig;
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
            let analysis_config = AnalysisConfig::from(&config.sast);

            let ast_cache: Option<Arc<dyn AstCacheService>> = if analysis_config.enable_ast_cache {
                Some(Arc::new(DragonflyAstCache::with_ttl(
                    cache_service.dragonfly_cache(),
                    Duration::from_secs(analysis_config.ast_cache_ttl_hours * 3600),
                )))
            } else {
                None
            };

            let mut builder = SastModule::builder()
                .sast_config(&config.sast)
                .analysis_config(analysis_config);

            if let Some(cache) = ast_cache {
                builder = builder.ast_cache(cache);
            }

            Arc::new(builder.build())
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
