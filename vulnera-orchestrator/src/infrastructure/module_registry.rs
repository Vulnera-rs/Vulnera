//! Module registry for managing analysis modules
//!
//! The registry is tier-aware: each module carries its [`ModuleTier`] derived from
//! [`ModuleType::tier()`]. Callers can query the registry for community-only modules
//! or filter by enterprise entitlement.

use std::collections::HashMap;
use std::sync::Arc;

use vulnera_core::domain::module::{AnalysisModule, ModuleTier, ModuleType};

/// Registry for analysis modules with tier-aware access control
pub struct ModuleRegistry {
    modules: HashMap<ModuleType, Arc<dyn AnalysisModule>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Register a module. The tier is derived from `module.module_type().tier()`.
    pub fn register(&mut self, module: Arc<dyn AnalysisModule>) {
        self.modules.insert(module.module_type(), module);
    }

    /// Get a module by type (no tier check — callers must validate entitlement first).
    pub fn get_module(&self, module_type: &ModuleType) -> Option<Arc<dyn AnalysisModule>> {
        self.modules.get(module_type).cloned()
    }

    /// Get a module only if it belongs to the given tier (or is community).
    ///
    /// Enterprise-entitled callers should pass `enterprise_entitled = true`.
    pub fn get_module_entitled(
        &self,
        module_type: &ModuleType,
        enterprise_entitled: bool,
    ) -> Option<Arc<dyn AnalysisModule>> {
        let module = self.modules.get(module_type)?;
        let tier = module_type.tier();
        match tier {
            ModuleTier::Community => Some(module.clone()),
            ModuleTier::Enterprise if enterprise_entitled => Some(module.clone()),
            ModuleTier::Enterprise => None,
        }
    }

    /// Get all registered module types
    pub fn registered_modules(&self) -> Vec<ModuleType> {
        self.modules.keys().cloned().collect()
    }

    /// Get only community-tier module types
    pub fn community_modules(&self) -> Vec<ModuleType> {
        self.modules
            .keys()
            .filter(|mt| mt.is_community())
            .cloned()
            .collect()
    }

    /// Get only enterprise-tier module types
    pub fn enterprise_modules(&self) -> Vec<ModuleType> {
        self.modules
            .keys()
            .filter(|mt| mt.is_enterprise())
            .cloned()
            .collect()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use vulnera_core::domain::module::ModuleResultMetadata;
    use vulnera_core::domain::module::{ModuleConfig, ModuleExecutionError, ModuleResult};

    /// Minimal stub for testing registry behavior
    struct StubModule(ModuleType);

    #[async_trait]
    impl AnalysisModule for StubModule {
        fn module_type(&self) -> ModuleType {
            self.0.clone()
        }
        async fn execute(
            &self,
            _config: &ModuleConfig,
        ) -> Result<ModuleResult, ModuleExecutionError> {
            Ok(ModuleResult {
                job_id: uuid::Uuid::nil(),
                module_type: self.0.clone(),
                findings: vec![],
                metadata: ModuleResultMetadata::default(),
                error: None,
            })
        }
    }

    #[test]
    fn community_module_accessible_without_entitlement() {
        let mut registry = ModuleRegistry::new();
        registry.register(Arc::new(StubModule(ModuleType::SAST)));

        assert!(
            registry
                .get_module_entitled(&ModuleType::SAST, false)
                .is_some()
        );
    }

    #[test]
    fn enterprise_module_blocked_without_entitlement() {
        let mut registry = ModuleRegistry::new();
        registry.register(Arc::new(StubModule(ModuleType::DAST)));

        assert!(
            registry
                .get_module_entitled(&ModuleType::DAST, false)
                .is_none()
        );
    }

    #[test]
    fn enterprise_module_accessible_with_entitlement() {
        let mut registry = ModuleRegistry::new();
        registry.register(Arc::new(StubModule(ModuleType::DAST)));

        assert!(
            registry
                .get_module_entitled(&ModuleType::DAST, true)
                .is_some()
        );
    }

    #[test]
    fn community_and_enterprise_filtering() {
        let mut registry = ModuleRegistry::new();
        registry.register(Arc::new(StubModule(ModuleType::SAST)));
        registry.register(Arc::new(StubModule(ModuleType::SecretDetection)));
        registry.register(Arc::new(StubModule(ModuleType::DAST)));
        registry.register(Arc::new(StubModule(ModuleType::IaC)));

        let community = registry.community_modules();
        let enterprise = registry.enterprise_modules();

        assert_eq!(community.len(), 2);
        assert_eq!(enterprise.len(), 2);
        assert!(community.iter().all(|m| m.is_community()));
        assert!(enterprise.iter().all(|m| m.is_enterprise()));
    }
}
