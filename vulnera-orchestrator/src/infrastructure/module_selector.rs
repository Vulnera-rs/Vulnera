//! Module selector implementation
//!
//! Selects analysis modules based on project metadata, analysis depth,
//! and the caller's module tier entitlement (community vs enterprise).

use async_trait::async_trait;

use vulnera_core::domain::module::{ModuleTier, ModuleType};

use crate::domain::entities::Project;
use crate::domain::services::ModuleSelector;
use crate::domain::value_objects::AnalysisDepth;

/// Rule-based module selector with tier-aware filtering
pub struct RuleBasedModuleSelector {
    /// Whether the current caller/context holds an enterprise license
    enterprise_entitled: bool,
}

impl RuleBasedModuleSelector {
    /// Create a selector for community-only access (default for open-source users)
    pub fn community() -> Self {
        Self {
            enterprise_entitled: false,
        }
    }

    /// Create a selector with enterprise entitlement
    pub fn enterprise() -> Self {
        Self {
            enterprise_entitled: true,
        }
    }

    /// Create a selector with explicit entitlement flag
    pub fn with_entitlement(enterprise_entitled: bool) -> Self {
        Self {
            enterprise_entitled,
        }
    }

    /// Returns true if the given module type is accessible under current entitlement
    fn is_entitled(&self, module_type: &ModuleType) -> bool {
        match module_type.tier() {
            ModuleTier::Community => true,
            ModuleTier::Enterprise => self.enterprise_entitled,
        }
    }
}

impl Default for RuleBasedModuleSelector {
    fn default() -> Self {
        Self::community()
    }
}

#[async_trait]
impl ModuleSelector for RuleBasedModuleSelector {
    fn select_modules(&self, project: &Project, analysis_depth: &AnalysisDepth) -> Vec<ModuleType> {
        let mut modules = Vec::new();

        match analysis_depth {
            AnalysisDepth::DependenciesOnly => {
                // Only dependency analysis
                modules.push(ModuleType::DependencyAnalyzer);
            }
            AnalysisDepth::FastScan => {
                // Fast scan: dependencies + basic SAST
                modules.push(ModuleType::DependencyAnalyzer);
                if !project.metadata.languages.is_empty() {
                    modules.push(ModuleType::SAST);
                }
            }
            AnalysisDepth::Full => {
                // Full analysis: all applicable modules
                modules.push(ModuleType::DependencyAnalyzer);

                // SAST if we have source code
                if !project.metadata.languages.is_empty() {
                    modules.push(ModuleType::SAST);
                }

                // Secret detection for all projects
                modules.push(ModuleType::SecretDetection);

                // API security if we have source code or specific frameworks
                if !project.metadata.languages.is_empty()
                    || project.metadata.frameworks.contains(&"django".to_string())
                    || project.metadata.frameworks.contains(&"fastapi".to_string())
                    || project.metadata.frameworks.contains(&"spring".to_string())
                {
                    modules.push(ModuleType::ApiSecurity);
                }

                // --- Enterprise modules (only if entitled) ---
                // License compliance for dependency-heavy projects
                modules.push(ModuleType::LicenseCompliance);

                // SBOM generation
                modules.push(ModuleType::SBOM);

                // IaC security if infrastructure files are present
                if project.metadata.frameworks.contains(&"terraform".to_string())
                    || project.metadata.frameworks.contains(&"docker".to_string())
                    || project.metadata.frameworks.contains(&"kubernetes".to_string())
                {
                    modules.push(ModuleType::IaC);
                }
            }
        }

        // Filter out modules the caller is not entitled to
        modules
            .into_iter()
            .filter(|m| self.is_entitled(m))
            .collect()
    }
}
