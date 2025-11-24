//! Module selector implementation

use async_trait::async_trait;

use vulnera_core::domain::module::ModuleType;

use crate::domain::entities::Project;
use crate::domain::services::ModuleSelector;
use crate::domain::value_objects::AnalysisDepth;

/// Simple rule-based module selector
pub struct RuleBasedModuleSelector;

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
                // Full analysis: only modules that are registered
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

                // Container security if Dockerfiles are present
                if project.metadata.frameworks.contains(&"docker".to_string()) {
                    modules.push(ModuleType::IaC);
                }
            }
        }

        modules
    }
}
