//! Module selector implementation

use async_trait::async_trait;

use crate::domain::entities::Project;
use crate::domain::services::ModuleSelector;
use crate::domain::value_objects::{AnalysisDepth, ModuleType};

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
                // Full analysis: all applicable modules
                modules.push(ModuleType::DependencyAnalyzer);

                // SAST if we have source code
                if !project.metadata.languages.is_empty() {
                    modules.push(ModuleType::SAST);
                }

                // Secret detection for all projects
                modules.push(ModuleType::SecretDetection);

                // License compliance if we have dependencies
                if !project.metadata.dependency_files.is_empty() {
                    modules.push(ModuleType::LicenseCompliance);
                }

                // SBOM generation
                modules.push(ModuleType::SBOM);
            }
        }

        modules
    }
}
