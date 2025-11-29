//! Analysis Executor - Hybrid local/remote execution layer
//!
//! This module provides unified execution of analysis modules:
//! - SAST, Secrets, API: Run locally using embedded modules
//! - Dependencies: Run via server API (requires connectivity)

use std::path::Path;

use anyhow::{Context, Result};
use uuid::Uuid;

use vulnera_api::module::ApiSecurityModule;
use vulnera_core::config::Config;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig, ModuleResult, ModuleType};
use vulnera_sast::module::SastModule;
use vulnera_secrets::module::SecretDetectionModule;

use crate::api_client::{DependencyAnalysisResponse, DependencyFileRequest, VulneraClient};

/// Analysis executor for running vulnerability scans
pub struct AnalysisExecutor {
    /// SAST module (embedded, offline)
    sast_module: SastModule,
    /// Secret detection module (embedded, offline)
    secrets_module: SecretDetectionModule,
    /// API security module (embedded, offline)
    api_module: ApiSecurityModule,
    /// API client for server communication (deps analysis)
    api_client: Option<VulneraClient>,
    /// Whether we're in offline mode
    offline_mode: bool,
}

/// Result of local analysis execution
pub struct LocalAnalysisResult {
    pub module_type: ModuleType,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration_ms: u64,
}

/// Unified finding representation for CLI output
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub rule_id: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub description: String,
    pub recommendation: Option<String>,
    pub file: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub module: String,
}

impl AnalysisExecutor {
    /// Create a new analysis executor
    pub fn new(config: &Config, api_client: Option<VulneraClient>, offline_mode: bool) -> Self {
        let sast_module = SastModule::with_config(&config.sast);
        let secrets_module = SecretDetectionModule::with_config(&config.secret_detection);
        let api_module = ApiSecurityModule::with_config(&config.api_security);

        Self {
            sast_module,
            secrets_module,
            api_module,
            api_client,
            offline_mode,
        }
    }

    /// Check if offline mode is enabled
    pub fn is_offline(&self) -> bool {
        self.offline_mode
    }

    /// Check if API client is available
    pub fn has_api_client(&self) -> bool {
        self.api_client.is_some()
    }

    /// Get a reference to the API client (if available)
    pub fn get_api_client(&self) -> Option<&VulneraClient> {
        self.api_client.as_ref()
    }

    /// Run SAST analysis locally
    pub async fn run_sast(&self, source_path: &Path) -> Result<LocalAnalysisResult> {
        let job_id = Uuid::new_v4();
        let config = ModuleConfig {
            job_id,
            project_id: "cli-project".to_string(),
            source_uri: source_path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let result = self
            .sast_module
            .execute(&config)
            .await
            .context("SAST analysis failed")?;

        Ok(self.convert_module_result(result, "sast"))
    }

    /// Run secret detection locally
    pub async fn run_secrets(&self, source_path: &Path) -> Result<LocalAnalysisResult> {
        let job_id = Uuid::new_v4();
        let config = ModuleConfig {
            job_id,
            project_id: "cli-project".to_string(),
            source_uri: source_path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let result = self
            .secrets_module
            .execute(&config)
            .await
            .context("Secret detection failed")?;

        Ok(self.convert_module_result(result, "secrets"))
    }

    /// Run API security analysis locally
    pub async fn run_api(&self, source_path: &Path) -> Result<LocalAnalysisResult> {
        let job_id = Uuid::new_v4();
        let config = ModuleConfig {
            job_id,
            project_id: "cli-project".to_string(),
            source_uri: source_path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let result = self
            .api_module
            .execute(&config)
            .await
            .context("API security analysis failed")?;

        Ok(self.convert_module_result(result, "api"))
    }

    /// Run dependency analysis via server API
    ///
    /// Returns error if offline mode is enabled
    pub async fn run_deps(
        &self,
        files: Vec<DependencyFileRequest>,
    ) -> Result<DependencyAnalysisResponse> {
        if self.offline_mode {
            anyhow::bail!(
                "Dependency analysis requires server connection. Remove --offline flag or run without deps."
            );
        }

        let client = self
            .api_client
            .as_ref()
            .context("API client not configured. Server URL may be invalid.")?;

        client.analyze_dependencies_raw(files).await
    }

    /// Convert module result to unified format
    fn convert_module_result(
        &self,
        result: ModuleResult,
        module_name: &str,
    ) -> LocalAnalysisResult {
        let findings = result
            .findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                rule_id: f.rule_id,
                severity: format!("{:?}", f.severity).to_lowercase(),
                confidence: format!("{:?}", f.confidence).to_lowercase(),
                description: f.description,
                recommendation: f.recommendation,
                file: f.location.path,
                line: f.location.line,
                column: f.location.column,
                module: module_name.to_string(),
            })
            .collect();

        LocalAnalysisResult {
            module_type: result.module_type,
            findings,
            files_scanned: result.metadata.files_scanned,
            duration_ms: result.metadata.duration_ms,
        }
    }
}

impl Finding {
    /// Convert severity string to numeric level for filtering
    pub fn severity_level(&self) -> u8 {
        match self.severity.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            "info" => 0,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_severity_level() {
        let finding = Finding {
            id: "test".to_string(),
            rule_id: None,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            description: "test".to_string(),
            recommendation: None,
            file: "test.rs".to_string(),
            line: Some(1),
            column: None,
            module: "sast".to_string(),
        };

        assert_eq!(finding.severity_level(), 3);
    }

    #[test]
    fn test_finding_severity_level_critical() {
        let finding = Finding {
            id: "test".to_string(),
            rule_id: None,
            severity: "CRITICAL".to_string(),
            confidence: "high".to_string(),
            description: "test".to_string(),
            recommendation: None,
            file: "test.rs".to_string(),
            line: Some(1),
            column: None,
            module: "sast".to_string(),
        };

        assert_eq!(finding.severity_level(), 4);
    }
}
