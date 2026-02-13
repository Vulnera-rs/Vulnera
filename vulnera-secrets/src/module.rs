//! Secret detection module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_core::config::SecretDetectionConfig;
use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
    SecretFindingMetadata, SecretVerificationState, VulnerabilityFindingMetadata,
};

use crate::application::use_cases::ScanForSecretsUseCase;
use crate::domain::entities::Severity as SecretSeverity;

/// Secret detection analysis module
pub struct SecretDetectionModule {
    use_case: Arc<ScanForSecretsUseCase>,
}

impl SecretDetectionModule {
    pub fn new() -> Self {
        Self::with_config(&SecretDetectionConfig::default())
    }

    pub fn with_config(config: &SecretDetectionConfig) -> Self {
        Self {
            use_case: Arc::new(ScanForSecretsUseCase::with_config(config)),
        }
    }
}

#[async_trait]
impl AnalysisModule for SecretDetectionModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::SecretDetection
    }

    async fn execute(&self, config: &ModuleConfig) -> Result<ModuleResult, ModuleExecutionError> {
        let start_time = std::time::Instant::now();

        // Get source path from config
        let source_path = Path::new(&config.source_uri);
        if !source_path.exists() {
            return Err(ModuleExecutionError::InvalidConfig(format!(
                "Source path does not exist: {}",
                config.source_uri
            )));
        }

        // Execute scan
        let scan_result = self
            .use_case
            .execute(source_path)
            .await
            .map_err(|e| ModuleExecutionError::ExecutionFailed(e.to_string()))?;

        // Convert secret findings to orchestrator findings
        let findings: Vec<Finding> = scan_result
            .findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                r#type: FindingType::Secret,
                rule_id: Some(f.rule_id),
                location: Location {
                    path: f.location.file_path,
                    line: Some(f.location.line),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    end_column: f.location.end_column,
                },
                severity: match f.severity {
                    SecretSeverity::Critical => FindingSeverity::Critical,
                    SecretSeverity::High => FindingSeverity::High,
                    SecretSeverity::Medium => FindingSeverity::Medium,
                    SecretSeverity::Low => FindingSeverity::Low,
                    SecretSeverity::Info => FindingSeverity::Info,
                },
                confidence: match f.confidence {
                    crate::domain::value_objects::Confidence::High => FindingConfidence::High,
                    crate::domain::value_objects::Confidence::Medium => FindingConfidence::Medium,
                    crate::domain::value_objects::Confidence::Low => FindingConfidence::Low,
                },
                description: f.description,
                recommendation: f.recommendation,
                secret_metadata: Some(SecretFindingMetadata {
                    detector_id: f.detector_id,
                    verification_state: match f.verification_state {
                        crate::domain::entities::SecretVerificationState::Verified => {
                            SecretVerificationState::Verified
                        }
                        crate::domain::entities::SecretVerificationState::Invalid => {
                            SecretVerificationState::Invalid
                        }
                        crate::domain::entities::SecretVerificationState::Unknown => {
                            SecretVerificationState::Unknown
                        }
                        crate::domain::entities::SecretVerificationState::Unverified => {
                            SecretVerificationState::Unverified
                        }
                        crate::domain::entities::SecretVerificationState::NotSupported => {
                            SecretVerificationState::NotSupported
                        }
                    },
                    redacted_secret: redact_secret(&f.matched_secret),
                    entropy: f.entropy,
                    evidence: f.evidence,
                }),
                vulnerability_metadata: VulnerabilityFindingMetadata::default(),
                enrichment: None,
            })
            .collect();

        let mut additional_info = std::collections::HashMap::new();
        additional_info.insert(
            "baseline_suppressed".to_string(),
            scan_result.baseline_suppressed.to_string(),
        );
        additional_info.insert(
            "allowlist_suppressed".to_string(),
            scan_result.allowlist_suppressed.to_string(),
        );
        for (reason, count) in scan_result.suppression_breakdown {
            additional_info.insert(format!("suppressed:{}", reason), count.to_string());
        }

        let duration = start_time.elapsed();

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: ModuleType::SecretDetection,
            findings,
            metadata: ModuleResultMetadata {
                files_scanned: scan_result.files_scanned,
                duration_ms: duration.as_millis() as u64,
                additional_info,
            },
            error: None,
        })
    }
}

impl Default for SecretDetectionModule {
    fn default() -> Self {
        Self::new()
    }
}

fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
}
