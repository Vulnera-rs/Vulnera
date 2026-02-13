//! SAST module implementation

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{
    AnalysisModule, Finding, FindingConfidence, FindingSeverity, FindingType, Location,
    ModuleConfig, ModuleExecutionError, ModuleResult, ModuleResultMetadata, ModuleType,
    VulnerabilityDataFlowNode, VulnerabilityDataFlowPath, VulnerabilityFindingMetadata,
};

use crate::application::use_cases::{AnalysisConfig, ScanProjectUseCase};
use crate::domain::finding::Severity as SastSeverity;
use crate::infrastructure::ast_cache::AstCacheService;

/// SAST analysis module.
///
/// Construct via the builder:
/// ```rust
/// use vulnera_sast::SastModule;
/// let module = SastModule::builder().build();
/// ```
pub struct SastModule {
    use_case: Arc<ScanProjectUseCase>,
    sast_config: SastConfig,
}

/// Builder for [`SastModule`].
///
/// All fields are optional — omitting everything yields a sensible default
/// configuration (zero-config UX).
pub struct SastModuleBuilder {
    sast_config: Option<SastConfig>,
    analysis_config: Option<AnalysisConfig>,
    ast_cache: Option<Arc<dyn AstCacheService>>,
    use_case_override: Option<Arc<ScanProjectUseCase>>,
}

impl SastModuleBuilder {
    /// Override the SAST config (scanning depth, excludes, rule file, etc.).
    pub fn sast_config(mut self, config: &SastConfig) -> Self {
        self.sast_config = Some(config.clone());
        self
    }

    /// Override the analysis config (concurrency, timeouts, cache, etc.).
    ///
    /// If omitted and a `SastConfig` is set, `AnalysisConfig::from(&sast_config)` is used.
    /// If both are omitted, `AnalysisConfig::default()` applies.
    pub fn analysis_config(mut self, config: AnalysisConfig) -> Self {
        self.analysis_config = Some(config);
        self
    }

    /// Attach a Dragonfly-backed AST cache for parsed file caching.
    pub fn ast_cache(mut self, cache: Arc<dyn AstCacheService>) -> Self {
        self.ast_cache = Some(cache);
        self
    }

    /// Inject a fully-constructed `ScanProjectUseCase` (overrides all other settings).
    ///
    /// Use this from the composition root when you need full control.
    pub fn use_case(mut self, use_case: Arc<ScanProjectUseCase>) -> Self {
        self.use_case_override = Some(use_case);
        self
    }

    /// Build the `SastModule`.
    pub fn build(self) -> SastModule {
        let SastModuleBuilder {
            sast_config,
            analysis_config,
            ast_cache,
            use_case_override,
        } = self;

        let sast_config = sast_config.unwrap_or_default();

        let use_case = if let Some(uc) = use_case_override {
            uc
        } else {
            let analysis_cfg = analysis_config.unwrap_or_else(|| AnalysisConfig::from(&sast_config));

            let uc = ScanProjectUseCase::with_config(&sast_config, analysis_cfg);
            let uc = if let Some(cache) = ast_cache {
                uc.with_ast_cache(cache)
            } else {
                uc
            };
            Arc::new(uc)
        };

        SastModule {
            use_case,
            sast_config,
        }
    }
}

impl SastModule {
    /// Create a builder for configuring and constructing a `SastModule`.
    pub fn builder() -> SastModuleBuilder {
        SastModuleBuilder {
            sast_config: None,
            analysis_config: None,
            ast_cache: None,
            use_case_override: None,
        }
    }

    // ── Convenience constructors (thin wrappers around the builder) ──

    /// Zero-config constructor — sensible defaults, auto-detect depth.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Construct from a `SastConfig` (derives `AnalysisConfig` automatically).
    pub fn with_config(config: &SastConfig) -> Self {
        Self::builder().sast_config(config).build()
    }
}

#[async_trait]
impl AnalysisModule for SastModule {
    fn module_type(&self) -> ModuleType {
        ModuleType::SAST
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

        let policy = SastFindingPolicy::from_config(&self.sast_config, config)?;
        let mut filtered_by_severity = 0usize;
        let mut filtered_by_confidence = 0usize;
        let mut filtered_by_dataflow = 0usize;
        let mut filtered_by_quality = 0usize;

        // Convert SAST findings to orchestrator findings
        let findings: Vec<Finding> = scan_result
            .findings
            .into_iter()
            .filter(|f| {
                if f.description.trim().is_empty() {
                    filtered_by_quality += 1;
                    return false;
                }

                if policy.require_recommendation
                    && f.recommendation
                        .as_ref()
                        .is_none_or(|r| r.trim().is_empty())
                {
                    filtered_by_quality += 1;
                    return false;
                }

                if severity_rank(&f.severity) < severity_rank(&policy.min_severity) {
                    filtered_by_severity += 1;
                    return false;
                }

                if confidence_rank(&f.confidence) < confidence_rank(&policy.min_confidence) {
                    filtered_by_confidence += 1;
                    return false;
                }

                if policy.require_data_flow_evidence_for_dataflow
                    && is_data_flow_rule(&f.rule_id)
                    && f.data_flow_path.is_none()
                {
                    filtered_by_dataflow += 1;
                    return false;
                }

                true
            })
            .map(|f| Finding {
                id: f.id,
                r#type: FindingType::Vulnerability,
                rule_id: Some(f.rule_id),
                location: Location {
                    path: f.location.file_path,
                    line: Some(f.location.line),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    end_column: f.location.end_column,
                },
                severity: match f.severity {
                    SastSeverity::Critical => FindingSeverity::Critical,
                    SastSeverity::High => FindingSeverity::High,
                    SastSeverity::Medium => FindingSeverity::Medium,
                    SastSeverity::Low => FindingSeverity::Low,
                    SastSeverity::Info => FindingSeverity::Info,
                },
                confidence: match f.confidence {
                    crate::domain::value_objects::Confidence::High => FindingConfidence::High,
                    crate::domain::value_objects::Confidence::Medium => FindingConfidence::Medium,
                    crate::domain::value_objects::Confidence::Low => FindingConfidence::Low,
                },
                description: f.description.trim().to_string(),
                recommendation: f
                    .recommendation
                    .map(|r| r.trim().to_string())
                    .filter(|r| !r.is_empty()),
                secret_metadata: None,
                vulnerability_metadata: VulnerabilityFindingMetadata {
                    snippet: f.snippet,
                    bindings: f.bindings,
                    data_flow_path: f.data_flow_path.map(|path| VulnerabilityDataFlowPath {
                        source: VulnerabilityDataFlowNode {
                            location: Location {
                                path: path.source.location.file_path,
                                line: Some(path.source.location.line),
                                column: path.source.location.column,
                                end_line: path.source.location.end_line,
                                end_column: path.source.location.end_column,
                            },
                            description: path.source.description,
                            expression: path.source.expression,
                        },
                        steps: path
                            .steps
                            .into_iter()
                            .map(|step| VulnerabilityDataFlowNode {
                                location: Location {
                                    path: step.location.file_path,
                                    line: Some(step.location.line),
                                    column: step.location.column,
                                    end_line: step.location.end_line,
                                    end_column: step.location.end_column,
                                },
                                description: step.description,
                                expression: step.expression,
                            })
                            .collect(),
                        sink: VulnerabilityDataFlowNode {
                            location: Location {
                                path: path.sink.location.file_path,
                                line: Some(path.sink.location.line),
                                column: path.sink.location.column,
                                end_line: path.sink.location.end_line,
                                end_column: path.sink.location.end_column,
                            },
                            description: path.sink.description,
                            expression: path.sink.expression,
                        },
                    }),
                },
                enrichment: None,
            })
            .collect();

        let duration = start_time.elapsed();

        let mut additional_info = std::collections::HashMap::new();
        additional_info.insert(
            "policy_min_severity".to_string(),
            format!("{}", policy.min_severity),
        );
        additional_info.insert(
            "policy_min_confidence".to_string(),
            confidence_name(&policy.min_confidence).to_string(),
        );
        additional_info.insert(
            "policy_require_data_flow_evidence_for_dataflow".to_string(),
            policy.require_data_flow_evidence_for_dataflow.to_string(),
        );
        additional_info.insert(
            "policy_require_recommendation".to_string(),
            policy.require_recommendation.to_string(),
        );
        additional_info.insert(
            "filtered_by_severity".to_string(),
            filtered_by_severity.to_string(),
        );
        additional_info.insert(
            "filtered_by_confidence".to_string(),
            filtered_by_confidence.to_string(),
        );
        additional_info.insert(
            "filtered_by_data_flow_evidence".to_string(),
            filtered_by_dataflow.to_string(),
        );
        additional_info.insert(
            "filtered_by_quality".to_string(),
            filtered_by_quality.to_string(),
        );

        Ok(ModuleResult {
            job_id: config.job_id,
            module_type: ModuleType::SAST,
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

#[derive(Debug, Clone)]
struct SastFindingPolicy {
    min_severity: SastSeverity,
    min_confidence: crate::domain::value_objects::Confidence,
    require_data_flow_evidence_for_dataflow: bool,
    require_recommendation: bool,
}

impl SastFindingPolicy {
    fn from_config(
        default_config: &SastConfig,
        module_config: &ModuleConfig,
    ) -> Result<Self, ModuleExecutionError> {
        let default_min_severity = default_config
            .min_finding_severity
            .as_deref()
            .map(parse_severity)
            .transpose()?;

        let default_min_confidence = default_config
            .min_finding_confidence
            .as_deref()
            .map(parse_confidence)
            .transpose()?;

        let min_severity = module_config
            .config
            .get("sast.min_severity")
            .and_then(serde_json::Value::as_str)
            .map(parse_severity)
            .transpose()?
            .or(default_min_severity)
            .unwrap_or(SastSeverity::Info);

        let min_confidence = module_config
            .config
            .get("sast.min_confidence")
            .and_then(serde_json::Value::as_str)
            .map(parse_confidence)
            .transpose()?
            .or(default_min_confidence)
            .unwrap_or(crate::domain::value_objects::Confidence::Low);

        let require_data_flow_evidence_for_dataflow = module_config
            .config
            .get("sast.require_data_flow_evidence_for_dataflow")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(default_config.require_data_flow_evidence_for_dataflow);

        let require_recommendation = module_config
            .config
            .get("sast.require_recommendation")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(default_config.require_recommendation);

        Ok(Self {
            min_severity,
            min_confidence,
            require_data_flow_evidence_for_dataflow,
            require_recommendation,
        })
    }
}

fn parse_severity(input: &str) -> Result<SastSeverity, ModuleExecutionError> {
    match input.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(SastSeverity::Critical),
        "high" => Ok(SastSeverity::High),
        "medium" => Ok(SastSeverity::Medium),
        "low" => Ok(SastSeverity::Low),
        "info" => Ok(SastSeverity::Info),
        other => Err(ModuleExecutionError::InvalidConfig(format!(
            "Invalid SAST severity threshold: {other}"
        ))),
    }
}

fn parse_confidence(
    input: &str,
) -> Result<crate::domain::value_objects::Confidence, ModuleExecutionError> {
    match input.trim().to_ascii_lowercase().as_str() {
        "high" => Ok(crate::domain::value_objects::Confidence::High),
        "medium" => Ok(crate::domain::value_objects::Confidence::Medium),
        "low" => Ok(crate::domain::value_objects::Confidence::Low),
        other => Err(ModuleExecutionError::InvalidConfig(format!(
            "Invalid SAST confidence threshold: {other}"
        ))),
    }
}

fn severity_rank(severity: &SastSeverity) -> u8 {
    match severity {
        SastSeverity::Info => 0,
        SastSeverity::Low => 1,
        SastSeverity::Medium => 2,
        SastSeverity::High => 3,
        SastSeverity::Critical => 4,
    }
}

fn confidence_rank(confidence: &crate::domain::value_objects::Confidence) -> u8 {
    match confidence {
        crate::domain::value_objects::Confidence::Low => 0,
        crate::domain::value_objects::Confidence::Medium => 1,
        crate::domain::value_objects::Confidence::High => 2,
    }
}

fn confidence_name(confidence: &crate::domain::value_objects::Confidence) -> &'static str {
    match confidence {
        crate::domain::value_objects::Confidence::Low => "low",
        crate::domain::value_objects::Confidence::Medium => "medium",
        crate::domain::value_objects::Confidence::High => "high",
    }
}

fn is_data_flow_rule(rule_id: &str) -> bool {
    rule_id.starts_with("data-flow-") || rule_id.contains("dataflow") || rule_id.contains("taint")
}

impl Default for SastModule {
    fn default() -> Self {
        Self::new()
    }
}
