//! API security use cases

use std::path::Path;
use tracing::{debug, error, info, instrument};
use vulnera_core::config::ApiSecurityConfig;

use crate::domain::entities::{ApiFinding, FindingSeverity};
use crate::infrastructure::analyzers::*;
use crate::infrastructure::parser::OpenApiParser;

type AnalyzerFn = fn(&crate::domain::value_objects::OpenApiSpec) -> Vec<ApiFinding>;

/// Result of an API security scan
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<ApiFinding>,
    pub score: u8,
}

/// Use case for scanning an API specification
pub struct ScanApiSpecificationUseCase {
    config: ApiSecurityConfig,
}

impl ScanApiSpecificationUseCase {
    pub fn new() -> Self {
        Self::with_config(&ApiSecurityConfig::default())
    }

    pub fn with_config(config: &ApiSecurityConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    #[instrument(skip(self), fields(spec_path = %spec_path.display()))]
    pub fn execute(&self, spec_path: &Path) -> Result<ScanResult, ScanError> {
        info!("Starting API security scan");

        // Parse OpenAPI specification
        let spec = OpenApiParser::parse_file(spec_path).map_err(|e| {
            error!(
                error = %e,
                file = %spec_path.display(),
                "Failed to parse OpenAPI specification"
            );
            ScanError::ParseError {
                message: e.to_string(),
                file: spec_path.display().to_string(),
            }
        })?;

        // Validate OpenAPI version
        if !spec.version.starts_with("3.") {
            return Err(ScanError::UnsupportedVersion {
                version: spec.version.clone(),
            });
        }

        // Run analyzers based on configuration
        let mut all_findings = Vec::new();

        // Define analyzer names and their corresponding analyzer functions
        let analyzers: Vec<(&str, AnalyzerFn)> = vec![
            ("authentication", |s| AuthenticationAnalyzer::analyze(s)),
            ("authorization", |s| AuthorizationAnalyzer::analyze(s)),
            ("input_validation", |s| InputValidationAnalyzer::analyze(s)),
            ("data_exposure", |s| DataExposureAnalyzer::analyze(s)),
            ("design", |s| DesignAnalyzer::analyze(s)),
            ("security_headers", |s| SecurityHeadersAnalyzer::analyze(s)),
            ("oauth", |s| OAuthAnalyzer::analyze(s)),
        ];

        // Filter analyzers if enabled_analyzers is specified
        let analyzers_to_run = if self.config.enabled_analyzers.is_empty() {
            // All analyzers enabled
            analyzers
                .iter()
                .map(|(name, func)| (*name, *func))
                .collect::<Vec<_>>()
        } else {
            // Only run enabled analyzers
            analyzers
                .iter()
                .filter(|(name, _)| {
                    self.config.enabled_analyzers.iter().any(|enabled| {
                        enabled.eq_ignore_ascii_case(name)
                            || enabled.eq_ignore_ascii_case(&format!("{}_analyzer", name))
                    })
                })
                .map(|(name, func)| (*name, *func))
                .collect::<Vec<_>>()
        };

        debug!(
            total_analyzers = analyzers.len(),
            enabled_analyzers = analyzers_to_run.len(),
            "Running analyzers"
        );

        // Run selected analyzers
        for (analyzer_name, analyzer_func) in analyzers_to_run {
            debug!(analyzer = analyzer_name, "Running analyzer");
            let findings = analyzer_func(&spec);
            all_findings.extend(findings);
        }

        // Apply path exclusions
        if !self.config.exclude_paths.is_empty() {
            let initial_count = all_findings.len();
            all_findings.retain(|finding| {
                if let Some(ref path) = finding.path {
                    !self.config.exclude_paths.iter().any(|excluded| {
                        // Simple prefix matching - could be enhanced with glob/regex
                        path.starts_with(excluded) || excluded == "*"
                    })
                } else {
                    true // Keep findings without paths
                }
            });
            debug!(
                excluded_count = initial_count - all_findings.len(),
                "Applied path exclusions"
            );
        }

        // Apply severity overrides
        if !self.config.severity_overrides.is_empty() {
            for finding in &mut all_findings {
                let vuln_type_str = format!("{:?}", finding.vulnerability_type);
                if let Some(severity_str) = self.config.severity_overrides.get(&vuln_type_str) {
                    if let Ok(new_severity) = Self::parse_severity(severity_str) {
                        finding.severity = new_severity;
                    }
                }
            }
        }

        // Apply strict mode (escalate severity levels)
        if self.config.strict_mode {
            for finding in &mut all_findings {
                finding.severity = match finding.severity {
                    FindingSeverity::Info => FindingSeverity::Low,
                    FindingSeverity::Low => FindingSeverity::Medium,
                    FindingSeverity::Medium => FindingSeverity::High,
                    FindingSeverity::High => FindingSeverity::High,
                    FindingSeverity::Critical => FindingSeverity::Critical,
                };
            }
        }

        // Calculate security score (Contract Integrity Score)
        // Base: 100
        // Deductions: Critical=25, High=15, Medium=5, Low=1
        let mut deduction = 0;
        for finding in &all_findings {
            match finding.severity {
                FindingSeverity::Critical => deduction += 25,
                FindingSeverity::High => deduction += 15,
                FindingSeverity::Medium => deduction += 5,
                FindingSeverity::Low => deduction += 1,
                FindingSeverity::Info => {}
            }
        }

        let score = (100_i32 - deduction).max(0) as u8;

        info!(
            finding_count = all_findings.len(),
            score = score,
            "API security scan completed"
        );

        Ok(ScanResult {
            findings: all_findings,
            score,
        })
    }

    /// Parse severity string to FindingSeverity enum
    fn parse_severity(severity_str: &str) -> Result<FindingSeverity, ()> {
        match severity_str.to_lowercase().as_str() {
            "critical" => Ok(FindingSeverity::Critical),
            "high" => Ok(FindingSeverity::High),
            "medium" => Ok(FindingSeverity::Medium),
            "low" => Ok(FindingSeverity::Low),
            "info" => Ok(FindingSeverity::Info),
            _ => Err(()),
        }
    }
}

impl Default for ScanApiSpecificationUseCase {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan error with context
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Parse error: {message} (file: {file})")]
    ParseError { message: String, file: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("OpenAPI version not supported: {version} (supported: 3.0.0+)")]
    UnsupportedVersion { version: String },
}
