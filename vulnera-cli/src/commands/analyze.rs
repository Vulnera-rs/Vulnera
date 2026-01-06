//! Analyze Command - Full vulnerability analysis
//!
//! Runs comprehensive vulnerability analysis including:
//! - Static analysis (SAST) - offline
//! - Secret detection - offline
//! - API security analysis - offline
//! - Dependency vulnerability scanning - requires server
//!
//! In offline mode, runs all offline modules and skips deps with a warning.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use uuid::Uuid;
use vulnera_api::module::ApiSecurityModule;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::module::SastModule;
use vulnera_secrets::module::SecretDetectionModule;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};
use crate::severity::{parse_severity, severity_meets_minimum_str};

/// Arguments for the analyze command
#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Skip dependency vulnerability scanning
    #[arg(long)]
    pub skip_deps: bool,

    /// Skip static analysis (SAST)
    #[arg(long)]
    pub skip_sast: bool,

    /// Skip secret detection
    #[arg(long)]
    pub skip_secrets: bool,

    /// Skip API security analysis
    #[arg(long)]
    pub skip_api: bool,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any vulnerability is found (useful for CI)
    #[arg(long)]
    pub fail_on_vuln: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
}

/// Analysis result summary
#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub summary: AnalysisSummary,
    pub modules_run: Vec<String>,
    pub warnings: Vec<String>,
}

/// Individual vulnerability information
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub description: String,
    pub module: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub fix_available: bool,
    pub fixed_version: Option<String>,
}

impl VulnerabilityDisplay for VulnerabilityInfo {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.id.clone()
    }
    fn package(&self) -> String {
        self.package.clone()
    }
    fn version(&self) -> String {
        self.version.clone()
    }
    fn description(&self) -> String {
        self.description.clone()
    }
}

/// Summary of analysis results
#[derive(Debug, Serialize)]
pub struct AnalysisSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub files_scanned: usize,
    pub duration_ms: u64,
}

/// Run the analyze command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &AnalyzeArgs) -> Result<i32> {
    let start = std::time::Instant::now();

    // Resolve path
    let path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        ctx.working_dir.join(&args.path)
    };

    if !path.exists() {
        ctx.output
            .error(&format!("Path does not exist: {:?}", path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Show analysis start
    if !cli.quiet {
        ctx.output.banner();
        ctx.output.info(&format!("Analyzing: {:?}", path));

        if cli.offline {
            ctx.output
                .warn("Running in offline mode - dependency analysis will be skipped");
        }
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Initializing analysis..."))
    } else {
        None
    };

    let _min_severity = parse_severity(&args.min_severity);

    let mut result = AnalysisResult {
        path: path.clone(),
        vulnerabilities: Vec::new(),
        summary: AnalysisSummary {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            files_scanned: 0,
            duration_ms: 0,
        },
        modules_run: Vec::new(),
        warnings: Vec::new(),
    };

    // Run SAST analysis (works offline)
    if !args.skip_sast {
        if let Some(p) = &progress {
            p.set_message("Running static analysis (SAST)...");
        }

        run_sast_analysis(&path, &mut result).await;
        result.modules_run.push("sast".to_string());
    }

    // Run secret detection (works offline)
    if !args.skip_secrets {
        if let Some(p) = &progress {
            p.set_message("Detecting secrets...");
        }

        run_secrets_analysis(&path, &mut result).await;
        result.modules_run.push("secrets".to_string());
    }

    // Run API analysis (works offline)
    if !args.skip_api {
        if let Some(p) = &progress {
            p.set_message("Analyzing API endpoints...");
        }

        run_api_analysis(&path, &mut result).await;
        result.modules_run.push("api".to_string());
    }

    // Run dependency analysis (requires server)
    if !args.skip_deps {
        if cli.offline {
            // Skip deps in offline mode with warning
            result
                .warnings
                .push("Dependency analysis skipped (requires server connection)".to_string());
            if !cli.quiet {
                ctx.output
                    .warn("Dependency analysis skipped (requires server connection)");
            }
        } else {
            if let Some(p) = &progress {
                p.set_message("Scanning dependencies (requires server)...");
            }

            run_deps_analysis(ctx, &path, &mut result, &args.min_severity).await;
            result.modules_run.push("deps".to_string());
        }
    }

    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Calculate summary
    let duration = start.elapsed();
    result.summary.duration_ms = duration.as_millis() as u64;
    result.summary.total = result.vulnerabilities.len();

    for vuln in &result.vulnerabilities {
        match vuln.severity.to_lowercase().as_str() {
            "critical" => result.summary.critical += 1,
            "high" => result.summary.high += 1,
            "medium" => result.summary.medium += 1,
            "low" => result.summary.low += 1,
            _ => {}
        }
    }

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.vulnerabilities, "vulnera", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.vulnerabilities.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerabilities found ({:.2}s)",
                    duration.as_secs_f64()
                ));
            } else {
                ctx.output.print_findings_table(&result.vulnerabilities);

                ctx.output.print(&format!(
                    "\nSummary: {} total ({} critical, {} high, {} medium, {} low)",
                    result.summary.total,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));
            }

            // Show modules run with styling
            ctx.output.divider();
            ctx.output
                .print(&format!("Modules: {}", result.modules_run.join(", ")));

            // Show warnings
            for warning in &result.warnings {
                ctx.output.warn(warning);
            }

            ctx.output
                .print(&format!("✓ Completed in {:.2}s", duration.as_secs_f64()));
            ctx.output.divider();
        }
    }

    // Determine exit code
    if args.fail_on_vuln && !result.vulnerabilities.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Run SAST analysis
async fn run_sast_analysis(path: &PathBuf, result: &mut AnalysisResult) {
    let sast_module = SastModule::new();
    let config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    match sast_module.execute(&config).await {
        Ok(res) => {
            result.summary.files_scanned += res.metadata.files_scanned;

            for finding in res.findings {
                result.vulnerabilities.push(VulnerabilityInfo {
                    id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                    severity: format!("{:?}", finding.severity).to_lowercase(),
                    package: finding.location.path.clone(),
                    version: finding
                        .location
                        .line
                        .map(|l| format!("L{}", l))
                        .unwrap_or_default(),
                    description: finding.description,
                    module: "sast".to_string(),
                    file: Some(finding.location.path),
                    line: finding.location.line,
                    fix_available: finding.recommendation.is_some(),
                    fixed_version: None,
                });
            }
        }
        Err(e) => {
            result.warnings.push(format!("SAST analysis failed: {}", e));
        }
    }
}

/// Run secrets analysis
async fn run_secrets_analysis(path: &PathBuf, result: &mut AnalysisResult) {
    let secrets_module = SecretDetectionModule::new();
    let config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    match secrets_module.execute(&config).await {
        Ok(res) => {
            result.summary.files_scanned += res.metadata.files_scanned;

            for finding in res.findings {
                result.vulnerabilities.push(VulnerabilityInfo {
                    id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                    severity: format!("{:?}", finding.severity).to_lowercase(),
                    package: finding.location.path.clone(),
                    version: finding
                        .location
                        .line
                        .map(|l| format!("L{}", l))
                        .unwrap_or_default(),
                    description: finding.description,
                    module: "secrets".to_string(),
                    file: Some(finding.location.path),
                    line: finding.location.line,
                    fix_available: true,
                    fixed_version: None,
                });
            }
        }
        Err(e) => {
            result
                .warnings
                .push(format!("Secret detection failed: {}", e));
        }
    }
}

/// Run API analysis
async fn run_api_analysis(path: &PathBuf, result: &mut AnalysisResult) {
    let api_module = ApiSecurityModule::new();
    let config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    match api_module.execute(&config).await {
        Ok(res) => {
            for finding in res.findings {
                result.vulnerabilities.push(VulnerabilityInfo {
                    id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                    severity: format!("{:?}", finding.severity).to_lowercase(),
                    package: finding.location.path.clone(),
                    version: finding
                        .location
                        .line
                        .map(|l| format!("L{}", l))
                        .unwrap_or_default(),
                    description: finding.description,
                    module: "api".to_string(),
                    file: Some(finding.location.path),
                    line: finding.location.line,
                    fix_available: finding.recommendation.is_some(),
                    fixed_version: None,
                });
            }
        }
        Err(e) => {
            // Check if it's just "no spec found" vs actual error
            let err_msg = e.to_string();
            if !err_msg.contains("No OpenAPI specification found") {
                result
                    .warnings
                    .push(format!("API security analysis failed: {}", e));
            }
        }
    }
}

/// Run deps analysis (requires server)
async fn run_deps_analysis(
    ctx: &CliContext,
    path: &PathBuf,
    result: &mut AnalysisResult,
    min_severity: &str,
) {
    // Use the executor's already-configured API client if available
    if !ctx.executor.has_api_client() {
        result
            .warnings
            .push("Dependency analysis requires server connection".to_string());
        return;
    }

    let client = match ctx.executor.get_api_client() {
        Some(c) => c,
        None => {
            result
                .warnings
                .push("API client not available for dependency analysis".to_string());
            return;
        }
    };

    match client.analyze_dependencies(path, None, false).await {
        Ok(response) => {
            for vuln in response.vulnerabilities {
                if severity_meets_minimum_str(&vuln.severity, min_severity) {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: vuln.cve.unwrap_or(vuln.id),
                        severity: vuln.severity,
                        package: vuln.package.clone(),
                        version: vuln.version,
                        description: vuln.description,
                        module: "deps".to_string(),
                        file: None,
                        line: None,
                        fix_available: vuln.fixed_version.is_some(),
                        fixed_version: vuln.fixed_version,
                    });
                }
            }
        }
        Err(e) => {
            result
                .warnings
                .push(format!("Dependency analysis failed: {}", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), FindingSeverity::Critical);
        assert_eq!(parse_severity("high"), FindingSeverity::High);
        assert_eq!(parse_severity("medium"), FindingSeverity::Medium);
        assert_eq!(parse_severity("low"), FindingSeverity::Low);
        assert_eq!(parse_severity("info"), FindingSeverity::Low); // Default fallback
        assert_eq!(parse_severity("unknown"), FindingSeverity::Low); // Default fallback
        assert_eq!(parse_severity("CRITICAL"), FindingSeverity::Critical); // Case insensitive
    }

    #[test]
    fn test_severity_meets_minimum() {
        // Critical meets everything
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Low
        ));

        // High meets High and Low, but not Critical
        assert!(!severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Low
        ));

        // Low meets Low, but not High or Critical
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Critical
        ));
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Low
        ));
    }

    #[test]
    fn test_severity_meets_minimum_str() {
        assert!(severity_meets_minimum_str("critical", "high"));
        assert!(severity_meets_minimum_str("high", "high"));
        assert!(!severity_meets_minimum_str("medium", "high"));
        assert!(!severity_meets_minimum_str("low", "high"));
    }

    #[test]
    fn test_vulnerability_display() {
        let vuln = VulnerabilityInfo {
            id: "TEST-001".to_string(),
            severity: "high".to_string(),
            package: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: "Test description".to_string(),
            module: "test".to_string(),
            file: Some("test.rs".to_string()),
            line: Some(10),
            fix_available: true,
            fixed_version: Some("1.0.1".to_string()),
        };

        assert_eq!(vuln.id(), "TEST-001");
        assert_eq!(vuln.severity(), "high");
        assert_eq!(vuln.package(), "test-pkg");
        assert_eq!(vuln.version(), "1.0.0");
        assert_eq!(vuln.description(), "Test description");
    }
}
