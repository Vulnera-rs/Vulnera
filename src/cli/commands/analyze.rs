//! Analyze Command - Full vulnerability analysis
//!
//! Runs comprehensive vulnerability analysis including:
//! - Dependency vulnerability scanning
//! - Static analysis (SAST)
//! - Secret detection
//! - API security analysis

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

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

    // Check quota
    if !check_quota(ctx, cli).await? {
        return Ok(exit_codes::QUOTA_EXCEEDED);
    }

    // Show analysis start
    if !cli.quiet {
        ctx.output.header("Vulnera Analysis");
        ctx.output.info(&format!("Analyzing: {:?}", path));

        if ctx.offline_mode {
            ctx.output
                .warn("Running in offline mode - vulnerability data may be stale");
        }
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Initializing analysis..."))
    } else {
        None
    };

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

    // Run dependency analysis
    if !args.skip_deps {
        if let Some(p) = &progress {
            p.set_message("Scanning dependencies...");
        }
        run_deps_analysis(ctx, &path, &mut result, &args).await?;
    }

    // Run SAST analysis (works offline)
    if !args.skip_sast {
        if let Some(p) = &progress {
            p.set_message("Running static analysis...");
        }
        run_sast_analysis(ctx, &path, &mut result, &args).await?;
    }

    // Run secret detection (works offline)
    if !args.skip_secrets {
        if let Some(p) = &progress {
            p.set_message("Detecting secrets...");
        }
        run_secrets_analysis(ctx, &path, &mut result, &args).await?;
    }

    // Run API analysis (works offline)
    if !args.skip_api {
        if let Some(p) = &progress {
            p.set_message("Analyzing API endpoints...");
        }
        run_api_analysis(ctx, &path, &mut result, &args).await?;
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

    // Finish progress
    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Filter by minimum severity
    let filtered = filter_by_severity(&result.vulnerabilities, &args.min_severity);

    // Output results
    output_results(ctx, cli, &result, &filtered)?;

    // Determine exit code
    let exit_code = if args.fail_on_vuln && !filtered.is_empty() {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    };

    Ok(exit_code)
}

/// Check and consume quota
async fn check_quota(ctx: &CliContext, cli: &Cli) -> Result<bool> {
    // Clone quota to allow mutation
    let quota = ctx.quota.status();

    if quota.remaining == 0 {
        ctx.output.error(&format!(
            "Daily quota exceeded ({}/{}). Resets in {}h {}m",
            quota.used,
            quota.limit,
            quota.reset_time.num_hours(),
            quota.reset_time.num_minutes() % 60
        ));

        if !ctx.is_authenticated() {
            ctx.output
                .info("Tip: Run 'vulnera auth login' to get 40 requests/day");
        }

        return Ok(false);
    }

    // Note: Actual quota consumption would happen here
    // ctx.consume_quota().await?;

    if !cli.quiet && quota.remaining <= 3 {
        ctx.output.warn(&format!(
            "Low quota: {} requests remaining",
            quota.remaining
        ));
    }

    Ok(true)
}

/// Run dependency vulnerability analysis
async fn run_deps_analysis(
    ctx: &CliContext,
    path: &PathBuf,
    result: &mut AnalysisResult,
    _args: &AnalyzeArgs,
) -> Result<()> {
    result.modules_run.push("deps".to_string());

    // In offline mode, warn about potentially stale data
    if ctx.offline_mode {
        result.warnings.push(
            "Dependency analysis may use cached vulnerability data. Run online for latest data."
                .to_string(),
        );
    }

    // TODO: Integrate with vulnera-deps module
    // For now, this is a placeholder that demonstrates the structure

    // Example of how this would work:
    // let deps_module = DependencyAnalyzerModule::new(...);
    // let findings = deps_module.analyze(path).await?;
    // result.vulnerabilities.extend(findings.into_iter().map(|f| f.into()));

    tracing::debug!("Dependency analysis completed for {:?}", path);

    Ok(())
}

/// Run SAST analysis (works fully offline)
async fn run_sast_analysis(
    _ctx: &CliContext,
    path: &PathBuf,
    result: &mut AnalysisResult,
    _args: &AnalyzeArgs,
) -> Result<()> {
    result.modules_run.push("sast".to_string());

    // SAST works fully offline - no warning needed

    // TODO: Integrate with vulnera-sast module
    // let sast_module = SastModule::new(...);
    // let findings = sast_module.analyze(path).await?;
    // result.vulnerabilities.extend(findings.into_iter().map(|f| f.into()));

    tracing::debug!("SAST analysis completed for {:?}", path);

    Ok(())
}

/// Run secret detection (works fully offline)
async fn run_secrets_analysis(
    _ctx: &CliContext,
    path: &PathBuf,
    result: &mut AnalysisResult,
    _args: &AnalyzeArgs,
) -> Result<()> {
    result.modules_run.push("secrets".to_string());

    // Secret detection works fully offline - no warning needed

    // TODO: Integrate with vulnera-secrets module
    // let secrets_module = SecretDetectionModule::new(...);
    // let findings = secrets_module.analyze(path).await?;
    // result.vulnerabilities.extend(findings.into_iter().map(|f| f.into()));

    tracing::debug!("Secrets analysis completed for {:?}", path);

    Ok(())
}

/// Run API security analysis (works fully offline)
async fn run_api_analysis(
    _ctx: &CliContext,
    path: &PathBuf,
    result: &mut AnalysisResult,
    _args: &AnalyzeArgs,
) -> Result<()> {
    result.modules_run.push("api".to_string());

    // API analysis works fully offline - no warning needed

    // TODO: Integrate with vulnera-api module
    // let api_module = ApiSecurityModule::new(...);
    // let findings = api_module.analyze(path).await?;
    // result.vulnerabilities.extend(findings.into_iter().map(|f| f.into()));

    tracing::debug!("API analysis completed for {:?}", path);

    Ok(())
}

/// Filter vulnerabilities by minimum severity
fn filter_by_severity(vulns: &[VulnerabilityInfo], min_severity: &str) -> Vec<VulnerabilityInfo> {
    let min_level = severity_level(min_severity);

    vulns
        .iter()
        .filter(|v| severity_level(&v.severity) >= min_level)
        .cloned()
        .collect()
}

/// Convert severity string to numeric level
fn severity_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Output analysis results
fn output_results(
    ctx: &CliContext,
    cli: &Cli,
    result: &AnalysisResult,
    filtered: &[VulnerabilityInfo],
) -> Result<()> {
    // Show warnings first
    for warning in &result.warnings {
        ctx.output.warn(warning);
    }

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.vulnerabilities(filtered)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            // Print vulnerability table
            ctx.output.vulnerabilities(filtered)?;

            // Print summary
            if !cli.quiet {
                println!();
                ctx.output.info(&format!(
                    "Analysis completed in {}ms",
                    result.summary.duration_ms
                ));
                ctx.output
                    .info(&format!("Modules: {}", result.modules_run.join(", ")));

                if result.summary.total > 0 {
                    ctx.output.info(&format!(
                        "Severity breakdown: {} critical, {} high, {} medium, {} low",
                        result.summary.critical,
                        result.summary.high,
                        result.summary.medium,
                        result.summary.low
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_level() {
        assert_eq!(severity_level("critical"), 4);
        assert_eq!(severity_level("HIGH"), 3);
        assert_eq!(severity_level("Medium"), 2);
        assert_eq!(severity_level("low"), 1);
        assert_eq!(severity_level("unknown"), 0);
    }

    #[test]
    fn test_filter_by_severity() {
        let vulns = vec![
            VulnerabilityInfo {
                id: "1".to_string(),
                severity: "critical".to_string(),
                package: "pkg".to_string(),
                version: "1.0".to_string(),
                description: "test".to_string(),
                module: "deps".to_string(),
                file: None,
                line: None,
                fix_available: false,
                fixed_version: None,
            },
            VulnerabilityInfo {
                id: "2".to_string(),
                severity: "low".to_string(),
                package: "pkg".to_string(),
                version: "1.0".to_string(),
                description: "test".to_string(),
                module: "deps".to_string(),
                file: None,
                line: None,
                fix_available: false,
                fixed_version: None,
            },
        ];

        let filtered = filter_by_severity(&vulns, "high");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].severity, "critical");
    }
}
