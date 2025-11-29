//! SAST Command - Static Application Security Testing
//!
//! Runs static analysis to find security vulnerabilities in source code.
//! Works fully offline using embedded vulnera-sast module.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use uuid::Uuid;
use vulnera_core::domain::module::{AnalysisModule, FindingSeverity, ModuleConfig};
use vulnera_sast::module::SastModule;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the sast command
#[derive(Args, Debug)]
pub struct SastArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any vulnerability is found
    #[arg(long)]
    pub fail_on_vuln: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Specific files to analyze
    #[arg(long, value_delimiter = ',')]
    pub files: Vec<PathBuf>,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Languages to analyze (auto-detected if not specified)
    #[arg(long, value_delimiter = ',')]
    pub languages: Vec<String>,

    /// Enable specific rule categories
    #[arg(long, value_delimiter = ',')]
    pub rules: Vec<String>,
}

/// SAST analysis result
#[derive(Debug, Serialize)]
pub struct SastResult {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub languages_detected: Vec<String>,
    pub findings: Vec<SastFinding>,
    pub summary: SastSummary,
}

/// Individual SAST finding
#[derive(Debug, Clone, Serialize)]
pub struct SastFinding {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub snippet: Option<String>,
    pub fix_suggestion: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
}

impl VulnerabilityDisplay for SastFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.rule_id.clone()
    }
    fn package(&self) -> String {
        self.file.clone()
    }
    fn version(&self) -> String {
        format!("L{}", self.line)
    }
    fn description(&self) -> String {
        self.message.clone()
    }
}

/// Summary of SAST results
#[derive(Debug, Serialize)]
pub struct SastSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub files_scanned: usize,
    pub lines_scanned: usize,
}

/// Run the sast command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &SastArgs) -> Result<i32> {
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

    // SAST works fully offline
    if !cli.quiet {
        ctx.output.header("Static Analysis (SAST)");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning source files..."))
    } else {
        None
    };

    // Parse minimum severity
    let min_severity = parse_severity(&args.min_severity);

    // Run SAST analysis using embedded module
    let sast_module = SastModule::new();
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    let module_result = sast_module.execute(&module_config).await;

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match module_result {
        Ok(res) => {
            // Convert module findings to CLI findings
            let findings: Vec<SastFinding> = res
                .findings
                .into_iter()
                .filter(|f| severity_meets_minimum(&f.severity, &min_severity))
                .map(|f| SastFinding {
                    id: f.id,
                    rule_id: f.rule_id.unwrap_or_else(|| "unknown".to_string()),
                    severity: format!("{:?}", f.severity).to_lowercase(),
                    category: "SAST".to_string(),
                    message: f.description.clone(),
                    file: f.location.path,
                    line: f.location.line.unwrap_or(0),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    snippet: None,
                    fix_suggestion: f.recommendation,
                    cwe: None,
                    owasp: None,
                })
                .collect();

            let mut summary = SastSummary {
                total_findings: findings.len(),
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                files_scanned: res.metadata.files_scanned,
                lines_scanned: 0,
            };

            for finding in &findings {
                match finding.severity.as_str() {
                    "critical" => summary.critical += 1,
                    "high" => summary.high += 1,
                    "medium" => summary.medium += 1,
                    "low" => summary.low += 1,
                    _ => {}
                }
            }

            SastResult {
                path: path.clone(),
                files_scanned: res.metadata.files_scanned,
                languages_detected: Vec::new(),
                findings,
                summary,
            }
        }
        Err(e) => {
            ctx.output.error(&format!("SAST analysis failed: {}", e));
            return Ok(exit_codes::INTERNAL_ERROR);
        }
    };

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.findings, "vulnera-sast", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            let duration = start.elapsed();

            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerabilities found in {} files ({:.2}s)",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            } else {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} total ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));

                ctx.output.print(&format!(
                    "Scanned {} files in {:.2}s",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            }
        }
    }

    // Determine exit code
    if args.fail_on_vuln && !result.findings.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Parse severity string to FindingSeverity
fn parse_severity(s: &str) -> FindingSeverity {
    match s.to_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Low,
    }
}

/// Check if finding severity meets minimum threshold
fn severity_meets_minimum(severity: &FindingSeverity, minimum: &FindingSeverity) -> bool {
    let severity_order = |s: &FindingSeverity| match s {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 1,
        FindingSeverity::Info => 0,
    };

    severity_order(severity) >= severity_order(minimum)
}
