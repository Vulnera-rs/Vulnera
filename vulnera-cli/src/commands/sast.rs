//! SAST Command - Static Application Security Testing
//!
//! Runs static analysis to find security vulnerabilities in source code.
//! Works fully offline using embedded vulnera-sast module.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use uuid::Uuid;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::module::SastModule;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};
use crate::severity::{parse_severity, severity_meets_minimum};

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

    /// Disable incremental caching (re-scan all files)
    #[arg(long)]
    pub no_cache: bool,

    /// Watch for file changes and re-scan automatically
    #[arg(long)]
    pub watch: bool,

    /// Generate LLM-powered fix suggestions (requires online mode, SARIF output)
    #[arg(long)]
    pub fix: bool,
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

    // Handle watch mode
    if args.watch {
        return run_watch_mode(ctx, cli, args, &path).await;
    }

    // Single scan
    run_single_scan(ctx, cli, args, &path).await
}

/// Run a single SAST scan with cache integration
async fn run_single_scan(
    ctx: &CliContext,
    cli: &Cli,
    args: &SastArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::file_cache::{CachedFinding, FileCache};

    let start = std::time::Instant::now();

    if !cli.quiet {
        ctx.output.header("Static Analysis (SAST)");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Initialize file cache unless --no-cache
    let mut file_cache = if !args.no_cache {
        FileCache::new(path).ok()
    } else {
        if cli.verbose {
            ctx.output.info("Cache disabled (--no-cache)");
        }
        None
    };

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
                    file: f.location.path.clone(),
                    line: f.location.line.unwrap_or(0),
                    column: f.location.column,
                    end_line: f.location.end_line,
                    snippet: None,
                    fix_suggestion: f.recommendation,
                    cwe: None,
                    owasp: None,
                })
                .collect();

            // Update file cache with findings
            if let Some(ref mut cache) = file_cache {
                // Group findings by file and update cache
                let mut findings_by_file: std::collections::HashMap<String, Vec<CachedFinding>> =
                    std::collections::HashMap::new();

                for finding in &findings {
                    let cached = CachedFinding {
                        id: finding.id.clone(),
                        rule_id: Some(finding.rule_id.clone()),
                        severity: finding.severity.clone(),
                        description: finding.message.clone(),
                        line: Some(finding.line),
                        column: finding.column,
                        module: "sast".to_string(),
                    };
                    findings_by_file
                        .entry(finding.file.clone())
                        .or_default()
                        .push(cached);
                }

                // Update cache for each scanned file
                for (file, file_findings) in findings_by_file {
                    let file_path = std::path::Path::new(&file);
                    if file_path.exists() {
                        let _ = cache.update_file(file_path, file_findings);
                    }
                }

                // Save cache
                if let Err(e) = cache.save() {
                    if cli.verbose {
                        ctx.output.warn(&format!("Failed to save cache: {}", e));
                    }
                } else if cli.verbose {
                    ctx.output
                        .info(&format!("Cache updated ({} entries)", cache.len()));
                }
            }

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
    output_results(ctx, cli, args, &result, start.elapsed())
}

/// Run watch mode - continuously monitor for file changes
async fn run_watch_mode(
    ctx: &CliContext,
    cli: &Cli,
    args: &SastArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::watcher::FileWatcher;

    if !cli.quiet {
        ctx.output.header("Static Analysis (SAST) - Watch Mode");
        ctx.output.info(&format!("Watching: {:?}", path));
    }

    // Run initial scan
    let initial_result = run_single_scan(ctx, cli, args, path).await?;
    if initial_result != exit_codes::SUCCESS && args.fail_on_vuln {
        ctx.output.warn("Vulnerabilities found in initial scan");
    }

    // Start file watcher
    let watcher = FileWatcher::new(path, 500)?;

    ctx.output.info("Watching for changes... (Ctrl+C to stop)");

    // Watch loop - blocks until stopped
    watcher.start(|event| {
        println!("\n📝 {} file(s) changed", event.paths.len());

        // Create a new runtime for the async scan
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt.block_on(async { run_single_scan(ctx, cli, args, path).await });

        match scan_result {
            Ok(code) => {
                if code == exit_codes::VULNERABILITIES_FOUND {
                    println!("⚠ Vulnerabilities detected");
                }
            }
            Err(e) => {
                eprintln!("Scan error: {}", e);
            }
        }

        true // Continue watching
    })?;

    Ok(exit_codes::SUCCESS)
}

/// Output results in the appropriate format
fn output_results(
    ctx: &CliContext,
    cli: &Cli,
    args: &SastArgs,
    result: &SastResult,
    duration: std::time::Duration,
) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.findings, "vulnera-sast", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerabilities found in {} files ({:.2}s)",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            } else {
                if !cli.quiet {
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
    }

    // Determine exit code
    if args.fail_on_vuln && !result.findings.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}
