//! Secrets Command - Secret and credential detection
//!
//! Scans for hardcoded secrets, API keys, passwords, and other credentials.
//! Works fully offline using embedded vulnera-secrets module.
//!

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use uuid::Uuid;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_secrets::module::SecretDetectionModule;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the secrets command
#[derive(Args, Debug)]
pub struct SecretsArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Fail if any secret is found
    #[arg(long)]
    pub fail_on_secret: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Specific files to analyze
    #[arg(long, value_delimiter = ',')]
    pub files: Vec<PathBuf>,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Include patterns that are usually excluded (e.g., test files)
    #[arg(long)]
    pub include_tests: bool,

    /// Show entropy-based detections (more false positives)
    #[arg(long)]
    pub include_entropy: bool,

    /// Disable incremental caching (re-scan all files)
    #[arg(long)]
    pub no_cache: bool,

    /// Watch for file changes and re-scan automatically
    #[arg(long)]
    pub watch: bool,
}

/// Secrets detection result
#[derive(Debug, Serialize)]
pub struct SecretsResult {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub findings: Vec<SecretFinding>,
    pub summary: SecretsSummary,
}

/// Individual secret finding
#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub id: String,
    pub secret_type: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub match_text: String,
    pub redacted_value: String,
    pub description: String,
    pub remediation: String,
}

impl VulnerabilityDisplay for SecretFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.secret_type.clone()
    }
    fn package(&self) -> String {
        self.file.clone()
    }
    fn version(&self) -> String {
        format!("L{}", self.line)
    }
    fn description(&self) -> String {
        format!("{}: {}", self.secret_type, self.redacted_value)
    }
}

/// Summary of secrets detection
#[derive(Debug, Serialize)]
pub struct SecretsSummary {
    pub total_findings: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: SeverityCounts,
    pub files_scanned: usize,
}

/// Severity breakdown
#[derive(Debug, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Run the secrets command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &SecretsArgs) -> Result<i32> {
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

/// Run a single secrets scan with cache integration
async fn run_single_scan(
    ctx: &CliContext,
    cli: &Cli,
    args: &SecretsArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::file_cache::{CachedFinding, FileCache};

    let start = std::time::Instant::now();

    if !cli.quiet {
        ctx.output.header("Secret Detection");
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
        Some(ProgressIndicator::spinner("Scanning for secrets..."))
    } else {
        None
    };

    // Run secrets detection using embedded module
    let secrets_module = SecretDetectionModule::new();
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    let module_result = secrets_module.execute(&module_config).await;

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match module_result {
        Ok(res) => {
            // Convert module findings to CLI findings
            let findings: Vec<SecretFinding> = res
                .findings
                .into_iter()
                .map(|f| SecretFinding {
                    id: f.id,
                    secret_type: f.rule_id.unwrap_or_else(|| "unknown".to_string()),
                    severity: format!("{:?}", f.severity).to_lowercase(),
                    file: f.location.path.clone(),
                    line: f.location.line.unwrap_or(0),
                    column: f.location.column,
                    match_text: String::new(), // Redacted for security
                    redacted_value: redact_secret(&f.description),
                    description: f.description,
                    remediation: f.recommendation.unwrap_or_else(|| {
                        "Remove the secret and rotate credentials immediately".to_string()
                    }),
                })
                .collect();

            // Update file cache with findings
            if let Some(ref mut cache) = file_cache {
                let mut findings_by_file: std::collections::HashMap<String, Vec<CachedFinding>> =
                    std::collections::HashMap::new();

                for finding in &findings {
                    let cached = CachedFinding {
                        id: finding.id.clone(),
                        rule_id: Some(finding.secret_type.clone()),
                        severity: finding.severity.clone(),
                        description: finding.description.clone(),
                        line: Some(finding.line),
                        column: finding.column,
                        module: "secrets".to_string(),
                    };
                    findings_by_file
                        .entry(finding.file.clone())
                        .or_default()
                        .push(cached);
                }

                for (file, file_findings) in findings_by_file {
                    let file_path = std::path::Path::new(&file);
                    if file_path.exists() {
                        let _ = cache.update_file(file_path, file_findings);
                    }
                }

                if let Err(e) = cache.save() {
                    if cli.verbose {
                        ctx.output.warn(&format!("Failed to save cache: {}", e));
                    }
                } else if cli.verbose {
                    ctx.output
                        .info(&format!("Cache updated ({} entries)", cache.len()));
                }
            }

            let mut by_type: HashMap<String, usize> = HashMap::new();
            let mut by_severity = SeverityCounts {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            };

            for finding in &findings {
                *by_type.entry(finding.secret_type.clone()).or_insert(0) += 1;
                match finding.severity.as_str() {
                    "critical" => by_severity.critical += 1,
                    "high" => by_severity.high += 1,
                    "medium" => by_severity.medium += 1,
                    "low" => by_severity.low += 1,
                    _ => {}
                }
            }

            SecretsResult {
                path: path.clone(),
                files_scanned: res.metadata.files_scanned,
                findings,
                summary: SecretsSummary {
                    total_findings: by_type.values().sum(),
                    by_type,
                    by_severity,
                    files_scanned: res.metadata.files_scanned,
                },
            }
        }
        Err(e) => {
            ctx.output.error(&format!("Secret detection failed: {}", e));
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
    args: &SecretsArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::watcher::FileWatcher;

    if !cli.quiet {
        ctx.output.header("Secret Detection - Watch Mode");
        ctx.output.info(&format!("Watching: {:?}", path));
    }

    // Run initial scan
    let initial_result = run_single_scan(ctx, cli, args, path).await?;
    if initial_result != exit_codes::SUCCESS && args.fail_on_secret {
        ctx.output.warn("Secrets found in initial scan");
    }

    // Start file watcher
    let watcher = FileWatcher::new(path, 500)?;

    ctx.output.info("Watching for changes... (Ctrl+C to stop)");

    // Watch loop
    watcher.start(|event| {
        println!("\n📝 {} file(s) changed", event.paths.len());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt.block_on(async { run_single_scan(ctx, cli, args, path).await });

        match scan_result {
            Ok(code) => {
                if code == exit_codes::VULNERABILITIES_FOUND {
                    println!("⚠ Secrets detected");
                }
            }
            Err(e) => {
                eprintln!("Scan error: {}", e);
            }
        }

        true
    })?;

    Ok(exit_codes::SUCCESS)
}

/// Output results in the appropriate format
fn output_results(
    ctx: &CliContext,
    cli: &Cli,
    args: &SecretsArgs,
    result: &SecretsResult,
    duration: std::time::Duration,
) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.findings, "vulnera-secrets", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No secrets found in {} files ({:.2}s)",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            } else if !cli.quiet {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} secrets found ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.by_severity.critical,
                    result.summary.by_severity.high,
                    result.summary.by_severity.medium,
                    result.summary.by_severity.low
                ));

                if !result.summary.by_type.is_empty() {
                    ctx.output.print("\nBy type:");
                    for (secret_type, count) in &result.summary.by_type {
                        ctx.output.print(&format!("  {}: {}", secret_type, count));
                    }
                }

                ctx.output.print(&format!(
                    "\nScanned {} files in {:.2}s",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));

                ctx.output.warn(
                    "⚠ IMPORTANT: Rotate all detected credentials immediately. \
                     Secrets may have been exposed in version control history.",
                );
            }
        }
    }

    // Determine exit code
    if args.fail_on_secret && !result.findings.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Redact a secret value for safe display
fn redact_secret(description: &str) -> String {
    // If description contains what looks like a secret, redact it
    if description.len() > 20 {
        let prefix = &description[..8];
        let suffix = &description[description.len() - 4..];
        format!("{}...{}", prefix, suffix)
    } else if description.len() > 8 {
        format!("{}...", &description[..4])
    } else {
        "[REDACTED]".to_string()
    }
}
