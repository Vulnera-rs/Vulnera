//! API Command - API Security Analysis
//!
//! Analyzes API endpoints for security issues.
//! Works fully offline using embedded vulnera-api module.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use uuid::Uuid;
use vulnera_api::module::ApiSecurityModule;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};
use crate::severity::{parse_severity, severity_meets_minimum};

/// Arguments for the api command
#[derive(Args, Debug)]
pub struct ApiArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Path to OpenAPI/Swagger specification file
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any issue is found
    #[arg(long)]
    pub fail_on_issue: bool,

    /// Framework to analyze (auto-detected if not specified)
    #[arg(long)]
    pub framework: Option<String>,
}

/// API analysis result
#[derive(Debug, Serialize)]
pub struct ApiResult {
    pub path: PathBuf,
    pub spec_file: Option<String>,
    pub framework: Option<String>,
    pub endpoints_found: usize,
    pub findings: Vec<ApiFinding>,
    pub summary: ApiSummary,
}

/// Individual API finding
#[derive(Debug, Clone, Serialize)]
pub struct ApiFinding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub endpoint: String,
    pub method: String,
    pub issue: String,
    pub description: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub owasp_category: Option<String>,
    pub remediation: String,
}

impl VulnerabilityDisplay for ApiFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.category.clone()
    }
    fn package(&self) -> String {
        format!("{} {}", self.method, self.endpoint)
    }
    fn version(&self) -> String {
        self.file.clone().unwrap_or_default()
    }
    fn description(&self) -> String {
        self.issue.clone()
    }
}

/// Summary of API analysis
#[derive(Debug, Serialize)]
pub struct ApiSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub endpoints_analyzed: usize,
    pub by_category: HashMap<String, usize>,
}

/// Run the api command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &ApiArgs) -> Result<i32> {
    let start = std::time::Instant::now();

    // Resolve path
    let path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        ctx.working_dir.join(&args.path)
    };

    // If spec is provided, use that instead
    let source_path = if let Some(spec) = &args.spec {
        if spec.is_absolute() {
            spec.clone()
        } else {
            ctx.working_dir.join(spec)
        }
    } else {
        path.clone()
    };

    if !source_path.exists() {
        ctx.output
            .error(&format!("Path does not exist: {:?}", source_path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // API analysis works fully offline
    if !cli.quiet {
        ctx.output.header("API Security Analysis");
        ctx.output.info(&format!("Scanning: {:?}", source_path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Analyzing API endpoints..."))
    } else {
        None
    };

    // Parse minimum severity
    let min_severity = parse_severity(&args.min_severity);

    // Run API security analysis using embedded module
    let api_module = ApiSecurityModule::new();
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: source_path.to_string_lossy().to_string(),
        config: Default::default(),
    };

    let module_result = api_module.execute(&module_config).await;

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match module_result {
        Ok(res) => {
            // Convert module findings to CLI findings
            let findings: Vec<ApiFinding> = res
                .findings
                .into_iter()
                .filter(|f| severity_meets_minimum(&f.severity, &min_severity))
                .map(|f| ApiFinding {
                    id: f.id,
                    severity: format!("{:?}", f.severity).to_lowercase(),
                    category: f.rule_id.unwrap_or_else(|| "api-security".to_string()),
                    endpoint: extract_endpoint(&f.description),
                    method: extract_method(&f.description),
                    issue: f.description.clone(),
                    description: f.description,
                    file: Some(f.location.path),
                    line: f.location.line,
                    owasp_category: None,
                    remediation: f.recommendation.unwrap_or_else(|| {
                        "Review and fix the identified API security issue".to_string()
                    }),
                })
                .collect();

            let mut summary = ApiSummary {
                total_findings: findings.len(),
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                endpoints_analyzed: 0, // Module doesn't expose this
                by_category: HashMap::new(),
            };

            for finding in &findings {
                match finding.severity.as_str() {
                    "critical" => summary.critical += 1,
                    "high" => summary.high += 1,
                    "medium" => summary.medium += 1,
                    "low" => summary.low += 1,
                    _ => {}
                }
                *summary
                    .by_category
                    .entry(finding.category.clone())
                    .or_insert(0) += 1;
            }

            ApiResult {
                path: source_path.clone(),
                spec_file: if source_path.is_file() {
                    Some(source_path.to_string_lossy().to_string())
                } else {
                    None
                },
                framework: args.framework.clone(),
                endpoints_found: summary.endpoints_analyzed,
                findings,
                summary,
            }
        }
        Err(e) => {
            // Check if it's just "no spec found" vs actual error
            let err_msg = e.to_string();
            if err_msg.contains("No OpenAPI specification found") {
                if !cli.quiet {
                    ctx.output
                        .info("No OpenAPI specification found in directory");
                    ctx.output
                        .info("To analyze an API, provide a spec file with --spec");
                }
                return Ok(exit_codes::SUCCESS);
            }

            ctx.output
                .error(&format!("API security analysis failed: {}", e));
            return Ok(exit_codes::INTERNAL_ERROR);
        }
    };

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.sarif(&result.findings, "vulnera-api", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            let duration = start.elapsed();

            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No API security issues found ({:.2}s)",
                    duration.as_secs_f64()
                ));

                if let Some(spec) = &result.spec_file {
                    ctx.output.info(&format!("Analyzed spec: {}", spec));
                }
            } else {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} issues ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));

                if !result.summary.by_category.is_empty() {
                    ctx.output.print("\nBy category:");
                    for (category, count) in &result.summary.by_category {
                        ctx.output.print(&format!("  {}: {}", category, count));
                    }
                }

                ctx.output
                    .print(&format!("\nCompleted in {:.2}s", duration.as_secs_f64()));
            }
        }
    }

    // Determine exit code
    if args.fail_on_issue && !result.findings.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Extract endpoint from description (best effort)
fn extract_endpoint(description: &str) -> String {
    // Look for URL-like patterns
    if let Some(start) = description.find('/') {
        let end = description[start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .map(|i| start + i)
            .unwrap_or(description.len());
        return description[start..end].to_string();
    }
    "N/A".to_string()
}

/// Extract HTTP method from description (best effort)
fn extract_method(description: &str) -> String {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    for method in methods {
        if description.contains(method) {
            return method.to_string();
        }
    }
    "N/A".to_string()
}
