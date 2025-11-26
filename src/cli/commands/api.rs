//! API Command - API Security Analysis
//!
//! Analyzes API endpoints for security issues.
//! Works fully offline.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};
use crate::cli::Cli;

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
    pub by_category: std::collections::HashMap<String, usize>,
}

/// Run the api command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &ApiArgs) -> Result<i32> {
    // Resolve path
    let path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        ctx.working_dir.join(&args.path)
    };

    if !path.exists() {
        ctx.output.error(&format!("Path does not exist: {:?}", path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // API analysis works fully offline
    if !cli.quiet {
        ctx.output.header("API Security Analysis");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Analyzing API endpoints..."))
    } else {
        None
    };

    // Detect or use specified spec file
    let spec_file = args.spec.clone().or_else(|| find_openapi_spec(&path));
    let framework = args.framework.clone().or_else(|| detect_api_framework(&path));

    let mut result = ApiResult {
        path: path.clone(),
        spec_file: spec_file.as_ref().map(|p| p.to_string_lossy().to_string()),
        framework: framework.clone(),
        endpoints_found: 0,
        findings: Vec::new(),
        summary: ApiSummary {
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            endpoints_analyzed: 0,
            by_category: std::collections::HashMap::new(),
        },
    };

    if let Some(p) = &progress {
        if let Some(f) = &framework {
            p.set_message(&format!("Analyzing {} API...", f));
        }
    }

    if spec_file.is_none() && framework.is_none() {
        if let Some(p) = progress {
            p.finish_and_clear();
        }
        ctx.output.warn("No API specification or supported framework detected");
        ctx.output.info("Supported: OpenAPI/Swagger, Express, Flask, FastAPI, Axum, Django REST");
        return Ok(exit_codes::SUCCESS);
    }

    // TODO: Integrate with vulnera-api module
    // let api_module = ApiSecurityModule::new(ctx.config.clone());
    // let analysis = api_module.analyze(&path, spec_file.as_ref()).await?;
    // result.findings = analysis.findings;
    // result.endpoints_found = analysis.endpoints_found;

    // Calculate summary
    for finding in &result.findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => result.summary.critical += 1,
            "high" => result.summary.high += 1,
            "medium" => result.summary.medium += 1,
            "low" => result.summary.low += 1,
            _ => {}
        }
        *result
            .summary
            .by_category
            .entry(finding.category.clone())
            .or_insert(0) += 1;
    }
    result.summary.total_findings = result.findings.len();
    result.summary.endpoints_analyzed = result.endpoints_found;

    // Finish progress
    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Output results
    output_results(ctx, cli, &result)?;

    // Determine exit code
    let exit_code = if args.fail_on_issue && !result.findings.is_empty() {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    };

    Ok(exit_code)
}

/// Find OpenAPI/Swagger spec file
fn find_openapi_spec(path: &PathBuf) -> Option<PathBuf> {
    let candidates = [
        "openapi.yaml",
        "openapi.yml",
        "openapi.json",
        "swagger.yaml",
        "swagger.yml",
        "swagger.json",
        "api/openapi.yaml",
        "api/openapi.yml",
        "docs/openapi.yaml",
        "docs/swagger.yaml",
    ];

    for candidate in candidates {
        let spec_path = path.join(candidate);
        if spec_path.exists() {
            return Some(spec_path);
        }
    }

    None
}

/// Detect API framework from project files
fn detect_api_framework(path: &PathBuf) -> Option<String> {
    // Check package.json for Node.js frameworks
    if let Ok(content) = std::fs::read_to_string(path.join("package.json")) {
        if content.contains("\"express\"") {
            return Some("Express".to_string());
        }
        if content.contains("\"fastify\"") {
            return Some("Fastify".to_string());
        }
        if content.contains("\"koa\"") {
            return Some("Koa".to_string());
        }
        if content.contains("\"@nestjs/core\"") {
            return Some("NestJS".to_string());
        }
    }

    // Check requirements.txt or pyproject.toml for Python frameworks
    if let Ok(content) = std::fs::read_to_string(path.join("requirements.txt")) {
        if content.contains("fastapi") {
            return Some("FastAPI".to_string());
        }
        if content.contains("flask") {
            return Some("Flask".to_string());
        }
        if content.contains("django") {
            return Some("Django".to_string());
        }
    }

    // Check Cargo.toml for Rust frameworks
    if let Ok(content) = std::fs::read_to_string(path.join("Cargo.toml")) {
        if content.contains("axum") {
            return Some("Axum".to_string());
        }
        if content.contains("actix-web") {
            return Some("Actix-web".to_string());
        }
        if content.contains("rocket") {
            return Some("Rocket".to_string());
        }
    }

    // Check go.mod for Go frameworks
    if let Ok(content) = std::fs::read_to_string(path.join("go.mod")) {
        if content.contains("gin-gonic/gin") {
            return Some("Gin".to_string());
        }
        if content.contains("labstack/echo") {
            return Some("Echo".to_string());
        }
        if content.contains("gofiber/fiber") {
            return Some("Fiber".to_string());
        }
    }

    None
}

/// Output API analysis results
fn output_results(ctx: &CliContext, cli: &Cli, result: &ApiResult) -> Result<()> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.vulnerabilities(&result.findings)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if let Some(f) = &result.framework {
                ctx.output.info(&format!("Framework: {}", f));
            }
            if let Some(s) = &result.spec_file {
                ctx.output.info(&format!("Spec file: {}", s));
            }
            ctx.output.print(&format!(
                "Endpoints analyzed: {}",
                result.endpoints_found
            ));

            if result.findings.is_empty() {
                ctx.output.success("No API security issues found!");
            } else {
                println!();
                ctx.output.vulnerabilities(&result.findings)?;

                if !cli.quiet {
                    ctx.output.print("\nIssues by category:");
                    for (category, count) in &result.summary.by_category {
                        ctx.output.print(&format!("  {}: {}", category, count));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_detect_express() {
        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();

        let framework = detect_api_framework(&temp.path().to_path_buf());
        assert_eq!(framework, Some("Express".to_string()));
    }

    #[test]
    fn test_detect_fastapi() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("requirements.txt"), "fastapi==0.100.0").unwrap();

        let framework = detect_api_framework(&temp.path().to_path_buf());
        assert_eq!(framework, Some("FastAPI".to_string()));
    }
}
