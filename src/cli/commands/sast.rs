//! SAST Command - Static Application Security Testing
//!
//! Runs static analysis to find security vulnerabilities in source code.
//! Works fully offline.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};
use crate::cli::Cli;

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
    let _start = std::time::Instant::now();

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

    let mut result = SastResult {
        path: path.clone(),
        files_scanned: 0,
        languages_detected: Vec::new(),
        findings: Vec::new(),
        summary: SastSummary {
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            files_scanned: 0,
            lines_scanned: 0,
        },
    };

    // Detect languages
    if let Some(p) = &progress {
        p.set_message("Detecting languages...");
    }

    result.languages_detected = detect_languages(&path);

    if result.languages_detected.is_empty() {
        if let Some(p) = progress {
            p.finish_and_clear();
        }
        ctx.output.warn("No supported source files found");
        ctx.output.info("Supported: Python, JavaScript, TypeScript, Go, Rust, C/C++");
        return Ok(exit_codes::SUCCESS);
    }

    if let Some(p) = &progress {
        p.set_message(&format!(
            "Analyzing {} code...",
            result.languages_detected.join(", ")
        ));
    }

    // TODO: Integrate with vulnera-sast module
    // let sast_module = SastModule::new(ctx.config.clone());
    // let analysis = sast_module.analyze(&path, &args.languages, &args.exclude).await?;
    // result.findings = analysis.findings;
    // result.summary = analysis.summary;

    // Calculate summary
    for finding in &result.findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => result.summary.critical += 1,
            "high" => result.summary.high += 1,
            "medium" => result.summary.medium += 1,
            "low" => result.summary.low += 1,
            _ => {}
        }
    }
    result.summary.total_findings = result.findings.len();

    // Finish progress
    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Output results
    output_results(ctx, cli, &result)?;

    // Determine exit code
    let exit_code = if args.fail_on_vuln && !result.findings.is_empty() {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    };

    Ok(exit_code)
}

/// Detect programming languages in the project
fn detect_languages(path: &PathBuf) -> Vec<String> {
    let mut languages = Vec::new();

    let extensions = [
        ("py", "Python"),
        ("js", "JavaScript"),
        ("ts", "TypeScript"),
        ("jsx", "JavaScript"),
        ("tsx", "TypeScript"),
        ("go", "Go"),
        ("rs", "Rust"),
        ("c", "C"),
        ("cpp", "C++"),
        ("h", "C"),
        ("hpp", "C++"),
        ("java", "Java"),
        ("rb", "Ruby"),
        ("php", "PHP"),
    ];

    for entry in walkdir::WalkDir::new(path)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if let Some(ext) = entry.path().extension() {
            if let Some(ext_str) = ext.to_str() {
                for (e, lang) in &extensions {
                    if ext_str == *e && !languages.contains(&lang.to_string()) {
                        languages.push(lang.to_string());
                    }
                }
            }
        }
    }

    languages
}

/// Output SAST results
fn output_results(ctx: &CliContext, cli: &Cli, result: &SastResult) -> Result<()> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.vulnerabilities(&result.findings)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            ctx.output.info(&format!(
                "Languages: {}",
                result.languages_detected.join(", ")
            ));
            ctx.output.print(&format!(
                "Files scanned: {}",
                result.summary.files_scanned
            ));

            println!();
            ctx.output.vulnerabilities(&result.findings)?;

            if !cli.quiet && !result.findings.is_empty() {
                ctx.output.print(&format!(
                    "\nSeverity breakdown: {} critical, {} high, {} medium, {} low",
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));
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
    fn test_detect_languages() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("main.py"), "print('hello')").unwrap();
        std::fs::write(temp.path().join("app.js"), "console.log('hi')").unwrap();

        let languages = detect_languages(&temp.path().to_path_buf());
        assert!(languages.contains(&"Python".to_string()));
        assert!(languages.contains(&"JavaScript".to_string()));
    }
}
