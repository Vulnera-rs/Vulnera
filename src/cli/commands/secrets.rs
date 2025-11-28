//! Secrets Command - Secret and credential detection
//!
//! Scans for hardcoded secrets, API keys, passwords, and other credentials.
//! Works fully offline.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

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

    /// Verify if detected secrets are valid (makes network requests)
    #[arg(long)]
    pub verify: bool,

    /// Show entropy-based detections (more false positives)
    #[arg(long)]
    pub include_entropy: bool,
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
    pub verified: Option<bool>,
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
    pub verified_secrets: usize,
    pub unverified_secrets: usize,
    pub by_type: std::collections::HashMap<String, usize>,
    pub files_scanned: usize,
}

/// Run the secrets command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &SecretsArgs) -> Result<i32> {
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

    // Secrets detection works fully offline
    if !cli.quiet {
        ctx.output.header("Secret Detection");
        ctx.output.info(&format!("Scanning: {:?}", path));

        if args.verify && ctx.offline_mode {
            ctx.output.warn("Verification disabled in offline mode");
        }
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning for secrets..."))
    } else {
        None
    };

    let mut result = SecretsResult {
        path: path.clone(),
        files_scanned: 0,
        findings: Vec::new(),
        summary: SecretsSummary {
            total_findings: 0,
            verified_secrets: 0,
            unverified_secrets: 0,
            by_type: std::collections::HashMap::new(),
            files_scanned: 0,
        },
    };

    // TODO: Integrate with vulnera-secrets module
    // let secrets_module = SecretDetectionModule::new(ctx.config.clone());
    // let analysis = secrets_module.analyze(&path, &args.exclude).await?;
    // result.findings = analysis.findings;

    // Optionally verify secrets
    if args.verify && !ctx.offline_mode {
        if let Some(p) = &progress {
            p.set_message("Verifying detected secrets...");
        }
        // TODO: Verify secrets against external APIs
    }

    // Calculate summary
    result.summary.total_findings = result.findings.len();
    for finding in &result.findings {
        *result
            .summary
            .by_type
            .entry(finding.secret_type.clone())
            .or_insert(0) += 1;

        if finding.verified == Some(true) {
            result.summary.verified_secrets += 1;
        } else {
            result.summary.unverified_secrets += 1;
        }
    }

    // Finish progress
    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Output results
    output_results(ctx, cli, &result)?;

    // Determine exit code
    let exit_code = if args.fail_on_secret && !result.findings.is_empty() {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    };

    Ok(exit_code)
}

/// Output secrets results
fn output_results(ctx: &CliContext, cli: &Cli, result: &SecretsResult) -> Result<()> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.vulnerabilities(&result.findings)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            ctx.output
                .print(&format!("Files scanned: {}", result.summary.files_scanned));

            if result.findings.is_empty() {
                ctx.output.success("No secrets detected!");
            } else {
                println!();
                ctx.output.vulnerabilities(&result.findings)?;

                if !cli.quiet {
                    ctx.output.print("\nSecret types found:");
                    for (secret_type, count) in &result.summary.by_type {
                        ctx.output.print(&format!("  {}: {}", secret_type, count));
                    }

                    if result.summary.verified_secrets > 0 {
                        ctx.output.warn(&format!(
                            "{} secrets verified as active!",
                            result.summary.verified_secrets
                        ));
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

    #[test]
    fn test_secret_finding_display() {
        let finding = SecretFinding {
            id: "1".to_string(),
            secret_type: "AWS Key".to_string(),
            severity: "high".to_string(),
            file: "config.py".to_string(),
            line: 10,
            column: Some(5),
            match_text: "AKIA...".to_string(),
            redacted_value: "AKIA****XXXX".to_string(),
            verified: Some(true),
            description: "AWS access key".to_string(),
            remediation: "Rotate the key immediately".to_string(),
        };

        assert_eq!(finding.severity(), "high");
        assert_eq!(finding.id(), "AWS Key");
    }
}
