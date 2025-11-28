//! Deps Command - Dependency vulnerability analysis
//!
//! Scans project dependencies for known vulnerabilities.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the deps command
#[derive(Args, Debug)]
pub struct DepsArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any vulnerability is found
    #[arg(long)]
    pub fail_on_vuln: bool,

    /// Show transitive dependencies
    #[arg(long)]
    pub include_transitive: bool,

    /// Output format for dependencies (tree, flat)
    #[arg(long, default_value = "flat")]
    pub deps_format: String,

    /// Check for outdated dependencies (not just vulnerable ones)
    #[arg(long)]
    pub check_outdated: bool,
}

/// Dependency vulnerability result
#[derive(Debug, Serialize)]
pub struct DepsResult {
    pub path: PathBuf,
    pub manifest_file: Option<String>,
    pub package_manager: Option<String>,
    pub dependencies: Vec<DependencyInfo>,
    pub vulnerabilities: Vec<DepsVulnerability>,
    pub summary: DepsSummary,
}

/// Dependency information
#[derive(Debug, Clone, Serialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: String,
    pub is_direct: bool,
    pub is_dev: bool,
    pub latest_version: Option<String>,
    pub is_outdated: bool,
}

/// Vulnerability in a dependency
#[derive(Debug, Clone, Serialize)]
pub struct DepsVulnerability {
    pub id: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub description: String,
    pub cve: Option<String>,
    pub cvss_score: Option<f32>,
    pub fix_available: bool,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
}

impl VulnerabilityDisplay for DepsVulnerability {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.cve.clone().unwrap_or_else(|| self.id.clone())
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

/// Summary of dependency analysis
#[derive(Debug, Serialize)]
pub struct DepsSummary {
    pub total_dependencies: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub vulnerable_dependencies: usize,
    pub outdated_dependencies: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Run the deps command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &DepsArgs) -> Result<i32> {
    let _start = std::time::Instant::now();

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
        ctx.output.header("Dependency Analysis");
        ctx.output.info(&format!("Scanning: {:?}", path));

        if ctx.offline_mode {
            ctx.output
                .warn("Running in offline mode - vulnerability data may be stale or incomplete");
        }
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning dependencies..."))
    } else {
        None
    };

    // Detect package manager and manifest
    let (manifest_file, package_manager) = detect_package_manager(&path);

    if let Some(p) = &progress {
        if let Some(pm) = &package_manager {
            p.set_message(&format!("Found {} project, scanning...", pm));
        }
    }

    let mut result = DepsResult {
        path: path.clone(),
        manifest_file: manifest_file.clone(),
        package_manager: package_manager.clone(),
        dependencies: Vec::new(),
        vulnerabilities: Vec::new(),
        summary: DepsSummary {
            total_dependencies: 0,
            direct_dependencies: 0,
            transitive_dependencies: 0,
            vulnerable_dependencies: 0,
            outdated_dependencies: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        },
    };

    if manifest_file.is_none() {
        if let Some(p) = progress {
            p.finish_and_clear();
        }
        ctx.output.warn("No supported package manifest found");
        ctx.output
            .info("Supported: package.json, Cargo.toml, requirements.txt, pom.xml, go.mod");
        return Ok(exit_codes::SUCCESS);
    }

    // TODO: Integrate with vulnera-deps module
    // This is a placeholder showing the expected structure
    //
    // let deps_module = DependencyAnalyzerModule::new(ctx.config.clone(), ctx.cache.clone());
    // let analysis = deps_module.analyze(&path).await?;
    // result.dependencies = analysis.dependencies;
    // result.vulnerabilities = analysis.vulnerabilities;

    if let Some(p) = &progress {
        p.set_message("Checking vulnerability databases...");
    }

    // Calculate summary
    result.summary.total_dependencies = result.dependencies.len();
    result.summary.direct_dependencies = result.dependencies.iter().filter(|d| d.is_direct).count();
    result.summary.transitive_dependencies =
        result.summary.total_dependencies - result.summary.direct_dependencies;
    result.summary.outdated_dependencies =
        result.dependencies.iter().filter(|d| d.is_outdated).count();

    for vuln in &result.vulnerabilities {
        match vuln.severity.to_lowercase().as_str() {
            "critical" => result.summary.critical += 1,
            "high" => result.summary.high += 1,
            "medium" => result.summary.medium += 1,
            "low" => result.summary.low += 1,
            _ => {}
        }
    }

    result.summary.vulnerable_dependencies = result
        .dependencies
        .iter()
        .filter(|d| {
            result
                .vulnerabilities
                .iter()
                .any(|v| v.package == d.name && v.version == d.version)
        })
        .count();

    // Finish progress
    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Output results
    output_results(ctx, cli, &result, &args)?;

    // Determine exit code
    let exit_code = if args.fail_on_vuln && !result.vulnerabilities.is_empty() {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    };

    Ok(exit_code)
}

/// Detect package manager from project files
fn detect_package_manager(path: &PathBuf) -> (Option<String>, Option<String>) {
    let checks = [
        ("package.json", "npm/yarn"),
        ("Cargo.toml", "cargo"),
        ("requirements.txt", "pip"),
        ("Pipfile", "pipenv"),
        ("pyproject.toml", "poetry/pip"),
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("go.mod", "go"),
        ("composer.json", "composer"),
        ("Gemfile", "bundler"),
    ];

    for (file, pm) in checks {
        if path.join(file).exists() {
            return (Some(file.to_string()), Some(pm.to_string()));
        }
    }

    (None, None)
}

/// Output dependency analysis results
fn output_results(ctx: &CliContext, cli: &Cli, result: &DepsResult, args: &DepsArgs) -> Result<()> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.vulnerabilities(&result.vulnerabilities)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            // Show package manager info
            if let Some(pm) = &result.package_manager {
                ctx.output.info(&format!(
                    "Package manager: {} ({})",
                    pm,
                    result.manifest_file.as_deref().unwrap_or("unknown")
                ));
            }

            // Show dependencies summary
            ctx.output.print(&format!(
                "Dependencies: {} total ({} direct, {} transitive)",
                result.summary.total_dependencies,
                result.summary.direct_dependencies,
                result.summary.transitive_dependencies
            ));

            if args.check_outdated && result.summary.outdated_dependencies > 0 {
                ctx.output.warn(&format!(
                    "{} outdated dependencies",
                    result.summary.outdated_dependencies
                ));
            }

            // Show vulnerabilities
            println!();
            ctx.output.vulnerabilities(&result.vulnerabilities)?;

            if !cli.quiet && !result.vulnerabilities.is_empty() {
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
    fn test_detect_package_manager() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("package.json"), "{}").unwrap();

        let (manifest, pm) = detect_package_manager(&temp.path().to_path_buf());
        assert_eq!(manifest, Some("package.json".to_string()));
        assert_eq!(pm, Some("npm/yarn".to_string()));
    }

    #[test]
    fn test_detect_cargo() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("Cargo.toml"), "[package]").unwrap();

        let (manifest, pm) = detect_package_manager(&temp.path().to_path_buf());
        assert_eq!(manifest, Some("Cargo.toml".to_string()));
        assert_eq!(pm, Some("cargo".to_string()));
    }
}
