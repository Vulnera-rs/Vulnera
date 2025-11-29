//! Deps Command - Dependency vulnerability analysis
//!
//! Scans project dependencies for known vulnerabilities.
//! REQUIRES server connection - cannot run offline.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::api_client::VulneraClient;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

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

    // Check if online - deps analysis REQUIRES server
    if cli.offline {
        ctx.output
            .error("Dependency analysis requires server connection");
        ctx.output
            .info("The deps command uses vulnerability databases hosted on the Vulnera server");
        ctx.output.info(
            "Remove --offline flag or use 'vulnera analyze --skip-deps' for offline analysis",
        );
        return Ok(exit_codes::NETWORK_ERROR);
    }

    // Show analysis start
    if !cli.quiet {
        ctx.output.header("Dependency Analysis");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Detect package manager and manifest
    let (manifest_file, package_manager) = detect_package_manager(&path);

    if manifest_file.is_none() {
        ctx.output.warn("No supported package manifest found");
        ctx.output
            .info("Supported: package.json, Cargo.toml, requirements.txt, pom.xml, go.mod");
        return Ok(exit_codes::SUCCESS);
    }

    // Create API client
    let api_key = ctx.credentials.get_api_key().ok().flatten();
    let client = VulneraClient::new(
        ctx.config.server.host.clone(),
        ctx.config.server.port,
        api_key,
    )?;

    // Check connectivity
    if !cli.quiet {
        ctx.output.info("Connecting to Vulnera server...");
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning dependencies..."))
    } else {
        None
    };

    if let Some(p) = &progress {
        if let Some(pm) = &package_manager {
            p.set_message(&format!("Found {} project, analyzing...", pm));
        }
    }

    // Call server API
    let api_result = client
        .analyze_dependencies(&path, package_manager.as_deref(), args.include_transitive)
        .await;

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match api_result {
        Ok(response) => {
            // Convert API response to CLI result
            let vulnerabilities: Vec<DepsVulnerability> = response
                .vulnerabilities
                .into_iter()
                .filter(|v| severity_meets_minimum(&v.severity, &args.min_severity))
                .map(|v| DepsVulnerability {
                    id: v.id,
                    severity: v.severity,
                    package: v.package,
                    version: v.version,
                    description: v.description,
                    cve: v.cve,
                    cvss_score: v.cvss_score,
                    fix_available: v.fixed_version.is_some(),
                    fixed_version: v.fixed_version,
                    references: v.references.unwrap_or_default(),
                })
                .collect();

            let dependencies: Vec<DependencyInfo> = response
                .dependencies
                .into_iter()
                .map(|d| DependencyInfo {
                    name: d.name,
                    version: d.version,
                    is_direct: d.is_direct,
                    is_dev: d.is_dev,
                    latest_version: d.latest_version,
                    is_outdated: d.is_outdated,
                })
                .collect();

            let mut summary = DepsSummary {
                total_dependencies: dependencies.len(),
                direct_dependencies: dependencies.iter().filter(|d| d.is_direct).count(),
                transitive_dependencies: dependencies.iter().filter(|d| !d.is_direct).count(),
                vulnerable_dependencies: 0,
                outdated_dependencies: dependencies.iter().filter(|d| d.is_outdated).count(),
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            };

            let mut vulnerable_packages = std::collections::HashSet::new();
            for vuln in &vulnerabilities {
                vulnerable_packages.insert(vuln.package.clone());
                match vuln.severity.to_lowercase().as_str() {
                    "critical" => summary.critical += 1,
                    "high" => summary.high += 1,
                    "medium" => summary.medium += 1,
                    "low" => summary.low += 1,
                    _ => {}
                }
            }
            summary.vulnerable_dependencies = vulnerable_packages.len();

            DepsResult {
                path: path.clone(),
                manifest_file,
                package_manager,
                dependencies,
                vulnerabilities,
                summary,
            }
        }
        Err(e) => {
            ctx.output
                .error(&format!("Dependency analysis failed: {}", e));

            // Provide helpful hints
            if e.to_string().contains("401") || e.to_string().contains("unauthorized") {
                ctx.output
                    .info("Authentication required. Run 'vulnera auth login'");
            } else if e.to_string().contains("429") {
                ctx.output
                    .info("Rate limit exceeded. Please wait or upgrade your plan");
            } else if e.to_string().contains("connection") || e.to_string().contains("network") {
                ctx.output
                    .info("Check your network connection and server URL");
            }

            return Ok(exit_codes::NETWORK_ERROR);
        }
    };

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.vulnerabilities, "vulnera-deps", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            let duration = start.elapsed();

            if result.vulnerabilities.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerable dependencies found in {} packages ({:.2}s)",
                    result.summary.total_dependencies,
                    duration.as_secs_f64()
                ));
            } else {
                ctx.output.print_findings_table(&result.vulnerabilities);

                ctx.output.print(&format!(
                    "\nSummary: {} vulnerabilities in {} packages",
                    result.vulnerabilities.len(),
                    result.summary.vulnerable_dependencies
                ));
                ctx.output.print(&format!(
                    "Severity: {} critical, {} high, {} medium, {} low",
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));

                // Show fixable count
                let fixable = result
                    .vulnerabilities
                    .iter()
                    .filter(|v| v.fix_available)
                    .count();
                if fixable > 0 {
                    ctx.output
                        .info(&format!("{} vulnerabilities have fixes available", fixable));
                }

                ctx.output.print(&format!(
                    "\nAnalyzed {} dependencies ({} direct, {} transitive) in {:.2}s",
                    result.summary.total_dependencies,
                    result.summary.direct_dependencies,
                    result.summary.transitive_dependencies,
                    duration.as_secs_f64()
                ));
            }

            // Show outdated if requested
            if args.check_outdated && result.summary.outdated_dependencies > 0 {
                ctx.output.warn(&format!(
                    "{} dependencies are outdated",
                    result.summary.outdated_dependencies
                ));
            }
        }
    }

    // Determine exit code
    if args.fail_on_vuln && !result.vulnerabilities.is_empty() {
        Ok(exit_codes::VULNERABILITIES_FOUND)
    } else {
        Ok(exit_codes::SUCCESS)
    }
}

/// Detect package manager and manifest file
fn detect_package_manager(path: &PathBuf) -> (Option<String>, Option<String>) {
    let manifests = [
        ("package.json", "npm"),
        ("package-lock.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
        ("Cargo.toml", "cargo"),
        ("requirements.txt", "pip"),
        ("Pipfile", "pipenv"),
        ("pyproject.toml", "poetry"),
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("go.mod", "go"),
        ("Gemfile", "bundler"),
        ("composer.json", "composer"),
    ];

    for (manifest, pm) in manifests {
        let manifest_path = path.join(manifest);
        if manifest_path.exists() {
            return (Some(manifest.to_string()), Some(pm.to_string()));
        }
    }

    (None, None)
}

/// Check if severity meets minimum threshold
fn severity_meets_minimum(severity: &str, minimum: &str) -> bool {
    let severity_order = |s: &str| match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    severity_order(severity) >= severity_order(minimum)
}
