//! Vulnera CLI - Standalone vulnerability analysis tool
//!
//! This crate provides a standalone CLI for vulnerability analysis that can be
//! distributed independently from the server. It embeds three offline-capable
//! analysis modules (SAST, secrets, API) and uses the Vulnera server API for
//! dependency vulnerability scanning.
//!
//! ## Features
//! - **Offline Analysis**: SAST, secret detection, and API security work fully offline
//! - **Online Dependency Scanning**: Uses server API for CVE database lookups
//! - **Quota Management**: 10 requests/day unauthenticated, 40 with API key
//! - **Credential Storage**: OS keyring with AES-256-GCM encrypted file fallback
//! - **CI/CD Integration**: Exit codes, SARIF output, non-interactive mode

pub mod api_client;
pub mod commands;
pub mod constants;
pub mod context;
pub mod credentials;
pub mod executor;
pub mod file_cache;
pub mod fix_generator;
pub mod manifest_cache;
pub mod output;
pub mod quota_tracker;
pub mod severity;
pub mod watcher;

pub use context::CliContext;
pub use credentials::CredentialManager;
pub use executor::AnalysisExecutor;
pub use output::{OutputFormat, OutputWriter};
pub use quota_tracker::QuotaTracker;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Vulnera - Comprehensive vulnerability analysis from the command line
#[derive(Parser, Debug)]
#[command(
    name = "vulnera",
    author = "Vulnera Team",
    version,
    about = "Comprehensive vulnerability analysis for your codebase",
    long_about = "Vulnera CLI provides offline-first vulnerability analysis including dependency \
                  scanning, SAST, secret detection, and API security analysis.\n\n\
                  Offline modules: SAST, Secrets, API Security\n\
                  Online modules: Dependency vulnerability scanning (requires server)\n\n\
                  Daily limits: 10 requests unauthenticated, 40 with API key.\n\
                  Run 'vulnera auth login' to authenticate for higher limits."
)]
pub struct Cli {
    /// Output format
    #[arg(short, long, value_enum, default_value = "table", global = true)]
    pub format: OutputFormat,

    /// CI mode: disable prompts, read credentials from env, exit with status codes
    #[arg(long, global = true, env = "VULNERA_CI")]
    pub ci: bool,

    /// Force offline mode (skip network requests, deps analysis unavailable)
    #[arg(long, global = true)]
    pub offline: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Configuration file path
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Server URL for API calls (default: https://api.vulnera.studio/)
    #[arg(long, global = true, env = "VULNERA_SERVER_URL")]
    pub server: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run full vulnerability analysis on a project
    #[command(visible_alias = "a")]
    Analyze(commands::analyze::AnalyzeArgs),

    /// Analyze dependencies for known vulnerabilities (requires server)
    #[command(visible_alias = "d")]
    Deps(commands::deps::DepsArgs),

    /// Run static analysis for security issues (SAST) - works offline
    #[command(visible_alias = "s")]
    Sast(commands::sast::SastArgs),

    /// Detect hardcoded secrets and credentials - works offline
    #[command(visible_alias = "sec")]
    Secrets(commands::secrets::SecretsArgs),

    /// Analyze API endpoints for security issues - works offline
    Api(commands::api::ApiArgs),

    /// Show or manage quota status
    #[command(visible_alias = "q")]
    Quota(commands::quota::QuotaArgs),

    /// Authentication management (login, logout, status)
    Auth(commands::auth::AuthArgs),

    /// Configuration management
    #[command(visible_alias = "cfg")]
    Config(commands::config::ConfigArgs),
}

/// Output format for CLI results
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CliOutputFormat {
    /// Pretty-printed table format (default)
    #[default]
    Table,
    /// JSON output for machine processing
    Json,
    /// Plain text output
    Plain,
    /// SARIF format for IDE/CI integration
    Sarif,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(f: CliOutputFormat) -> Self {
        match f {
            CliOutputFormat::Table => OutputFormat::Table,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Plain => OutputFormat::Plain,
            CliOutputFormat::Sarif => OutputFormat::Sarif,
        }
    }
}

/// CLI application runner
pub struct CliApp {
    cli: Cli,
    context: CliContext,
}

impl CliApp {
    /// Create a new CLI application instance
    pub async fn new() -> anyhow::Result<Self> {
        let cli = Cli::parse();
        let context = CliContext::new(&cli).await?;
        Ok(Self { cli, context })
    }

    /// Run the CLI application
    pub async fn run(self) -> anyhow::Result<i32> {
        let exit_code = match self.cli.command {
            Commands::Analyze(ref args) => {
                commands::analyze::run(&self.context, &self.cli, args).await
            }
            Commands::Deps(ref args) => commands::deps::run(&self.context, &self.cli, args).await,
            Commands::Sast(ref args) => commands::sast::run(&self.context, &self.cli, args).await,
            Commands::Secrets(ref args) => {
                commands::secrets::run(&self.context, &self.cli, args).await
            }
            Commands::Api(ref args) => commands::api::run(&self.context, &self.cli, args).await,
            Commands::Quota(ref args) => commands::quota::run(&self.context, &self.cli, args).await,
            Commands::Auth(ref args) => commands::auth::run(&self.context, &self.cli, args).await,
            Commands::Config(ref args) => {
                commands::config::run(&self.context, &self.cli, args).await
            }
        }?;

        Ok(exit_code)
    }
}

/// Exit codes for CI integration
pub mod exit_codes {
    /// Success - no issues found
    pub const SUCCESS: i32 = 0;
    /// Analysis completed with vulnerabilities found
    pub const VULNERABILITIES_FOUND: i32 = 1;
    /// Configuration or input error
    pub const CONFIG_ERROR: i32 = 2;
    /// Network error (when online mode required)
    pub const NETWORK_ERROR: i32 = 3;
    /// Quota exceeded
    pub const QUOTA_EXCEEDED: i32 = 4;
    /// Authentication required but not provided
    pub const AUTH_REQUIRED: i32 = 5;
    /// Internal error
    pub const INTERNAL_ERROR: i32 = 99;
}
