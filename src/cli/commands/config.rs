//! Config Command - Configuration management
//!
//! View and modify CLI configuration.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::OutputFormat;

/// Arguments for the config command
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Show current configuration
    Show,
    /// Show configuration file path
    Path,
    /// Set a configuration value
    Set(SetArgs),
    /// Get a configuration value
    Get(GetArgs),
    /// Reset configuration to defaults
    Reset,
    /// Initialize a new configuration file
    Init(InitArgs),
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Configuration key (e.g., "server.url", "analysis.timeout")
    pub key: String,
    /// Value to set
    pub value: String,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Configuration key to retrieve
    pub key: String,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Create config in project directory instead of user config
    #[arg(long)]
    pub local: bool,

    /// Overwrite existing configuration
    #[arg(long)]
    pub force: bool,
}

/// Configuration info for JSON output
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ConfigInfo {
    pub config_file: Option<PathBuf>,
    pub values: serde_json::Value,
}

/// Run the config command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &ConfigArgs) -> Result<i32> {
    match &args.command {
        ConfigCommand::Show => show_config(ctx, cli).await,
        ConfigCommand::Path => show_path(ctx, cli).await,
        ConfigCommand::Set(set_args) => set_config(ctx, cli, set_args).await,
        ConfigCommand::Get(get_args) => get_config(ctx, cli, get_args).await,
        ConfigCommand::Reset => reset_config(ctx, cli).await,
        ConfigCommand::Init(init_args) => init_config(ctx, cli, init_args).await,
    }
}

/// Show current configuration
async fn show_config(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            let config_value = serde_json::to_value(&*ctx.config)?;
            ctx.output.json(&config_value)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Sarif => {
            ctx.output.header("Current Configuration");

            // Server settings
            ctx.output.print("\n[Server]");
            ctx.output
                .print(&format!("  host: {}", ctx.config.server.host));
            ctx.output
                .print(&format!("  port: {}", ctx.config.server.port));

            // Analysis settings
            ctx.output.print("\n[Analysis]");
            ctx.output.print(&format!(
                "  max_concurrent_packages: {}",
                ctx.config.analysis.max_concurrent_packages
            ));

            // Cache settings
            ctx.output.print("\n[Cache]");
            ctx.output.print(&format!(
                "  dragonfly_url: {}",
                ctx.config.cache.dragonfly_url
            ));

            // Rate limit settings
            ctx.output.print("\n[Rate Limits]");
            ctx.output.print(&format!(
                "  enabled: {}",
                ctx.config.server.rate_limit.enabled
            ));
            ctx.output.print(&format!(
                "  storage_backend: {:?}",
                ctx.config.server.rate_limit.storage_backend
            ));
            ctx.output.print("\n  API Key tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .api_key
                    .requests_per_minute
            ));
            ctx.output.print(&format!(
                "    requests_per_hour: {}",
                ctx.config.server.rate_limit.tiers.api_key.requests_per_hour
            ));
            ctx.output.print("\n  Authenticated tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .authenticated
                    .requests_per_minute
            ));
            ctx.output.print("\n  Anonymous tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .anonymous
                    .requests_per_minute
            ));
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Show configuration file path
async fn show_path(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    let config_paths = get_config_paths();

    ctx.output.header("Configuration File Locations");

    ctx.output.print("\nSearch order (first found is used):");
    for (i, path) in config_paths.iter().enumerate() {
        let exists = path.exists();
        let marker = if exists { "✓" } else { " " };
        ctx.output
            .print(&format!("  {} {}. {:?}", marker, i + 1, path));
    }

    ctx.output.print("\nEnvironment variables:");
    ctx.output.print("  VULNERA__* - Override any config value");
    ctx.output.print("  Example: VULNERA__SERVER__PORT=9000");

    Ok(exit_codes::SUCCESS)
}

/// Set a configuration value
async fn set_config(ctx: &CliContext, _cli: &Cli, args: &SetArgs) -> Result<i32> {
    ctx.output.warn("Config modification not yet implemented");
    ctx.output
        .info(&format!("Would set {} = {}", args.key, args.value));

    // TODO: Implement config modification
    // 1. Load config file (or create new one)
    // 2. Parse the key path (e.g., "server.port" -> ["server", "port"])
    // 3. Update the value
    // 4. Save the config file

    Ok(exit_codes::SUCCESS)
}

/// Get a configuration value
async fn get_config(ctx: &CliContext, _cli: &Cli, args: &GetArgs) -> Result<i32> {
    let config_value = serde_json::to_value(&*ctx.config)?;

    // Navigate to the requested key
    let parts: Vec<&str> = args.key.split('.').collect();
    let mut current = &config_value;

    for part in &parts {
        match current.get(part) {
            Some(v) => current = v,
            None => {
                ctx.output
                    .error(&format!("Configuration key not found: {}", args.key));
                return Ok(exit_codes::CONFIG_ERROR);
            }
        }
    }

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(current)?;
        }
        _ => {
            ctx.output.print(&format!("{} = {}", args.key, current));
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Reset configuration to defaults
async fn reset_config(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    if !cli.ci {
        let confirm =
            crate::cli::output::confirm("Reset configuration to defaults?", false, cli.ci)?;
        if !confirm {
            ctx.output.info("Reset cancelled");
            return Ok(exit_codes::SUCCESS);
        }
    }

    // TODO: Implement config reset
    // 1. Find the config file being used
    // 2. Delete it or overwrite with defaults

    ctx.output.warn("Config reset not yet implemented");

    Ok(exit_codes::SUCCESS)
}

/// Initialize a new configuration file
async fn init_config(ctx: &CliContext, _cli: &Cli, args: &InitArgs) -> Result<i32> {
    let config_path = if args.local {
        ctx.working_dir.join(".vulnera.toml")
    } else {
        get_user_config_path()
    };

    if config_path.exists() && !args.force {
        ctx.output.error(&format!(
            "Configuration file already exists: {:?}",
            config_path
        ));
        ctx.output.info("Use --force to overwrite");
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Create default config
    let default_config = r#"# Vulnera CLI Configuration
# For full documentation, see: https://docs.vulnera.dev/cli/configuration

[server]
# Vulnera API server URL
host = "127.0.0.1"
port = 8080

[server.rate_limit]
enabled = true
storage_backend = "dragonfly"

[server.rate_limit.tiers.api_key]
requests_per_minute = 100
requests_per_hour = 2000

[server.rate_limit.tiers.authenticated]
requests_per_minute = 60
requests_per_hour = 1000

[server.rate_limit.tiers.anonymous]
requests_per_minute = 20
requests_per_hour = 100

[analysis]
# Maximum number of packages to analyze concurrently
max_concurrent_packages = 10

[cache]
# Dragonfly/Redis URL for caching vulnerability data
dragonfly_url = "redis://127.0.0.1:6379"
"#;

    // Create parent directories
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, default_config)?;

    ctx.output
        .success(&format!("Created configuration file: {:?}", config_path));
    ctx.output.info("Edit this file to customize your settings");

    Ok(exit_codes::SUCCESS)
}

/// Get possible configuration file paths
fn get_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Current directory
    paths.push(PathBuf::from(".vulnera.toml"));
    paths.push(PathBuf::from("vulnera.toml"));

    // User config directory
    if let Some(dirs) = directories::ProjectDirs::from("dev", "vulnera", "vulnera-cli") {
        paths.push(dirs.config_dir().join("config.toml"));
    }

    // System config (Unix)
    #[cfg(unix)]
    {
        paths.push(PathBuf::from("/etc/vulnera/config.toml"));
    }

    paths
}

/// Get user configuration file path
fn get_user_config_path() -> PathBuf {
    directories::ProjectDirs::from("dev", "vulnera", "vulnera-cli")
        .map(|d| d.config_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("vulnera.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_config_paths() {
        let paths = get_config_paths();
        assert!(!paths.is_empty());
        assert!(paths[0].to_string_lossy().contains("vulnera"));
    }
}
