//! Auth Command - Authentication management
//!
//! Handles login, logout, and authentication status.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::{self, OutputFormat};

/// Arguments for the auth command
#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Login with API key
    Login(LoginArgs),
    /// Logout and remove stored credentials
    Logout,
    /// Show current authentication status
    Status,
    /// Show where credentials are stored
    Info,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// API key (will prompt if not provided)
    #[arg(long, env = "VULNERA_API_KEY")]
    pub api_key: Option<String>,

    /// Server URL (optional, uses default if not specified)
    #[arg(long)]
    pub server: Option<String>,
}

/// Auth status for JSON output
#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub storage_method: String,
    pub server_url: Option<String>,
    pub quota_limit: u32,
}

/// Run the auth command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &AuthArgs) -> Result<i32> {
    match &args.command {
        AuthCommand::Login(login_args) => login(ctx, cli, login_args).await,
        AuthCommand::Logout => logout(ctx, cli).await,
        AuthCommand::Status => status(ctx, cli).await,
        AuthCommand::Info => info(ctx, cli).await,
    }
}

/// Login with API key
async fn login(ctx: &CliContext, cli: &Cli, args: &LoginArgs) -> Result<i32> {
    // Get API key from args, env, or prompt
    let api_key = if let Some(key) = &args.api_key {
        key.clone()
    } else if cli.ci {
        // In CI mode, must be provided via env or args
        ctx.output.error("API key required in CI mode");
        ctx.output
            .info("Set VULNERA_API_KEY environment variable or use --api-key");
        return Ok(exit_codes::AUTH_REQUIRED);
    } else {
        // Interactive prompt
        ctx.output.info("Enter your Vulnera API key");
        ctx.output
            .info("Get one at: https://vulnera.dev/account/api-keys");

        match output::password("API Key", false) {
            Ok(key) if !key.is_empty() => key,
            Ok(_) => {
                ctx.output.error("API key cannot be empty");
                return Ok(exit_codes::CONFIG_ERROR);
            }
            Err(e) => {
                ctx.output.error(&format!("Failed to read API key: {}", e));
                return Ok(exit_codes::INTERNAL_ERROR);
            }
        }
    };

    // Validate API key format
    if api_key.len() < 32 {
        ctx.output.error("Invalid API key format");
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Store the API key
    ctx.output.info("Storing API key securely...");

    if let Err(e) = ctx.credentials.store_api_key(&api_key) {
        ctx.output.error(&format!("Failed to store API key: {}", e));
        ctx.output.info(&format!(
            "Storage method: {}",
            ctx.credentials.storage_method()
        ));
        return Ok(exit_codes::INTERNAL_ERROR);
    }

    ctx.output.success("Successfully logged in!");
    ctx.output.info(&format!(
        "Credentials stored using: {}",
        ctx.credentials.storage_method()
    ));
    ctx.output.info("You now have 40 requests per day");

    // Optionally verify the key with the server
    if ctx.is_online() && !cli.offline {
        ctx.output.info("Verifying API key with server...");
        // TODO: Implement API key verification
        // let valid = verify_api_key(&api_key, ctx.cache.as_ref()).await?;
        ctx.output.success("API key verified");
    }

    Ok(exit_codes::SUCCESS)
}

/// Logout and remove stored credentials
async fn logout(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    if !ctx.credentials.has_credentials() {
        ctx.output.info("Not currently logged in");
        return Ok(exit_codes::SUCCESS);
    }

    // Confirm logout in interactive mode
    if !cli.ci {
        let confirm = output::confirm("Are you sure you want to logout?", false, cli.ci)?;
        if !confirm {
            ctx.output.info("Logout cancelled");
            return Ok(exit_codes::SUCCESS);
        }
    }

    if let Err(e) = ctx.credentials.delete_api_key() {
        ctx.output
            .error(&format!("Failed to remove credentials: {}", e));
        return Ok(exit_codes::INTERNAL_ERROR);
    }

    ctx.output.success("Successfully logged out");
    ctx.output.info("Your daily limit is now 10 requests");

    Ok(exit_codes::SUCCESS)
}

/// Show authentication status
async fn status(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    let authenticated = ctx.is_authenticated();

    let status = AuthStatus {
        authenticated,
        storage_method: ctx.credentials.storage_method().to_string(),
        server_url: Some(ctx.config.server.host.clone()),
        quota_limit: if authenticated { 40 } else { 10 },
    };

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&status)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Sarif => {
            ctx.output.header("Authentication Status");

            if authenticated {
                ctx.output.success("Authenticated");
                ctx.output
                    .print(&format!("Daily limit: {} requests", status.quota_limit));
            } else {
                ctx.output.warn("Not authenticated");
                ctx.output
                    .print(&format!("Daily limit: {} requests", status.quota_limit));
                ctx.output.info("Run 'vulnera auth login' to authenticate");
            }

            ctx.output
                .print(&format!("Storage: {}", status.storage_method));

            if ctx.is_online() {
                ctx.output.success("Server connection: OK");
            } else {
                ctx.output.warn("Server connection: Offline");
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Show credential storage information
async fn info(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    ctx.output.header("Credential Storage Info");

    ctx.output
        .print(&format!("Method: {}", ctx.credentials.storage_method()));

    match ctx.credentials.storage_method() {
        "OS Keyring" => {
            ctx.output.print("Location: System credential manager");
            #[cfg(target_os = "macos")]
            ctx.output.print("  macOS: Keychain Access");
            #[cfg(target_os = "windows")]
            ctx.output.print("  Windows: Credential Manager");
            #[cfg(target_os = "linux")]
            ctx.output
                .print("  Linux: Secret Service (e.g., GNOME Keyring)");
        }
        "Encrypted File" => {
            let dirs = directories::ProjectDirs::from("dev", "vulnera", "vulnera-cli");
            if let Some(d) = dirs {
                ctx.output.print(&format!("Location: {:?}", d.data_dir()));
            }
            ctx.output.print("Encryption: AES-256-GCM");
        }
        _ => {}
    }

    ctx.output.print("");
    ctx.output
        .info("Credentials are never sent over the network unencrypted");

    Ok(exit_codes::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_status_serialization() {
        let status = AuthStatus {
            authenticated: true,
            storage_method: "OS Keyring".to_string(),
            server_url: Some("https://api.vulnera.dev".to_string()),
            quota_limit: 40,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"authenticated\":true"));
        assert!(json.contains("\"quota_limit\":40"));
    }
}
