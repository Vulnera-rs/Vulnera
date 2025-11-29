//! Auth Command - Authentication management
//!
//! Handles login, logout, and authentication status.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{self, OutputFormat};

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
    pub server_url: String,
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
        ctx.output.info("Get one at: https://vulnera.studio/");

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

    // Validate API key format (must be at least 1 character)
    // Master keys can be any length; regular API keys should be 32+ chars
    if api_key.is_empty() {
        ctx.output.error("API key cannot be empty");
        return Ok(exit_codes::CONFIG_ERROR);
    }

    if api_key.len() < 32 {
        ctx.output
            .warn("Warning: API key is shorter than recommended (32+ characters)");
        ctx.output
            .info("Master keys are supported but should be treated as development-only");
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

    // Verify the key with the server if not offline
    if !cli.offline {
        ctx.output.info("Verifying API key with server...");

        let server_url = args
            .server
            .clone()
            .unwrap_or_else(|| ctx.server_url.clone());

        let client =
            crate::api_client::VulneraClient::with_url(server_url.clone(), Some(api_key.clone()))?;

        match client.verify_api_key().await {
            Ok(true) => {
                ctx.output.success("API key verified");
            }
            Ok(false) => {
                ctx.output
                    .warn("API key could not be verified - it may be invalid");
                ctx.output
                    .info("The key has been stored, but you may need to check it");
            }
            Err(e) => {
                ctx.output.warn(&format!("Could not verify API key: {}", e));
                ctx.output.info("Possible reasons:");
                ctx.output
                    .info("  1. Server is not reachable at the configured URL");
                ctx.output
                    .info(&format!("  2. Current server: {}", server_url));
                ctx.output
                    .info("  3. Set VULNERA_SERVER_URL to connect to a different server");
                ctx.output
                    .info("  4. Run 'vulnera auth login --help' to see options");
                ctx.output.info(&format!("Original error: {}", e));
                ctx.output.info("The key has been stored for offline use");
            }
        }
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
async fn status(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    let authenticated = ctx.credentials.has_credentials();

    let status = AuthStatus {
        authenticated,
        storage_method: ctx.credentials.storage_method().to_string(),
        server_url: ctx.server_url.clone(),
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
            ctx.output.print(&format!("Server: {}", status.server_url));

            // Check server connectivity if not offline
            if !cli.offline {
                let api_key = ctx.credentials.get_api_key().ok().flatten();
                let client =
                    crate::api_client::VulneraClient::with_url(ctx.server_url.clone(), api_key)?;

                match client.health_check().await {
                    Ok(true) => ctx.output.success("Server connection: OK"),
                    Ok(false) | Err(_) => ctx.output.warn("Server connection: Failed"),
                }
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Show credential storage information
async fn info(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    ctx.output.header("Credential Storage Information");

    ctx.output.print(&format!(
        "Current method: {}",
        ctx.credentials.storage_method()
    ));

    ctx.output
        .print("\nStorage methods (in order of preference):");
    ctx.output.print(
        "  1. OS Keychain (macOS Keychain / Linux Secret Service / Windows Credential Manager)",
    );
    ctx.output
        .print("  2. Encrypted file (~/.vulnera/credentials.enc)");

    ctx.output.print("\nEnvironment variables:");
    ctx.output
        .print("  VULNERA_API_KEY - API key for authentication");
    ctx.output
        .print("  VULNERA_SERVER_URL - Override server URL");

    if ctx.credentials.has_credentials() {
        ctx.output.success("\nCredentials are currently stored");
    } else {
        ctx.output.info("\nNo credentials stored");
    }

    Ok(exit_codes::SUCCESS)
}
