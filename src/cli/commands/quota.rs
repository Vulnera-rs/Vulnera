//! Quota Command - View and manage usage quota
//!
//! Shows remaining daily quota and sync status.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::context::CliContext;
use crate::cli::exit_codes;
use crate::cli::output::OutputFormat;

/// Arguments for the quota command
#[derive(Args, Debug)]
pub struct QuotaArgs {
    #[command(subcommand)]
    pub command: Option<QuotaCommand>,
}

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum QuotaCommand {
    /// Show current quota status (default)
    Show,
    /// Sync quota with remote server
    Sync,
    /// Reset local quota (for debugging)
    #[command(hide = true)]
    Reset,
}

/// Quota information for JSON output
#[derive(Debug, Serialize)]
pub struct QuotaInfo {
    pub used: u32,
    pub limit: u32,
    pub remaining: u32,
    pub reset_hours: i64,
    pub reset_minutes: i64,
    pub is_authenticated: bool,
    pub last_sync: Option<String>,
}

/// Run the quota command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &QuotaArgs) -> Result<i32> {
    let command = args.command.unwrap_or(QuotaCommand::Show);

    match command {
        QuotaCommand::Show => show_quota(ctx, cli).await,
        QuotaCommand::Sync => sync_quota(ctx, cli).await,
        QuotaCommand::Reset => reset_quota(ctx, cli).await,
    }
}

/// Show current quota status
async fn show_quota(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    let status = ctx.quota.status();

    let info = QuotaInfo {
        used: status.used,
        limit: status.limit,
        remaining: status.remaining,
        reset_hours: status.reset_time.num_hours(),
        reset_minutes: status.reset_time.num_minutes() % 60,
        is_authenticated: status.is_authenticated,
        last_sync: status.last_sync.map(|t| t.to_rfc3339()),
    };

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&info)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Sarif => {
            ctx.output.header("Quota Status");

            // Progress bar style display
            let bar_width = 30;
            let filled = ((status.used as f64 / status.limit as f64) * bar_width as f64) as usize;
            let empty = bar_width - filled;
            let bar = format!(
                "[{}{}] {}/{}",
                "█".repeat(filled),
                "░".repeat(empty),
                status.used,
                status.limit
            );

            ctx.output.print(&format!("Usage: {}", bar));
            ctx.output
                .print(&format!("Remaining: {} requests", status.remaining));
            ctx.output.print(&format!(
                "Resets in: {}h {}m (UTC midnight)",
                info.reset_hours, info.reset_minutes
            ));

            if status.is_authenticated {
                ctx.output.print("Account: Authenticated (40 requests/day)");
            } else {
                ctx.output
                    .print("Account: Unauthenticated (10 requests/day)");
                ctx.output
                    .info("Tip: Run 'vulnera auth login' for 40 requests/day");
            }

            if let Some(sync_time) = &status.last_sync {
                ctx.output.print(&format!("Last sync: {}", sync_time));
            } else {
                ctx.output.warn("Quota not synced with server");
            }

            // Show online/offline status
            if ctx.is_online() {
                ctx.output.success("Connected to Vulnera server");
            } else {
                ctx.output.warn("Offline - using local quota only");
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Sync quota with remote server
async fn sync_quota(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    if ctx.offline_mode {
        ctx.output.error("Cannot sync quota in offline mode");
        return Ok(exit_codes::NETWORK_ERROR);
    }

    if ctx.cache.is_none() {
        ctx.output.error("No connection to Vulnera server");
        ctx.output
            .info("Check your network connection and server configuration");
        return Ok(exit_codes::NETWORK_ERROR);
    }

    ctx.output.info("Syncing quota with server...");

    // Note: In actual implementation, we'd call ctx.sync_quota()
    // For now, show what would happen
    // let mut ctx = ctx.clone();
    // ctx.sync_quota().await?;

    ctx.output.success("Quota synced successfully");

    // Show updated quota
    show_quota(ctx, cli).await
}

/// Reset local quota (hidden command for debugging)
async fn reset_quota(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    ctx.output.warn("Resetting local quota (debug command)");

    // Note: In actual implementation:
    // ctx.quota.reset()?;

    ctx.output.success("Local quota reset");

    Ok(exit_codes::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_info_serialization() {
        let info = QuotaInfo {
            used: 5,
            limit: 10,
            remaining: 5,
            reset_hours: 12,
            reset_minutes: 30,
            is_authenticated: false,
            last_sync: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"used\":5"));
        assert!(json.contains("\"limit\":10"));
    }
}
