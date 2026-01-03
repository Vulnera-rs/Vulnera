//! Background workers for the Vulnera application
//!
//! This module contains background tasks for periodic synchronization,
//! analytics cleanup, and job processing.

use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use vulnera_core::Config;
use vulnera_core::application::analytics::AnalyticsAggregationService;
use vulnera_core::infrastructure::VulneraAdvisorRepository;

/// Spawn a background worker for periodic vulnerability data synchronization
pub fn spawn_sync_worker(
    vulnerability_repository: Arc<VulneraAdvisorRepository>,
    config: &Config,
    shutdown_token: CancellationToken,
) {
    let interval_hours = config.sync.interval_hours;
    let sync_on_startup = config.sync.on_startup;

    tokio::spawn(async move {
        info!(
            interval_hours = interval_hours,
            "Vulnerability sync worker started"
        );

        if sync_on_startup {
            info!("Performing initial vulnerability sync on startup");
            if let Err(e) = vulnerability_repository.sync_all().await {
                error!(error = %e, "Initial vulnerability sync failed");
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(interval_hours * 3600));
        // Skip the first tick if we already synced on startup
        if sync_on_startup {
            interval.tick().await;
        }

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    info!("Starting periodic vulnerability sync");
                    if let Err(e) = vulnerability_repository.sync_all().await {
                        error!(error = %e, "Periodic vulnerability sync failed");
                    }
                }
                _ = shutdown_token.cancelled() => {
                    info!("Vulnerability sync worker shutting down");
                    break;
                }
            }
        }
    });
}

/// Spawn a background worker for periodic analytics data cleanup and aggregation
pub fn spawn_analytics_cleanup_worker(
    analytics_service: Arc<AnalyticsAggregationService>,
    config: &Config,
    shutdown_token: CancellationToken,
) {
    let interval_hours = config.analytics.cleanup_interval_hours;
    let cleanup_on_startup = config.analytics.cleanup_on_startup;
    let retention_days = config.analytics.event_retention_days;

    tokio::spawn(async move {
        info!(
            interval_hours = interval_hours,
            retention_days = retention_days,
            "Analytics cleanup worker started"
        );

        if cleanup_on_startup {
            info!("Performing initial analytics cleanup on startup");
            if let Err(e) = analytics_service
                .cleanup_old_events(retention_days as u32)
                .await
            {
                error!(error = %e, "Initial analytics cleanup failed");
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(interval_hours * 3600));
        if cleanup_on_startup {
            interval.tick().await;
        }

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    info!("Starting periodic analytics cleanup");
                    if let Err(e) = analytics_service.cleanup_old_events(retention_days as u32).await {
                        error!(error = %e, "Periodic analytics cleanup failed");
                    }
                }
                _ = shutdown_token.cancelled() => {
                    info!("Analytics cleanup worker shutting down");
                    break;
                }
            }
        }
    });
}
