//! Health check controller

use axum::{extract::State, http::StatusCode, response::Json};
use chrono::Utc;
use tokio::time::{Duration, timeout};

use crate::presentation::controllers::OrchestratorState;
use crate::presentation::models::HealthResponse;

/// Basic health check endpoint for liveness probe
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service unhealthy", body = HealthResponse)
    )
)]
pub async fn health_check(
    State(app_state): State<OrchestratorState>,
) -> (StatusCode, Json<HealthResponse>) {
    let probe_timeout = Duration::from_secs(3);
    let mut db_healthy = false;
    let mut cache_healthy = false;

    // Probe database connectivity
    if let Ok(Ok(_)) = timeout(probe_timeout, async {
        let mut conn = app_state
            .orchestrator
            .db_pool
            .acquire()
            .await
            .map_err(drop)?;
        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .map_err(drop)
    })
    .await
    {
        db_healthy = true;
    }

    // Probe cache connectivity
    if let Ok(Ok(())) = timeout(probe_timeout, app_state.orchestrator.cache_service.ping()).await {
        cache_healthy = true;
    }

    let all_healthy = db_healthy && cache_healthy;

    let details = serde_json::json!({
        "dependencies": {
            "database": if db_healthy { "healthy" } else { "unhealthy" },
            "cache": if cache_healthy { "healthy" } else { "unhealthy" },
        }
    });

    let response = HealthResponse {
        status: if all_healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
        details: Some(details),
    };

    let status = if all_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Prometheus-style metrics endpoint
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "health",
    responses(
        (status = 200, description = "metrics", content_type = "text/plain")
    )
)]
pub async fn metrics(State(app_state): State<OrchestratorState>) -> Result<String, StatusCode> {
    let mut metrics = String::new();

    // Add basic service metrics
    metrics.push_str("# HELP vulnera_info Information about the Vulnera service\n");
    metrics.push_str("# TYPE vulnera_info gauge\n");
    metrics.push_str(&format!(
        "vulnera_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    // Add cache metrics if available
    if let Ok(cache_stats) = app_state.orchestrator.cache_service.get_statistics().await {
        metrics.push_str("# HELP vulnera_cache_hits_total Total number of cache hits\n");
        metrics.push_str("# TYPE vulnera_cache_hits_total counter\n");
        metrics.push_str(&format!("vulnera_cache_hits_total {}\n", cache_stats.hits));

        metrics.push_str("# HELP vulnera_cache_misses_total Total number of cache misses\n");
        metrics.push_str("# TYPE vulnera_cache_misses_total counter\n");
        metrics.push_str(&format!(
            "vulnera_cache_misses_total {}\n",
            cache_stats.misses
        ));

        metrics.push_str("# HELP vulnera_cache_hit_rate Cache hit rate (0.0 to 1.0)\n");
        metrics.push_str("# TYPE vulnera_cache_hit_rate gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_hit_rate {}\n",
            cache_stats.hit_rate
        ));

        metrics.push_str("# HELP vulnera_cache_entries_total Total number of cache entries\n");
        metrics.push_str("# TYPE vulnera_cache_entries_total gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_entries_total {}\n",
            cache_stats.total_entries
        ));

        metrics.push_str("# HELP vulnera_cache_size_bytes Total cache size in bytes\n");
        metrics.push_str("# TYPE vulnera_cache_size_bytes gauge\n");
        metrics.push_str(&format!(
            "vulnera_cache_size_bytes {}\n",
            cache_stats.total_size_bytes
        ));
    }

    // Add uptime metric
    let uptime_seconds = app_state.startup_time.elapsed().as_secs();
    metrics.push_str("# HELP vulnera_uptime_seconds Service uptime in seconds\n");
    metrics.push_str("# TYPE vulnera_uptime_seconds counter\n");
    metrics.push_str(&format!("vulnera_uptime_seconds {}\n", uptime_seconds));

    // Add database pool metrics
    let pool_size = app_state.orchestrator.db_pool.size();
    let pool_idle = app_state.orchestrator.db_pool.num_idle();

    metrics.push_str("# HELP vulnera_db_pool_size Current number of connections in the pool\n");
    metrics.push_str("# TYPE vulnera_db_pool_size gauge\n");
    metrics.push_str(&format!("vulnera_db_pool_size {}\n", pool_size));

    metrics.push_str("# HELP vulnera_db_pool_idle Number of idle connections in the pool\n");
    metrics.push_str("# TYPE vulnera_db_pool_idle gauge\n");
    metrics.push_str(&format!("vulnera_db_pool_idle {}\n", pool_idle));

    metrics.push_str("# HELP vulnera_db_pool_active Number of active connections in the pool\n");
    metrics.push_str("# TYPE vulnera_db_pool_active gauge\n");
    metrics.push_str(&format!(
        "vulnera_db_pool_active {}\n",
        pool_size.saturating_sub(pool_idle as u32)
    ));

    Ok(metrics)
}
