//! Route definitions and server setup

use axum::{Router, response::IntoResponse};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::presentation::{
    controllers::{
        OrchestratorState, analyze,
        health::{health_check, metrics},
        jobs::get_job,
    },
    models::{
        AnalysisRequest, ErrorResponse, HealthResponse, JobAcceptedResponse,
        JobInvocationContextDto,
    },
};

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::presentation::controllers::analyze,
        crate::presentation::controllers::jobs::get_job,
        crate::presentation::controllers::health::health_check,
        crate::presentation::controllers::health::metrics,
    ),
    components(
        schemas(
            AnalysisRequest,
            JobAcceptedResponse,
            JobInvocationContextDto,
            ErrorResponse,
            HealthResponse,
        )
    ),
    tags(
        (name = "analysis", description = "Vulnerability analysis endpoints using job-based orchestration"),
        (name = "jobs", description = "Job retrieval and status endpoints"),
        (name = "health", description = "System health monitoring and metrics endpoints")
    ),
    info(
        title = "Vulnera API",
        version = "1.0.0",
        description = "A comprehensive vulnerability analysis API for multiple programming language ecosystems.",
        license(
            name = "AGPL-3.0",
            url = "https://www.gnu.org/licenses/agpl-3.0.html"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "/", description = "Production server")
    ),
    external_docs(
        description = "Find more information about Vulnera",
        url = "https://github.com/Vulnera-rs/Vulnera"
    )
)]
pub struct ApiDoc;

/// Root route - redirect to docs if enabled, otherwise show API info
async fn root_handler() -> axum::response::Response {
    axum::Json(serde_json::json!({
        "name": "Vulnera API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "A comprehensive vulnerability analysis API",
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "api": "/api/v1",
            "docs": "/docs"
        }
    }))
    .into_response()
}

/// Create the application router with middleware stack
pub fn create_router(
    orchestrator_state: OrchestratorState,
    config: Arc<vulnera_infrastructure::Config>,
) -> Router {
    // Orchestrator job-based analysis route
    let api_routes = Router::new()
        .route("/analyze/job", axum::routing::post(analyze))
        .route("/jobs/{id}", axum::routing::get(get_job));

    let health_routes = Router::new()
        .route("/", axum::routing::get(root_handler))
        .route("/health", axum::routing::get(health_check))
        .route("/metrics", axum::routing::get(metrics));

    // Build CORS layer from configuration
    let cors_layer =
        if config.server.allowed_origins.len() == 1 && config.server.allowed_origins[0] == "*" {
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::any())
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                ])
                .allow_credentials(false)
                .max_age(Duration::from_secs(3600))
        } else {
            let origins: Vec<axum::http::HeaderValue> = config
                .server
                .allowed_origins
                .iter()
                .filter_map(|origin| {
                    axum::http::HeaderValue::from_str(origin)
                        .map_err(|_| {
                            tracing::warn!(origin, "Invalid CORS origin in config; skipping");
                        })
                        .ok()
                })
                .collect();

            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                ])
                .allow_credentials(true)
                .max_age(Duration::from_secs(3600))
        };

    let mut router = Router::new()
        .nest("/api/v1", api_routes)
        .merge(health_routes);

    // Conditionally expose Swagger UI based on configuration
    if config.server.enable_docs {
        router =
            router.merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }

    let service_builder = ServiceBuilder::new()
        // HTTP tracing
        .layer(TraceLayer::new_for_http())
        // CORS handling
        .layer(cors_layer)
        // Request timeout
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.server.request_timeout_seconds),
        ));

    router.layer(service_builder).with_state(orchestrator_state)
}
