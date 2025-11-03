//! Route definitions and server setup

use crate::Config;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::presentation::{
    controllers::{
        analysis::{
            AppState, analyze_dependencies, get_analysis_report, get_popular_packages,
            get_vulnerability, list_vulnerabilities, refresh_vulnerability_cache,
        },
        health::{health_check, metrics},
    },
    middleware::{
        ghsa_token_middleware, https_enforcement_middleware, logging_middleware,
        rate_limit_middleware, security_headers_middleware, RateLimiterState,
    },
    models::*,
};
use std::sync::Arc;

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::presentation::controllers::analysis::analyze_dependencies,
    crate::presentation::controllers::analysis::analyze_repository,
        crate::presentation::controllers::analysis::get_vulnerability,
        crate::presentation::controllers::analysis::list_vulnerabilities,
        crate::presentation::controllers::analysis::refresh_vulnerability_cache,
        crate::presentation::controllers::analysis::get_analysis_report,
        crate::presentation::controllers::analysis::get_popular_packages,
        crate::presentation::controllers::health::health_check,

        crate::presentation::controllers::health::metrics
    ),
    components(
        schemas(
            AnalysisRequest,
            AnalysisResponse,
            VulnerabilityDto,
            VulnerabilityListResponse,
            AffectedPackageDto,
            AnalysisMetadataDto,
            SeverityBreakdownDto,
            PaginationDto,
            ErrorResponse,
            HealthResponse,
            VersionRecommendationDto,
            RepositoryAnalysisRequest,
            RepositoryAnalysisResponse,
            RepositoryFileResultDto,
            RepositoryPackageDto,
            RepositoryAnalysisMetadataDto,
            RepositoryConfigCapsDto,
            RepositoryDescriptorDto
        )
    ),
    tags(
    (name = "analysis", description = "Vulnerability analysis endpoints for dependency files and repositories"),
        (name = "vulnerabilities", description = "Vulnerability information and lookup endpoints"),
        (name = "health", description = "System health monitoring and metrics endpoints")
    ),
    info(
        title = "Vulnera API",
        version = "1.0.0",
        description = "A comprehensive vulnerability analysis API for multiple programming language ecosystems. Supports analysis of dependency files from npm, PyPI, Maven, Cargo, Go modules, and Composer ecosystems.",
        license(
            name = "AGPL-3.0",
            url = "https://www.gnu.org/licenses/agpl-3.0.html"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),

        (url = "VULNERA__SERVER__HOST", description = "Production server")
    ),
    external_docs(
        description = "Find more information about Vulnera",
        url = "https://github.com/k5602/Vulnera"
    )
)]
pub struct ApiDoc;

/// Create the application router with comprehensive middleware stack
pub fn create_router(app_state: AppState, config: &Config) -> Router {
    let api_routes = Router::new()
        .route("/analyze", post(analyze_dependencies))
        .route(
            "/analyze/repository",
            post(crate::presentation::controllers::analysis::analyze_repository),
        )
        .route("/vulnerabilities", get(list_vulnerabilities))
        .route(
            "/vulnerabilities/refresh-cache",
            post(refresh_vulnerability_cache),
        )
        .route("/vulnerabilities/{id}", get(get_vulnerability))
        .route("/reports/{id}", get(get_analysis_report))
        .route("/popular", get(get_popular_packages));

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics));

    // Build CORS layer from configuration
    let cors_layer =
        if config.server.allowed_origins.len() == 1 && config.server.allowed_origins[0] == "*" {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                    axum::http::HeaderName::from_static("x-ghsa-token"),
                    axum::http::HeaderName::from_static("x-github-token"),
                ])
                .allow_credentials(false)
                .max_age(Duration::from_secs(3600))
        } else {
            let mut layer = CorsLayer::new();
            for origin in &config.server.allowed_origins {
                match axum::http::HeaderValue::from_str(origin) {
                    Ok(origin_header) => {
                        layer = layer.allow_origin(origin_header);
                    }
                    Err(_) => {
                        tracing::warn!(origin, "Invalid CORS origin in config; skipping");
                    }
                }
            }
            layer
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::ACCEPT,
                    axum::http::header::USER_AGENT,
                    axum::http::header::ORIGIN,
                    axum::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                    axum::http::HeaderName::from_static("x-ghsa-token"),
                    axum::http::HeaderName::from_static("x-github-token"),
                ])
                .allow_credentials(false)
                .max_age(Duration::from_secs(3600))
        };
    let mut router = Router::new()
        .nest("/api/v1", api_routes)
        .merge(health_routes);

    // Conditionally expose Swagger UI based on configuration (avoid leaking docs in production).
    if config.server.enable_docs {
        router =
            router.merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()));
    }

    let service_builder = ServiceBuilder::new()
        // HTTP tracing
        .layer(TraceLayer::new_for_http())
        // CORS handling
        .layer(cors_layer)
        // Request timeout (30 seconds)
        .layer(TimeoutLayer::new(Duration::from_secs(
            config.server.request_timeout_seconds,
        )))
        // Per-request GHSA token middleware (must run before handlers)
        .layer(middleware::from_fn(ghsa_token_middleware))
        // Custom logging middleware
        .layer(middleware::from_fn(logging_middleware));

    // Conditionally add security headers middleware
    if config.server.security.enable_security_headers {
        router = router.layer(middleware::from_fn(security_headers_middleware));
    }

    // Conditionally add HTTPS enforcement middleware
    if config.server.security.enforce_https {
        router = router.layer(middleware::from_fn(https_enforcement_middleware));
    }

    // Conditionally add rate limiting middleware
    if config.server.rate_limit.enabled {
        let rate_limiter_state = Arc::new(RateLimiterState::new(config.server.rate_limit.clone()));
        router = router
            .layer(middleware::from_fn_with_state(
                rate_limiter_state.clone(),
                rate_limit_middleware,
            ));
    }

    router
        // Serve documentation resources
        .layer(service_builder)
        .with_state(app_state)
}
