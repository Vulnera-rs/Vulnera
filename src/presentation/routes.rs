//! Route definitions and server setup

use crate::Config;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::presentation::{
    auth::{
        controller::{
            AuthAppState, create_api_key, list_api_keys, login, refresh_token, register,
            revoke_api_key,
        },
        extractors::AuthState,
    },
    controllers::{
        analysis::{
            AppState, analyze_dependencies, get_analysis_report, get_popular_packages,
            get_vulnerability, list_vulnerabilities, refresh_vulnerability_cache,
        },
        health::{health_check, metrics},
    },
    middleware::{
        RateLimiterState, ghsa_token_middleware, https_enforcement_middleware, logging_middleware,
        rate_limit_middleware, security_headers_middleware,
    },
    models::*,
};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
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
        crate::presentation::controllers::health::metrics,
        crate::presentation::auth::controller::login,
        crate::presentation::auth::controller::register,
        crate::presentation::auth::controller::refresh_token,
        crate::presentation::auth::controller::create_api_key,
        crate::presentation::auth::controller::list_api_keys,
        crate::presentation::auth::controller::revoke_api_key
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
            RepositoryDescriptorDto,
            crate::presentation::auth::models::LoginRequest,
            crate::presentation::auth::models::RegisterRequest,
            crate::presentation::auth::models::TokenResponse,
            crate::presentation::auth::models::RefreshRequest,
            crate::presentation::auth::models::CreateApiKeyRequest,
            crate::presentation::auth::models::ApiKeyResponse,
            crate::presentation::auth::models::ApiKeyListResponse,
            crate::presentation::auth::models::ApiKeyListItem,
            crate::domain::auth::value_objects::UserRole
        )
    ),
    tags(
    (name = "analysis", description = "Vulnerability analysis endpoints for dependency files and repositories"),
        (name = "vulnerabilities", description = "Vulnerability information and lookup endpoints"),
        (name = "health", description = "System health monitoring and metrics endpoints"),
        (name = "auth", description = "Authentication and authorization endpoints")
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

/// Middleware to inject AuthState into request extensions
async fn inject_auth_state_middleware(
    State(app_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Create AuthState from AppState and inject into extensions
    let auth_state = AuthState {
        validate_token: app_state.validate_token_use_case.clone(),
        validate_api_key: app_state.validate_api_key_use_case.clone(),
        user_repository: app_state.user_repository.clone(),
        api_key_repository: app_state.api_key_repository.clone(),
        api_key_generator: app_state.api_key_generator.clone(),
    };
    request.extensions_mut().insert(auth_state);
    next.run(request).await
}

/// Create the application router with comprehensive middleware stack
pub fn create_router(app_state: AppState, config: &Config) -> Router {
    // Create auth state for auth endpoints
    let auth_app_state = AuthAppState {
        login_use_case: app_state.login_use_case.clone(),
        register_use_case: app_state.register_use_case.clone(),
        refresh_token_use_case: app_state.refresh_token_use_case.clone(),
        auth_state: AuthState {
            validate_token: app_state.validate_token_use_case.clone(),
            validate_api_key: app_state.validate_api_key_use_case.clone(),
            user_repository: app_state.user_repository.clone(),
            api_key_repository: app_state.api_key_repository.clone(),
            api_key_generator: app_state.api_key_generator.clone(),
        },
        token_ttl_hours: config.auth.token_ttl_hours,
    };

    // Auth routes
    let auth_routes = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/api-keys", post(create_api_key).get(list_api_keys))
        .route(
            "/auth/api-keys/{key_id}",
            axum::routing::delete(revoke_api_key),
        )
        .with_state(auth_app_state);

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
        .route("/popular", get(get_popular_packages))
        .merge(auth_routes);

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics));

    // Build CORS layer from configuration
    let cors_layer =
        if config.server.allowed_origins.len() == 1 && config.server.allowed_origins[0] == "*" {
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
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
                    axum::http::HeaderName::from_static("x-api-key"),
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
                    axum::http::HeaderName::from_static("x-api-key"),
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
        // Inject auth state into request extensions
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            inject_auth_state_middleware,
        ))
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
        router = router.layer(middleware::from_fn_with_state(
            rate_limiter_state.clone(),
            rate_limit_middleware,
        ));
    }

    router
        // Serve documentation resources
        .layer(service_builder)
        .with_state(app_state)
}
