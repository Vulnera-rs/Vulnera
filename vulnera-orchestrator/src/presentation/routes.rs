//! Route definitions and server setup

use axum::{
    Router, middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use vulnera_core::Config;
use vulnera_core::infrastructure::auth::CsrfService;

use crate::presentation::{
    auth::controller::{
        AuthAppState, create_api_key, list_api_keys, login, logout, refresh_token, register,
        revoke_api_key,
    },
    controllers::{
        OrchestratorState, analyze, analyze_dependencies, analyze_repository,
        health::{health_check, metrics},
        llm::{
            enrich_job_findings, explain_vulnerability, generate_code_fix, natural_language_query,
        },
    },
    middleware::{
        CsrfMiddlewareState, LlmRateLimiterState, RateLimiterState, csrf_validation_middleware,
        ghsa_token_middleware, https_enforcement_middleware, llm_rate_limit_middleware,
        logging_middleware, rate_limit_middleware, security_headers_middleware,
    },
    models::*,
};
use axum::{
    extract::{Request, State},
    middleware::Next,
};

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::presentation::controllers::analyze,
        crate::presentation::controllers::analyze_dependencies,
        crate::presentation::controllers::jobs::get_job,
        crate::presentation::controllers::health::health_check,
        crate::presentation::controllers::health::metrics,
        crate::presentation::auth::controller::login,
        crate::presentation::auth::controller::register,
        crate::presentation::auth::controller::refresh_token,
        crate::presentation::auth::controller::logout,
        crate::presentation::auth::controller::create_api_key,
        crate::presentation::auth::controller::list_api_keys,
        crate::presentation::auth::controller::revoke_api_key,
        crate::presentation::controllers::llm::generate_code_fix,
        crate::presentation::controllers::llm::explain_vulnerability,
        crate::presentation::controllers::llm::natural_language_query,
        crate::presentation::controllers::llm::enrich_job_findings
    ),
    components(
        schemas(
            AnalysisRequest,
            FinalReportResponse,
            JobAcceptedResponse,
            JobInvocationContextDto,
            JobStatusResponse,
            ErrorResponse,
            HealthResponse,
            BatchDependencyAnalysisRequest,
            BatchDependencyAnalysisResponse,
            DependencyFileRequest,
            FileAnalysisResult,
            BatchAnalysisMetadata,
            PackageDto,
            DependencyGraphDto,
            DependencyGraphNodeDto,
            DependencyGraphEdgeDto,
            VulnerabilityDto,
            AffectedPackageDto,
            AnalysisMetadataDto,
            SeverityBreakdownDto,
            VersionRecommendationDto,
            GenerateCodeFixRequest,
            CodeFixResponse,
            ExplainVulnerabilityRequest,
            ExplanationResponse,
            NaturalLanguageQueryRequest,
            NaturalLanguageQueryResponse,
            EnrichFindingsRequest,
            EnrichFindingsResponse,
            EnrichedFindingDto,
            crate::presentation::auth::models::LoginRequest,
            crate::presentation::auth::models::RegisterRequest,
            crate::presentation::auth::models::AuthResponse,
            crate::presentation::auth::models::RefreshResponse,
            crate::presentation::auth::models::LogoutResponse,
            crate::presentation::auth::models::CreateApiKeyRequest,
            crate::presentation::auth::models::ApiKeyResponse,
            crate::presentation::auth::models::ApiKeyListResponse,
            crate::presentation::auth::models::ApiKeyListItem,
            vulnera_core::domain::auth::value_objects::UserRole
        )
    ),
    tags(
        (name = "analysis", description = "Vulnerability analysis endpoints using job-based orchestration"),
        (name = "jobs", description = "Job retrieval and status endpoints"),
        (name = "dependencies", description = "Dependency analysis endpoints optimized for LSP/IDE extensions"),
        (name = "health", description = "System health monitoring and metrics endpoints"),
        (name = "auth", description = "Authentication and authorization endpoints (HttpOnly cookie-based)"),
        (name = "llm", description = "AI-powered vulnerability analysis and code generation")
    ),
    info(
        title = "Vulnera API",
        version = "1.0.0",
        description = "A comprehensive vulnerability analysis API for multiple programming language ecosystems. Supports analysis of dependency files from npm, PyPI, Maven, Cargo, Go modules, and Composer ecosystems. Uses HttpOnly cookie authentication with CSRF protection.",
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
    State(orchestrator_state): State<OrchestratorState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Create AuthState from OrchestratorState and inject into extensions
    let auth_state = orchestrator_state.auth_state.clone();
    request.extensions_mut().insert(auth_state);
    next.run(request).await
}

/// Create the application router with comprehensive middleware stack
pub fn create_router(orchestrator_state: OrchestratorState, config: Arc<Config>) -> Router {
    // Create CSRF service for auth endpoints
    let csrf_service = Arc::new(CsrfService::new(config.auth.csrf_token_bytes));

    // Create CSRF middleware state
    let csrf_middleware_state = Arc::new(CsrfMiddlewareState::new(csrf_service.clone()));

    // Create LLM rate limiter state
    let llm_rate_limiter_state = Arc::new(LlmRateLimiterState::new(config.llm.rate_limit.clone()));

    // Create auth state for auth endpoints
    let auth_app_state = AuthAppState {
        login_use_case: orchestrator_state.login_use_case.clone(),
        register_use_case: orchestrator_state.register_use_case.clone(),
        refresh_token_use_case: orchestrator_state.refresh_token_use_case.clone(),
        auth_state: orchestrator_state.auth_state.clone(),
        token_ttl_hours: config.auth.token_ttl_hours,
        csrf_service: csrf_service.clone(),
        cookie_domain: config.auth.cookie_domain.clone(),
        cookie_secure: config.auth.cookie_secure,
        cookie_same_site: config.auth.cookie_same_site.clone(),
        cookie_path: config.auth.cookie_path.clone(),
        refresh_cookie_path: config.auth.refresh_cookie_path.clone(),
    };

    // Auth routes (login/register don't need CSRF, refresh/logout do)
    // Public auth routes (no CSRF required - these establish the session)
    let public_auth_routes = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .with_state(auth_app_state.clone());

    // Protected auth routes (CSRF required for state-changing operations)
    let protected_auth_routes = Router::new()
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/logout", post(logout))
        .route("/auth/api-keys", post(create_api_key).get(list_api_keys))
        .route(
            "/auth/api-keys/{key_id}",
            axum::routing::delete(revoke_api_key),
        )
        .layer(middleware::from_fn_with_state(
            csrf_middleware_state.clone(),
            csrf_validation_middleware,
        ))
        .with_state(auth_app_state);

    // LLM routes with specific rate limiting
    let llm_routes = Router::new()
        .route("/llm/fix", post(generate_code_fix))
        .route("/llm/explain", post(explain_vulnerability))
        .route("/llm/query", post(natural_language_query))
        .route("/jobs/{job_id}/enrich", post(enrich_job_findings))
        .layer(middleware::from_fn_with_state(
            llm_rate_limiter_state,
            llm_rate_limit_middleware,
        ));

    // Orchestrator job-based analysis route (protected by CSRF for POST/PUT/DELETE)
    let api_routes = Router::new()
        .route("/analyze/job", post(analyze))
        .route("/analyze/repository", post(analyze_repository))
        .route(
            "/jobs/{id}",
            get(crate::presentation::controllers::jobs::get_job),
        )
        .route("/dependencies/analyze", post(analyze_dependencies))
        .merge(llm_routes)
        .layer(middleware::from_fn_with_state(
            csrf_middleware_state,
            csrf_validation_middleware,
        ))
        .merge(public_auth_routes)
        .merge(protected_auth_routes);

    // Root route - redirect to docs if enabled, otherwise show API info
    async fn root_handler() -> Response {
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

    let health_routes = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics));

    // Build CORS layer from configuration
    // Note: For cookie-based auth, we need allow_credentials(true) which requires
    let cors_layer = if config.server.allowed_origins.len() == 1
        && config.server.allowed_origins[0] == "*"
    {
        // Development mode: allow all origins but without credentials
        // In development, cookies may not work across origins without proper config
        tracing::warn!(
            "CORS: Using wildcard origin (*) - cookies won't work cross-origin. Configure specific origins for production."
        );
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
                axum::http::HeaderName::from_static("x-ghsa-token"),
                axum::http::HeaderName::from_static("x-github-token"),
                axum::http::HeaderName::from_static("x-api-key"),
                axum::http::HeaderName::from_static("x-csrf-token"),
            ])
            .allow_credentials(false) // Cannot use credentials with wildcard origin
            .max_age(Duration::from_secs(3600))
    } else {
        // Production mode: specific origins with credentials enabled
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
                axum::http::HeaderName::from_static("x-ghsa-token"),
                axum::http::HeaderName::from_static("x-github-token"),
                axum::http::HeaderName::from_static("x-api-key"),
                axum::http::HeaderName::from_static("x-csrf-token"),
            ])
            .allow_credentials(true) // Enable credentials for cookie-based auth
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
            orchestrator_state.clone(),
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
        .with_state(orchestrator_state)
}
