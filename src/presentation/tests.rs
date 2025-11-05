use crate::{
    application::errors::VulnerabilityError,
    application::{
        reporting::ReportServiceImpl,
        vulnerability::services::{
            PopularPackageServiceImpl, VersionResolutionServiceImpl,
        },
    },
    infrastructure::cache::CacheServiceImpl,
    domain::vulnerability::entities::Package,
    infrastructure::{
        api_clients::traits::{RawVulnerability, VulnerabilityApiClient},
        cache::file_cache::FileCacheRepository,
        parsers::ParserFactory,
        registries::MultiplexRegistryClient,
        repositories::AggregatingVulnerabilityRepository,
    },
    presentation::{AppState, create_router},
};
use async_trait::async_trait;
use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

// Mock API client for testing
struct MockApiClient;

#[async_trait]
impl VulnerabilityApiClient for MockApiClient {
    async fn query_vulnerabilities(
        &self,
        _package: &Package,
    ) -> Result<Vec<RawVulnerability>, VulnerabilityError> {
        Ok(vec![])
    }

    async fn get_vulnerability_details(
        &self,
        _id: &str,
    ) -> Result<Option<RawVulnerability>, VulnerabilityError> {
        Ok(None)
    }
}

async fn dummy_state() -> AppState {
    let cache_repo = Arc::new(FileCacheRepository::new(
        std::path::PathBuf::from(".vulnera_cache_test"),
        Duration::from_secs(60),
    ));
    let cache_service = Arc::new(CacheServiceImpl::new(cache_repo));
    let parser_factory = Arc::new(ParserFactory::new());

    // Create mock API clients
    let mock_client = Arc::new(MockApiClient);
    let vuln_repo = Arc::new(AggregatingVulnerabilityRepository::new(
        mock_client.clone(),
        mock_client.clone(),
        mock_client,
    ));

    let config = crate::config::Config::default();
    // Create vulnerability analysis use cases
    let analyze_dependencies_use_case = Arc::new(
        crate::application::vulnerability::AnalyzeDependenciesUseCase::new(
            parser_factory.clone(),
            vuln_repo.clone(),
            cache_service.clone(),
            config.analysis.max_concurrent_packages,
        ),
    );
    let get_vulnerability_details_use_case = Arc::new(
        crate::application::vulnerability::GetVulnerabilityDetailsUseCase::new(
            vuln_repo.clone(),
            cache_service.clone(),
        ),
    );
    let report_service = Arc::new(ReportServiceImpl::new());

    // Create popular package service with test config
    let config_arc = Arc::new(crate::Config::default());
    let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
        vuln_repo.clone(),
        cache_service.clone(),
        config_arc.clone(),
    ));
    let list_vulnerabilities_use_case = Arc::new(
        crate::application::vulnerability::ListVulnerabilitiesUseCase::new(
            popular_package_service.clone(),
        ),
    );
    // Provide a simple version resolution service for tests
    let version_resolution_service = Arc::new(VersionResolutionServiceImpl::new(Arc::new(
        MultiplexRegistryClient::new(),
    )));

    // Create a minimal PostgreSQL pool for tests
    // Note: These presentation tests don't actually use the database, so we use connect_lazy
    // which defers the connection until it's actually needed (which won't happen in these tests)
    use sqlx::postgres::PgConnectOptions;
    use sqlx::postgres::PgPoolOptions;
    let db_pool = Arc::new(
        PgPoolOptions::new().max_connections(1).connect_lazy_with(
            "postgres://postgres:postgres@localhost/vulnera_test"
                .parse::<PgConnectOptions>()
                .unwrap(),
        ),
    );

    let user_repository: Arc<dyn crate::domain::auth::repositories::IUserRepository> = Arc::new(
        crate::infrastructure::auth::SqlxUserRepository::new(db_pool.clone()),
    );
    let api_key_repository: Arc<dyn crate::domain::auth::repositories::IApiKeyRepository> =
        Arc::new(crate::infrastructure::auth::SqlxApiKeyRepository::new(
            db_pool.clone(),
        ));

    let jwt_service = Arc::new(crate::infrastructure::auth::JwtService::new(
        "test-secret-key-for-testing-only".to_string(),
        24,
        720,
    ));
    let password_hasher = Arc::new(crate::infrastructure::auth::PasswordHasher::new());
    let api_key_generator = Arc::new(crate::infrastructure::auth::ApiKeyGenerator::new());

    let login_use_case = Arc::new(crate::application::auth::use_cases::LoginUseCase::new(
        user_repository.clone(),
        password_hasher.clone(),
        jwt_service.clone(),
    ));
    let register_use_case = Arc::new(
        crate::application::auth::use_cases::RegisterUserUseCase::new(
            user_repository.clone(),
            password_hasher.clone(),
            jwt_service.clone(),
        ),
    );
    let validate_token_use_case = Arc::new(
        crate::application::auth::use_cases::ValidateTokenUseCase::new(jwt_service.clone()),
    );
    let refresh_token_use_case = Arc::new(
        crate::application::auth::use_cases::RefreshTokenUseCase::new(
            jwt_service.clone(),
            user_repository.clone(),
        ),
    );
    let validate_api_key_use_case = Arc::new(
        crate::application::auth::use_cases::ValidateApiKeyUseCase::new(
            api_key_repository.clone(),
            api_key_generator.clone(),
        ),
    );

    AppState {
        analyze_dependencies_use_case,
        get_vulnerability_details_use_case,
        list_vulnerabilities_use_case,
        cache_service,
        report_service,
        vulnerability_repository: vuln_repo,
        popular_package_service,
        repository_analysis_service: None,
        version_resolution_service,
        config: config_arc,
        startup_time: std::time::Instant::now(),
        db_pool,
        user_repository,
        api_key_repository,
        jwt_service,
        password_hasher,
        api_key_generator,
        login_use_case,
        register_use_case,
        validate_token_use_case,
        refresh_token_use_case,
        validate_api_key_use_case,
    }
}

#[tokio::test]
async fn docs_disabled_returns_404() {
    let mut config = crate::Config::default();
    config.server.enable_docs = false;
    let app = create_router(dummy_state().await, &config);
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/docs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn docs_enabled_returns_ok() {
    let mut config = crate::Config::default();
    config.server.enable_docs = true;
    let app = create_router(dummy_state().await, &config);
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/docs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    //note: Swagger UI may redirect (303) before serving index depending on version
    assert!(
        matches!(response.status(), StatusCode::OK | StatusCode::SEE_OTHER),
        "unexpected status: {}",
        response.status()
    );
}

#[tokio::test]
async fn repository_analysis_disabled_returns_error() {
    let mut config = crate::Config::default();
    config.server.enable_docs = false;
    let app = create_router(dummy_state().await, &config);
    let body = serde_json::json!({"repository_url": "https://github.com/rust-lang/cargo"});
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/analyze/repository")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_server_error() || response.status().is_client_error());
}
