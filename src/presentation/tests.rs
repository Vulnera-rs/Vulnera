use crate::{
    application::errors::VulnerabilityError,
    application::{
        AnalysisServiceImpl, CacheServiceImpl, PopularPackageServiceImpl, ReportServiceImpl,
        VersionResolutionServiceImpl,
    },
    domain::Package,
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

fn dummy_state() -> AppState {
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
    let analysis_service = Arc::new(AnalysisServiceImpl::new(
        parser_factory,
        vuln_repo.clone(),
        cache_service.clone(),
        &config,
    ));
    let report_service = Arc::new(ReportServiceImpl::new());

    // Create popular package service with test config
    let config = Arc::new(crate::Config::default());
    let popular_package_service = Arc::new(PopularPackageServiceImpl::new(
        vuln_repo.clone(),
        cache_service.clone(),
        config,
    ));
    // Provide a simple version resolution service for tests
    let version_resolution_service = Arc::new(VersionResolutionServiceImpl::new(Arc::new(
        MultiplexRegistryClient::new(),
    )));

    let config = Arc::new(crate::Config::default());
    
    // Note: For tests, auth-related fields are required but won't be used in existing tests.
    // In a real test scenario, you would set up a test database or use mocks.
    // For now, we'll create minimal implementations that satisfy the type system.
    // TODO: Create proper test database setup or mock implementations for auth services
    
    // Create a minimal PostgreSQL pool for tests (this will fail if DB is not available)
    // In practice, tests should use a test database or mocks
    // Note: This is a sync function, so we can't use .await here
    // For now, we'll use a placeholder - tests should mock the database or use a test helper
    use sqlx::postgres::PgPoolOptions;
    let db_pool = Arc::new(
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(
                PgPoolOptions::new()
                    .max_connections(1)
                    .connect("postgres://postgres:postgres@localhost/vulnera_test")
            )
            .unwrap_or_else(|_| {
                // If DB is not available, we can't create a real pool
                // This is a limitation - tests should be run with a test database
                // For now, we'll panic - the user should set up a test database
                panic!("Test database not available. Please set up a test PostgreSQL database or use mocks.");
            })
    );
    
    let user_repository: Arc<dyn crate::domain::auth::repositories::IUserRepository> =
        Arc::new(crate::infrastructure::auth::SqlxUserRepository::new(db_pool.clone()));
    let api_key_repository: Arc<dyn crate::domain::auth::repositories::IApiKeyRepository> =
        Arc::new(crate::infrastructure::auth::SqlxApiKeyRepository::new(db_pool.clone()));
    
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
    let validate_token_use_case = Arc::new(crate::application::auth::use_cases::ValidateTokenUseCase::new(jwt_service.clone()));
    let refresh_token_use_case = Arc::new(crate::application::auth::use_cases::RefreshTokenUseCase::new(
        jwt_service.clone(),
        user_repository.clone(),
    ));
    let validate_api_key_use_case = Arc::new(crate::application::auth::use_cases::ValidateApiKeyUseCase::new(
        api_key_repository.clone(),
        api_key_generator.clone(),
    ));
    
    AppState {
        analysis_service,
        cache_service,
        report_service,
        vulnerability_repository: vuln_repo,
        popular_package_service,
        repository_analysis_service: None,
        version_resolution_service,
        config,
        startup_time: std::time::Instant::now(),
        db_pool,
        user_repository,
        api_key_repository,
        jwt_service,
        password_hasher,
        api_key_generator,
        login_use_case,
        validate_token_use_case,
        refresh_token_use_case,
        validate_api_key_use_case,
    }
}

#[tokio::test]
async fn docs_disabled_returns_404() {
    let mut config = crate::Config::default();
    config.server.enable_docs = false;
    let app = create_router(dummy_state(), &config);
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
    let app = create_router(dummy_state(), &config);
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
    let app = create_router(dummy_state(), &config);
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
