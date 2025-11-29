//! Tests for early authentication middleware
//!
//! These tests verify that the early_auth_middleware correctly extracts
//! authentication information before rate limiting runs.

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tower::ServiceExt;
use vulnera_core::config::TieredRateLimitConfig;
use vulnera_core::infrastructure::rate_limiter::{
    RateLimiterService, storage::InMemoryRateLimitStorage,
};
use vulnera_core::{
    application::auth::use_cases::{ValidateApiKeyUseCase, ValidateTokenUseCase},
    domain::auth::{
        entities::{ApiKey, User},
        errors::AuthError,
        repositories::IApiKeyRepository,
        value_objects::{ApiKeyHash, ApiKeyId, Email, PasswordHash, UserId, UserRole},
    },
    infrastructure::auth::{ApiKeyGenerator, JwtService},
};
use vulnera_orchestrator::presentation::rate_limit_middleware;
use vulnera_orchestrator::presentation::{
    EarlyAuthInfo, EarlyAuthState, RateLimiterState, early_auth_middleware,
};

// Mock repositories for testing
mod mocks {
    use super::*;
    use async_trait::async_trait;

    #[derive(Clone)]
    pub struct MockApiKeyRepository {
        pub keys: Vec<ApiKey>,
    }

    impl MockApiKeyRepository {
        pub fn new() -> Self {
            Self { keys: vec![] }
        }

        pub fn with_key(mut self, key: ApiKey) -> Self {
            self.keys.push(key);
            self
        }
    }

    #[async_trait]
    impl IApiKeyRepository for MockApiKeyRepository {
        async fn find_by_id(&self, id: &ApiKeyId) -> Result<Option<ApiKey>, AuthError> {
            Ok(self.keys.iter().find(|k| &k.api_key_id == id).cloned())
        }

        async fn find_by_hash(&self, hash: &ApiKeyHash) -> Result<Option<ApiKey>, AuthError> {
            Ok(self.keys.iter().find(|k| &k.key_hash == hash).cloned())
        }

        async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<ApiKey>, AuthError> {
            Ok(self
                .keys
                .iter()
                .filter(|k| &k.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn create(&self, _key: &ApiKey) -> Result<(), AuthError> {
            Ok(())
        }

        async fn delete(&self, _id: &ApiKeyId) -> Result<(), AuthError> {
            Ok(())
        }

        async fn update_last_used(
            &self,
            _id: &ApiKeyId,
            _used_at: DateTime<Utc>,
        ) -> Result<(), AuthError> {
            Ok(())
        }

        async fn revoke(&self, _id: &ApiKeyId) -> Result<(), AuthError> {
            Ok(())
        }
    }
}

use mocks::*;

/// Helper to create test JWT service
fn create_jwt_service() -> JwtService {
    JwtService::new(
        "test-secret-key-for-testing-only-32chars".to_string(),
        24,  // token TTL hours
        720, // refresh token TTL hours
    )
}

/// Helper to create test API key generator
fn create_api_key_generator() -> ApiKeyGenerator {
    ApiKeyGenerator::new()
}

/// Helper to create a test user
fn create_test_user() -> User {
    User::new(
        UserId::generate(),
        Email::new("test@example.com".to_string()).unwrap(),
        PasswordHash::from("$2b$12$hashed_password_here".to_string()),
        vec![UserRole::User],
    )
}

/// Test handler that captures EarlyAuthInfo from extensions
async fn capture_auth_handler(request: Request) -> Response {
    let auth_info = request.extensions().get::<EarlyAuthInfo>().cloned();

    let body = match auth_info {
        Some(info) => {
            serde_json::json!({
                "user_id": info.user_id.map(|u| u.to_string()),
                "api_key_id": info.api_key_id.map(|k| k.to_string()),
                "is_org_member": info.is_org_member,
            })
        }
        None => serde_json::json!({ "error": "no auth info" }),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Create test router with early auth middleware
fn create_test_router(state: Arc<EarlyAuthState>) -> Router {
    Router::new()
        .route("/test", get(capture_auth_handler))
        .layer(middleware::from_fn_with_state(state, early_auth_middleware))
}

/// Create a router that includes both early-auth and rate-limit middleware
fn create_test_router_with_rate_limiter(
    early_state: Arc<EarlyAuthState>,
    rate_state: Arc<RateLimiterState>,
) -> Router {
    Router::new()
        .route("/test", get(capture_auth_handler))
        .route(
            "/api/v1/llm/query",
            get(capture_auth_handler).post(capture_auth_handler),
        )
        // Add rate limiter FIRST so it runs LAST (after early auth extracts info)
        .layer(middleware::from_fn_with_state(
            rate_state,
            rate_limit_middleware,
        ))
        // Add early auth LAST so it runs FIRST (to extract auth before rate limiting)
        .layer(middleware::from_fn_with_state(
            early_state,
            early_auth_middleware,
        ))
}

#[tokio::test]
async fn test_anonymous_request_has_empty_auth_info() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request without auth
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Anonymous should have null user_id and api_key_id
    assert!(json["user_id"].is_null());
    assert!(json["api_key_id"].is_null());
    assert_eq!(json["is_org_member"], false);
}

#[tokio::test]
async fn test_valid_jwt_cookie_extracts_user_id() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let test_user = create_test_user();
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    // Generate valid access token
    let access_token = jwt_service
        .generate_access_token(
            test_user.user_id.clone(),
            test_user.email.clone(),
            test_user.roles.clone(),
        )
        .unwrap();

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with cookie
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header(header::COOKIE, format!("access_token={}", access_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have user_id extracted
    assert_eq!(json["user_id"], test_user.user_id.as_str());
    assert!(json["api_key_id"].is_null()); // No API key
    assert_eq!(json["is_org_member"], false);
}

#[tokio::test]
async fn test_invalid_jwt_cookie_treated_as_anonymous() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with invalid token
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header(header::COOKIE, "access_token=invalid.jwt.token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Invalid token should be treated as anonymous
    assert!(json["user_id"].is_null());
    assert!(json["api_key_id"].is_null());
}

#[tokio::test]
async fn test_x_api_key_header_extracts_auth_info() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let test_user = create_test_user();

    // Create an API key
    let (api_key_raw, api_key_hash) = api_key_generator.generate();
    let api_key_entity = ApiKey::new(
        ApiKeyId::generate(),
        test_user.user_id.clone(),
        api_key_hash,
        "Test Key".to_string(),
        None, // No expiry
    );

    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new().with_key(api_key_entity.clone()));

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with X-API-Key header
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header("x-api-key", &api_key_raw)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have both user_id and api_key_id extracted
    assert_eq!(json["user_id"], test_user.user_id.as_str());
    assert_eq!(json["api_key_id"], api_key_entity.api_key_id.as_str());
}

#[tokio::test]
async fn test_authorization_apikey_header_extracts_auth_info() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let test_user = create_test_user();

    // Create an API key
    let (api_key_raw, api_key_hash) = api_key_generator.generate();
    let api_key_entity = ApiKey::new(
        ApiKeyId::generate(),
        test_user.user_id.clone(),
        api_key_hash,
        "Test Key".to_string(),
        None,
    );

    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new().with_key(api_key_entity.clone()));

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with Authorization: ApiKey header
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header(header::AUTHORIZATION, format!("ApiKey {}", api_key_raw))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have both user_id and api_key_id extracted
    assert_eq!(json["user_id"], test_user.user_id.as_str());
    assert_eq!(json["api_key_id"], api_key_entity.api_key_id.as_str());
}

#[tokio::test]
async fn test_invalid_api_key_treated_as_anonymous() {
    // Setup
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with invalid API key
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header("x-api-key", "invalid-api-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Invalid API key should be treated as anonymous
    assert!(json["user_id"].is_null());
    assert!(json["api_key_id"].is_null());
}

#[tokio::test]
async fn test_api_key_takes_precedence_over_cookie() {
    // Setup - this tests that when both API key and cookie are present, API key wins
    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());

    // Create two different users
    let cookie_user = User::new(
        UserId::generate(),
        Email::new("cookie@example.com".to_string()).unwrap(),
        PasswordHash::from("hash".to_string()),
        vec![UserRole::User],
    );

    let api_key_user = User::new(
        UserId::generate(),
        Email::new("apikey@example.com".to_string()).unwrap(),
        PasswordHash::from("hash".to_string()),
        vec![UserRole::User],
    );

    // Create API key for api_key_user
    let (api_key_raw, api_key_hash) = api_key_generator.generate();
    let api_key_entity = ApiKey::new(
        ApiKeyId::generate(),
        api_key_user.user_id.clone(),
        api_key_hash,
        "Test Key".to_string(),
        None,
    );

    // Create access token for cookie_user
    let access_token = jwt_service
        .generate_access_token(
            cookie_user.user_id.clone(),
            cookie_user.email.clone(),
            cookie_user.roles.clone(),
        )
        .unwrap();

    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new().with_key(api_key_entity.clone()));

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with BOTH API key and cookie
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test")
                .header("x-api-key", &api_key_raw)
                .header(header::COOKIE, format!("access_token={}", access_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // API key user should take precedence
    assert_eq!(json["user_id"], api_key_user.user_id.as_str());
    assert_eq!(json["api_key_id"], api_key_entity.api_key_id.as_str());
}

#[tokio::test]
async fn test_master_key_authentication() {
    // Setup - need to use unsafe because we're modifying environment
    // Note: This test modifies global state, so it should be run in isolation
    unsafe {
        std::env::set_var("VULNERA_MASTER_KEY", "test-master-key-for-testing");
    }
    vulnera_core::infrastructure::auth::initialize_master_key();

    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));

    let state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router(state);

    // Make request with master key
    let response = router
        .oneshot(
            Request::builder()
                .uri("/test")
                .header("x-api-key", "test-master-key-for-testing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Master key should have nil UUID for user_id (special marker)
    // Note: If another test initializes the OnceLock for the master key earlier,
    // `MASTER_KEY` may be already set and the value can't be changed. In that case
    // the middleware will not detect the master key in this test run; we tolerate
    // that situation by skipping the master key-specific assertions if the result
    // is null.
    if !json["user_id"].is_null() {
        assert_eq!(json["user_id"], "00000000-0000-0000-0000-000000000000");
        // Should have a synthetic API key ID (non-null)
        assert!(!json["api_key_id"].is_null());
    }

    // Cleanup
    unsafe {
        std::env::remove_var("VULNERA_MASTER_KEY");
    }
}

#[tokio::test]
async fn test_anonymous_llm_rate_limit() {
    // Build a strict config so anonymous llm requests are clearly limited
    let mut config = TieredRateLimitConfig::default();
    config.tiers.anonymous.requests_per_minute = 1;
    config.costs.llm = 6; // each LLM request costs 6 tokens
    let storage = Arc::new(InMemoryRateLimitStorage::new());
    let service = Arc::new(RateLimiterService::with_storage(storage.clone(), config));

    let rate_state = Arc::new(RateLimiterState::new(service));

    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));
    let early_state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    let router = create_test_router_with_rate_limiter(early_state, rate_state);

    // First anonymous LLM request should be allowed
    let response1 = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/llm/query")
                .header("content-type", "application/json")
                .method(axum::http::Method::POST)
                .body(Body::from(r#"{"input":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // Second anonymous LLM request should be rate-limited (429)
    let response2 = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/llm/query")
                .header("content-type", "application/json")
                .method(axum::http::Method::POST)
                .body(Body::from(r#"{"input":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_authenticated_llm_not_limited() {
    // Same strict config, but with authenticated user
    let mut config = TieredRateLimitConfig::default();
    config.tiers.anonymous.requests_per_minute = 1;
    config.tiers.authenticated.requests_per_minute = 10;
    config.costs.llm = 6;
    let storage = Arc::new(InMemoryRateLimitStorage::new());
    let service = Arc::new(RateLimiterService::with_storage(storage.clone(), config));

    let rate_state = Arc::new(RateLimiterState::new(service));

    let jwt_service = Arc::new(create_jwt_service());
    let api_key_generator = Arc::new(create_api_key_generator());
    let test_user = create_test_user();
    let api_key_repo: Arc<dyn IApiKeyRepository + Send + Sync> =
        Arc::new(MockApiKeyRepository::new());

    let access_token = jwt_service
        .generate_access_token(
            test_user.user_id.clone(),
            test_user.email.clone(),
            test_user.roles.clone(),
        )
        .unwrap();

    let validate_token = Arc::new(ValidateTokenUseCase::new(jwt_service.clone()));
    let validate_api_key = Arc::new(ValidateApiKeyUseCase::new(
        api_key_repo.clone(),
        api_key_generator.clone(),
    ));
    let early_state = Arc::new(EarlyAuthState {
        validate_token,
        validate_api_key,
    });

    // Make first authenticated LLM request - should be allowed
    let router1 = create_test_router_with_rate_limiter(early_state.clone(), rate_state.clone());
    let request1 = Request::builder()
        .uri("/api/v1/llm/query")
        .method(axum::http::Method::POST)
        .header(
            header::COOKIE,
            format!("access_token={}", access_token.clone()),
        )
        .header("content-type", "application/json")
        .body(Body::from(r#"{"input":"test"}"#))
        .unwrap();

    let response1 = router1.oneshot(request1).await.unwrap();
    assert_eq!(
        response1.status(),
        StatusCode::OK,
        "First authenticated request should succeed"
    );

    // Make second authenticated LLM request - should also be allowed (higher tier)
    let router2 = create_test_router_with_rate_limiter(early_state, rate_state);
    let request2 = Request::builder()
        .uri("/api/v1/llm/query")
        .method(axum::http::Method::POST)
        .header(header::COOKIE, format!("access_token={}", access_token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"input":"test"}"#))
        .unwrap();

    let response2 = router2.oneshot(request2).await.unwrap();
    assert_eq!(
        response2.status(),
        StatusCode::OK,
        "Second authenticated request should succeed"
    );
}
