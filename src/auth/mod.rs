//! Authentication initialization for the Vulnera application
//!
//! This module handles the setup of authentication services, repositories,
//! and use cases.

use sqlx::PgPool;
use std::sync::Arc;

use vulnera_core::Config;
use vulnera_core::application::auth::use_cases::{
    LoginUseCase, RefreshTokenUseCase, RegisterUserUseCase, ValidateApiKeyUseCase,
    ValidateTokenUseCase,
};
use vulnera_core::domain::auth::repositories::{IApiKeyRepository, IUserRepository};
use vulnera_core::domain::organization::repositories::IOrganizationMemberRepository;
use vulnera_core::infrastructure::auth::{
    ApiKeyGenerator, CacheTokenBlacklistService, JwtService, PasswordHasher, SqlxApiKeyRepository,
    SqlxOrganizationMemberRepository, SqlxUserRepository, TokenBlacklistService,
};
use vulnera_core::infrastructure::cache::CacheServiceImpl;
use vulnera_orchestrator::presentation::auth::extractors::AuthState;

/// Authentication services and use cases initialized at startup
pub struct AuthServices {
    pub login_use_case: Arc<LoginUseCase>,
    pub register_use_case: Arc<RegisterUserUseCase>,
    pub validate_token_use_case: Arc<ValidateTokenUseCase>,
    pub refresh_token_use_case: Arc<RefreshTokenUseCase>,
    pub validate_api_key_use_case: Arc<ValidateApiKeyUseCase>,
    pub token_blacklist: Arc<dyn TokenBlacklistService>,
    pub auth_state: AuthState,
}

impl AuthServices {
    /// Initialize all authentication components
    pub fn init(
        config: &Config,
        db_pool: Arc<PgPool>,
        cache_service: Arc<CacheServiceImpl>,
    ) -> Self {
        // Initialize repositories
        let user_repository: Arc<dyn IUserRepository> =
            Arc::new(SqlxUserRepository::new(db_pool.clone()));
        let api_key_repository: Arc<dyn IApiKeyRepository> =
            Arc::new(SqlxApiKeyRepository::new(db_pool.clone()));
        let organization_member_repository: Arc<dyn IOrganizationMemberRepository> =
            Arc::new(SqlxOrganizationMemberRepository::new(db_pool.clone()));

        // Initialize services
        let jwt_service = Arc::new(JwtService::new(
            config.auth.jwt_secret.clone(),
            config.auth.token_ttl_hours,
            config.auth.refresh_token_ttl_hours,
        ));
        let password_hasher = Arc::new(PasswordHasher::new());
        let api_key_generator = Arc::new(ApiKeyGenerator::new());

        // Initialize token blacklist service
        let token_blacklist: Arc<dyn TokenBlacklistService> =
            Arc::new(CacheTokenBlacklistService::new(cache_service.clone()));

        // Initialize use cases
        let login_use_case = Arc::new(LoginUseCase::new(
            user_repository.clone(),
            password_hasher.clone(),
            jwt_service.clone(),
        ));
        let register_use_case = Arc::new(RegisterUserUseCase::new(
            user_repository.clone(),
            password_hasher.clone(),
            jwt_service.clone(),
        ));
        let validate_token_use_case = Arc::new(ValidateTokenUseCase::with_blacklist(
            jwt_service.clone(),
            token_blacklist.clone(),
        ));
        let refresh_token_use_case = Arc::new(
            RefreshTokenUseCase::new(jwt_service.clone(), user_repository.clone())
                .with_blacklist(token_blacklist.clone()),
        );
        let validate_api_key_use_case = Arc::new(ValidateApiKeyUseCase::new(
            api_key_repository.clone(),
            api_key_generator.clone(),
        ));

        // Create auth state for extractors
        let auth_state = AuthState {
            validate_token: validate_token_use_case.clone(),
            validate_api_key: validate_api_key_use_case.clone(),
            user_repository: user_repository.clone(),
            api_key_repository: api_key_repository.clone(),
            api_key_generator: api_key_generator.clone(),
            organization_member_repository: Some(organization_member_repository.clone()),
        };

        Self {
            login_use_case,
            register_use_case,
            validate_token_use_case,
            refresh_token_use_case,
            validate_api_key_use_case,
            token_blacklist,
            auth_state,
        }
    }
}
