//! Authentication use cases

use chrono::Utc;
use std::sync::Arc;

use crate::domain::auth::{
    entities::{ApiKey, User},
    errors::AuthError,
    repositories::{IApiKeyRepository, IUserRepository},
    value_objects::{ApiKeyId, Email, UserId, UserRole},
};
use crate::infrastructure::auth::{ApiKeyGenerator, JwtService, PasswordHasher};

/// Result type for login operations
pub struct LoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: UserId,
    pub email: Email,
    pub roles: Vec<UserRole>,
}

/// Result of successful user registration
pub struct RegisterResult {
    pub user_id: UserId,
    pub access_token: String,
    pub refresh_token: String,
}

/// Use case for user login
pub struct LoginUseCase {
    user_repository: Arc<dyn IUserRepository>,
    password_hasher: Arc<PasswordHasher>,
    jwt_service: Arc<JwtService>,
}

impl LoginUseCase {
    pub fn new(
        user_repository: Arc<dyn IUserRepository>,
        password_hasher: Arc<PasswordHasher>,
        jwt_service: Arc<JwtService>,
    ) -> Self {
        Self {
            user_repository,
            password_hasher,
            jwt_service,
        }
    }

    pub async fn execute(&self, email: Email, password: String) -> Result<LoginResult, AuthError> {
        // Find user by email
        let user = self
            .user_repository
            .find_by_email(&email)
            .await?
            .ok_or_else(|| AuthError::InvalidCredentials)?;

        // Verify password
        let is_valid = self
            .password_hasher
            .verify(&password, &user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate tokens
        let access_token = self.jwt_service.generate_access_token(
            user.user_id,
            user.email.clone(),
            user.roles.clone(),
        )?;

        let refresh_token = self.jwt_service.generate_refresh_token(user.user_id)?;

        Ok(LoginResult {
            access_token,
            refresh_token,
            user_id: user.user_id,
            email: user.email,
            roles: user.roles,
        })
    }
}

/// Use case for registering new users
pub struct RegisterUserUseCase {
    user_repository: Arc<dyn IUserRepository>,
    password_hasher: Arc<PasswordHasher>,
    jwt_service: Arc<JwtService>,
}

impl RegisterUserUseCase {
    pub fn new(
        user_repository: Arc<dyn IUserRepository>,
        password_hasher: Arc<PasswordHasher>,
        jwt_service: Arc<JwtService>,
    ) -> Self {
        Self {
            user_repository,
            password_hasher,
            jwt_service,
        }
    }

    pub async fn execute(
        &self,
        email: Email,
        password: String,
        roles: Option<Vec<UserRole>>,
    ) -> Result<RegisterResult, AuthError> {
        // Check if user already exists
        if let Some(_existing_user) = self.user_repository.find_by_email(&email).await? {
            return Err(AuthError::EmailAlreadyExists {
                email: email.as_str().to_string(),
            });
        }

        // Validate password strength (minimum 8 characters)
        if password.len() < 8 {
            return Err(AuthError::WeakPassword);
        }

        // Hash password
        let password_hash = self.password_hasher.hash(&password)?;

        // Create user entity
        let user = User::new(
            UserId::generate(),
            email.clone(),
            password_hash,
            roles.unwrap_or_else(|| vec![UserRole::User]),
        );

        // Save user to repository
        self.user_repository.create(&user).await?;

        // Generate tokens
        let access_token = self.jwt_service.generate_access_token(
            user.user_id.clone(),
            user.email.clone(),
            user.roles.clone(),
        )?;

        let refresh_token = self
            .jwt_service
            .generate_refresh_token(user.user_id.clone())?;

        Ok(RegisterResult {
            user_id: user.user_id,
            access_token,
            refresh_token,
        })
    }
}

/// Use case for validating JWT tokens
pub struct ValidateTokenUseCase {
    jwt_service: Arc<JwtService>,
}

impl ValidateTokenUseCase {
    pub fn new(jwt_service: Arc<JwtService>) -> Self {
        Self { jwt_service }
    }

    pub fn execute(&self, token: &str) -> Result<(UserId, Email, Vec<UserRole>), AuthError> {
        let claims = self.jwt_service.validate_token(token)?;

        // Only accept access tokens for validation
        if !claims.is_access_token() {
            return Err(AuthError::InvalidToken);
        }

        let user_id = claims.user_id().map_err(|_| AuthError::InvalidToken)?;
        let email = Email::new(claims.email).map_err(|_| AuthError::InvalidToken)?;

        let roles = claims
            .roles
            .iter()
            .filter_map(|r| UserRole::from_str(r).ok())
            .collect();

        Ok((user_id, email, roles))
    }
}

/// Use case for refreshing access tokens
pub struct RefreshTokenUseCase {
    jwt_service: Arc<JwtService>,
    user_repository: Arc<dyn IUserRepository>,
}

impl RefreshTokenUseCase {
    pub fn new(jwt_service: Arc<JwtService>, user_repository: Arc<dyn IUserRepository>) -> Self {
        Self {
            jwt_service,
            user_repository,
        }
    }

    pub async fn execute(&self, refresh_token: &str) -> Result<String, AuthError> {
        // Validate refresh token
        let claims = self.jwt_service.validate_token(refresh_token)?;

        if !claims.is_refresh_token() {
            return Err(AuthError::InvalidToken);
        }

        // Get user from token
        let user_id = claims.user_id().map_err(|_| AuthError::InvalidToken)?;
        let user = self
            .user_repository
            .find_by_id(&user_id)
            .await?
            .ok_or_else(|| AuthError::UserNotFound {
                email: user_id.as_str(),
            })?;

        // Generate new access token
        let access_token =
            self.jwt_service
                .generate_access_token(user.user_id, user.email, user.roles)?;

        Ok(access_token)
    }
}

/// Use case for generating API keys
pub struct GenerateApiKeyUseCase {
    api_key_repository: Arc<dyn IApiKeyRepository>,
    api_key_generator: Arc<ApiKeyGenerator>,
    user_id: UserId,
}

impl GenerateApiKeyUseCase {
    pub fn new(
        api_key_repository: Arc<dyn IApiKeyRepository>,
        api_key_generator: Arc<ApiKeyGenerator>,
        user_id: UserId,
    ) -> Self {
        Self {
            api_key_repository,
            api_key_generator,
            user_id,
        }
    }

    pub async fn execute(
        &self,
        name: String,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(String, ApiKey), AuthError> {
        // Generate API key
        let (plaintext_key, key_hash) = self.api_key_generator.generate();

        // Create API key entity
        let api_key_id = crate::domain::auth::value_objects::ApiKeyId::generate();
        let api_key = ApiKey::new(api_key_id, self.user_id, key_hash, name, expires_at);

        // Save to database
        self.api_key_repository.create(&api_key).await?;

        Ok((plaintext_key, api_key))
    }
}

/// Use case for validating API keys
pub struct ValidateApiKeyUseCase {
    api_key_repository: Arc<dyn IApiKeyRepository>,
    api_key_generator: Arc<ApiKeyGenerator>,
}

impl ValidateApiKeyUseCase {
    pub fn new(
        api_key_repository: Arc<dyn IApiKeyRepository>,
        api_key_generator: Arc<ApiKeyGenerator>,
    ) -> Self {
        Self {
            api_key_repository,
            api_key_generator,
        }
    }

    pub async fn execute(&self, api_key: &str) -> Result<UserId, AuthError> {
        // Hash the provided API key
        let key_hash = self.api_key_generator.hash_key(api_key);

        // Find API key by hash
        let mut api_key_entity = self
            .api_key_repository
            .find_by_hash(&key_hash)
            .await?
            .ok_or_else(|| AuthError::ApiKeyInvalid)?;

        // Check if revoked
        if api_key_entity.is_revoked() {
            return Err(AuthError::ApiKeyInvalid);
        }

        // Check if expired
        if api_key_entity.is_expired() {
            return Err(AuthError::ApiKeyExpired);
        }

        // Update last_used_at
        api_key_entity.mark_as_used();
        self.api_key_repository
            .update_last_used(&api_key_entity.api_key_id, Utc::now())
            .await
            .ok(); // Don't fail if update fails, just log it

        Ok(api_key_entity.user_id)
    }
}

/// Use case for listing user's API keys
pub struct ListApiKeysUseCase {
    api_key_repository: Arc<dyn IApiKeyRepository>,
    user_id: UserId,
}

impl ListApiKeysUseCase {
    pub fn new(api_key_repository: Arc<dyn IApiKeyRepository>, user_id: UserId) -> Self {
        Self {
            api_key_repository,
            user_id,
        }
    }

    pub async fn execute(&self) -> Result<Vec<ApiKey>, AuthError> {
        self.api_key_repository.find_by_user_id(&self.user_id).await
    }
}

/// Use case for revoking API keys
pub struct RevokeApiKeyUseCase {
    api_key_repository: Arc<dyn IApiKeyRepository>,
    user_id: UserId,
}

impl RevokeApiKeyUseCase {
    pub fn new(api_key_repository: Arc<dyn IApiKeyRepository>, user_id: UserId) -> Self {
        Self {
            api_key_repository,
            user_id,
        }
    }

    pub async fn execute(&self, key_id: ApiKeyId) -> Result<(), AuthError> {
        // Verify the API key belongs to the user
        let api_key = self
            .api_key_repository
            .find_by_id(&key_id)
            .await?
            .ok_or_else(|| AuthError::ApiKeyNotFound)?;

        if api_key.user_id != self.user_id {
            return Err(AuthError::ApiKeyNotFound);
        }

        // Revoke the key
        self.api_key_repository.revoke(&key_id).await
    }
}

use std::str::FromStr;
