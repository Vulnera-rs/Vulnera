//! JWT service for token generation and validation

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::sync::Arc;

use crate::domain::auth::{
    errors::AuthError,
    value_objects::{AuthToken, Email, UserId, UserRole},
};

/// JWT service for generating and validating tokens
#[derive(Clone)]
pub struct JwtService {
    /// Secret key for signing tokens
    secret: Arc<String>,
    /// Access token TTL in hours
    access_token_ttl_hours: u64,
    /// Refresh token TTL in hours
    refresh_token_ttl_hours: u64,
}

impl JwtService {
    /// Create a new JWT service
    pub fn new(secret: String, access_token_ttl_hours: u64, refresh_token_ttl_hours: u64) -> Self {
        Self {
            secret: Arc::new(secret),
            access_token_ttl_hours,
            refresh_token_ttl_hours,
        }
    }

    /// Generate an access token for a user
    pub fn generate_access_token(
        &self,
        user_id: UserId,
        email: Email,
        roles: Vec<UserRole>,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.access_token_ttl_hours as i64);
        
        let claims = AuthToken::new_access(
            user_id,
            email,
            roles,
            exp.timestamp() as usize,
            now.timestamp() as usize,
        );

        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(self.secret.as_bytes());

        encode(&header, &claims, &encoding_key).map_err(|e| {
            tracing::error!("Failed to encode JWT token: {}", e);
            AuthError::InvalidToken
        })
    }

    /// Generate a refresh token for a user
    pub fn generate_refresh_token(&self, user_id: UserId) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.refresh_token_ttl_hours as i64);
        
        let claims = AuthToken::new_refresh(
            user_id,
            exp.timestamp() as usize,
            now.timestamp() as usize,
        );

        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(self.secret.as_bytes());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| {
                tracing::error!("Failed to encode refresh token: {}", e);
                AuthError::InvalidToken
            })
    }

    /// Validate and decode a token
    pub fn validate_token(&self, token: &str) -> Result<AuthToken, AuthError> {
        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());
        let mut validation = Validation::default();
        validation.validate_exp = true;

        decode::<AuthToken>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                tracing::debug!("Token validation failed: {}", e);
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::InvalidToken,
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_validation() {
        let service = JwtService::new("test-secret-key-at-least-32-characters-long".to_string(), 24, 720);
        let user_id = UserId::generate();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let roles = vec![UserRole::User];

        let token = service.generate_access_token(user_id, email, roles.clone()).unwrap();
        let validated = service.validate_token(&token).unwrap();

        assert_eq!(validated.user_id().unwrap(), user_id);
        assert!(validated.is_access_token());
    }

    #[test]
    fn test_refresh_token() {
        let service = JwtService::new("test-secret-key-at-least-32-characters-long".to_string(), 24, 720);
        let user_id = UserId::generate();

        let token = service.generate_refresh_token(user_id).unwrap();
        let validated = service.validate_token(&token).unwrap();

        assert_eq!(validated.user_id().unwrap(), user_id);
        assert!(validated.is_refresh_token());
    }
}

