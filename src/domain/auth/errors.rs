//! Authentication domain errors

use thiserror::Error;

/// Authentication-specific domain errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum AuthError {
    #[error("User not found: {email}")]
    UserNotFound { email: String },

    #[error("Invalid credentials provided")]
    InvalidCredentials,

    #[error("Invalid token provided")]
    InvalidToken,

    #[error("Token has expired")]
    TokenExpired,

    #[error("API key not found")]
    ApiKeyNotFound,

    #[error("API key has expired")]
    ApiKeyExpired,

    #[error("API key is invalid or revoked")]
    ApiKeyInvalid,

    #[error("Email already exists: {email}")]
    EmailAlreadyExists { email: String },

    #[error("Invalid email format: {email}")]
    InvalidEmail { email: String },

    #[error("Invalid password: {reason}")]
    InvalidPassword { reason: String },

    #[error("Password is too weak - must be at least 8 characters")]
    WeakPassword,

    #[error("User ID not found: {user_id}")]
    UserIdNotFound { user_id: String },

    #[error("Database error: {message}")]
    DatabaseError { message: String },
}


