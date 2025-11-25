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

    #[error("Token has been revoked")]
    TokenRevoked,

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

    #[error("Password does not meet requirements: {requirements}")]
    PasswordRequirementsNotMet { requirements: String },

    #[error("Account temporarily locked due to too many failed login attempts. Try again in {retry_after_seconds} seconds.")]
    AccountLocked { retry_after_seconds: u64 },

    #[error("User ID not found: {user_id}")]
    UserIdNotFound { user_id: String },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Insufficient permissions - admin role required")]
    InsufficientPermissions,

    #[error("Role assignment not allowed - only admins can assign roles")]
    RoleAssignmentNotAllowed,
}
