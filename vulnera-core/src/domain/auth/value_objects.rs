//! Authentication value objects

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// User ID value object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    /// Create a new UserId from UUID
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Generate a new random UserId
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Get as string
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<UserId> for Uuid {
    fn from(user_id: UserId) -> Self {
        user_id.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Email value object with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Email(String);

impl Email {
    /// Create a new Email with validation
    pub fn new(email: String) -> Result<Self, String> {
        let email = email.trim().to_lowercase();

        if email.is_empty() {
            return Err("Email cannot be empty".to_string());
        }

        // Basic email validation
        if !email.contains('@') {
            return Err("Invalid email format: missing @ symbol".to_string());
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Err("Invalid email format: multiple @ symbols".to_string());
        }

        let local = parts[0];
        let domain = parts[1];

        if local.is_empty() {
            return Err("Invalid email format: empty local part".to_string());
        }

        if domain.is_empty() {
            return Err("Invalid email format: empty domain part".to_string());
        }

        if !domain.contains('.') {
            return Err("Invalid email format: domain must contain a dot".to_string());
        }

        if email.len() > 255 {
            return Err("Email too long (max 255 characters)".to_string());
        }

        Ok(Email(email))
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get as owned string
    pub fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for Email {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Password validation result containing details about why validation failed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordValidationError {
    pub message: String,
    pub missing_requirements: Vec<String>,
}

impl fmt::Display for PasswordValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Password value object with strong validation
///
/// Validates passwords against the following requirements:
/// - Minimum 8 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)
#[derive(Debug, Clone)]
pub struct Password(String);

impl Password {
    /// Minimum password length
    pub const MIN_LENGTH: usize = 8;

    /// Create a new Password with validation
    pub fn new(password: String) -> Result<Self, PasswordValidationError> {
        Self::validate(&password)?;
        Ok(Password(password))
    }

    /// Validate a password string against security requirements
    pub fn validate(password: &str) -> Result<(), PasswordValidationError> {
        let mut missing = Vec::new();

        if password.len() < Self::MIN_LENGTH {
            missing.push(format!("at least {} characters", Self::MIN_LENGTH));
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            missing.push("at least one uppercase letter".to_string());
        }

        if !password.chars().any(|c| c.is_lowercase()) {
            missing.push("at least one lowercase letter".to_string());
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            missing.push("at least one digit".to_string());
        }

        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        if !password.chars().any(|c| special_chars.contains(c)) {
            missing.push("at least one special character".to_string());
        }

        if !missing.is_empty() {
            return Err(PasswordValidationError {
                message: format!(
                    "Password must contain: {}",
                    missing.join(", ")
                ),
                missing_requirements: missing,
            });
        }

        Ok(())
    }

    /// Check if a password meets the minimum requirements (legacy method for backward compatibility)
    pub fn is_strong_enough(password: &str) -> bool {
        Self::validate(password).is_ok()
    }

    /// Get the inner password string (for hashing)
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Password hash value object (never exposes raw hash)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Create a new PasswordHash
    pub fn new(hash: String) -> Self {
        Self(hash)
    }

    /// Get the hash for verification (internal use only)
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get as owned string (internal use only)
    pub fn into_string(self) -> String {
        self.0
    }
}

// Intentionally not implementing Display or Serialize to prevent accidental exposure
impl From<String> for PasswordHash {
    fn from(hash: String) -> Self {
        Self(hash)
    }
}

/// User role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    /// Regular user role
    User,
    /// Administrator role
    Admin,
}

impl UserRole {
    /// Get all available roles
    pub fn all() -> Vec<UserRole> {
        vec![UserRole::User, UserRole::Admin]
    }

    /// Check if this role has admin privileges
    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

impl FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(UserRole::User),
            "admin" => Ok(UserRole::Admin),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
        }
    }
}

/// JWT authentication token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Subject (user_id)
    pub sub: String,
    /// User email
    pub email: String,
    /// User roles
    pub roles: Vec<String>,
    /// Expiration timestamp (Unix time)
    pub exp: usize,
    /// Issued at timestamp (Unix time)
    pub iat: usize,
    /// Token type: "access" or "refresh"
    pub typ: String,
}

impl AuthToken {
    /// Create a new access token
    pub fn new_access(
        user_id: UserId,
        email: Email,
        roles: Vec<UserRole>,
        exp: usize,
        iat: usize,
    ) -> Self {
        Self {
            sub: user_id.as_str(),
            email: email.as_str().to_string(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            exp,
            iat,
            typ: "access".to_string(),
        }
    }

    /// Create a new refresh token
    pub fn new_refresh(user_id: UserId, exp: usize, iat: usize) -> Self {
        Self {
            sub: user_id.as_str(),
            email: String::new(), // Not needed for refresh tokens
            roles: vec![],        // Not needed for refresh tokens
            exp,
            iat,
            typ: "refresh".to_string(),
        }
    }

    /// Get user ID from token
    pub fn user_id(&self) -> Result<UserId, String> {
        Uuid::parse_str(&self.sub)
            .map(UserId::from)
            .map_err(|e| format!("Invalid user ID in token: {}", e))
    }

    /// Check if token is an access token
    pub fn is_access_token(&self) -> bool {
        self.typ == "access"
    }

    /// Check if token is a refresh token
    pub fn is_refresh_token(&self) -> bool {
        self.typ == "refresh"
    }
}

/// API Key ID value object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKeyId(pub Uuid);

impl ApiKeyId {
    /// Create a new ApiKeyId from UUID
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Generate a new random ApiKeyId
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Get as string
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl From<Uuid> for ApiKeyId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<ApiKeyId> for Uuid {
    fn from(key_id: ApiKeyId) -> Self {
        key_id.0
    }
}

impl fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// API Key hash value object (never exposes raw hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiKeyHash(String);

impl ApiKeyHash {
    /// Create a new ApiKeyHash
    pub fn new(hash: String) -> Self {
        Self(hash)
    }

    /// Get the hash for verification (internal use only)
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get as owned string (internal use only)
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for ApiKeyHash {
    fn from(hash: String) -> Self {
        Self(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(Email::new("user@example.com".to_string()).is_ok());
        assert!(Email::new("test.user@example.co.uk".to_string()).is_ok());
        assert!(Email::new("  USER@EXAMPLE.COM  ".to_string()).is_ok()); // Should normalize

        // Invalid emails
        assert!(Email::new("".to_string()).is_err());
        assert!(Email::new("invalid".to_string()).is_err());
        assert!(Email::new("@example.com".to_string()).is_err());
        assert!(Email::new("user@".to_string()).is_err());
        assert!(Email::new("user@domain".to_string()).is_err());
    }

    #[test]
    fn test_email_normalization() {
        let email = Email::new("  USER@EXAMPLE.COM  ".to_string()).unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }

    #[test]
    fn test_password_validation_strong() {
        // Strong password that meets all requirements
        let strong = "MyP@ssw0rd!";
        assert!(Password::new(strong.to_string()).is_ok());
        assert!(Password::is_strong_enough(strong));
    }

    #[test]
    fn test_password_validation_weak() {
        // Too short
        let result = Password::new("Ab1!".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().missing_requirements.iter().any(|r| r.contains("8 characters")));

        // No uppercase
        let result = Password::new("myp@ssw0rd!".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().missing_requirements.iter().any(|r| r.contains("uppercase")));

        // No lowercase
        let result = Password::new("MYP@SSW0RD!".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().missing_requirements.iter().any(|r| r.contains("lowercase")));

        // No digit
        let result = Password::new("MyP@ssword!".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().missing_requirements.iter().any(|r| r.contains("digit")));

        // No special character
        let result = Password::new("MyPassword1".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().missing_requirements.iter().any(|r| r.contains("special")));
    }

    #[test]
    fn test_password_validation_multiple_missing() {
        // Multiple requirements missing
        let result = Password::new("password".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be missing uppercase, digit, and special character
        assert!(err.missing_requirements.len() >= 3);
    }

    #[test]
    fn test_user_role_parsing() {
        assert_eq!(UserRole::from_str("user").unwrap(), UserRole::User);
        assert_eq!(UserRole::from_str("admin").unwrap(), UserRole::Admin);
        assert_eq!(UserRole::from_str("User").unwrap(), UserRole::User); // Case insensitive
        assert_eq!(UserRole::from_str("ADMIN").unwrap(), UserRole::Admin);
        assert!(UserRole::from_str("invalid").is_err());
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Admin.to_string(), "admin");
    }

    #[test]
    fn test_user_role_admin_check() {
        assert!(!UserRole::User.is_admin());
        assert!(UserRole::Admin.is_admin());
    }

    #[test]
    fn test_user_id() {
        let uuid = Uuid::new_v4();
        let user_id = UserId::new(uuid);
        assert_eq!(user_id.as_uuid(), uuid);
        assert_eq!(UserId::from(uuid), user_id);
    }

    #[test]
    fn test_api_key_id() {
        let uuid = Uuid::new_v4();
        let key_id = ApiKeyId::new(uuid);
        assert_eq!(key_id.as_uuid(), uuid);
        assert_eq!(ApiKeyId::from(uuid), key_id);
    }

    #[test]
    fn test_auth_token() {
        let user_id = UserId::generate();
        let email = Email::new("user@example.com".to_string()).unwrap();
        let roles = vec![UserRole::User];
        let now = chrono::Utc::now().timestamp() as usize;
        let exp = now + 3600;

        let token = AuthToken::new_access(user_id, email, roles, exp, now);
        assert_eq!(token.user_id().unwrap(), user_id);
        assert!(token.is_access_token());
        assert!(!token.is_refresh_token());
    }
}
