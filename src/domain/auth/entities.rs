//! Authentication domain entities

use chrono::{DateTime, Utc};

use super::value_objects::*;

/// User aggregate root
#[derive(Debug, Clone)]
pub struct User {
    /// Unique user identifier
    pub user_id: UserId,
    /// User email address
    pub email: Email,
    /// Hashed password (never expose raw hash)
    pub password_hash: PasswordHash,
    /// User roles
    pub roles: Vec<UserRole>,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user
    pub fn new(
        user_id: UserId,
        email: Email,
        password_hash: PasswordHash,
        roles: Vec<UserRole>,
    ) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            email,
            password_hash,
            roles,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update user email
    pub fn update_email(&mut self, email: Email) {
        self.email = email;
        self.updated_at = Utc::now();
    }

    /// Update password hash
    pub fn update_password_hash(&mut self, password_hash: PasswordHash) {
        self.password_hash = password_hash;
        self.updated_at = Utc::now();
    }

    /// Add a role to the user
    pub fn add_role(&mut self, role: UserRole) {
        if !self.roles.contains(&role) {
            self.roles.push(role);
            self.updated_at = Utc::now();
        }
    }

    /// Remove a role from the user
    pub fn remove_role(&mut self, role: UserRole) {
        self.roles.retain(|r| *r != role);
        self.updated_at = Utc::now();
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: UserRole) -> bool {
        self.roles.contains(&role)
    }

    /// Check if user is an admin
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r.is_admin())
    }
}

/// API Key aggregate root
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// Unique API key identifier
    pub api_key_id: ApiKeyId,
    /// User who owns this API key
    pub user_id: UserId,
    /// Hashed API key (never expose raw key)
    pub key_hash: ApiKeyHash,
    /// Human-readable name for the API key
    pub name: String,
    /// Last time this API key was used (None if never used)
    pub last_used_at: Option<DateTime<Utc>>,
    /// When this API key was created
    pub created_at: DateTime<Utc>,
    /// When this API key expires (None if no expiration)
    pub expires_at: Option<DateTime<Utc>>,
    /// When this API key was revoked (None if still active)
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// Create a new API key
    pub fn new(
        api_key_id: ApiKeyId,
        user_id: UserId,
        key_hash: ApiKeyHash,
        name: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            api_key_id,
            user_id,
            key_hash,
            name,
            last_used_at: None,
            created_at: Utc::now(),
            expires_at,
            revoked_at: None,
        }
    }

    /// Mark the API key as used (updates last_used_at)
    pub fn mark_as_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Revoke the API key
    pub fn revoke(&mut self) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(Utc::now());
        }
    }

    /// Check if the API key is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if the API key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false // No expiration means never expired
        }
    }

    /// Check if the API key is active (not revoked and not expired)
    pub fn is_active(&self) -> bool {
        !self.is_revoked() && !self.is_expired()
    }

    /// Update the name of the API key
    pub fn update_name(&mut self, name: String) {
        self.name = name;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user_id = UserId::generate();
        let email = Email::new("user@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("hashed_password".to_string());
        let roles = vec![UserRole::User];

        let user = User::new(user_id, email, password_hash, roles);

        assert_eq!(user.user_id, user_id);
        assert!(!user.is_admin());
        assert!(user.has_role(UserRole::User));
    }

    #[test]
    fn test_user_role_management() {
        let user_id = UserId::generate();
        let email = Email::new("admin@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("hashed_password".to_string());
        let mut user = User::new(user_id, email, password_hash, vec![]);

        assert!(!user.has_role(UserRole::Admin));
        user.add_role(UserRole::Admin);
        assert!(user.has_role(UserRole::Admin));
        assert!(user.is_admin());

        user.remove_role(UserRole::Admin);
        assert!(!user.has_role(UserRole::Admin));
        assert!(!user.is_admin());
    }

    #[test]
    fn test_api_key_creation() {
        let key_id = ApiKeyId::generate();
        let user_id = UserId::generate();
        let key_hash = ApiKeyHash::new("hashed_key".to_string());
        let name = "Test API Key".to_string();

        let api_key = ApiKey::new(key_id, user_id, key_hash, name, None);

        assert_eq!(api_key.api_key_id, key_id);
        assert_eq!(api_key.user_id, user_id);
        assert!(!api_key.is_revoked());
        assert!(!api_key.is_expired());
        assert!(api_key.is_active());
    }

    #[test]
    fn test_api_key_revocation() {
        let key_id = ApiKeyId::generate();
        let user_id = UserId::generate();
        let key_hash = ApiKeyHash::new("hashed_key".to_string());
        let mut api_key = ApiKey::new(key_id, user_id, key_hash, "Test".to_string(), None);

        assert!(!api_key.is_revoked());
        api_key.revoke();
        assert!(api_key.is_revoked());
        assert!(!api_key.is_active());
    }

    #[test]
    fn test_api_key_expiration() {
        let key_id = ApiKeyId::generate();
        let user_id = UserId::generate();
        let key_hash = ApiKeyHash::new("hashed_key".to_string());
        let expires_at = Utc::now() - chrono::Duration::hours(1); // Expired 1 hour ago

        let api_key = ApiKey::new(key_id, user_id, key_hash, "Test".to_string(), Some(expires_at));

        assert!(api_key.is_expired());
        assert!(!api_key.is_active());
    }

    #[test]
    fn test_api_key_mark_as_used() {
        let key_id = ApiKeyId::generate();
        let user_id = UserId::generate();
        let key_hash = ApiKeyHash::new("hashed_key".to_string());
        let mut api_key = ApiKey::new(key_id, user_id, key_hash, "Test".to_string(), None);

        assert!(api_key.last_used_at.is_none());
        api_key.mark_as_used();
        assert!(api_key.last_used_at.is_some());
    }
}

