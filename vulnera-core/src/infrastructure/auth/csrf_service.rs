//! CSRF (Cross-Site Request Forgery) protection service
//!
//! Implements double-submit cookie pattern for CSRF protection:
//! - Generate cryptographically secure random tokens
//! - Constant-time comparison to prevent timing attacks
//! - Token stored in both HttpOnly cookie and returned to client for header submission

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use subtle::ConstantTimeEq;

/// CSRF service for generating and validating tokens
#[derive(Clone, Debug)]
pub struct CsrfService {
    /// Token length in bytes (before base64 encoding)
    token_bytes: usize,
}

impl CsrfService {
    /// Create a new CSRF service with the specified token length
    pub fn new(token_bytes: usize) -> Self {
        Self { token_bytes }
    }

    /// Generate a new cryptographically secure CSRF token
    ///
    /// Returns a URL-safe base64-encoded token
    pub fn generate_token(&self) -> String {
        let mut bytes = vec![0u8; self.token_bytes];
        rand::rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Validate a CSRF token using constant-time comparison
    ///
    /// # Arguments
    /// * `provided` - The token provided in the request header/form
    /// * `expected` - The token from the cookie
    ///
    /// # Returns
    /// `true` if tokens match, `false` otherwise
    pub fn validate_token(&self, provided: &str, expected: &str) -> bool {
        // Early return if lengths differ to avoid unnecessary work
        // (length comparison is not timing-sensitive for CSRF tokens)
        if provided.len() != expected.len() {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        provided.as_bytes().ct_eq(expected.as_bytes()).into()
    }

    /// Get the configured token length in bytes
    pub fn token_bytes(&self) -> usize {
        self.token_bytes
    }
}

impl Default for CsrfService {
    fn default() -> Self {
        Self::new(32) // 256 bits of entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let service = CsrfService::new(32);
        let token = service.generate_token();

        // 32 bytes = 43 base64 characters (URL-safe, no padding)
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let service = CsrfService::new(32);
        let token1 = service.generate_token();
        let token2 = service.generate_token();

        // Tokens should be unique (with overwhelming probability)
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_validate_token_matching() {
        let service = CsrfService::new(32);
        let token = service.generate_token();

        // Same token should validate
        assert!(service.validate_token(&token, &token));
    }

    #[test]
    fn test_validate_token_non_matching() {
        let service = CsrfService::new(32);
        let token1 = service.generate_token();
        let token2 = service.generate_token();

        // Different tokens should not validate
        assert!(!service.validate_token(&token1, &token2));
    }

    #[test]
    fn test_validate_token_different_lengths() {
        let service = CsrfService::new(32);
        let token = service.generate_token();
        let short_token = &token[..10];

        // Different length tokens should not validate
        assert!(!service.validate_token(short_token, &token));
    }

    #[test]
    fn test_validate_token_empty() {
        let service = CsrfService::new(32);
        let token = service.generate_token();

        // Empty token should not validate
        assert!(!service.validate_token("", &token));
        assert!(!service.validate_token(&token, ""));

        // Both empty should match (edge case)
        assert!(service.validate_token("", ""));
    }

    #[test]
    fn test_token_is_url_safe() {
        let service = CsrfService::new(32);

        // Generate many tokens to check URL safety
        for _ in 0..100 {
            let token = service.generate_token();

            // Should only contain URL-safe base64 characters
            assert!(
                token
                    .chars()
                    .all(|c| { c.is_ascii_alphanumeric() || c == '-' || c == '_' })
            );

            // Should not contain padding
            assert!(!token.contains('='));
        }
    }

    #[test]
    fn test_default_service() {
        let service = CsrfService::default();
        assert_eq!(service.token_bytes(), 32);
    }
}
