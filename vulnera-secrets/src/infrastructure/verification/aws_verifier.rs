//! AWS credential verifier
//!
//! This verifier validates AWS credential formats. Full verification of AWS credentials
//! requires both the access key ID and secret access key to create a valid AWS Signature
//! Version 4 signature. Since secret detection typically finds these separately, this
//! verifier focuses on format validation.
//!
//! **Limitations:**
//! - Access key IDs can only be validated for format (AKIA followed by 16 alphanumeric chars)
//! - Secret access keys can only be validated for format (40 character base64-like string)
//! - Full verification (checking if credentials are active) requires both parts and is not
//!   supported when scanning code where credentials are typically found separately

use crate::domain::entities::SecretType;
use crate::infrastructure::verification::{SecretVerifier, VerificationResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

/// AWS credential verifier
pub struct AwsVerifier;

impl AwsVerifier {
    /// Validate AWS access key ID format
    /// Format: AKIA followed by exactly 16 uppercase alphanumeric characters
    fn validate_access_key_format(access_key: &str) -> bool {
        access_key.len() == 20
            && access_key.starts_with("AKIA")
            && access_key[4..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }

    /// Validate AWS secret access key format
    /// Format: Exactly 40 characters, base64-like (A-Z, a-z, 0-9, /, +, =)
    fn validate_secret_key_format(secret_key: &str) -> bool {
        secret_key.len() == 40
            && secret_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+' || c == '=')
    }

    /// Validate AWS session token format
    /// Format: Base64-like string, typically 100+ characters
    fn validate_session_token_format(token: &str) -> bool {
        token.len() >= 100
            && token.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == '/'
                    || c == '+'
                    || c == '='
                    || c == '_'
                    || c == '-'
            })
    }
}

#[async_trait]
impl SecretVerifier for AwsVerifier {
    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::AwsAccessKey | SecretType::AwsSecretKey | SecretType::AwsSessionToken
        )
    }

    async fn verify(
        &self,
        secret: &str,
        secret_type: &SecretType,
        context: Option<&HashMap<SecretType, String>>,
        _timeout: Duration,
    ) -> VerificationResult {
        // Trim whitespace that might be present in detected secrets
        let secret = secret.trim();

        // Validate format based on secret type
        let format_valid = match secret_type {
            SecretType::AwsAccessKey => {
                let valid = Self::validate_access_key_format(secret);
                if !valid {
                    debug!(
                        secret_preview = %Self::redact_secret(secret),
                        "AWS access key format validation failed"
                    );
                }
                valid
            }
            SecretType::AwsSecretKey => {
                let valid = Self::validate_secret_key_format(secret);
                if !valid {
                    debug!(
                        secret_preview = %Self::redact_secret(secret),
                        "AWS secret key format validation failed"
                    );
                }
                valid
            }
            SecretType::AwsSessionToken => {
                let valid = Self::validate_session_token_format(secret);
                if !valid {
                    debug!(
                        secret_preview = %Self::redact_secret(secret),
                        "AWS session token format validation failed"
                    );
                }
                valid
            }
            _ => false,
        };

        if !format_valid {
            return VerificationResult::Invalid;
        }

        // If we have context, check if we have both parts for more thorough validation
        if let Some(ctx) = context {
            match secret_type {
                SecretType::AwsAccessKey => {
                    if let Some(secret_key) = ctx.get(&SecretType::AwsSecretKey)
                        && Self::validate_secret_key_format(secret_key)
                    {
                        debug!("Found both AWS access key and secret key with valid formats");
                    }
                }
                SecretType::AwsSecretKey => {
                    if let Some(access_key) = ctx.get(&SecretType::AwsAccessKey)
                        && Self::validate_access_key_format(access_key)
                    {
                        debug!("Found both AWS access key and secret key with valid formats");
                    }
                }
                _ => {}
            }
        }

        // Format is valid, but we cannot fully verify without both access key and secret key
        // AWS requires Signature Version 4 signing which needs both parts.
        // Even if we have both in context, performing a real API call requires more setup (STS/IAM).
        debug!(
            secret_type = ?secret_type,
            secret_preview = %Self::redact_secret(secret),
            "AWS credential format is valid, but full live verification is not yet implemented"
        );

        // Return NotSupported to indicate format is valid but live verification isn't performed
        VerificationResult::NotSupported
    }
}

impl AwsVerifier {
    /// Redact secret for safe logging
    fn redact_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            return "***".to_string();
        }
        format!(
            "{}...{}",
            &secret[..4],
            &secret[secret.len().saturating_sub(4)..]
        )
    }
}
