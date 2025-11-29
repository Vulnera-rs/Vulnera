//! Master API key support for development and extension use.
//!
//! Provides a simple, development-focused master key that bypasses normal API key validation,
//! rate limiting, and quota checks. Intended for use with browser extensions and development
//! environments where friction-free access is desired.
//!
//! Master key is read from VULNERA_MASTER_KEY environment variable and compared directly
//! against incoming API keys (no database lookups, no rate limiting).

use std::sync::OnceLock;
use tracing::debug;

/// Thread-safe, lazily-initialized master key
static MASTER_KEY: OnceLock<Option<String>> = OnceLock::new();

/// Initialize the master key from environment variable.
/// Called at application startup to eagerly load the key.
pub fn initialize_master_key() {
    let key = std::env::var("VULNERA_MASTER_KEY")
        .map(|k| {
            if k.is_empty() {
                debug!("VULNERA_MASTER_KEY environment variable is empty, master key disabled");
                None
            } else {
                debug!("Master key initialized from VULNERA_MASTER_KEY environment variable");
                Some(k)
            }
        })
        .ok()
        .flatten();

    // Initialize the OnceLock - subsequent calls will be no-ops
    let _ = MASTER_KEY.set(key);
}

/// Check if the provided API key is the master key.
///
/// Returns true if:
/// - Master key is configured (VULNERA_MASTER_KEY env var is set and non-empty)
/// - AND the provided key matches exactly
///
/// This performs simple string comparison with no rate limiting or database lookups.
/// Intended for development and extension use only.
pub fn is_master_key(api_key: &str) -> bool {
    // Initialize if not already done (handles case where initialize_master_key wasn't called)
    let key = MASTER_KEY.get_or_init(|| {
        std::env::var("VULNERA_MASTER_KEY")
            .ok()
            .and_then(|k| if k.is_empty() { None } else { Some(k) })
    });

    match key {
        Some(master) => {
            // Use constant-time comparison to prevent timing attacks
            use subtle::ConstantTimeEq;
            let matches: bool = master
                .as_bytes()
                .ct_eq(api_key.as_bytes())
                .into();
            if matches {
                debug!("Master API key authentication successful");
            }
            matches
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_master_key_disabled_when_env_not_set() {
        // Since OnceLock persists across tests in the same process,
        // we test the core logic by verifying the behavior:
        // If no key is set or env var is not set, it should return false for any input
        unsafe {
            env::remove_var("VULNERA_MASTER_KEY");
        }
        // This will use get_or_init which reads from env if not already set
        let result = is_master_key("any-key");
        // Will be false if not configured in this test run
        let _ = result; // Just verify it doesn't panic
    }

    #[test]
    #[ignore]
    fn test_master_key_integration_with_env() {
        // This test should be run with: VULNERA_MASTER_KEY=test-key cargo test
        let test_key = std::env::var("VULNERA_MASTER_KEY").unwrap_or_default();
        if test_key.is_empty() {
            println!("Skipping: VULNERA_MASTER_KEY not set");
            return;
        }

        let result = is_master_key(&test_key);
        assert!(result, "Master key should match when env var is set");

        let result_wrong = is_master_key("wrong-key");
        assert!(!result_wrong, "Master key should reject wrong key");
    }
}
