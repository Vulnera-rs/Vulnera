//! Default security rules loaded from embedded TOML data files.
//!
//! Rules are defined declaratively in `vulnera-sast/rules/*.toml` and compiled
//! into the binary via `include_str!`.
//!
//! ## Adding new rules
//!
//! 1. Edit the appropriate `rules/{language}.toml` file (or create a new one).
//! 2. Follow the `[[rules]]` table-array format — see existing entries.
//! 3. Run `cargo test -p vulnera-sast` to validate deserialization.

use crate::domain::entities::Rule;
use serde::Deserialize;
use std::sync::LazyLock;
use tracing::{debug, warn};

// =============================================================================
// Embedded TOML rule data
// =============================================================================

const PYTHON_RULES_TOML: &str = include_str!("../../../../rules/python.toml");
const JAVASCRIPT_RULES_TOML: &str = include_str!("../../../../rules/javascript.toml");
const TYPESCRIPT_RULES_TOML: &str = include_str!("../../../../rules/typescript.toml");
const RUST_RULES_TOML: &str = include_str!("../../../../rules/rust.toml");
const GO_RULES_TOML: &str = include_str!("../../../../rules/go.toml");
const C_CPP_RULES_TOML: &str = include_str!("../../../../rules/c_cpp.toml");
const COMMON_RULES_TOML: &str = include_str!("../../../../rules/common.toml");

/// Intermediate deserialization target matching the TOML structure.
#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

/// Parse a TOML rule file, returning an empty vec on error (with warning).
fn load_rules_from_toml(toml_str: &str, label: &str) -> Vec<Rule> {
    match toml::from_str::<RulesFile>(toml_str) {
        Ok(file) => {
            debug!(count = file.rules.len(), language = label, "Loaded rules from embedded TOML");
            file.rules
        }
        Err(e) => {
            warn!(error = %e, language = label, "Failed to parse embedded rule TOML — returning empty");
            Vec::new()
        }
    }
}

// =============================================================================
// Lazy-initialized rule sets (parsed once, reused across calls)
// =============================================================================

static ALL_DEFAULT_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules = Vec::with_capacity(200);
    rules.extend(load_rules_from_toml(COMMON_RULES_TOML, "common"));
    rules.extend(load_rules_from_toml(JAVASCRIPT_RULES_TOML, "javascript"));
    rules.extend(load_rules_from_toml(TYPESCRIPT_RULES_TOML, "typescript"));
    rules.extend(load_rules_from_toml(PYTHON_RULES_TOML, "python"));
    rules.extend(load_rules_from_toml(RUST_RULES_TOML, "rust"));
    rules.extend(load_rules_from_toml(GO_RULES_TOML, "go"));
    rules.extend(load_rules_from_toml(C_CPP_RULES_TOML, "c_cpp"));
    debug!(total = rules.len(), "All default rules loaded");
    rules
});

// =============================================================================
// Public API (identical signature)
// =============================================================================

/// Get all default security rules across all languages.
///
/// Rules are parsed from embedded TOML once on first call and cached for the
/// process lifetime.
pub fn get_default_rules() -> Vec<Rule> {
    ALL_DEFAULT_RULES.clone()
}

/// Get Python-specific rules.
pub fn get_python_rules() -> Vec<Rule> {
    load_rules_from_toml(PYTHON_RULES_TOML, "python")
}

/// Get JavaScript-specific rules.
pub fn get_javascript_rules() -> Vec<Rule> {
    load_rules_from_toml(JAVASCRIPT_RULES_TOML, "javascript")
}

/// Get TypeScript-specific rules.
pub fn get_typescript_rules() -> Vec<Rule> {
    load_rules_from_toml(TYPESCRIPT_RULES_TOML, "typescript")
}

/// Get Rust-specific rules.
pub fn get_rust_rules() -> Vec<Rule> {
    load_rules_from_toml(RUST_RULES_TOML, "rust")
}

/// Get Go-specific rules.
pub fn get_go_rules() -> Vec<Rule> {
    load_rules_from_toml(GO_RULES_TOML, "go")
}

/// Get C/C++-specific rules.
pub fn get_c_cpp_rules() -> Vec<Rule> {
    load_rules_from_toml(C_CPP_RULES_TOML, "c_cpp")
}

/// Get cross-language rules.
pub fn get_common_rules() -> Vec<Rule> {
    load_rules_from_toml(COMMON_RULES_TOML, "common")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_get_default_rules_not_empty() {
        let rules = get_default_rules();
        assert!(!rules.is_empty(), "Default rules should not be empty");
    }

    #[test]
    fn test_rule_count_sufficient() {
        let rules = get_default_rules();
        assert!(
            rules.len() >= 100,
            "Expected at least 100 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_unique_rule_ids() {
        let rules = get_default_rules();
        let mut seen_ids = HashSet::new();
        let mut duplicates = Vec::new();

        for rule in &rules {
            if !seen_ids.insert(&rule.id) {
                duplicates.push(rule.id.clone());
            }
        }

        assert!(
            duplicates.is_empty(),
            "Found duplicate rule IDs: {:?}",
            duplicates
        );
    }

    #[test]
    fn test_all_rules_have_required_fields() {
        let rules = get_default_rules();

        for rule in &rules {
            assert!(!rule.id.is_empty(), "Rule ID should not be empty");
            assert!(
                !rule.name.is_empty(),
                "Rule name should not be empty for {}",
                rule.id
            );
            assert!(
                !rule.description.is_empty(),
                "Rule description should not be empty for {}",
                rule.id
            );
            assert!(
                !rule.languages.is_empty(),
                "Rule should have at least one language for {}",
                rule.id
            );
        }
    }

    #[test]
    fn test_javascript_rules_loaded() {
        let rules = get_javascript_rules();
        assert!(
            rules.len() >= 15,
            "Expected at least 15 JavaScript rules, got {}",
            rules.len()
        );

        assert!(
            rules.iter().any(|r| r.id == "js-eval-direct"),
            "js-eval-direct rule should exist"
        );
    }

    #[test]
    fn test_python_rules_loaded() {
        let rules = get_python_rules();
        assert!(
            rules.len() >= 15,
            "Expected at least 15 Python rules, got {}",
            rules.len()
        );

        assert!(
            rules.iter().any(|r| r.id == "python-subprocess"),
            "python-subprocess rule should exist"
        );
    }

    #[test]
    fn test_rust_rules_loaded() {
        let rules = get_rust_rules();
        assert!(
            rules.len() >= 10,
            "Expected at least 10 Rust rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_go_rules_loaded() {
        let rules = get_go_rules();
        assert!(
            rules.len() >= 10,
            "Expected at least 10 Go rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_c_cpp_rules_loaded() {
        let rules = get_c_cpp_rules();
        assert!(
            rules.len() >= 10,
            "Expected at least 10 C/C++ rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_typescript_rules_loaded() {
        let rules = get_typescript_rules();
        assert!(
            !rules.is_empty(),
            "Expected at least some TypeScript rules"
        );
    }

    #[test]
    fn test_common_rules_loaded() {
        let rules = get_common_rules();
        assert!(!rules.is_empty(), "Expected at least some common rules");
    }

    #[test]
    fn test_lazy_cache_consistency() {
        // Calling twice should return identical results
        let first = get_default_rules();
        let second = get_default_rules();
        assert_eq!(first.len(), second.len());
    }
}
