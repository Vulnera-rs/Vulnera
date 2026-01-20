//! Default hardcoded security rules with tree-sitter query patterns
//!
//! This module provides the default SAST rules organized by programming language.
//! Each language has its own submodule containing rules specific to that language.
//!
//! ## Module Structure
//!
//! - `common`: Cross-language rules (SQL injection, command injection)
//! - `javascript`: JavaScript/Node.js security rules
//! - `typescript`: TypeScript-specific type safety and security rules
//! - `python`: Python security rules
//! - `rust_rules`: Rust security and safety rules
//! - `go`: Go security rules
//! - `c_cpp`: C/C++ security rules
//!
//! ## Usage
//!
/// ```rust
/// use vulnera_sast::infrastructure::rules::get_default_rules;
///
/// let rules = get_default_rules();
/// println!("Loaded {} rules", rules.len());
/// ```
mod c_cpp;
mod common;
mod go;
mod javascript;
mod python;
mod rust_rules;
mod typescript;

use crate::domain::entities::Rule;

// Re-export language-specific rule getters for advanced usage
pub use c_cpp::get_c_cpp_rules;
pub use common::get_common_rules;
pub use go::get_go_rules;
pub use javascript::get_javascript_rules;
pub use python::get_python_rules;
pub use rust_rules::get_rust_rules;
pub use typescript::get_typescript_rules;

/// Get all default security rules across all languages.
///
/// This function combines rules from all language-specific modules into a single
/// vector. Rules are ordered by language grouping:
///
/// 1. Cross-language rules (SQL injection, command injection)
/// 2. JavaScript rules
/// 3. TypeScript rules
/// 4. Python rules
/// 5. Rust rules
/// 6. Go rules
/// 7. C/C++ rules
///
/// # Returns
///
/// A `Vec<Rule>` containing all default rules.
///
/// # Example
///
/// ```rust
/// use vulnera_sast::infrastructure::rules::get_default_rules;
///
/// let rules = get_default_rules();
/// for rule in &rules {
///     println!("{}: {}", rule.id, rule.name);
/// }
/// ```
pub fn get_default_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // Cross-language rules
    rules.extend(get_common_rules());

    // JavaScript rules
    rules.extend(get_javascript_rules());

    // TypeScript rules
    rules.extend(get_typescript_rules());

    // Python rules
    rules.extend(get_python_rules());

    // Rust rules
    rules.extend(get_rust_rules());

    // Go rules
    rules.extend(get_go_rules());

    // C/C++ rules
    rules.extend(get_c_cpp_rules());

    rules
}

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
    fn test_rule_count_increased() {
        let rules = get_default_rules();
        // We should have at least 140 rules now with expanded catastrophic vulnerability coverage
        assert!(
            rules.len() >= 140,
            "Expected at least 140 rules, got {}",
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
            rules.len() >= 20,
            "Expected at least 20 JavaScript rules, got {}",
            rules.len()
        );

        // Check for specific rule
        assert!(
            rules.iter().any(|r| r.id == "js-eval-direct"),
            "js-eval-direct rule should exist"
        );
    }

    #[test]
    fn test_python_rules_loaded() {
        let rules = get_python_rules();
        assert!(
            rules.len() >= 20,
            "Expected at least 20 Python rules, got {}",
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

        assert!(
            rules.iter().any(|r| r.id == "rust-unsafe"),
            "rust-unsafe rule should exist"
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

        assert!(
            rules.iter().any(|r| r.id == "go-command-injection"),
            "go-command-injection rule should exist"
        );
    }

    #[test]
    fn test_c_cpp_rules_loaded() {
        let rules = get_c_cpp_rules();
        assert!(
            rules.len() >= 15,
            "Expected at least 15 C/C++ rules, got {}",
            rules.len()
        );

        assert!(
            rules.iter().any(|r| r.id == "c-buffer-overflow"),
            "c-buffer-overflow rule should exist"
        );
    }
}
