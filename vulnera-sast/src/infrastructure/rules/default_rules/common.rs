//! Common utilities and cross-language rules for SAST detection
//!
//! This module contains:
//! - Rules that apply to multiple languages
//! - Shared helper functions for building rules

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Cross-Language Rules
// ============================================================================

/// SQL injection rule - detects execute() calls that may contain SQL
/// Applies to: Python, JavaScript
pub fn sql_injection_rule() -> Rule {
    Rule {
        id: "sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Potential SQL injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: [
                (identifier) @fn
                (attribute attribute: (identifier) @fn)
              ]
              (#match? @fn "^execute$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "sql".to_string()],
        message: None,
        fix: None,
    }
}

/// Command injection rule - detects exec() calls
/// Applies to: Python, JavaScript
pub fn command_injection_rule() -> Rule {
    Rule {
        id: "command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: [
                (identifier) @fn
                (attribute attribute: (identifier) @fn)
              ]
              (#match? @fn "^exec$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "command".to_string()],
        message: None,
        fix: None,
    }
}

/// Get all common/cross-language rules
pub fn get_common_rules() -> Vec<Rule> {
    vec![sql_injection_rule(), command_injection_rule()]
}
