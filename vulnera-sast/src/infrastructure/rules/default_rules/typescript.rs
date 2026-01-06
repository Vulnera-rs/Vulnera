//! TypeScript security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! and type safety issues specific to TypeScript code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Type Safety Rules
// ============================================================================

/// any type usage
pub fn ts_any_type_rule() -> Rule {
    Rule {
        id: "ts-any-type".to_string(),
        name: "Any Type Usage".to_string(),
        description: "Using 'any' type bypasses TypeScript's type checking".to_string(),
        severity: Severity::Low,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(type_annotation
              (predefined_type) @type
              (#eq? @type "any")
            ) @any"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["type-safety".to_string(), "typescript".to_string()],
        message: Some(
            "Use specific types instead of 'any'. Consider 'unknown' for truly unknown types."
                .to_string(),
        ),
        fix: None,
    }
}

/// @ts-ignore comment
pub fn ts_ignore_rule() -> Rule {
    Rule {
        id: "ts-ignore".to_string(),
        name: "@ts-ignore Suppression".to_string(),
        description: "@ts-ignore suppresses TypeScript errors and may hide issues".to_string(),
        severity: Severity::Low,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(comment) @comment
              (#match? @comment "@ts-ignore")"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["type-safety".to_string(), "typescript".to_string()],
        message: Some(
            "Use @ts-expect-error instead of @ts-ignore for better error handling.".to_string(),
        ),
        fix: None,
    }
}

/// Non-null assertion operator (!)
pub fn ts_non_null_assertion_rule() -> Rule {
    Rule {
        id: "ts-non-null-assertion".to_string(),
        name: "Non-Null Assertion".to_string(),
        description: "Non-null assertion (!) bypasses null checks and can cause runtime errors"
            .to_string(),
        severity: Severity::Low,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(r#"(non_null_expression) @assertion"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "type-safety".to_string(),
            "null-pointer".to_string(),
            "typescript".to_string(),
        ],
        message: Some(
            "Use optional chaining (?.) or null checks instead of non-null assertion.".to_string(),
        ),
        fix: None,
    }
}

/// Type assertion (as T)
pub fn ts_type_assertion_rule() -> Rule {
    Rule {
        id: "ts-type-assertion".to_string(),
        name: "Type Assertion".to_string(),
        description: "Type assertions bypass type checking and may cause runtime errors"
            .to_string(),
        severity: Severity::Low,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(r#"(as_expression) @assertion"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["type-safety".to_string(), "typescript".to_string()],
        message: Some("Consider using type guards or proper type narrowing.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Security Rules (inherited from JavaScript)
// ============================================================================

/// eval in TypeScript
pub fn ts_eval_rule() -> Rule {
    Rule {
        id: "ts-eval".to_string(),
        name: "Eval Usage".to_string(),
        description: "eval() allows arbitrary code execution".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "eval")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Avoid using eval() with user-controlled input.".to_string()),
        fix: None,
    }
}

/// innerHTML in TypeScript/Angular
pub fn ts_innerhtml_rule() -> Rule {
    Rule {
        id: "ts-innerhtml".to_string(),
        name: "innerHTML XSS".to_string(),
        description: "Setting innerHTML can lead to XSS".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop
              )
              (#eq? @prop "innerHTML")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "typescript".to_string()],
        message: Some("Use textContent or Angular's DOM sanitizer.".to_string()),
        fix: None,
    }
}

/// Get all TypeScript rules
pub fn get_typescript_rules() -> Vec<Rule> {
    vec![
        // Type safety
        ts_any_type_rule(),
        ts_ignore_rule(),
        ts_non_null_assertion_rule(),
        ts_type_assertion_rule(),
        // Security
        ts_eval_rule(),
        ts_innerhtml_rule(),
    ]
}
