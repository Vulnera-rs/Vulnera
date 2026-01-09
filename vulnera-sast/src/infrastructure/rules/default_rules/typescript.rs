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

// ============================================================================
// NEW RULES
// ============================================================================

/// child_process command execution
pub fn ts_child_process_rule() -> Rule {
    Rule {
        id: "ts-child-process".to_string(),
        name: "Child Process Execution".to_string(),
        description: "Potential command injection via child_process".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(exec|execSync|spawn|spawnSync)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Validate and sanitize command arguments.".to_string()),
        fix: None,
    }
}

/// SQL injection via string concatenation
pub fn ts_sql_injection_rule() -> Rule {
    Rule {
        id: "ts-sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "SQL query built with string concatenation is vulnerable to injection"
            .to_string(),
        severity: Severity::Critical,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                [(binary_expression) (template_string)]
              )
              (#match? @fn "^(query|execute|raw)$")
            ) @sql"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "sql".to_string(),
            "injection".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Use parameterized queries with proper binding.".to_string()),
        fix: None,
    }
}

/// NoSQL injection (MongoDB)
pub fn ts_nosql_injection_rule() -> Rule {
    Rule {
        id: "ts-nosql-injection".to_string(),
        name: "NoSQL Injection".to_string(),
        description: "Potential NoSQL injection via MongoDB query".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(find|findOne|updateOne|deleteOne)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-943".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "nosql".to_string(),
            "mongodb".to_string(),
            "typescript".to_string(),
        ],
        message: Some(
            "Validate and sanitize user input before using in MongoDB queries.".to_string(),
        ),
        fix: None,
    }
}

/// JWT verify without algorithm
pub fn ts_jwt_verify_rule() -> Rule {
    Rule {
        id: "ts-jwt-verify".to_string(),
        name: "JWT Algorithm Not Specified".to_string(),
        description: "JWT verification without algorithm restriction".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(verify|decode)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-347".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "jwt".to_string(),
            "authentication".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Always specify algorithms: {algorithms: ['HS256']}".to_string()),
        fix: None,
    }
}

/// Prototype pollution
pub fn ts_prototype_pollution_rule() -> Rule {
    Rule {
        id: "ts-prototype-pollution".to_string(),
        name: "Prototype Pollution".to_string(),
        description: "Object merge without filtering can lead to prototype pollution".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              (#eq? @obj "Object")
              (#eq? @fn "assign")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1321".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["prototype-pollution".to_string(), "typescript".to_string()],
        message: Some("Filter out __proto__, constructor, prototype before merging.".to_string()),
        fix: None,
    }
}

/// SSTI via template engines
pub fn ts_ssti_rule() -> Rule {
    Rule {
        id: "ts-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "Template engine may execute user input".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(compile|render|renderString)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "ssti".to_string(),
            "injection".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Never pass user input directly to template engines.".to_string()),
        fix: None,
    }
}

/// CORS wildcard
pub fn ts_cors_wildcard_rule() -> Rule {
    Rule {
        id: "ts-cors-wildcard".to_string(),
        name: "CORS Wildcard Origin".to_string(),
        description: "CORS with wildcard origin exposes API".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(object
              (pair
                key: (property_identifier) @key
                value: (string) @value
              )
              (#match? @key "(?i)origin")
              (#eq? @value "\"*\"")
            ) @cors"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-942".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cors".to_string(),
            "misconfiguration".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Specify allowed origins explicitly.".to_string()),
        fix: None,
    }
}

/// SSRF via HTTP requests
pub fn ts_ssrf_rule() -> Rule {
    Rule {
        id: "ts-ssrf".to_string(),
        name: "Server-Side Request Forgery".to_string(),
        description: "HTTP request with user-controlled URL can lead to SSRF".to_string(),
        severity: Severity::High,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(fetch|axios|got|request)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec![
            "ssrf".to_string(),
            "network".to_string(),
            "typescript".to_string(),
        ],
        message: Some("Validate and allowlist URLs before making requests.".to_string()),
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
        // === NEW RULES ===
        ts_child_process_rule(),
        ts_sql_injection_rule(),
        ts_nosql_injection_rule(),
        ts_jwt_verify_rule(),
        ts_prototype_pollution_rule(),
        ts_ssti_rule(),
        ts_cors_wildcard_rule(),
        ts_ssrf_rule(),
    ]
}
