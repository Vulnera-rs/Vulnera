//! Go security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! in Go code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Command Injection Rules
// ============================================================================

/// exec.Command with user input
pub fn go_command_injection_rule() -> Rule {
    Rule {
        id: "go-command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "exec.Command may be vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "exec")
              (#eq? @fn "Command")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "go".to_string(),
        ],
        message: Some("Validate and sanitize command arguments.".to_string()),
        fix: None,
    }
}

/// os/exec CommandContext
pub fn go_command_context_rule() -> Rule {
    Rule {
        id: "go-command-context".to_string(),
        name: "CommandContext Injection".to_string(),
        description: "exec.CommandContext may be vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "exec")
              (#eq? @fn "CommandContext")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "go".to_string(),
        ],
        message: Some("Validate and sanitize command arguments.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SQL Injection Rules
// ============================================================================

/// database/sql Query/Exec
pub fn go_sql_injection_rule() -> Rule {
    Rule {
        id: "go-sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "SQL query may be vulnerable to injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                field: (field_identifier) @fn
              )
              (#match? @fn "^(Query|QueryRow|Exec|QueryContext|ExecContext)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "sql".to_string(), "go".to_string()],
        message: Some("Use parameterized queries with placeholders.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Unsafe Code Rules
// ============================================================================

/// unsafe.Pointer usage
pub fn go_unsafe_rule() -> Rule {
    Rule {
        id: "go-unsafe".to_string(),
        name: "Unsafe Pointer".to_string(),
        description: "unsafe.Pointer bypasses Go's type safety".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "unsafe")
              (#eq? @fn "Pointer")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-119".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "unsafe".to_string(),
            "pointer".to_string(),
            "go".to_string(),
        ],
        message: Some("Avoid unsafe.Pointer unless absolutely necessary.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SSRF Rules
// ============================================================================

/// http.Get/Post with user input
pub fn go_ssrf_rule() -> Rule {
    Rule {
        id: "go-ssrf".to_string(),
        name: "Server-Side Request Forgery".to_string(),
        description: "Potential SSRF using net/http or other HTTP clients".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"[
              (call_expression
                function: (selector_expression
                  operand: (identifier) @pkg
                  field: (field_identifier) @fn
                )
                (#eq? @pkg "http")
                (#match? @fn "^(Get|Post|Head|PostForm)$")
              ) @call
              (call_expression
                function: (selector_expression
                  operand: (identifier) @pkg
                  field: (field_identifier) @fn
                )
                arguments: (argument_list
                  (identifier) @url_var
                )
                (#eq? @pkg "http")
                (#eq? @fn "NewRequest")
              ) @call
            ]"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec!["ssrf".to_string(), "network".to_string(), "go".to_string()],
        message: Some("Validate and sanitize user-controlled URLs before making HTTP requests. Use allowlists for permitted domains.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Cryptography Rules
// ============================================================================

/// math/rand instead of crypto/rand
pub fn go_math_rand_rule() -> Rule {
    Rule {
        id: "go-insecure-rand".to_string(),
        name: "Insecure Randomness".to_string(),
        description: "math/rand is not cryptographically secure".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "rand")
              (#match? @fn "^(Int|Intn|Float64|Uint32|Read)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-330".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "randomness".to_string(),
            "go".to_string(),
        ],
        message: Some("Use crypto/rand for security-sensitive random values.".to_string()),
        fix: None,
    }
}

/// Weak crypto algorithms
pub fn go_weak_crypto_rule() -> Rule {
    Rule {
        id: "go-weak-crypto".to_string(),
        name: "Weak Cryptographic Algorithm".to_string(),
        description: "MD5, SHA1, DES, RC4 are cryptographically weak".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#match? @pkg "^(md5|sha1|des|rc4)$")
              (#eq? @fn "New")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string(), "CWE-328".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "weak-algorithm".to_string(),
            "go".to_string(),
        ],
        message: Some("Use SHA-256 or stronger algorithms.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Secrets and Credentials Rules
// ============================================================================

/// Hardcoded credentials
pub fn go_hardcoded_credentials_rule() -> Rule {
    Rule {
        id: "go-hardcoded-credentials".to_string(),
        name: "Hardcoded Credentials".to_string(),
        description: "Potential hardcoded password or secret".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(short_var_declaration
              left: (expression_list
                (identifier) @name
              )
              right: (expression_list
                (interpreted_string_literal) @value
              )
              (#match? @name "(?i)(password|passwd|secret|api_key|apikey|token|auth)")
            ) @decl"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec![
            "secrets".to_string(),
            "credentials".to_string(),
            "go".to_string(),
        ],
        message: Some("Store secrets in environment variables or a secrets manager.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Path Traversal Rules
// ============================================================================

/// filepath.Join with user input
pub fn go_path_traversal_rule() -> Rule {
    Rule {
        id: "go-path-traversal".to_string(),
        name: "Path Traversal".to_string(),
        description: "Potential path traversal via file operations".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "filepath")
              (#eq? @fn "Join")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-22".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["path-traversal".to_string(), "go".to_string()],
        message: Some("Validate that file paths don't contain .. or absolute paths.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Template Injection Rules
// ============================================================================

/// template.HTML without escaping
pub fn go_template_html_rule() -> Rule {
    Rule {
        id: "go-template-html".to_string(),
        name: "Unescaped HTML Template".to_string(),
        description: "template.HTML bypasses auto-escaping and can lead to XSS".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "template")
              (#eq? @fn "HTML")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "template".to_string(), "go".to_string()],
        message: Some(
            "Avoid template.HTML with user input. Let templates auto-escape.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Concurrency Rules
// ============================================================================

/// defer in loop
pub fn go_defer_in_loop_rule() -> Rule {
    Rule {
        id: "go-defer-loop".to_string(),
        name: "Defer in Loop".to_string(),
        description: "defer in loop may cause resource exhaustion".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(for_statement
              body: (block
                (defer_statement) @defer
              )
            ) @loop"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-404".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "resource".to_string(),
            "defer".to_string(),
            "go".to_string(),
        ],
        message: Some(
            "Move cleanup logic to a separate function to avoid deferred resource accumulation."
                .to_string(),
        ),
        fix: None,
    }
}

/// goroutine without sync
pub fn go_goroutine_leak_rule() -> Rule {
    Rule {
        id: "go-goroutine-leak".to_string(),
        name: "Potential Goroutine Leak".to_string(),
        description: "Anonymous goroutine may leak without proper synchronization".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(go_statement
              (call_expression
                function: (func_literal)
              )
            ) @goroutine"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-404".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "concurrency".to_string(),
            "goroutine".to_string(),
            "go".to_string(),
        ],
        message: Some(
            "Ensure goroutines have proper exit conditions and use WaitGroups or channels."
                .to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Error Handling Rules
// ============================================================================

/// Ignored error return
pub fn go_ignored_error_rule() -> Rule {
    Rule {
        id: "go-ignored-error".to_string(),
        name: "Ignored Error".to_string(),
        description: "Error return value ignored".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_statement
              left: (expression_list
                (identifier) @var
              )
              (#eq? @var "_")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-252".to_string()],
        owasp_categories: vec![],
        tags: vec!["error-handling".to_string(), "go".to_string()],
        message: Some("Handle errors explicitly instead of ignoring with _.".to_string()),
        fix: None,
    }
}

/// Get all Go rules
pub fn get_go_rules() -> Vec<Rule> {
    vec![
        // Command injection
        go_command_injection_rule(),
        go_command_context_rule(),
        // SQL injection
        go_sql_injection_rule(),
        // Unsafe code
        go_unsafe_rule(),
        // SSRF
        go_ssrf_rule(),
        // Cryptography
        go_math_rand_rule(),
        go_weak_crypto_rule(),
        // Secrets
        go_hardcoded_credentials_rule(),
        // Path traversal
        go_path_traversal_rule(),
        // Templates
        go_template_html_rule(),
        // Concurrency
        go_defer_in_loop_rule(),
        go_goroutine_leak_rule(),
        // Error handling
        go_ignored_error_rule(),
    ]
}
