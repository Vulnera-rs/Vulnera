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

// ============================================================================
// NEW RULES
// ============================================================================

/// XXE via xml.Unmarshal
pub fn go_xxe_rule() -> Rule {
    Rule {
        id: "go-xxe".to_string(),
        name: "XML External Entity (XXE)".to_string(),
        description: "XML parsing may be vulnerable to XXE attacks".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "xml")
              (#match? @fn "^(Unmarshal|NewDecoder)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-611".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["xxe".to_string(), "xml".to_string(), "go".to_string()],
        message: Some(
            "Use encoding/xml with caution. Disable entity expansion if possible.".to_string(),
        ),
        fix: None,
    }
}

/// TLS InsecureSkipVerify
pub fn go_tls_skip_verify_rule() -> Rule {
    Rule {
        id: "go-tls-insecure-skip-verify".to_string(),
        name: "TLS Certificate Verification Disabled".to_string(),
        description: "InsecureSkipVerify disables TLS certificate validation".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(keyed_element
              (field_identifier) @field
              (true)
              (#eq? @field "InsecureSkipVerify")
            ) @config"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-295".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec![
            "tls".to_string(),
            "certificate".to_string(),
            "go".to_string(),
        ],
        message: Some(
            "Never set InsecureSkipVerify: true in production. Use proper certificate validation."
                .to_string(),
        ),
        fix: None,
    }
}

/// text/template injection (unescaped)
pub fn go_text_template_rule() -> Rule {
    Rule {
        id: "go-text-template".to_string(),
        name: "Text Template Injection".to_string(),
        description: "text/template does not escape HTML - use html/template instead".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(import_spec
              path: (interpreted_string_literal) @path
              (#eq? @path "\"text/template\"")
            ) @import"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string(), "CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["ssti".to_string(), "template".to_string(), "go".to_string()],
        message: Some("Use html/template for HTML output to auto-escape content.".to_string()),
        fix: None,
    }
}

/// pprof enabled in production
pub fn go_pprof_enabled_rule() -> Rule {
    Rule {
        id: "go-pprof-enabled".to_string(),
        name: "pprof Debug Endpoint Enabled".to_string(),
        description: "pprof endpoints expose sensitive profiling data".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(import_spec
              path: (interpreted_string_literal) @path
              (#eq? @path "\"net/http/pprof\"")
            ) @import"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-200".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["pprof".to_string(), "debug".to_string(), "go".to_string()],
        message: Some(
            "Disable pprof in production or restrict access to authenticated users.".to_string(),
        ),
        fix: None,
    }
}

/// Timing attack via bytes.Equal or == for secrets
pub fn go_timing_attack_rule() -> Rule {
    Rule {
        id: "go-timing-attack".to_string(),
        name: "Timing Attack Vulnerability".to_string(),
        description:
            "Using bytes.Equal or == for secret comparison is vulnerable to timing attacks"
                .to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "bytes")
              (#eq? @fn "Equal")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-208".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec!["timing".to_string(), "crypto".to_string(), "go".to_string()],
        message: Some("Use subtle.ConstantTimeCompare() for secret comparison.".to_string()),
        fix: None,
    }
}

/// NoSQL injection (MongoDB mgo/mongo-driver)
pub fn go_nosql_injection_rule() -> Rule {
    Rule {
        id: "go-nosql-injection".to_string(),
        name: "NoSQL Injection".to_string(),
        description: "MongoDB query with user input may be vulnerable".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                field: (field_identifier) @fn
              )
              (#match? @fn "^(Find|FindOne|UpdateOne|DeleteOne|Aggregate)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-943".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["nosql".to_string(), "mongodb".to_string(), "go".to_string()],
        message: Some(
            "Validate and sanitize user input before using in MongoDB queries.".to_string(),
        ),
        fix: None,
    }
}

/// Open redirect
pub fn go_open_redirect_rule() -> Rule {
    Rule {
        id: "go-open-redirect".to_string(),
        name: "Open Redirect".to_string(),
        description: "http.Redirect with user-controlled URL can lead to phishing".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#eq? @pkg "http")
              (#eq? @fn "Redirect")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-601".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "redirect".to_string(),
            "phishing".to_string(),
            "go".to_string(),
        ],
        message: Some(
            "Validate redirect URLs against an allowlist of trusted domains.".to_string(),
        ),
        fix: None,
    }
}

/// Hardcoded IP binding
pub fn go_hardcoded_bind_rule() -> Rule {
    Rule {
        id: "go-hardcoded-bind".to_string(),
        name: "Hardcoded IP Binding".to_string(),
        description: "Binding to 0.0.0.0 exposes the service to all interfaces".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              arguments: (argument_list
                (interpreted_string_literal) @addr
              )
              (#eq? @pkg "http")
              (#match? @fn "^(ListenAndServe|ListenAndServeTLS)$")
              (#match? @addr "0\\.0\\.0\\.0")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-668".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "network".to_string(),
            "binding".to_string(),
            "go".to_string(),
        ],
        message: Some("Bind to specific interfaces or use environment configuration.".to_string()),
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
        // Path traversal
        go_path_traversal_rule(),
        // Templates
        go_template_html_rule(),
        // Concurrency
        go_defer_in_loop_rule(),
        go_goroutine_leak_rule(),
        // Error handling
        go_ignored_error_rule(),
        // === NEW CATASTROPHIC RULES ===
        go_xxe_rule(),
        go_tls_skip_verify_rule(),
        go_text_template_rule(),
        go_pprof_enabled_rule(),
        go_timing_attack_rule(),
        go_nosql_injection_rule(),
        go_open_redirect_rule(),
        go_hardcoded_bind_rule(),
    ]
}
