//! Rust security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! and potential issues in Rust code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Panic and Error Handling Rules
// ============================================================================

/// unwrap() can panic on None/Err
pub fn rust_unwrap_rule() -> Rule {
    Rule {
        id: "null-pointer".to_string(),
        name: "Unwrap Without Check".to_string(),
        description: "unwrap() can panic if the value is None or Err".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @fn
              )
              (#eq? @fn "unwrap")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            ..Default::default()
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "panic".to_string(),
            "error-handling".to_string(),
            "rust".to_string(),
        ],
        message: Some("Use match, if let, or ? operator instead of unwrap().".to_string()),
        fix: None,
    }
}

/// expect() can panic with a message
pub fn rust_expect_rule() -> Rule {
    Rule {
        id: "expect-panic".to_string(),
        name: "Expect Panic".to_string(),
        description: "expect() can panic with a custom message".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @fn
              )
              (#eq? @fn "expect")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            ..Default::default()
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "panic".to_string(),
            "error-handling".to_string(),
            "rust".to_string(),
        ],
        message: Some("Consider using match or ? operator for recoverable errors.".to_string()),
        fix: None,
    }
}

/// panic!() macro
pub fn rust_panic_rule() -> Rule {
    Rule {
        id: "rust-panic".to_string(),
        name: "Explicit Panic".to_string(),
        description: "panic!() will abort the program".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#eq? @macro "panic")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-754".to_string()],
        owasp_categories: vec![],
        tags: vec!["panic".to_string(), "rust".to_string()],
        message: Some("Return Result/Option instead of panicking where appropriate.".to_string()),
        fix: None,
    }
}

/// todo!() and unimplemented!() macros
pub fn rust_todo_rule() -> Rule {
    Rule {
        id: "rust-todo".to_string(),
        name: "Unimplemented Code".to_string(),
        description: "todo!() / unimplemented!() will panic at runtime".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#match? @macro "^(todo|unimplemented)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-754".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "incomplete".to_string(),
            "panic".to_string(),
            "rust".to_string(),
        ],
        message: Some(
            "Ensure todo!() and unimplemented!() are not in production code.".to_string(),
        ),
        fix: None,
    }
}

/// unreachable!() macro
pub fn rust_unreachable_rule() -> Rule {
    Rule {
        id: "rust-unreachable".to_string(),
        name: "Unreachable Code".to_string(),
        description: "unreachable!() will panic if reached".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#eq? @macro "unreachable")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-754".to_string()],
        owasp_categories: vec![],
        tags: vec!["panic".to_string(), "rust".to_string()],
        message: Some("Verify that unreachable!() is truly unreachable.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Unsafe Code Rules
// ============================================================================

/// unsafe block
pub fn rust_unsafe_rule() -> Rule {
    Rule {
        id: "rust-unsafe".to_string(),
        name: "Unsafe Block".to_string(),
        description: "unsafe block bypasses Rust's safety guarantees".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(r#"(unsafe_block) @unsafe"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-119".to_string()],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "rust".to_string()],
        message: Some("Review unsafe code carefully. Document safety invariants.".to_string()),
        fix: None,
    }
}

/// std::mem::transmute - dangerous conversion
pub fn rust_transmute_rule() -> Rule {
    Rule {
        id: "rust-transmute".to_string(),
        name: "Transmute".to_string(),
        description: "std::mem::transmute can cause undefined behavior".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                name: (identifier) @fn
              )
              (#eq? @fn "transmute")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-843".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "unsafe".to_string(),
            "transmute".to_string(),
            "rust".to_string(),
        ],
        message: Some("Avoid transmute. Use safe alternatives like TryFrom/TryInto.".to_string()),
        fix: None,
    }
}

/// Raw pointer dereference
pub fn rust_raw_pointer_rule() -> Rule {
    Rule {
        id: "rust-raw-pointer".to_string(),
        name: "Raw Pointer Dereference".to_string(),
        description: "Dereferencing raw pointers is unsafe".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(unary_expression
              operator: "*"
              argument: (identifier) @ptr
            ) @deref"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-119".to_string(), "CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "unsafe".to_string(),
            "pointer".to_string(),
            "rust".to_string(),
        ],
        message: Some("Ensure pointer validity before dereferencing.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Command Injection Rules
// ============================================================================

/// Command::new with potential user input
pub fn rust_command_rule() -> Rule {
    Rule {
        id: "rust-command".to_string(),
        name: "Command Execution".to_string(),
        description: "Command::new may be vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                path: (identifier) @mod
                name: (identifier) @fn
              )
              (#eq? @mod "Command")
              (#eq? @fn "new")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "rust".to_string(),
        ],
        message: Some("Validate and sanitize command arguments.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SQL Injection Rules
// ============================================================================

/// Raw SQL queries
pub fn rust_sql_injection_rule() -> Rule {
    Rule {
        id: "rust-sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Raw SQL query may be vulnerable to injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @fn
              )
              (#match? @fn "^(query|execute)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "sql".to_string(),
            "rust".to_string(),
        ],
        message: Some("Use parameterized queries instead of string concatenation.".to_string()),
        fix: None,
    }
}

// ============================================================================
// File Operations Rules
// ============================================================================

/// File permission with 0o777
pub fn rust_file_permission_rule() -> Rule {
    Rule {
        id: "rust-file-permission".to_string(),
        name: "Overly Permissive File".to_string(),
        description: "File created with overly permissive permissions".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                name: (identifier) @fn
              )
              arguments: (arguments
                (integer_literal) @perm
              )
              (#eq? @fn "set_mode")
              (#match? @perm "0o7")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-732".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "file".to_string(),
            "permissions".to_string(),
            "rust".to_string(),
        ],
        message: Some("Avoid overly permissive file modes like 0o777.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Cryptography Rules
// ============================================================================

/// Weak hash functions
pub fn rust_weak_crypto_rule() -> Rule {
    Rule {
        id: "rust-weak-crypto".to_string(),
        name: "Weak Cryptographic Hash".to_string(),
        description: "MD5 and SHA1 are cryptographically weak".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(use_declaration
              argument: (scoped_identifier) @import
              (#match? @import "(?i)(md5|sha1)")
            ) @use"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string(), "CWE-328".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "weak-algorithm".to_string(),
            "rust".to_string(),
        ],
        message: Some("Use SHA-256 or stronger hash algorithms.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Concurrency Rules
// ============================================================================

/// Static mut - data race risk
pub fn rust_static_mut_rule() -> Rule {
    Rule {
        id: "rust-static-mut".to_string(),
        name: "Static Mutable Variable".to_string(),
        description: "static mut can cause data races".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(static_item
              (mutable_specifier) @mut
            ) @static"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-362".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "concurrency".to_string(),
            "data-race".to_string(),
            "rust".to_string(),
        ],
        message: Some("Use Mutex, RwLock, or atomic types instead of static mut.".to_string()),
        fix: None,
    }
}

// ============================================================================
// NEW RULES
// ============================================================================

/// Box::leak - intentional memory leak
pub fn rust_box_leak_rule() -> Rule {
    Rule {
        id: "rust-box-leak".to_string(),
        name: "Box::leak Memory Leak".to_string(),
        description: "Box::leak intentionally leaks memory".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                path: (identifier) @type
                name: (identifier) @fn
              )
              (#eq? @type "Box")
              (#eq? @fn "leak")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-401".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "leak".to_string(), "rust".to_string()],
        message: Some("Box::leak should only be used for truly static data. Consider Arc for shared ownership.".to_string()),
        fix: None,
    }
}

/// format! in SQL query construction
pub fn rust_format_sql_rule() -> Rule {
    Rule {
        id: "rust-format-sql".to_string(),
        name: "Format String SQL".to_string(),
        description: "Using format! for SQL queries can lead to SQL injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (token_tree
                (string_literal) @sql
              )
              (#eq? @macro "format")
              (#match? @sql "(?i)(SELECT|INSERT|UPDATE|DELETE|WHERE)")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "sql".to_string(),
            "injection".to_string(),
            "rust".to_string(),
        ],
        message: Some(
            "Use parameterized queries with sqlx::query! or diesel instead of format!.".to_string(),
        ),
        fix: None,
    }
}

/// User-controlled regex (potential ReDoS)
pub fn rust_regex_user_input_rule() -> Rule {
    Rule {
        id: "rust-regex-user-input".to_string(),
        name: "User-Controlled Regex".to_string(),
        description: "Regex compiled from user input can cause ReDoS".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                path: (identifier) @type
                name: (identifier) @fn
              )
              (#eq? @type "Regex")
              (#eq? @fn "new")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1333".to_string(), "CWE-400".to_string()],
        owasp_categories: vec![],
        tags: vec!["redos".to_string(), "regex".to_string(), "rust".to_string()],
        message: Some(
            "Use Regex::new with size limits or fancy_regex with backtrack limits.".to_string(),
        ),
        fix: None,
    }
}

/// debug_assert! - removed in release builds
pub fn rust_debug_assert_rule() -> Rule {
    Rule {
        id: "rust-debug-assert".to_string(),
        name: "Debug Assert in Security Code".to_string(),
        description: "debug_assert! is removed in release builds".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#match? @macro "^debug_assert")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-617".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "assert".to_string(),
            "debug".to_string(),
            "rust".to_string(),
        ],
        message: Some(
            "Use assert! for security-critical checks that must run in release builds.".to_string(),
        ),
        fix: None,
    }
}

/// forget - prevents Drop from running
pub fn rust_forget_rule() -> Rule {
    Rule {
        id: "rust-forget".to_string(),
        name: "std::mem::forget".to_string(),
        description: "forget() prevents Drop from running, potentially leaking resources"
            .to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                name: (identifier) @fn
              )
              (#eq? @fn "forget")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-401".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "drop".to_string(), "rust".to_string()],
        message: Some(
            "Use ManuallyDrop if you need to prevent Drop. Ensure resources are properly handled."
                .to_string(),
        ),
        fix: None,
    }
}

/// Get all Rust rules
pub fn get_rust_rules() -> Vec<Rule> {
    vec![
        // Panic and error handling
        rust_unwrap_rule(),
        rust_expect_rule(),
        rust_panic_rule(),
        rust_todo_rule(),
        rust_unreachable_rule(),
        // Unsafe code
        rust_unsafe_rule(),
        rust_transmute_rule(),
        rust_raw_pointer_rule(),
        // Command injection
        rust_command_rule(),
        // SQL injection
        rust_sql_injection_rule(),
        // File operations
        rust_file_permission_rule(),
        // Cryptography
        rust_weak_crypto_rule(),
        // Concurrency
        rust_static_mut_rule(),
        // === NEW RULES ===
        rust_box_leak_rule(),
        rust_format_sql_rule(),
        rust_regex_user_input_rule(),
        rust_debug_assert_rule(),
        rust_forget_rule(),
    ]
}
