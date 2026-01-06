//! C/C++ security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! in C and C++ code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Buffer Overflow Rules
// ============================================================================

/// strcpy - no bounds checking
pub fn c_buffer_overflow_rule() -> Rule {
    Rule {
        id: "c-buffer-overflow".to_string(),
        name: "Buffer Overflow (strcpy)".to_string(),
        description: "strcpy does not check buffer bounds".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "strcpy")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-119".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Use strncpy or strlcpy with explicit size limit.".to_string()),
        fix: None,
    }
}

/// strcat - no bounds checking
pub fn c_strcat_rule() -> Rule {
    Rule {
        id: "c-strcat".to_string(),
        name: "Buffer Overflow (strcat)".to_string(),
        description: "strcat does not check buffer bounds".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "strcat")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-119".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Use strncat or strlcat with explicit size limit.".to_string()),
        fix: None,
    }
}

/// gets - always unsafe
pub fn c_gets_rule() -> Rule {
    Rule {
        id: "c-gets".to_string(),
        name: "Dangerous gets() Function".to_string(),
        description: "gets() is inherently unsafe and should never be used".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "gets")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-242".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Use fgets() with size limit instead of gets().".to_string()),
        fix: None,
    }
}

/// sprintf - no bounds checking
pub fn c_sprintf_rule() -> Rule {
    Rule {
        id: "c-sprintf".to_string(),
        name: "Buffer Overflow (sprintf)".to_string(),
        description: "sprintf does not check buffer bounds".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "sprintf")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-119".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Use snprintf with explicit size limit.".to_string()),
        fix: None,
    }
}

/// scanf - can overflow buffer
pub fn c_scanf_rule() -> Rule {
    Rule {
        id: "c-scanf".to_string(),
        name: "Buffer Overflow (scanf)".to_string(),
        description: "scanf %s can overflow buffer without width specifier".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "scanf")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Use width specifiers (e.g., %99s) or fgets.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Command Injection Rules
// ============================================================================

/// system() - command injection
pub fn c_command_injection_rule() -> Rule {
    Rule {
        id: "c-command-injection".to_string(),
        name: "Command Injection (system)".to_string(),
        description: "system() is vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "system")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "c".to_string(),
        ],
        message: Some("Use execve family with argument array instead of system.".to_string()),
        fix: None,
    }
}

/// popen() - command injection
pub fn c_popen_rule() -> Rule {
    Rule {
        id: "c-popen".to_string(),
        name: "Command Injection (popen)".to_string(),
        description: "popen() is vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "popen")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "c".to_string(),
        ],
        message: Some("Validate and sanitize command arguments.".to_string()),
        fix: None,
    }
}

/// exec family - command execution
pub fn c_exec_rule() -> Rule {
    Rule {
        id: "c-exec".to_string(),
        name: "Command Execution (exec)".to_string(),
        description: "exec family functions can execute arbitrary commands".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(execl|execle|execlp|execv|execve|execvp)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "c".to_string(),
        ],
        message: Some("Validate command arguments before execution.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Format String Rules
// ============================================================================

/// Format string vulnerability
pub fn c_format_string_rule() -> Rule {
    Rule {
        id: "c-format-string".to_string(),
        name: "Format String Vulnerability".to_string(),
        description: "printf-family without format string is vulnerable".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (identifier) @arg
              )
              (#match? @fn "^(printf|sprintf|fprintf|snprintf|vprintf|vsprintf)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-134".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["format-string".to_string(), "c".to_string()],
        message: Some("Use format string: printf(\"%s\", str) instead of printf(str).".to_string()),
        fix: None,
    }
}

// ============================================================================
// Memory Management Rules
// ============================================================================

/// malloc(0) - undefined behavior
pub fn c_malloc_zero_rule() -> Rule {
    Rule {
        id: "c-malloc-zero".to_string(),
        name: "Malloc Zero Size".to_string(),
        description: "malloc(0) behavior is implementation-defined".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (number_literal) @size
              )
              (#eq? @fn "malloc")
              (#eq? @size "0")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-131".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "memory".to_string(),
            "undefined-behavior".to_string(),
            "c".to_string(),
        ],
        message: Some("Avoid malloc(0). Always allocate at least 1 byte.".to_string()),
        fix: None,
    }
}

/// free(NULL) - while safe, may indicate logic error
pub fn c_free_null_rule() -> Rule {
    Rule {
        id: "c-free-null".to_string(),
        name: "Free NULL Check".to_string(),
        description: "free(NULL) is safe but may indicate logic error".to_string(),
        severity: Severity::Low,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (null)
              )
              (#eq? @fn "free")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "c".to_string()],
        message: Some("Check for potential logic errors if freeing NULL.".to_string()),
        fix: None,
    }
}

/// Use after free pattern (rough detection)
pub fn c_use_after_free_rule() -> Rule {
    Rule {
        id: "c-use-after-free".to_string(),
        name: "Potential Use After Free".to_string(),
        description: "Variable may be used after being freed".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "free")
            ) @free"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-416".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "memory".to_string(),
            "use-after-free".to_string(),
            "c".to_string(),
        ],
        message: Some("Set pointer to NULL after free to prevent use-after-free.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Integer Overflow Rules
// ============================================================================

/// Integer overflow potential
pub fn c_integer_overflow_rule() -> Rule {
    Rule {
        id: "c-integer-overflow".to_string(),
        name: "Potential Integer Overflow".to_string(),
        description: "Arithmetic operation may overflow".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(binary_expression
              operator: ["+" "-" "*"]
            ) @overflow"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-190".to_string(), "CWE-191".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "overflow".to_string(),
            "arithmetic".to_string(),
            "c".to_string(),
        ],
        message: Some("Consider using safe integer arithmetic or bounds checking.".to_string()),
        fix: None,
    }
}

// ============================================================================
// C++ Specific Rules
// ============================================================================

/// Raw pointer usage in modern C++
pub fn cpp_raw_ptr_rule() -> Rule {
    Rule {
        id: "cpp-raw-ptr".to_string(),
        name: "Raw Pointer Usage".to_string(),
        description: "Raw pointers should be avoided in modern C++".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Cpp],
        pattern: Pattern::TreeSitterQuery(r#"(new_expression) @new"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-401".to_string()],
        owasp_categories: vec![],
        tags: vec![
            "memory".to_string(),
            "modern-cpp".to_string(),
            "cpp".to_string(),
        ],
        message: Some(
            "Use smart pointers (unique_ptr, shared_ptr) instead of raw new.".to_string(),
        ),
        fix: None,
    }
}

/// delete without nullptr check
pub fn cpp_delete_rule() -> Rule {
    Rule {
        id: "cpp-delete".to_string(),
        name: "Delete Without Check".to_string(),
        description: "delete on potentially null pointer".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Cpp],
        pattern: Pattern::TreeSitterQuery(r#"(delete_expression) @delete"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "cpp".to_string()],
        message: Some("Use smart pointers or RAII patterns.".to_string()),
        fix: None,
    }
}

/// reinterpret_cast - dangerous type conversion
pub fn cpp_reinterpret_cast_rule() -> Rule {
    Rule {
        id: "cpp-reinterpret-cast".to_string(),
        name: "Reinterpret Cast".to_string(),
        description: "reinterpret_cast can lead to undefined behavior".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(cast_expression
              type: (type_descriptor) @cast
              (#match? @cast "reinterpret_cast")
            ) @reinterpret"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-843".to_string()],
        owasp_categories: vec![],
        tags: vec!["type-safety".to_string(), "cpp".to_string()],
        message: Some("Avoid reinterpret_cast. Use static_cast or dynamic_cast.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Miscellaneous Rules
// ============================================================================

/// memcpy without size check
pub fn c_memcpy_rule() -> Rule {
    Rule {
        id: "c-memcpy".to_string(),
        name: "Unsafe memcpy".to_string(),
        description: "memcpy may cause buffer overflow without proper size validation".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(memcpy|memmove|memset)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string()],
        owasp_categories: vec![],
        tags: vec!["buffer-overflow".to_string(), "c".to_string()],
        message: Some("Ensure size parameter is validated before memcpy.".to_string()),
        fix: None,
    }
}

/// rand() - not cryptographically secure
pub fn c_rand_rule() -> Rule {
    Rule {
        id: "c-insecure-rand".to_string(),
        name: "Insecure Randomness".to_string(),
        description: "rand() is not cryptographically secure".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "rand")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-330".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "randomness".to_string(),
            "c".to_string(),
        ],
        message: Some(
            "Use getrandom() or /dev/urandom for security-sensitive random values.".to_string(),
        ),
        fix: None,
    }
}

/// Get all C/C++ rules
pub fn get_c_cpp_rules() -> Vec<Rule> {
    vec![
        // Buffer overflow
        c_buffer_overflow_rule(),
        c_strcat_rule(),
        c_gets_rule(),
        c_sprintf_rule(),
        c_scanf_rule(),
        // Command injection
        c_command_injection_rule(),
        c_popen_rule(),
        c_exec_rule(),
        // Format string
        c_format_string_rule(),
        // Memory management
        c_malloc_zero_rule(),
        c_free_null_rule(),
        c_use_after_free_rule(),
        // Integer overflow
        c_integer_overflow_rule(),
        // C++ specific
        cpp_raw_ptr_rule(),
        cpp_delete_rule(),
        cpp_reinterpret_cast_rule(),
        // Miscellaneous
        c_memcpy_rule(),
        c_rand_rule(),
    ]
}
