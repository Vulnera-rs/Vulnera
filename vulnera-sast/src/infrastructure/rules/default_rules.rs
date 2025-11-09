//! Default hardcoded security rules

use crate::domain::entities::{Rule, RulePattern, Severity};
use crate::domain::value_objects::Language;

/// SQL injection rule
pub fn sql_injection_rule() -> Rule {
    Rule {
        id: "sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Potential SQL injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("execute".to_string()),
    }
}

/// Command injection rule
pub fn command_injection_rule() -> Rule {
    Rule {
        id: "command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("exec".to_string()),
    }
}

/// Unsafe deserialization rule
pub fn unsafe_deserialization_rule() -> Rule {
    Rule {
        id: "unsafe-deserialization".to_string(),
        name: "Unsafe Deserialization".to_string(),
        description: "Potential unsafe deserialization vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("pickle.loads".to_string()),
    }
}

/// Unsafe function call rule
pub fn unsafe_function_call_rule() -> Rule {
    Rule {
        id: "unsafe-function-call".to_string(),
        name: "Unsafe Function Call".to_string(),
        description: "Potentially unsafe function call".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("eval".to_string()),
    }
}

/// Null pointer rule
pub fn null_pointer_rule() -> Rule {
    Rule {
        id: "null-pointer".to_string(),
        name: "Potential Null Pointer".to_string(),
        description: "Potential null pointer dereference".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust], // More relevant for Rust
        pattern: RulePattern::AstNodeType("unwrap".to_string()),
    }
}

/// Get all default rules
pub fn get_default_rules() -> Vec<Rule> {
    vec![
        sql_injection_rule(),
        command_injection_rule(),
        unsafe_deserialization_rule(),
        unsafe_function_call_rule(),
        null_pointer_rule(),
    ]
}


