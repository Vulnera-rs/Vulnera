//! Default hardcoded security rules

use crate::domain::entities::{MethodCallPattern, Rule, RuleOptions, RulePattern, Severity};
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
        options: RuleOptions::default(),
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
        options: RuleOptions::default(),
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
        options: RuleOptions::default(),
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
        options: RuleOptions::default(),
    }
}

/// Null pointer rule - unwrap() can panic on None/Err
pub fn null_pointer_rule() -> Rule {
    Rule {
        id: "null-pointer".to_string(),
        name: "Potential Null Pointer".to_string(),
        description: "Potential panic from unwrap() on None or Err value".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: RulePattern::MethodCall(MethodCallPattern::new("unwrap")),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: false,
            suppress_in_benches: false,
            related_rules: vec!["expect-panic".to_string()],
        },
    }
}

/// Expect panic rule - expect() can panic with a message
pub fn expect_panic_rule() -> Rule {
    Rule {
        id: "expect-panic".to_string(),
        name: "Potential Panic from expect()".to_string(),
        description: "Potential panic from expect() on None or Err value".to_string(),
        severity: Severity::Low, // Lower than unwrap since it provides context
        languages: vec![Language::Rust],
        pattern: RulePattern::MethodCall(MethodCallPattern::new("expect")),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: false,
            suppress_in_benches: false,
            related_rules: vec!["null-pointer".to_string()],
        },
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
        expect_panic_rule(),
        go_command_injection_rule(),
        c_buffer_overflow_rule(),
        c_command_injection_rule(),
        // Python
        python_subprocess_rule(),
        python_yaml_load_rule(),
        python_ssti_rule(),
        // JavaScript
        js_child_process_rule(),
        js_xss_rule(),
        js_eval_rule(),
        // Rust
        rust_command_rule(),
        rust_unsafe_rule(),
        // Go
        go_sql_injection_rule(),
        go_unsafe_rule(),
        // C/C++
        c_gets_rule(),
        c_sprintf_rule(),
        c_exec_rule(),
    ]
}

/// Go command injection rule
pub fn go_command_injection_rule() -> Rule {
    Rule {
        id: "go-command-injection".to_string(),
        name: "Go Command Injection".to_string(),
        description: "Potential command injection in Go".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: RulePattern::FunctionCall("exec.Command".to_string()),
        options: RuleOptions::default(),
    }
}

/// C/C++ buffer overflow rule
pub fn c_buffer_overflow_rule() -> Rule {
    Rule {
        id: "c-buffer-overflow".to_string(),
        name: "Buffer Overflow".to_string(),
        description: "Potential buffer overflow using strcpy".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: RulePattern::FunctionCall("strcpy".to_string()),
        options: RuleOptions::default(),
    }
}

/// C/C++ command injection rule
pub fn c_command_injection_rule() -> Rule {
    Rule {
        id: "c-command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection using system".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: RulePattern::FunctionCall("system".to_string()),
        options: RuleOptions::default(),
    }
}

// --- Python Rules ---

pub fn python_subprocess_rule() -> Rule {
    Rule {
        id: "python-subprocess".to_string(),
        name: "Python Subprocess".to_string(),
        description: "Potential command injection using subprocess".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: RulePattern::FunctionCall("subprocess.call".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn python_yaml_load_rule() -> Rule {
    Rule {
        id: "python-yaml-load".to_string(),
        name: "Unsafe YAML Load".to_string(),
        description: "Unsafe deserialization using yaml.load".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: RulePattern::FunctionCall("yaml.load".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn python_ssti_rule() -> Rule {
    Rule {
        id: "python-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "Potential SSTI using render_template_string".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: RulePattern::FunctionCall("render_template_string".to_string()),
        options: RuleOptions::default(),
    }
}

// --- JavaScript Rules ---

pub fn js_child_process_rule() -> Rule {
    Rule {
        id: "js-child-process".to_string(),
        name: "Node.js Child Process".to_string(),
        description: "Potential command injection using child_process".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: RulePattern::FunctionCall("child_process.exec".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn js_xss_rule() -> Rule {
    Rule {
        id: "js-xss".to_string(),
        name: "Cross-Site Scripting".to_string(),
        description: "Potential XSS using dangerouslySetInnerHTML".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: RulePattern::FunctionCall("dangerouslySetInnerHTML".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn js_eval_rule() -> Rule {
    Rule {
        id: "js-eval-indirect".to_string(),
        name: "Indirect Eval".to_string(),
        description: "Potential indirect eval using setTimeout/setInterval".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: RulePattern::FunctionCall("setTimeout".to_string()),
        options: RuleOptions::default(),
    }
}

// --- Rust Rules ---

pub fn rust_command_rule() -> Rule {
    Rule {
        id: "rust-command".to_string(),
        name: "Rust Command Injection".to_string(),
        description: "Potential command injection using std::process::Command".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: RulePattern::FunctionCall("Command::new".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn rust_unsafe_rule() -> Rule {
    Rule {
        id: "rust-unsafe".to_string(),
        name: "Unsafe Rust Block".to_string(),
        description: "Usage of unsafe block".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: RulePattern::AstNodeType("unsafe_block".to_string()),
        options: RuleOptions::default(),
    }
}

// --- Go Rules ---

pub fn go_sql_injection_rule() -> Rule {
    Rule {
        id: "go-sql-injection".to_string(),
        name: "Go SQL Injection".to_string(),
        description: "Potential SQL injection in Go".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: RulePattern::FunctionCall("sql.Query".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn go_unsafe_rule() -> Rule {
    Rule {
        id: "go-unsafe".to_string(),
        name: "Go Unsafe Pointer".to_string(),
        description: "Usage of unsafe.Pointer".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: RulePattern::FunctionCall("unsafe.Pointer".to_string()), // Matches call-like usage
        options: RuleOptions::default(),
    }
}

// --- C/C++ Rules ---

pub fn c_gets_rule() -> Rule {
    Rule {
        id: "c-gets".to_string(),
        name: "Unsafe gets()".to_string(),
        description: "Usage of unsafe gets() function".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::C, Language::Cpp],
        pattern: RulePattern::FunctionCall("gets".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn c_sprintf_rule() -> Rule {
    Rule {
        id: "c-sprintf".to_string(),
        name: "Unsafe sprintf()".to_string(),
        description: "Potential buffer overflow using sprintf".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: RulePattern::FunctionCall("sprintf".to_string()),
        options: RuleOptions::default(),
    }
}

pub fn c_exec_rule() -> Rule {
    Rule {
        id: "c-exec".to_string(),
        name: "C/C++ Exec".to_string(),
        description: "Potential command injection using exec family".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: RulePattern::FunctionCall("execl".to_string()),
        options: RuleOptions::default(),
    }
}
