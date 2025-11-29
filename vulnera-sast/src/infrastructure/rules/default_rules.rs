//! Default hardcoded security rules with tree-sitter query patterns

use crate::domain::entities::{Rule, RuleOptions, RulePattern, Severity};
use crate::domain::value_objects::Language;

/// SQL injection rule - detects execute() calls that may contain SQL
pub fn sql_injection_rule() -> Rule {
    Rule {
        id: "sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Potential SQL injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        // Matches: execute(...), cursor.execute(...), db.execute(...)
        pattern: RulePattern::TreeSitterQuery(
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
    }
}

/// Command injection rule - detects exec() calls
pub fn command_injection_rule() -> Rule {
    Rule {
        id: "command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        // Matches: exec(...), os.exec(...)
        pattern: RulePattern::TreeSitterQuery(
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
    }
}

/// Unsafe deserialization rule - detects pickle.loads() calls
pub fn unsafe_deserialization_rule() -> Rule {
    Rule {
        id: "unsafe-deserialization".to_string(),
        name: "Unsafe Deserialization".to_string(),
        description: "Potential unsafe deserialization vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        // Matches: pickle.loads(...), pickle.load(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "pickle")
              (#match? @fn "^loads?$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-502".to_string()],
        owasp_categories: vec!["A08:2021 - Software and Data Integrity Failures".to_string()],
        tags: vec!["deserialization".to_string()],
    }
}

/// Unsafe function call rule - detects eval() calls
pub fn unsafe_function_call_rule() -> Rule {
    Rule {
        id: "unsafe-function-call".to_string(),
        name: "Unsafe Function Call".to_string(),
        description: "Potentially unsafe function call".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python, Language::JavaScript],
        // Matches: eval(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "eval")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-95".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "code-execution".to_string()],
    }
}

/// Null pointer rule - unwrap() can panic on None/Err (Rust)
pub fn null_pointer_rule() -> Rule {
    Rule {
        id: "null-pointer".to_string(),
        name: "Potential Null Pointer".to_string(),
        description: "Potential panic from unwrap() on None or Err value".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        // Matches: .unwrap() method calls in Rust
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @method
              )
              (#eq? @method "unwrap")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: false,
            suppress_in_benches: false,
            related_rules: vec!["expect-panic".to_string()],
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["reliability".to_string(), "rust".to_string()],
    }
}

/// Expect panic rule - expect() can panic with a message (Rust)
pub fn expect_panic_rule() -> Rule {
    Rule {
        id: "expect-panic".to_string(),
        name: "Potential Panic from expect()".to_string(),
        description: "Potential panic from expect() on None or Err value".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Rust],
        // Matches: .expect(...) method calls in Rust
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (field_expression
                field: (field_identifier) @method
              )
              (#eq? @method "expect")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: false,
            suppress_in_benches: false,
            related_rules: vec!["null-pointer".to_string()],
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["reliability".to_string(), "rust".to_string()],
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

/// Go command injection rule - exec.Command()
pub fn go_command_injection_rule() -> Rule {
    Rule {
        id: "go-command-injection".to_string(),
        name: "Go Command Injection".to_string(),
        description: "Potential command injection in Go".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        // Matches: exec.Command(...)
        pattern: RulePattern::TreeSitterQuery(
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
        tags: vec!["injection".to_string(), "go".to_string()],
    }
}

/// C/C++ buffer overflow rule - strcpy()
pub fn c_buffer_overflow_rule() -> Rule {
    Rule {
        id: "c-buffer-overflow".to_string(),
        name: "Buffer Overflow".to_string(),
        description: "Potential buffer overflow using strcpy".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        // Matches: strcpy(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "strcpy")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-121".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory-safety".to_string(), "buffer-overflow".to_string()],
    }
}

/// C/C++ command injection rule - system()
pub fn c_command_injection_rule() -> Rule {
    Rule {
        id: "c-command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection using system".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        // Matches: system(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "system")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "command".to_string()],
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
        // Matches: subprocess.call(...), subprocess.run(...), subprocess.Popen(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "subprocess")
              (#match? @fn "^(call|run|Popen|check_output|check_call)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "python".to_string()],
    }
}

pub fn python_yaml_load_rule() -> Rule {
    Rule {
        id: "python-yaml-load".to_string(),
        name: "Unsafe YAML Load".to_string(),
        description: "Unsafe deserialization using yaml.load without safe_load".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        // Matches: yaml.load(...) but not yaml.safe_load(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "yaml")
              (#eq? @fn "load")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-502".to_string()],
        owasp_categories: vec!["A08:2021 - Software and Data Integrity Failures".to_string()],
        tags: vec!["deserialization".to_string(), "python".to_string()],
    }
}

pub fn python_ssti_rule() -> Rule {
    Rule {
        id: "python-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "Potential SSTI using render_template_string".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        // Matches: render_template_string(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "render_template_string")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "ssti".to_string()],
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
        // Matches: child_process.exec(...), require('child_process').exec(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(exec|execSync|spawn|spawnSync|execFile)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "javascript".to_string()],
    }
}

pub fn js_xss_rule() -> Rule {
    Rule {
        id: "js-xss".to_string(),
        name: "Cross-Site Scripting".to_string(),
        description: "Potential XSS using dangerouslySetInnerHTML or innerHTML".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        // Matches: dangerouslySetInnerHTML, innerHTML assignments
        pattern: RulePattern::TreeSitterQuery(
            r#"[
              (jsx_attribute
                (property_identifier) @attr
                (#eq? @attr "dangerouslySetInnerHTML")
              )
              (assignment_expression
                left: (member_expression
                  property: (property_identifier) @prop
                )
                (#eq? @prop "innerHTML")
              )
            ] @xss"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "javascript".to_string()],
    }
}

pub fn js_eval_rule() -> Rule {
    Rule {
        id: "js-eval-indirect".to_string(),
        name: "Indirect Eval".to_string(),
        description: "Potential indirect eval using setTimeout/setInterval with string".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        // Matches: setTimeout("...", ...), setInterval("...", ...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (arguments
                (string) @str
              )
              (#match? @fn "^(setTimeout|setInterval)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-95".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "javascript".to_string()],
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
        // Matches: Command::new(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                path: (identifier) @type
                name: (identifier) @fn
              )
              (#eq? @type "Command")
              (#eq? @fn "new")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "rust".to_string()],
    }
}

pub fn rust_unsafe_rule() -> Rule {
    Rule {
        id: "rust-unsafe".to_string(),
        name: "Unsafe Rust Block".to_string(),
        description: "Usage of unsafe block".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        // Matches: unsafe { ... }
        pattern: RulePattern::TreeSitterQuery(r#"(unsafe_block) @unsafe"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "rust".to_string()],
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
        // Matches: db.Query(...), db.Exec(...), sql.Query(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                field: (field_identifier) @fn
              )
              (#match? @fn "^(Query|Exec|QueryRow)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "sql".to_string(), "go".to_string()],
    }
}

pub fn go_unsafe_rule() -> Rule {
    Rule {
        id: "go-unsafe".to_string(),
        name: "Go Unsafe Pointer".to_string(),
        description: "Usage of unsafe.Pointer".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        // Matches: unsafe.Pointer(...)
        pattern: RulePattern::TreeSitterQuery(
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
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "go".to_string()],
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
        // Matches: gets(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "gets")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-676".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory-safety".to_string(), "deprecated".to_string()],
    }
}

pub fn c_sprintf_rule() -> Rule {
    Rule {
        id: "c-sprintf".to_string(),
        name: "Unsafe sprintf()".to_string(),
        description: "Potential buffer overflow using sprintf".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        // Matches: sprintf(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "sprintf")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-120".to_string(), "CWE-134".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory-safety".to_string(), "format-string".to_string()],
    }
}

pub fn c_exec_rule() -> Rule {
    Rule {
        id: "c-exec".to_string(),
        name: "C/C++ Exec".to_string(),
        description: "Potential command injection using exec family".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        // Matches: execl(...), execv(...), execle(...), execve(...), execlp(...), execvp(...)
        pattern: RulePattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^exec[lv]p?e?$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "command".to_string()],
    }
}
