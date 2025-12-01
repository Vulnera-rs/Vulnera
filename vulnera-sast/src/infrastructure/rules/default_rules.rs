//! Default hardcoded security rules with tree-sitter query patterns

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

/// SQL injection rule - detects execute() calls that may contain SQL
pub fn sql_injection_rule() -> Rule {
    Rule {
        id: "sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Potential SQL injection vulnerability".to_string(),
        severity: Severity::High,
        // Only Python/JavaScript - these use (call) node type
        languages: vec![Language::Python, Language::JavaScript],
        // Matches: execute(...), cursor.execute(...), db.execute(...)
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
pub fn command_injection_rule() -> Rule {
    Rule {
        id: "command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection vulnerability".to_string(),
        severity: Severity::High,
        // Only Python/JavaScript - these use (call) node type
        languages: vec![Language::Python, Language::JavaScript],
        // Matches: exec(...), os.exec(...)
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

/// Unsafe deserialization rule - detects pickle.loads() calls
pub fn unsafe_deserialization_rule() -> Rule {
    Rule {
        id: "unsafe-deserialization".to_string(),
        name: "Unsafe Deserialization".to_string(),
        description: "Potential unsafe deserialization vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        // Matches: pickle.loads(...), pickle.load(...)
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
    }
}

/// Unsafe function call rule - detects eval() calls (Python only)
/// Note: Uses Python AST syntax (call node type)
pub fn unsafe_function_call_rule() -> Rule {
    Rule {
        id: "unsafe-function-call".to_string(),
        name: "Unsafe Function Call".to_string(),
        description: "Potentially unsafe function call".to_string(),
        severity: Severity::Medium,
        // Only Python - JavaScript uses (call_expression) which has a separate rule
        languages: vec![Language::Python],
        // Matches: eval(...)
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
    }
}

/// JavaScript eval rule - detects eval() calls
pub fn js_eval_direct_rule() -> Rule {
    Rule {
        id: "js-eval-direct".to_string(),
        name: "Direct Eval".to_string(),
        description: "Potentially unsafe eval() call".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        // Matches: eval(...) in JavaScript
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "eval")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-95".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "javascript".to_string(),
        ],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
            min_confidence: None,
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["reliability".to_string(), "rust".to_string()],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
            min_confidence: None,
        },
        cwe_ids: vec!["CWE-476".to_string()],
        owasp_categories: vec![],
        tags: vec!["reliability".to_string(), "rust".to_string()],
        message: None,
        fix: None,
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
        python_hardcoded_password_rule(),
        python_weak_crypto_rule(),
        python_path_traversal_rule(),
        python_ssrf_rule(),
        python_debug_enabled_rule(),
        python_jwt_no_verify_rule(),
        python_xxe_rule(),
        // JavaScript/TypeScript
        js_child_process_rule(),
        js_ssti_rule(),
        js_path_traversal_rule(),
        js_xss_rule(),
        js_eval_rule(),
        js_eval_direct_rule(),
        js_prototype_pollution_rule(),
        js_open_redirect_rule(),
        js_hardcoded_secret_rule(),
        js_insecure_randomness_rule(),
        js_innerhtml_rule(),
        js_document_write_rule(),
        ts_any_type_rule(),
        // Rust
        rust_command_rule(),
        rust_unsafe_rule(),
        rust_transmute_rule(),
        rust_file_permission_rule(),
        rust_sql_injection_rule(),
        // Go
        go_sql_injection_rule(),
        go_unsafe_rule(),
        go_hardcoded_credentials_rule(),
        go_weak_crypto_rule(),
        go_path_traversal_rule(),
        go_math_rand_rule(),
        go_ssrf_rule(),
        // C/C++
        c_gets_rule(),
        c_sprintf_rule(),
        c_exec_rule(),
        c_format_string_rule(),
        c_malloc_zero_rule(),
        c_free_null_rule(),
        c_integer_overflow_rule(),
        cpp_raw_ptr_rule(),
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
        tags: vec!["injection".to_string(), "go".to_string()],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        tags: vec!["injection".to_string(), "command".to_string()],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
    }
}

pub fn python_yaml_load_rule() -> Rule {
    Rule {
        id: "python-yaml-load".to_string(),
        name: "Unsafe YAML Load".to_string(),
        description: "Unsafe deserialization using yaml.load or yaml.unsafe_load".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        // Matches: yaml.load(...), yaml.unsafe_load(...)
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "yaml")
              (#match? @fn "^(load|unsafe_load)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-502".to_string()],
        owasp_categories: vec!["A08:2021 - Software and Data Integrity Failures".to_string()],
        tags: vec!["deserialization".to_string(), "python".to_string()],
        message: Some("Use yaml.safe_load() instead of yaml.load() or yaml.unsafe_load() to prevent arbitrary code execution.".to_string()),
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
    }
}

/// Server-Side Template Injection (SSTI) rule for JavaScript
/// Detects dangerous template engine usage that could lead to RCE
pub fn js_ssti_rule() -> Rule {
    Rule {
        id: "js-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "Potential SSTI vulnerability - template engine may execute untrusted input".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        // Matches: pug.compile(), pug.render(), ejs.render(), nunjucks.render(), etc.
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @lib
                property: (property_identifier) @method)
              (#match? @lib "^(pug|jade|ejs|nunjucks|handlebars|Handlebars|doT|mustache|Mustache|underscore|_)$")
              (#match? @method "^(compile|compileFile|compileClient|render|renderFile|renderString|template|precompile|parse)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-1336".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["ssti".to_string(), "injection".to_string(), "rce".to_string(), "javascript".to_string()],
        message: Some("Template engines should not compile untrusted user input. Use pre-compiled templates or escape user data.".to_string()),
        fix: None,
    }
}

/// Zip Slip / Path Traversal rule for JavaScript
/// Detects unsafe archive extraction that could allow writing files outside target directory
pub fn js_path_traversal_rule() -> Rule {
    Rule {
        id: "js-path-traversal".to_string(),
        name: "Path Traversal / Zip Slip".to_string(),
        description: "Archive extraction without path validation may allow writing files outside target directory".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        // Matches: path.join with entry.path/fileName/entryName without prior validation
        pattern: Pattern::TreeSitterQuery(
            r#"(comment) @ignore"#.to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-22".to_string(), "CWE-73".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["path-traversal".to_string(), "zip-slip".to_string(), "javascript".to_string()],
        message: Some("Validate that archive entry paths don't escape the target directory using path.resolve() and startsWith() check.".to_string()),
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(r#"(unsafe_block) @unsafe"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "rust".to_string()],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "go".to_string()],
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
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
        pattern: Pattern::TreeSitterQuery(
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
        message: None,
        fix: None,
    }
}

// ============================================================================
// Additional Python Rules
// ============================================================================

pub fn python_hardcoded_password_rule() -> Rule {
    Rule {
        id: "python-hardcoded-password".to_string(),
        name: "Hardcoded Password".to_string(),
        description: "Potential hardcoded password or secret in code".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment
              left: (identifier) @var
              right: (string) @val
              (#match? @var "(?i)(password|passwd|secret|api_key|apikey|token)")
            ) @assignment"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec!["secrets".to_string(), "hardcoded".to_string()],
        message: None,
        fix: None,
    }
}

pub fn python_weak_crypto_rule() -> Rule {
    Rule {
        id: "python-weak-crypto".to_string(),
        name: "Weak Cryptographic Algorithm".to_string(),
        description: "Usage of weak cryptographic algorithm (MD5, SHA1)".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "hashlib")
              (#match? @fn "^(md5|sha1)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string(), "CWE-328".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec!["crypto".to_string(), "weak".to_string()],
        message: None,
        fix: None,
    }
}

pub fn python_path_traversal_rule() -> Rule {
    Rule {
        id: "python-path-traversal".to_string(),
        name: "Path Traversal".to_string(),
        description: "Potential path traversal vulnerability using open()".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "open")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-22".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["path-traversal".to_string(), "file".to_string()],
        message: None,
        fix: None,
    }
}

pub fn python_ssrf_rule() -> Rule {
    Rule {
        id: "python-ssrf".to_string(),
        name: "Server-Side Request Forgery".to_string(),
        description: "Potential SSRF using requests library".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "requests")
              (#match? @fn "^(get|post|put|delete|patch|head|options)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec!["ssrf".to_string(), "network".to_string()],
        message: None,
        fix: None,
    }
}

pub fn python_debug_enabled_rule() -> Rule {
    Rule {
        id: "python-debug-enabled".to_string(),
        name: "Debug Mode Enabled".to_string(),
        description: "Debug mode enabled in production (Flask/Django)".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @arg
                  value: (true)
                )
              )
              (#eq? @fn "run")
              (#eq? @arg "debug")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-489".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["debug".to_string(), "config".to_string()],
        message: None,
        fix: None,
    }
}

// ============================================================================
// Additional JavaScript/TypeScript Rules
// ============================================================================

pub fn js_prototype_pollution_rule() -> Rule {
    Rule {
        id: "js-prototype-pollution".to_string(),
        name: "Prototype Pollution".to_string(),
        description: "Potential prototype pollution vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop
              )
              (#match? @prop "^(__proto__|constructor|prototype)$")
            ) @assignment"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1321".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["prototype-pollution".to_string(), "javascript".to_string()],
        message: None,
        fix: None,
    }
}

pub fn js_open_redirect_rule() -> Rule {
    Rule {
        id: "js-open-redirect".to_string(),
        name: "Open Redirect".to_string(),
        description: "Potential open redirect vulnerability".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                object: (member_expression
                  property: (property_identifier) @obj
                )
                property: (property_identifier) @prop
              )
              (#eq? @obj "location")
              (#eq? @prop "href")
            ) @redirect"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-601".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["redirect".to_string(), "javascript".to_string()],
        message: None,
        fix: None,
    }
}

pub fn js_hardcoded_secret_rule() -> Rule {
    Rule {
        id: "js-hardcoded-secret".to_string(),
        name: "Hardcoded Secret".to_string(),
        description: "Potential hardcoded secret or API key".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(variable_declarator
              name: (identifier) @var
              value: (string) @val
              (#match? @var "(?i)(api_key|apikey|secret|password|token|auth)")
            ) @decl"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec!["secrets".to_string(), "hardcoded".to_string()],
        message: None,
        fix: None,
    }
}

pub fn js_insecure_randomness_rule() -> Rule {
    Rule {
        id: "js-insecure-random".to_string(),
        name: "Insecure Randomness".to_string(),
        description: "Usage of Math.random() for security-sensitive operations".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              (#eq? @obj "Math")
              (#eq? @fn "random")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-330".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec!["crypto".to_string(), "random".to_string()],
        message: None,
        fix: None,
    }
}

pub fn ts_any_type_rule() -> Rule {
    Rule {
        id: "ts-any-type".to_string(),
        name: "TypeScript Any Type".to_string(),
        description: "Usage of 'any' type defeats TypeScript's type safety".to_string(),
        severity: Severity::Low,
        languages: vec![Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(type_annotation
              (predefined_type) @type
              (#eq? @type "any")
            ) @annotation"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: true,
            suppress_in_benches: true,
            related_rules: vec![],
            min_confidence: None,
        },
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["typescript".to_string(), "type-safety".to_string()],
        message: None,
        fix: None,
    }
}

// ============================================================================
// Additional Rust Rules
// ============================================================================

pub fn rust_transmute_rule() -> Rule {
    Rule {
        id: "rust-transmute".to_string(),
        name: "Unsafe Transmute".to_string(),
        description: "Usage of std::mem::transmute is dangerous".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier) @fn
              (#match? @fn "transmute")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-843".to_string()],
        owasp_categories: vec![],
        tags: vec!["unsafe".to_string(), "rust".to_string()],
        message: None,
        fix: None,
    }
}

pub fn rust_file_permission_rule() -> Rule {
    Rule {
        id: "rust-file-permissions".to_string(),
        name: "Insecure File Permissions".to_string(),
        description: "Setting world-writable file permissions".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (scoped_identifier
                name: (identifier) @fn
              )
              (#eq? @fn "set_permissions")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-732".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["file".to_string(), "permissions".to_string()],
        message: None,
        fix: None,
    }
}

// ============================================================================
// Additional Go Rules
// ============================================================================

pub fn go_hardcoded_credentials_rule() -> Rule {
    Rule {
        id: "go-hardcoded-credentials".to_string(),
        name: "Hardcoded Credentials".to_string(),
        description: "Potential hardcoded credentials in Go".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(short_var_declaration
              left: (expression_list
                (identifier) @var
              )
              right: (expression_list
                (interpreted_string_literal)
              )
              (#match? @var "(?i)(password|secret|token|api_key)")
            ) @decl"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec!["secrets".to_string(), "hardcoded".to_string()],
        message: None,
        fix: None,
    }
}

pub fn go_weak_crypto_rule() -> Rule {
    Rule {
        id: "go-weak-crypto".to_string(),
        name: "Weak Cryptographic Algorithm".to_string(),
        description: "Usage of weak cryptographic algorithm in Go".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn
              )
              (#match? @pkg "^(md5|sha1)$")
              (#eq? @fn "New")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec!["crypto".to_string(), "weak".to_string()],
        message: None,
        fix: None,
    }
}

pub fn go_path_traversal_rule() -> Rule {
    Rule {
        id: "go-path-traversal".to_string(),
        name: "Path Traversal".to_string(),
        description: "Potential path traversal vulnerability in Go".to_string(),
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
        tags: vec!["path-traversal".to_string(), "file".to_string()],
        message: None,
        fix: None,
    }
}

// ============================================================================
// Additional C/C++ Rules
// ============================================================================

pub fn c_format_string_rule() -> Rule {
    Rule {
        id: "c-format-string".to_string(),
        name: "Format String Vulnerability".to_string(),
        description: "Potential format string vulnerability using printf family".to_string(),
        severity: Severity::High,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-134".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["format-string".to_string(), "injection".to_string()],
        message: None,
        fix: None,
    }
}

pub fn c_malloc_zero_rule() -> Rule {
    Rule {
        id: "c-malloc-zero".to_string(),
        name: "Malloc Zero Size".to_string(),
        description: "malloc(0) behavior is implementation-defined".to_string(),
        severity: Severity::Low,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (argument_list
                (number_literal) @arg
              )
              (#eq? @fn "malloc")
              (#eq? @arg "0")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-131".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "undefined-behavior".to_string()],
        message: None,
        fix: None,
    }
}

pub fn c_free_null_rule() -> Rule {
    Rule {
        id: "c-double-free".to_string(),
        name: "Potential Double Free".to_string(),
        description: "Potential double-free or use-after-free vulnerability".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "free")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-415".to_string(), "CWE-416".to_string()],
        owasp_categories: vec![],
        tags: vec!["memory".to_string(), "double-free".to_string()],
        message: None,
        fix: None,
    }
}

pub fn cpp_raw_ptr_rule() -> Rule {
    Rule {
        id: "cpp-raw-pointer".to_string(),
        name: "Raw Pointer Usage".to_string(),
        description: "Consider using smart pointers instead of raw pointers".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(declaration
              declarator: (pointer_declarator)
            ) @decl"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: true,
            suppress_in_benches: true,
            related_rules: vec![],
            min_confidence: None,
        },
        cwe_ids: vec![],
        owasp_categories: vec![],
        tags: vec!["cpp".to_string(), "memory-safety".to_string()],
        message: None,
        fix: None,
    }
}

// === Additional Security Rules ===

/// Python JWT without verification
pub fn python_jwt_no_verify_rule() -> Rule {
    Rule {
        id: "python-jwt-no-verify".to_string(),
        name: "JWT Decode Without Verification".to_string(),
        description: "JWT decoded without signature verification".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @attr)
              arguments: (argument_list) @args
              (#eq? @obj "jwt")
              (#eq? @attr "decode")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-347".to_string()],
        owasp_categories: vec!["A02:2021".to_string()],
        tags: vec!["jwt".to_string(), "authentication".to_string()],
        message: Some("JWT decoded without verification - ensure verify=True".to_string()),
        fix: None,
    }
}

/// JavaScript innerHTML XSS
pub fn js_innerhtml_rule() -> Rule {
    Rule {
        id: "js-innerhtml-xss".to_string(),
        name: "InnerHTML XSS".to_string(),
        description: "Setting innerHTML can lead to XSS if input is not sanitized".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop)
              (#eq? @prop "innerHTML")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021".to_string()],
        tags: vec!["xss".to_string(), "dom".to_string()],
        message: Some("Use textContent or sanitize input before using innerHTML".to_string()),
        fix: None,
    }
}

/// Rust SQL query without parameterization
pub fn rust_sql_injection_rule() -> Rule {
    Rule {
        id: "rust-sql-injection".to_string(),
        name: "Potential SQL Injection in Rust".to_string(),
        description: "SQL query built using format! may be vulnerable to injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Rust],
        pattern: Pattern::TreeSitterQuery(
            r#"(macro_invocation
              macro: (identifier) @macro
              (#match? @macro "format|format_args")
              (token_tree) @args
            ) @invocation"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: true,
            suppress_in_benches: false,
            related_rules: vec!["rust-command-injection".to_string()],
            min_confidence: Some(crate::domain::value_objects::Confidence::Medium),
        },
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021".to_string()],
        tags: vec!["sql".to_string(), "injection".to_string()],
        message: Some("Use parameterized queries with sqlx or diesel".to_string()),
        fix: None,
    }
}

/// Go crypto/rand vs math/rand
pub fn go_math_rand_rule() -> Rule {
    Rule {
        id: "go-insecure-rand".to_string(),
        name: "Insecure Random Number Generator".to_string(),
        description: "math/rand is not cryptographically secure, use crypto/rand".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (selector_expression
                operand: (identifier) @pkg
                field: (field_identifier) @fn)
              (#eq? @pkg "rand")
              (#match? @fn "Int|Intn|Float|Read")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-330".to_string()],
        owasp_categories: vec!["A02:2021".to_string()],
        tags: vec!["crypto".to_string(), "random".to_string()],
        message: Some("Use crypto/rand for security-sensitive operations".to_string()),
        fix: None,
    }
}

/// Python XML External Entity (XXE) - lxml without defusing
pub fn python_xxe_rule() -> Rule {
    Rule {
        id: "python-xxe".to_string(),
        name: "XML External Entity (XXE) Vulnerability".to_string(),
        description: "XML parsing without disabling external entities".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @module
                attribute: (identifier) @fn)
              (#match? @module "etree|lxml|xml")
              (#match? @fn "parse|fromstring|XML")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-611".to_string()],
        owasp_categories: vec!["A05:2021".to_string()],
        tags: vec!["xxe".to_string(), "xml".to_string()],
        message: Some("Use defusedxml or disable external entities".to_string()),
        fix: None,
    }
}

/// JavaScript document.write XSS
pub fn js_document_write_rule() -> Rule {
    Rule {
        id: "js-document-write".to_string(),
        name: "Document.write XSS".to_string(),
        description: "document.write can lead to XSS vulnerabilities".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript, Language::TypeScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn)
              (#eq? @obj "document")
              (#match? @fn "write|writeln")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021".to_string()],
        tags: vec!["xss".to_string(), "dom".to_string()],
        message: Some("Avoid document.write, use DOM manipulation methods".to_string()),
        fix: None,
    }
}

/// C/C++ integer overflow potential
pub fn c_integer_overflow_rule() -> Rule {
    Rule {
        id: "c-integer-overflow".to_string(),
        name: "Potential Integer Overflow".to_string(),
        description: "Arithmetic operation without overflow check".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::C, Language::Cpp],
        pattern: Pattern::TreeSitterQuery(
            r#"(binary_expression
              operator: ["+" "-" "*"]
            ) @expr"#
                .to_string(),
        ),
        options: RuleOptions {
            suppress_in_tests: true,
            suppress_in_examples: true,
            suppress_in_benches: true,
            related_rules: vec![],
            min_confidence: Some(crate::domain::value_objects::Confidence::Low),
        },
        cwe_ids: vec!["CWE-190".to_string()],
        owasp_categories: vec![],
        tags: vec!["overflow".to_string(), "arithmetic".to_string()],
        message: Some("Consider using safe arithmetic or bounds checking".to_string()),
        fix: None,
    }
}

pub fn go_ssrf_rule() -> Rule {
    Rule {
        id: "go-ssrf".to_string(),
        name: "Go Server-Side Request Forgery".to_string(),
        description: "Potential SSRF using net/http or other HTTP clients".to_string(),
        severity: Severity::High,
        languages: vec![Language::Go],
        pattern: Pattern::TreeSitterQuery(r#"(comment) @ignore"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec!["ssrf".to_string(), "network".to_string(), "go".to_string()],
        message: None,
        fix: None,
    }
}
