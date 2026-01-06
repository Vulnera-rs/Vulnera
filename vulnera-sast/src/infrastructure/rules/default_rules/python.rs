//! Python security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! in Python code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Code Injection Rules
// ============================================================================

/// Unsafe eval() usage
pub fn python_eval_rule() -> Rule {
    Rule {
        id: "unsafe-function-call".to_string(),
        name: "Unsafe Function Call".to_string(),
        description: "Potentially unsafe function call".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
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
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Avoid using eval() with user input. Use ast.literal_eval() for safe data parsing."
                .to_string(),
        ),
        fix: None,
    }
}

/// exec() function - arbitrary code execution
pub fn python_exec_rule() -> Rule {
    Rule {
        id: "python-exec".to_string(),
        name: "Exec Function".to_string(),
        description: "exec() allows arbitrary code execution".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "exec")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "python".to_string(),
        ],
        message: Some("Avoid using exec() with user input.".to_string()),
        fix: None,
    }
}

/// compile() function - code compilation
pub fn python_compile_rule() -> Rule {
    Rule {
        id: "python-compile".to_string(),
        name: "Compile Function".to_string(),
        description: "compile() can be used for code injection".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "compile")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "python".to_string()],
        message: Some("Avoid using compile() with user input.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Command Injection Rules
// ============================================================================

/// subprocess with shell=True
pub fn python_subprocess_rule() -> Rule {
    Rule {
        id: "python-subprocess".to_string(),
        name: "Subprocess Shell".to_string(),
        description: "subprocess with shell=True is vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "subprocess")
              (#match? @fn "^(call|run|Popen|check_call|check_output)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "python".to_string(),
        ],
        message: Some("Avoid shell=True. Pass arguments as a list instead.".to_string()),
        fix: None,
    }
}

/// os.system - command injection
pub fn python_os_system_rule() -> Rule {
    Rule {
        id: "python-os-system".to_string(),
        name: "os.system Command".to_string(),
        description: "os.system is vulnerable to command injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "os")
              (#match? @fn "^(system|popen)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "command".to_string(),
            "python".to_string(),
        ],
        message: Some("Use subprocess with list arguments instead of os.system.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Deserialization Rules
// ============================================================================

/// pickle.loads - unsafe deserialization
pub fn python_pickle_rule() -> Rule {
    Rule {
        id: "unsafe-deserialization".to_string(),
        name: "Unsafe Deserialization".to_string(),
        description: "Potential unsafe deserialization vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
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
        tags: vec!["deserialization".to_string(), "python".to_string()],
        message: Some("Never unpickle untrusted data. Use JSON or other safe formats.".to_string()),
        fix: None,
    }
}

/// yaml.load without safe loader
pub fn python_yaml_load_rule() -> Rule {
    Rule {
        id: "python-yaml-load".to_string(),
        name: "Unsafe YAML Load".to_string(),
        description: "yaml.load without safe Loader is vulnerable to code execution".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "yaml")
              (#eq? @fn "load")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-502".to_string()],
        owasp_categories: vec!["A08:2021 - Software and Data Integrity Failures".to_string()],
        tags: vec![
            "deserialization".to_string(),
            "yaml".to_string(),
            "python".to_string(),
        ],
        message: Some("Use yaml.safe_load() instead of yaml.load().".to_string()),
        fix: None,
    }
}

/// marshal.loads - unsafe deserialization
pub fn python_marshal_rule() -> Rule {
    Rule {
        id: "python-marshal".to_string(),
        name: "Marshal Deserialization".to_string(),
        description: "marshal.loads can execute arbitrary code".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @fn
              )
              (#eq? @obj "marshal")
              (#match? @fn "^loads?$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-502".to_string()],
        owasp_categories: vec!["A08:2021 - Software and Data Integrity Failures".to_string()],
        tags: vec!["deserialization".to_string(), "python".to_string()],
        message: Some("Avoid unmarshalling untrusted data.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Server-Side Template Injection (SSTI) Rules
// ============================================================================

/// Flask render_template_string - SSTI
pub fn python_ssti_rule() -> Rule {
    Rule {
        id: "python-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "render_template_string with user input is vulnerable to SSTI".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#eq? @fn "render_template_string")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-1336".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "ssti".to_string(),
            "flask".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Use render_template with a file instead of render_template_string.".to_string(),
        ),
        fix: None,
    }
}

/// Jinja2 from string - SSTI
pub fn python_jinja_ssti_rule() -> Rule {
    Rule {
        id: "python-jinja-ssti".to_string(),
        name: "Jinja2 Template from String".to_string(),
        description: "Creating Jinja2 templates from user input is vulnerable to SSTI".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#eq? @fn "from_string")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-1336".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "ssti".to_string(),
            "jinja2".to_string(),
            "python".to_string(),
        ],
        message: Some("Avoid using Environment.from_string with user input.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Secrets and Credentials Rules
// ============================================================================

/// Hardcoded password
pub fn python_hardcoded_password_rule() -> Rule {
    Rule {
        id: "python-hardcoded-password".to_string(),
        name: "Hardcoded Password".to_string(),
        description: "Potential hardcoded password or credential".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment
              left: (identifier) @name
              right: (string) @value
              (#match? @name "(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A07:2021 - Identification and Authentication Failures".to_string()],
        tags: vec![
            "secrets".to_string(),
            "credentials".to_string(),
            "python".to_string(),
        ],
        message: Some("Store secrets in environment variables or a secrets manager.".to_string()),
        fix: None,
    }
}

/// Flask secret key hardcoded
pub fn python_flask_secret_key_rule() -> Rule {
    Rule {
        id: "python-flask-secret-key".to_string(),
        name: "Flask Secret Key Hardcoded".to_string(),
        description: "Flask SECRET_KEY should not be hardcoded".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment
              left: (subscript
                subscript: (string) @key
              )
              right: (string) @value
              (#match? @key "(?i)secret")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-798".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "flask".to_string(),
            "secrets".to_string(),
            "python".to_string(),
        ],
        message: Some("Load Flask SECRET_KEY from environment variables.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Cryptography Rules
// ============================================================================

/// Weak cryptographic hash (MD5, SHA1)
pub fn python_weak_crypto_rule() -> Rule {
    Rule {
        id: "python-weak-crypto".to_string(),
        name: "Weak Cryptographic Hash".to_string(),
        description: "MD5 and SHA1 are cryptographically weak".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "hashlib")
              (#match? @fn "^(md5|sha1)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string(), "CWE-328".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "weak-algorithm".to_string(),
            "python".to_string(),
        ],
        message: Some("Use SHA-256 or stronger hash algorithms.".to_string()),
        fix: None,
    }
}

/// random module for security
pub fn python_insecure_random_rule() -> Rule {
    Rule {
        id: "python-insecure-random".to_string(),
        name: "Insecure Randomness".to_string(),
        description: "random module is not cryptographically secure".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "random")
              (#match? @fn "^(random|randint|choice|sample)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-330".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "randomness".to_string(),
            "python".to_string(),
        ],
        message: Some("Use secrets module for security-sensitive random values.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Path Traversal Rules
// ============================================================================

/// open() with user input
pub fn python_path_traversal_rule() -> Rule {
    Rule {
        id: "python-path-traversal".to_string(),
        name: "Path Traversal".to_string(),
        description: "Potential path traversal via file operations".to_string(),
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
        tags: vec!["path-traversal".to_string(), "python".to_string()],
        message: Some("Validate file paths to prevent directory traversal attacks.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SSRF Rules
// ============================================================================

/// requests.get with user input
pub fn python_ssrf_rule() -> Rule {
    Rule {
        id: "python-ssrf".to_string(),
        name: "Server-Side Request Forgery".to_string(),
        description: "Potential SSRF via HTTP requests with user-controlled URL".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "requests")
              (#match? @fn "^(get|post|put|delete|patch|head|options)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec!["ssrf".to_string(), "python".to_string()],
        message: Some("Validate URLs against an allowlist of permitted domains.".to_string()),
        fix: None,
    }
}

/// urllib/urllib3 SSRF
pub fn python_urllib_ssrf_rule() -> Rule {
    Rule {
        id: "python-urllib-ssrf".to_string(),
        name: "urllib SSRF".to_string(),
        description: "Potential SSRF via urllib".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#match? @fn "^(urlopen|urlretrieve)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_categories: vec!["A10:2021 - Server-Side Request Forgery".to_string()],
        tags: vec!["ssrf".to_string(), "python".to_string()],
        message: Some("Validate URLs before making requests.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SQL Injection Rules
// ============================================================================

/// Django raw SQL
pub fn python_django_raw_sql_rule() -> Rule {
    Rule {
        id: "python-django-raw-sql".to_string(),
        name: "Django Raw SQL".to_string(),
        description: "Raw SQL in Django can lead to SQL injection".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#match? @fn "^(raw|execute)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "sql".to_string(),
            "django".to_string(),
            "python".to_string(),
        ],
        message: Some("Use parameterized queries instead of raw SQL.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Configuration Rules
// ============================================================================

/// Debug mode enabled
pub fn python_debug_enabled_rule() -> Rule {
    Rule {
        id: "python-debug-enabled".to_string(),
        name: "Debug Mode Enabled".to_string(),
        description: "Debug mode should be disabled in production".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment
              left: (identifier) @name
              right: (true) @value
              (#match? @name "(?i)debug")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-489".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "debug".to_string(),
            "configuration".to_string(),
            "python".to_string(),
        ],
        message: Some("Disable debug mode in production.".to_string()),
        fix: None,
    }
}

/// Assert statements in production
pub fn python_assert_rule() -> Rule {
    Rule {
        id: "python-assert".to_string(),
        name: "Assert in Production".to_string(),
        description: "Assert statements are disabled with -O flag".to_string(),
        severity: Severity::Low,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(r#"(assert_statement) @assert"#.to_string()),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-617".to_string()],
        owasp_categories: vec![],
        tags: vec!["assert".to_string(), "python".to_string()],
        message: Some(
            "Don't rely on assert for security checks; they're disabled with -O.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// XML Processing Rules
// ============================================================================

/// JWT without verification
pub fn python_jwt_no_verify_rule() -> Rule {
    Rule {
        id: "python-jwt-no-verify".to_string(),
        name: "JWT Without Verification".to_string(),
        description: "JWT decoded without signature verification".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "jwt")
              (#eq? @fn "decode")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-347".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "jwt".to_string(),
            "authentication".to_string(),
            "python".to_string(),
        ],
        message: Some("Always verify JWT signatures. Don't use verify=False.".to_string()),
        fix: None,
    }
}

/// XXE vulnerability - lxml without defusing
pub fn python_xxe_rule() -> Rule {
    Rule {
        id: "python-xxe".to_string(),
        name: "XML External Entity (XXE)".to_string(),
        description: "XML parsing without disabling external entities is vulnerable to XXE"
            .to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "etree")
              (#eq? @fn "parse")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-611".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["xxe".to_string(), "xml".to_string(), "python".to_string()],
        message: Some("Use defusedxml library or disable external entities.".to_string()),
        fix: None,
    }
}

/// Get all Python rules
pub fn get_python_rules() -> Vec<Rule> {
    vec![
        // Code injection
        python_eval_rule(),
        python_exec_rule(),
        python_compile_rule(),
        // Command injection
        python_subprocess_rule(),
        python_os_system_rule(),
        // Deserialization
        python_pickle_rule(),
        python_yaml_load_rule(),
        python_marshal_rule(),
        // SSTI
        python_ssti_rule(),
        python_jinja_ssti_rule(),
        // Secrets
        python_hardcoded_password_rule(),
        python_flask_secret_key_rule(),
        // Cryptography
        python_weak_crypto_rule(),
        python_insecure_random_rule(),
        // Path traversal
        python_path_traversal_rule(),
        // SSRF
        python_ssrf_rule(),
        python_urllib_ssrf_rule(),
        // SQL injection
        python_django_raw_sql_rule(),
        // Configuration
        python_debug_enabled_rule(),
        python_assert_rule(),
        // JWT/XML
        python_jwt_no_verify_rule(),
        python_xxe_rule(),
    ]
}
