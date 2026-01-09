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

// ============================================================================
// NEW RULES
// ============================================================================

/// LDAP injection via python-ldap
pub fn python_ldap_injection_rule() -> Rule {
    Rule {
        id: "python-ldap-injection".to_string(),
        name: "LDAP Injection".to_string(),
        description: "LDAP query with unvalidated user input can lead to authentication bypass"
            .to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#match? @fn "^(search|search_s|search_ext|search_ext_s)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-90".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "ldap".to_string(),
            "injection".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Escape special LDAP characters using ldap.filter.escape_filter_chars().".to_string(),
        ),
        fix: None,
    }
}

/// Timing attack via non-constant comparison
pub fn python_timing_attack_rule() -> Rule {
    Rule {
        id: "python-timing-attack".to_string(),
        name: "Timing Attack Vulnerability".to_string(),
        description: "Using == for secret comparison is vulnerable to timing attacks".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(comparison_operator
              (identifier) @left
              (identifier) @right
              (#match? @left "(?i)(password|token|secret|key|hash|signature)")
            ) @compare"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-208".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "timing".to_string(),
            "crypto".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison."
                .to_string(),
        ),
        fix: None,
    }
}

/// NoSQL injection (MongoDB/PyMongo)
pub fn python_nosql_injection_rule() -> Rule {
    Rule {
        id: "python-nosql-injection".to_string(),
        name: "NoSQL Injection".to_string(),
        description: "MongoDB query with user input can lead to NoSQL injection".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#match? @fn "^(find|find_one|update|update_one|update_many|delete|delete_one|delete_many|aggregate)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-943".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["nosql".to_string(), "mongodb".to_string(), "injection".to_string(), "python".to_string()],
        message: Some("Validate and sanitize user input. Avoid passing $where or user-controlled operators.".to_string()),
        fix: None,
    }
}

/// Path traversal via zipfile (Zip Slip)
pub fn python_zipfile_path_traversal_rule() -> Rule {
    Rule {
        id: "python-zipfile-path-traversal".to_string(),
        name: "Zip Slip Vulnerability".to_string(),
        description: "Extracting zip files without path validation allows arbitrary file write".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              (#match? @fn "^(extractall|extract)$")
            ) @extract"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-22".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["zip-slip".to_string(), "path-traversal".to_string(), "python".to_string()],
        message: Some("Validate extracted file paths start with the target directory using os.path.realpath().".to_string()),
        fix: None,
    }
}

/// Jinja2 autoescape disabled
pub fn python_jinja_autoescape_disabled_rule() -> Rule {
    Rule {
        id: "python-jinja-autoescape-off".to_string(),
        name: "Jinja2 Autoescape Disabled".to_string(),
        description: "Disabling Jinja2 autoescape allows XSS vulnerabilities".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @key
                  value: (false)
                )
              )
              (#eq? @fn "Environment")
              (#eq? @key "autoescape")
            ) @env"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "jinja2".to_string(),
            "xss".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Enable autoescape: Environment(autoescape=True) or use select_autoescape()."
                .to_string(),
        ),
        fix: None,
    }
}

/// Flask-CORS wildcard
pub fn python_cors_wildcard_rule() -> Rule {
    Rule {
        id: "python-cors-wildcard".to_string(),
        name: "CORS Wildcard Origin".to_string(),
        description: "CORS with wildcard origin exposes API to all domains".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @key
                  value: (string) @val
                )
              )
              (#match? @fn "^(CORS|cors)$")
              (#eq? @key "origins")
              (#eq? @val "\"*\"")
            ) @cors"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-942".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cors".to_string(),
            "misconfiguration".to_string(),
            "python".to_string(),
        ],
        message: Some("Specify allowed origins explicitly instead of using '*'.".to_string()),
        fix: None,
    }
}

/// subprocess shell=True
pub fn python_subprocess_shell_true_rule() -> Rule {
    Rule {
        id: "python-shell-true".to_string(),
        name: "Subprocess shell=True".to_string(),
        description: "subprocess with shell=True allows command injection".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              arguments: (argument_list
                (keyword_argument
                  name: (identifier) @key
                  value: (true)
                )
              )
              (#eq? @mod "subprocess")
              (#match? @fn "^(call|run|Popen|check_call|check_output)$")
              (#eq? @key "shell")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "command-injection".to_string(),
            "subprocess".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Use shell=False and pass command as a list: subprocess.run(['cmd', 'arg'])."
                .to_string(),
        ),
        fix: None,
    }
}

/// Sensitive data in logs
pub fn python_logging_sensitive_rule() -> Rule {
    Rule {
        id: "python-logging-sensitive".to_string(),
        name: "Sensitive Data in Logs".to_string(),
        description: "Logging potentially sensitive data".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @log
                attribute: (identifier) @fn
              )
              arguments: (argument_list
                (identifier) @arg
              )
              (#match? @log "^(logging|logger|log)$")
              (#match? @fn "^(debug|info|warning|error|critical)$")
              (#match? @arg "(?i)(password|secret|token|key|credential)")
            ) @log"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-532".to_string()],
        owasp_categories: vec!["A09:2021 - Security Logging and Monitoring Failures".to_string()],
        tags: vec![
            "logging".to_string(),
            "sensitive-data".to_string(),
            "python".to_string(),
        ],
        message: Some("Mask or redact sensitive data before logging.".to_string()),
        fix: None,
    }
}

/// ReDoS via regex with user input
pub fn python_regex_redos_rule() -> Rule {
    Rule {
        id: "python-regex-redos".to_string(),
        name: "ReDoS Vulnerability".to_string(),
        description: "User-controlled regex pattern can lead to ReDoS".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                object: (identifier) @mod
                attribute: (identifier) @fn
              )
              (#eq? @mod "re")
              (#match? @fn "^(compile|match|search|findall|sub)$")
            ) @regex"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1333".to_string(), "CWE-400".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "redos".to_string(),
            "regex".to_string(),
            "dos".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Avoid user-controlled regex patterns. Consider using regex2 or google-re2."
                .to_string(),
        ),
        fix: None,
    }
}

/// Mass assignment vulnerability (Django/Flask)
pub fn python_mass_assignment_rule() -> Rule {
    Rule {
        id: "python-mass-assignment".to_string(),
        name: "Mass Assignment Vulnerability".to_string(),
        description: "Directly passing request data to model update allows privilege escalation"
            .to_string(),
        severity: Severity::High,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (attribute
                attribute: (identifier) @fn
              )
              arguments: (argument_list
                (dictionary_splat) @splat
              )
              (#match? @fn "^(update|create|filter|get_or_create)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-915".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "mass-assignment".to_string(),
            "authorization".to_string(),
            "python".to_string(),
        ],
        message: Some(
            "Explicitly whitelist allowed fields instead of passing **kwargs.".to_string(),
        ),
        fix: None,
    }
}

/// Open redirect vulnerability
pub fn python_open_redirect_rule() -> Rule {
    Rule {
        id: "python-open-redirect".to_string(),
        name: "Open Redirect".to_string(),
        description: "Redirect without URL validation can lead to phishing".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python],
        pattern: Pattern::TreeSitterQuery(
            r#"(call
              function: (identifier) @fn
              (#match? @fn "^(redirect|HttpResponseRedirect)$")
            ) @redirect"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-601".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "redirect".to_string(),
            "phishing".to_string(),
            "python".to_string(),
        ],
        message: Some("Validate redirect URL against an allowlist of trusted domains.".to_string()),
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
        // === NEW CATASTROPHIC RULES ===
        python_ldap_injection_rule(),
        python_timing_attack_rule(),
        python_nosql_injection_rule(),
        python_zipfile_path_traversal_rule(),
        python_jinja_autoescape_disabled_rule(),
        python_cors_wildcard_rule(),
        python_subprocess_shell_true_rule(),
        python_logging_sensitive_rule(),
        python_regex_redos_rule(),
        python_mass_assignment_rule(),
        python_open_redirect_rule(),
    ]
}
