//! JavaScript/Node.js security rules
//!
//! This module contains SAST rules for detecting security vulnerabilities
//! in JavaScript and Node.js code.

use crate::domain::entities::{Pattern, Rule, RuleOptions, Severity};
use crate::domain::value_objects::Language;

// ============================================================================
// Code Injection Rules
// ============================================================================

/// Direct eval() usage - allows arbitrary code execution
pub fn js_eval_direct_rule() -> Rule {
    Rule {
        id: "js-eval-direct".to_string(),
        name: "Direct Eval".to_string(),
        description: "Potentially unsafe eval() call".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
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
        tags: vec!["injection".to_string(), "code-execution".to_string(), "javascript".to_string()],
        message: Some("Avoid using eval() with user-controlled input. Consider using JSON.parse() for data or a sandboxed evaluation environment.".to_string()),
        fix: None,
    }
}

/// Indirect eval via setTimeout/setInterval with string argument
pub fn js_eval_indirect_rule() -> Rule {
    Rule {
        id: "js-eval-indirect".to_string(),
        name: "Indirect Eval".to_string(),
        description: "setTimeout/setInterval with string argument acts like eval()".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              arguments: (arguments (string) @str)
              (#match? @fn "^(setTimeout|setInterval)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Pass a function reference instead of a string to setTimeout/setInterval.".to_string(),
        ),
        fix: None,
    }
}

/// new Function() constructor - similar to eval
pub fn js_new_function_rule() -> Rule {
    Rule {
        id: "js-new-function".to_string(),
        name: "new Function Constructor".to_string(),
        description: "new Function() constructor allows dynamic code execution similar to eval"
            .to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(new_expression
              constructor: (identifier) @fn
              (#eq? @fn "Function")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "injection".to_string(),
            "code-execution".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Avoid using new Function() with user-controlled input.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Command Injection Rules
// ============================================================================

/// Child process execution with shell
pub fn js_child_process_rule() -> Rule {
    Rule {
        id: "js-child-process".to_string(),
        name: "Child Process Execution".to_string(),
        description: "Potential command injection via child_process".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["injection".to_string(), "command".to_string(), "javascript".to_string()],
        message: Some("Validate and sanitize input before passing to child_process functions. Prefer execFile over exec.".to_string()),
        fix: None,
    }
}

// ============================================================================
// XSS (Cross-Site Scripting) Rules
// ============================================================================

/// innerHTML assignment - potential XSS
pub fn js_innerhtml_rule() -> Rule {
    Rule {
        id: "js-xss".to_string(),
        name: "innerHTML XSS".to_string(),
        description: "Setting innerHTML can lead to XSS if input is not sanitized".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop
              )
              (#eq? @prop "innerHTML")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "javascript".to_string()],
        message: Some(
            "Use textContent instead of innerHTML, or sanitize input with DOMPurify.".to_string(),
        ),
        fix: None,
    }
}

/// document.write - potential XSS
pub fn js_document_write_rule() -> Rule {
    Rule {
        id: "js-document-write".to_string(),
        name: "document.write XSS".to_string(),
        description: "document.write can lead to XSS vulnerabilities".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              (#eq? @obj "document")
              (#match? @fn "^(write|writeln)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "javascript".to_string()],
        message: Some("Avoid document.write. Use DOM manipulation methods instead.".to_string()),
        fix: None,
    }
}

/// React dangerouslySetInnerHTML - XSS risk
pub fn js_xss_rule() -> Rule {
    Rule {
        id: "js-xss-react".to_string(),
        name: "XSS via dangerouslySetInnerHTML".to_string(),
        description: "Potential XSS using dangerouslySetInnerHTML or similar unsafe patterns"
            .to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(jsx_attribute
              (property_identifier) @attr
              (#eq? @attr "dangerouslySetInnerHTML")
            ) @xss"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "xss".to_string(),
            "react".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Sanitize HTML content before using dangerouslySetInnerHTML.".to_string()),
        fix: None,
    }
}

/// outerHTML assignment - potential XSS
pub fn js_outerhtml_rule() -> Rule {
    Rule {
        id: "js-outerhtml-xss".to_string(),
        name: "outerHTML XSS".to_string(),
        description: "Setting outerHTML can lead to XSS if input is not sanitized".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop
              )
              (#eq? @prop "outerHTML")
            ) @assign"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-79".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["xss".to_string(), "javascript".to_string()],
        message: Some("Avoid setting outerHTML with untrusted input.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Server-Side Template Injection (SSTI) Rules
// ============================================================================

/// Template engine with user input - SSTI risk
pub fn js_ssti_rule() -> Rule {
    Rule {
        id: "js-ssti".to_string(),
        name: "Server-Side Template Injection".to_string(),
        description: "Potential SSTI vulnerability - template engine may execute user input"
            .to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(compile|render|renderString|renderFile)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-1336".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "ssti".to_string(),
            "injection".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Never pass user input directly to template engines. Use parameterized templates."
                .to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Path Traversal Rules
// ============================================================================

/// Path traversal via fs operations with string concatenation
pub fn js_path_traversal_rule() -> Rule {
    Rule {
        id: "js-path-traversal".to_string(),
        name: "Path Traversal / Zip Slip".to_string(),
        description: "Archive extraction without path validation may allow writing files outside target directory".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"[
              (call_expression
                function: (member_expression
                  object: (identifier) @obj
                  property: (property_identifier) @fn
                )
                arguments: (arguments
                  (binary_expression
                    operator: "+"
                  ) @concat
                )
                (#eq? @obj "fs")
                (#match? @fn "^(readFileSync|writeFileSync|readFile|writeFile|createReadStream|createWriteStream)$")
              ) @call
              (call_expression
                function: (member_expression
                  object: (identifier) @obj
                  property: (property_identifier) @fn
                )
                arguments: (arguments
                  (template_string) @template
                )
                (#eq? @obj "fs")
                (#match? @fn "^(readFileSync|writeFileSync|readFile|writeFile|createReadStream|createWriteStream)$")
              ) @call
            ]"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-22".to_string(), "CWE-73".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["path-traversal".to_string(), "zip-slip".to_string(), "javascript".to_string()],
        message: Some("Validate that archive entry paths don't escape the target directory using path.resolve() and startsWith() check.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Prototype Pollution Rules
// ============================================================================

/// Prototype pollution via object merge/extend
pub fn js_prototype_pollution_rule() -> Rule {
    Rule {
        id: "js-prototype-pollution".to_string(),
        name: "Prototype Pollution".to_string(),
        description: "Object merge/extend without proper filtering can lead to prototype pollution".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              (#eq? @obj "Object")
              (#eq? @fn "assign")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1321".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["prototype-pollution".to_string(), "javascript".to_string()],
        message: Some("Validate object keys before merging. Filter out __proto__, constructor, and prototype.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Open Redirect Rules
// ============================================================================

/// Open redirect via location assignment
pub fn js_open_redirect_rule() -> Rule {
    Rule {
        id: "js-open-redirect".to_string(),
        name: "Open Redirect".to_string(),
        description: "Potential open redirect vulnerability".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                object: [(identifier) @obj (member_expression)]
                property: (property_identifier) @prop
              )
              (#match? @obj "^(window|location|document)$")
              (#match? @prop "^(href|location)$")
            ) @redirect"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-601".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec!["redirect".to_string(), "javascript".to_string()],
        message: Some(
            "Validate redirect URLs against an allowlist of permitted domains.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Cryptography Rules
// ============================================================================

/// Insecure randomness via Math.random()
pub fn js_insecure_randomness_rule() -> Rule {
    Rule {
        id: "js-insecure-random".to_string(),
        name: "Insecure Randomness".to_string(),
        description: "Usage of Math.random() for security-sensitive operations is insecure".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
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
        tags: vec!["crypto".to_string(), "randomness".to_string(), "javascript".to_string()],
        message: Some("Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values.".to_string()),
        fix: None,
    }
}

/// Weak crypto algorithms
pub fn js_weak_crypto_rule() -> Rule {
    Rule {
        id: "js-weak-crypto".to_string(),
        name: "Weak Cryptographic Algorithm".to_string(),
        description: "Usage of deprecated or weak cryptographic algorithms".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (string) @algo
              )
              (#eq? @fn "createHash")
              (#match? @algo "(?i)(md5|sha1)")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-327".to_string(), "CWE-328".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "crypto".to_string(),
            "weak-algorithm".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Use strong cryptographic algorithms like SHA-256 or SHA-3.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Security Misconfiguration Rules
// ============================================================================

/// CORS wildcard configuration
pub fn js_cors_wildcard_rule() -> Rule {
    Rule {
        id: "js-cors-wildcard".to_string(),
        name: "CORS Wildcard".to_string(),
        description: "CORS configuration with wildcard origin can expose sensitive data"
            .to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(object
              (pair
                key: (property_identifier) @key
                value: (string) @value
              )
              (#match? @key "(?i)origin")
              (#eq? @value "\"*\"")
            ) @cors"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-942".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cors".to_string(),
            "misconfiguration".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Specify allowed origins explicitly instead of using wildcard.".to_string()),
        fix: None,
    }
}

/// Disabled security headers
pub fn js_disabled_security_rule() -> Rule {
    Rule {
        id: "js-disabled-security".to_string(),
        name: "Disabled Security Feature".to_string(),
        description: "Security feature disabled in configuration".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(object
              (pair
                key: (property_identifier) @key
                value: (false) @value
              )
              (#match? @key "(?i)(secure|httpOnly|sameSite)")
            ) @config"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-614".to_string(), "CWE-1004".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cookies".to_string(),
            "security".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Enable security features like secure, httpOnly, and sameSite for cookies.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Data Exposure Rules
// ============================================================================

/// Logging sensitive data
pub fn js_sensitive_logging_rule() -> Rule {
    Rule {
        id: "js-sensitive-logging".to_string(),
        name: "Sensitive Data Logging".to_string(),
        description: "Potential logging of sensitive data".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (identifier) @arg
              )
              (#eq? @obj "console")
              (#match? @fn "^(log|debug|info|warn|error)$")
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
            "javascript".to_string(),
        ],
        message: Some(
            "Avoid logging sensitive data. Mask or omit sensitive fields before logging."
                .to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// JSON Parsing Rules
// ============================================================================

/// Unsafe JSON parsing without try-catch
pub fn js_unsafe_json_parse_rule() -> Rule {
    Rule {
        id: "js-unsafe-json-parse".to_string(),
        name: "Unsafe JSON Parse".to_string(),
        description: "JSON.parse without error handling can cause unhandled exceptions".to_string(),
        severity: Severity::Low,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @obj
                property: (property_identifier) @fn
              )
              (#eq? @obj "JSON")
              (#eq? @fn "parse")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-20".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "json".to_string(),
            "error-handling".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Wrap JSON.parse in try-catch to handle malformed JSON gracefully.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// PostMessage Rules
// ============================================================================

/// Unsafe postMessage without origin check
pub fn js_postmessage_rule() -> Rule {
    Rule {
        id: "js-postmessage-origin".to_string(),
        name: "Unsafe PostMessage".to_string(),
        description: "postMessage with wildcard origin can lead to data exposure".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (_)
                (string) @origin
              )
              (#eq? @fn "postMessage")
              (#eq? @origin "\"*\"")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-346".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "postmessage".to_string(),
            "origin".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Specify target origin explicitly instead of using wildcard.".to_string()),
        fix: None,
    }
}

// ============================================================================
// NoSQL Injection Rules
// ============================================================================

/// MongoDB/NoSQL operator injection
pub fn js_nosql_injection_rule() -> Rule {
    Rule {
        id: "js-nosql-injection".to_string(),
        name: "NoSQL Injection".to_string(),
        description: "Potential NoSQL injection via MongoDB query operators ($gt, $ne, $regex, etc.)".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (object) @query
              )
              (#match? @fn "^(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|aggregate)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-943".to_string(), "CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec!["nosql".to_string(), "mongodb".to_string(), "injection".to_string(), "javascript".to_string()],
        message: Some("Validate and sanitize user input before using in MongoDB queries. Use explicit query operators and avoid passing raw user input.".to_string()),
        fix: None,
    }
}

// ============================================================================
// XML External Entity (XXE) Rules
// ============================================================================

/// XXE via XML parser
pub fn js_xxe_rule() -> Rule {
    Rule {
        id: "js-xxe".to_string(),
        name: "XML External Entity (XXE) Injection".to_string(),
        description: "XML parser may be vulnerable to XXE attacks if external entities are not disabled".to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              (#match? @fn "^(parseString|parseStringSync|parse|parseSync|parseXml|parseXmlString)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-611".to_string(), "CWE-827".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["xxe".to_string(), "xml".to_string(), "injection".to_string(), "javascript".to_string()],
        message: Some("Disable external entity processing in XML parsers. Use {noent: false, noblanks: true} options.".to_string()),
        fix: None,
    }
}

// ============================================================================
// JWT Security Rules
// ============================================================================

/// JWT algorithm none bypass
pub fn js_jwt_none_algorithm_rule() -> Rule {
    Rule {
        id: "js-jwt-none-algorithm".to_string(),
        name: "JWT Algorithm None Bypass".to_string(),
        description: "JWT verification without algorithm restriction allows signature bypass"
            .to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (_)
                (_)
              )
              (#match? @fn "^(verify|decode)$")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-347".to_string(), "CWE-327".to_string()],
        owasp_categories: vec!["A02:2021 - Cryptographic Failures".to_string()],
        tags: vec![
            "jwt".to_string(),
            "authentication".to_string(),
            "crypto".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Always specify algorithms option: jwt.verify(token, secret, {algorithms: ['HS256']})"
                .to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Regular Expression DoS (ReDoS) Rules
// ============================================================================

/// ReDoS via catastrophic backtracking patterns
pub fn js_regex_redos_rule() -> Rule {
    Rule {
        id: "js-regex-redos".to_string(),
        name: "ReDoS Vulnerability".to_string(),
        description: "Regular expression with potential catastrophic backtracking".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(new_expression
              constructor: (identifier) @ctor
              arguments: (arguments
                (regex) @pattern
              )
              (#eq? @ctor "RegExp")
            ) @redos"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1333".to_string(), "CWE-400".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec!["redos".to_string(), "regex".to_string(), "dos".to_string(), "javascript".to_string()],
        message: Some("Avoid nested quantifiers and overlapping patterns. Use safe-regex or re2 for user-controlled patterns.".to_string()),
        fix: None,
    }
}

// ============================================================================
// File Upload Security Rules
// ============================================================================

/// Unrestricted file upload
pub fn js_file_upload_unsafe_rule() -> Rule {
    Rule {
        id: "js-file-upload-unsafe".to_string(),
        name: "Unrestricted File Upload".to_string(),
        description: "File upload without proper validation can lead to RCE".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(multer|upload|formidable)$")
            ) @upload"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-434".to_string()],
        owasp_categories: vec!["A04:2021 - Insecure Design".to_string()],
        tags: vec![
            "file-upload".to_string(),
            "rce".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Validate file type, size, and content. Store uploads outside webroot.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// Cookie Security Rules
// ============================================================================

/// Cookie without HttpOnly flag
pub fn js_cookie_no_httponly_rule() -> Rule {
    Rule {
        id: "js-cookie-no-httponly".to_string(),
        name: "Cookie Missing HttpOnly".to_string(),
        description: "Cookies without HttpOnly flag can be accessed via JavaScript XSS".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (string)
                (string)
                (object) @options
              )
              (#eq? @fn "cookie")
            ) @call"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-1004".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cookies".to_string(),
            "httponly".to_string(),
            "xss".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Set httpOnly: true for sensitive cookies to prevent XSS attacks.".to_string(),
        ),
        fix: None,
    }
}

/// Cookie without Secure flag
pub fn js_cookie_no_secure_rule() -> Rule {
    Rule {
        id: "js-cookie-no-secure".to_string(),
        name: "Cookie Missing Secure Flag".to_string(),
        description: "Cookies without Secure flag can be transmitted over HTTP".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(assignment_expression
              left: (member_expression
                property: (property_identifier) @prop
              )
              (#eq? @prop "cookie")
            ) @cookie"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-614".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "cookies".to_string(),
            "secure".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Set secure: true for cookies to ensure they're only sent over HTTPS.".to_string(),
        ),
        fix: None,
    }
}

// ============================================================================
// CSRF Protection Rules
// ============================================================================

/// CSRF protection disabled
pub fn js_csrf_disabled_rule() -> Rule {
    Rule {
        id: "js-csrf-disabled".to_string(),
        name: "CSRF Protection Disabled".to_string(),
        description: "CSRF protection explicitly disabled or not configured".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(object
              (pair
                key: (property_identifier) @key
                value: (false)
              )
              (#match? @key "(?i)(csrf|csrfProtection|xsrfProtection)")
            ) @config"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-352".to_string()],
        owasp_categories: vec!["A01:2021 - Broken Access Control".to_string()],
        tags: vec![
            "csrf".to_string(),
            "security".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Enable CSRF protection for state-changing operations.".to_string()),
        fix: None,
    }
}

// ============================================================================
// GraphQL Security Rules
// ============================================================================

/// GraphQL introspection enabled in production
pub fn js_graphql_introspection_rule() -> Rule {
    Rule {
        id: "js-graphql-introspection".to_string(),
        name: "GraphQL Introspection Enabled".to_string(),
        description: "GraphQL introspection enabled - may expose schema details".to_string(),
        severity: Severity::Low,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(object
              (pair
                key: (property_identifier) @key
                value: (true)
              )
              (#eq? @key "introspection")
            ) @config"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-200".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "graphql".to_string(),
            "introspection".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Disable introspection in production: {introspection: false}".to_string()),
        fix: None,
    }
}

/// GraphQL query depth limit missing
pub fn js_graphql_depth_limit_rule() -> Rule {
    Rule {
        id: "js-graphql-no-depth-limit".to_string(),
        name: "GraphQL No Depth Limit".to_string(),
        description: "GraphQL queries without depth limit are vulnerable to DoS".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#match? @fn "^(ApolloServer|GraphQLServer|graphqlHTTP)$")
            ) @server"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-400".to_string(), "CWE-770".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "graphql".to_string(),
            "dos".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Add depth limiting middleware: graphql-depth-limit or similar.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Helmet/Security Headers Rules
// ============================================================================

/// Missing security headers (Helmet)
pub fn js_helmet_missing_rule() -> Rule {
    Rule {
        id: "js-helmet-missing".to_string(),
        name: "Missing Security Headers".to_string(),
        description: "Express app without Helmet middleware for security headers".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (identifier) @fn
              (#eq? @fn "express")
            ) @app"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-693".to_string()],
        owasp_categories: vec!["A05:2021 - Security Misconfiguration".to_string()],
        tags: vec![
            "helmet".to_string(),
            "headers".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Use Helmet middleware: app.use(helmet()) for security headers.".to_string()),
        fix: None,
    }
}

// ============================================================================
// Rate Limiting Rules
// ============================================================================

/// Missing rate limiting
pub fn js_no_rate_limit_rule() -> Rule {
    Rule {
        id: "js-no-rate-limit".to_string(),
        name: "Missing Rate Limiting".to_string(),
        description: "API endpoint without rate limiting is vulnerable to brute force".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                object: (identifier) @app
                property: (property_identifier) @method
              )
              (#match? @app "^(app|router)$")
              (#match? @method "^(post|put|patch|delete)$")
            ) @endpoint"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-307".to_string(), "CWE-799".to_string()],
        owasp_categories: vec!["A04:2021 - Insecure Design".to_string()],
        tags: vec![
            "rate-limit".to_string(),
            "brute-force".to_string(),
            "javascript".to_string(),
        ],
        message: Some("Add rate limiting to sensitive endpoints: express-rate-limit.".to_string()),
        fix: None,
    }
}

// ============================================================================
// SQL Injection (for JS SQL libraries)
// ============================================================================

/// SQL injection via string concatenation
pub fn js_sql_injection_rule() -> Rule {
    Rule {
        id: "js-sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "SQL query built with string concatenation is vulnerable to injection"
            .to_string(),
        severity: Severity::Critical,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                [(binary_expression) (template_string)]
              )
              (#match? @fn "^(query|execute|raw|prepare)$")
            ) @sql"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "sql".to_string(),
            "injection".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [id])"
                .to_string(),
        ),
        fix: None,
    }
}

/// Sequelize raw query without bind
pub fn js_sequelize_raw_query_rule() -> Rule {
    Rule {
        id: "js-sequelize-raw".to_string(),
        name: "Sequelize Raw Query".to_string(),
        description: "Sequelize raw query without parameterization".to_string(),
        severity: Severity::High,
        languages: vec![Language::JavaScript],
        pattern: Pattern::TreeSitterQuery(
            r#"(call_expression
              function: (member_expression
                property: (property_identifier) @fn
              )
              arguments: (arguments
                (template_string) @query
              )
              (#eq? @fn "query")
            ) @raw"#
                .to_string(),
        ),
        options: RuleOptions::default(),
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_categories: vec!["A03:2021 - Injection".to_string()],
        tags: vec![
            "sql".to_string(),
            "sequelize".to_string(),
            "injection".to_string(),
            "javascript".to_string(),
        ],
        message: Some(
            "Use replacements or bind parameters: sequelize.query(sql, {replacements: {...}})"
                .to_string(),
        ),
        fix: None,
    }
}

/// Get all JavaScript rules
pub fn get_javascript_rules() -> Vec<Rule> {
    vec![
        // Code injection
        js_eval_direct_rule(),
        js_eval_indirect_rule(),
        js_new_function_rule(),
        // Command injection
        js_child_process_rule(),
        // XSS
        js_innerhtml_rule(),
        js_document_write_rule(),
        js_xss_rule(),
        js_outerhtml_rule(),
        // SSTI
        js_ssti_rule(),
        // Path traversal
        js_path_traversal_rule(),
        // Prototype pollution
        js_prototype_pollution_rule(),
        // Open redirect
        js_open_redirect_rule(),
        // Cryptography
        js_insecure_randomness_rule(),
        js_weak_crypto_rule(),
        // Security misconfiguration
        js_cors_wildcard_rule(),
        js_disabled_security_rule(),
        // Data exposure
        js_sensitive_logging_rule(),
        // JSON parsing
        js_unsafe_json_parse_rule(),
        // PostMessage
        js_postmessage_rule(),
        // === NEW CATASTROPHIC RULES ===
        // NoSQL injection
        js_nosql_injection_rule(),
        // XXE
        js_xxe_rule(),
        // JWT security
        js_jwt_none_algorithm_rule(),
        // ReDoS
        js_regex_redos_rule(),
        // File upload
        js_file_upload_unsafe_rule(),
        // Cookie security
        js_cookie_no_httponly_rule(),
        js_cookie_no_secure_rule(),
        // CSRF
        js_csrf_disabled_rule(),
        // GraphQL
        js_graphql_introspection_rule(),
        js_graphql_depth_limit_rule(),
        // Security headers
        js_helmet_missing_rule(),
        // Rate limiting
        js_no_rate_limit_rule(),
        // SQL injection
        js_sql_injection_rule(),
        js_sequelize_raw_query_rule(),
    ]
}
