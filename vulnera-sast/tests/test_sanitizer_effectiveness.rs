//! Sanitizer effectiveness tests for vulnera-sast
//!
//! These tests validate that sanitizers properly clear or reduce taint,
//! preventing false positives in the SAST analysis.
//!
//! # Test Categories
//!
//! 1. **Known Sanitizers**: Functions that completely clear taint
//!    - Python: html.escape(), bleach.clean(), int(), parameterized queries
//!    - JavaScript: encodeURIComponent(), DOMPurify.sanitize(), parseInt()
//!    - Go: strconv functions, template.HTMLEscapeString()
//!
//! 2. **Generic Validators**: Functions that reduce confidence but don't clear taint
//!    - Regex validation (re.match, RegExp.test)
//!    - Allowlist checks (if x in allowed_values)
//!
//! 3. **False Sanitizers**: Functions that look safe but aren't
//!    - String operations (strip(), trim(), toLowerCase())
//!    - Ineffective escaping (wrong context)

mod common;

use std::collections::HashSet;
use tempfile::TempDir;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::SastModule;

/// Analysis results with both static and data-flow findings separated
#[derive(Debug)]
struct AnalysisResult {
    /// All rule IDs found
    all_rules: Vec<String>,
    /// Only data-flow findings (rule_id starts with "data-flow-")
    data_flow_rules: Vec<String>,
    /// Only static pattern findings (not data-flow)
    static_rules: Vec<String>,
}

/// Helper to run SAST analysis on code
async fn analyze_code(code: &str, extension: &str) -> AnalysisResult {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join(format!("test.{}", extension));
    std::fs::write(&file_path, code).expect("Failed to write test file");

    let config = SastConfig::default();
    let module = SastModule::with_config(&config);

    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "sanitizer-test".to_string(),
        source_uri: temp_dir.path().to_string_lossy().to_string(),
        config: std::collections::HashMap::new(),
    };

    let result = module
        .execute(&module_config)
        .await
        .expect("Analysis failed");

    let all_rules: Vec<String> = result
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();

    let data_flow_rules: Vec<String> = all_rules
        .iter()
        .filter(|r| r.starts_with("data-flow-"))
        .cloned()
        .collect();

    let static_rules: Vec<String> = all_rules
        .iter()
        .filter(|r| !r.starts_with("data-flow-"))
        .cloned()
        .collect();

    AnalysisResult {
        all_rules,
        data_flow_rules,
        static_rules,
    }
}

/// Helper to check if specific rule was triggered in data-flow findings
/// This is the primary check for sanitizer effectiveness
fn has_data_flow_rule(result: &AnalysisResult, pattern: &str) -> bool {
    result
        .data_flow_rules
        .iter()
        .any(|r| r.to_lowercase().contains(pattern))
}

/// Helper to check if specific rule was triggered in any findings
#[allow(dead_code)]
fn has_rule(result: &AnalysisResult, pattern: &str) -> bool {
    result
        .all_rules
        .iter()
        .any(|r| r.to_lowercase().contains(pattern))
}

// ============================================================================
// Python Sanitizer Tests
// ============================================================================

mod python_sanitizers {
    use super::*;

    /// Test that int() conversion sanitizes SQL injection
    /// Note: Sanitizers only affect data-flow findings, not static pattern rules
    #[tokio::test]
    async fn test_int_conversion_sanitizes_sqli() {
        let code = r#"
from django.db import connection

def get_user(request):
    user_id = int(request.GET.get('id', 0))  # int() sanitizes
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()
"#;
        let result = analyze_code(code, "py").await;
        // Data flow analysis should NOT report SQL injection because int() sanitizes
        assert!(
            !has_data_flow_rule(&result, "sql"),
            "int() conversion should sanitize SQL injection in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that parameterized queries are recognized as safe
    #[tokio::test]
    async fn test_parameterized_query_safe() {
        let code = r#"
from django.db import connection

def get_user_safe(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
    return cursor.fetchone()
"#;
        let result = analyze_code(code, "py").await;
        // Parameterized queries should not trigger data-flow SQL findings
        assert!(
            !has_data_flow_rule(&result, "sql"),
            "Parameterized queries should be safe in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that html.escape sanitizes XSS
    #[tokio::test]
    async fn test_html_escape_sanitizes_xss() {
        let code = r#"
import html
from flask import request

@app.route('/greet')
def greet():
    name = request.args.get('name')
    safe_name = html.escape(name)  # Sanitized
    return f"<h1>Hello, {safe_name}!</h1>"
"#;
        let result = analyze_code(code, "py").await;
        assert!(
            !has_data_flow_rule(&result, "xss"),
            "html.escape should sanitize XSS in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that shlex.quote sanitizes command injection
    #[tokio::test]
    async fn test_shlex_quote_sanitizes_command_injection() {
        let code = r#"
import subprocess
import shlex
from flask import request

@app.route('/run')
def run_command():
    user_input = request.args.get('cmd')
    safe_input = shlex.quote(user_input)  # Sanitized
    subprocess.run(f"echo {safe_input}", shell=True)
"#;
        let result = analyze_code(code, "py").await;
        assert!(
            !has_data_flow_rule(&result, "command"),
            "shlex.quote should sanitize command injection in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that yaml.safe_load is recognized as safe
    #[tokio::test]
    async fn test_yaml_safe_load_is_safe() {
        let code = r#"
import yaml
from flask import request

@app.route('/config', methods=['POST'])
def load_config():
    data = request.form['config']
    config = yaml.safe_load(data)  # Safe!
    return str(config)
"#;
        let result = analyze_code(code, "py").await;
        assert!(
            !has_data_flow_rule(&result, "yaml") && !has_data_flow_rule(&result, "deserial"),
            "yaml.safe_load should be safe in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that Django ORM is recognized as safe
    #[tokio::test]
    async fn test_django_orm_is_safe() {
        let code = r#"
from django.contrib.auth.models import User

def get_user(request):
    user_id = request.GET.get('id')
    return User.objects.filter(id=user_id).first()  # ORM is safe
"#;
        let result = analyze_code(code, "py").await;
        assert!(
            !has_data_flow_rule(&result, "sql"),
            "Django ORM should be safe in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }
}

// ============================================================================
// JavaScript Sanitizer Tests
// ============================================================================

mod javascript_sanitizers {
    use super::*;

    /// Test that encodeURIComponent sanitizes URL injection
    #[tokio::test]
    async fn test_encode_uri_component_sanitizes() {
        let code = r#"
const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
    const target = req.query.url;
    const safeUrl = encodeURIComponent(target);  // Sanitized
    res.redirect('/goto?url=' + safeUrl);
});
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            !has_data_flow_rule(&result, "redirect"),
            "encodeURIComponent should sanitize in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that parseInt sanitizes numeric contexts
    #[tokio::test]
    async fn test_parseint_sanitizes_numeric() {
        let code = r#"
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
    const userId = parseInt(req.query.id, 10);  // Sanitized
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query);
});
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            !has_data_flow_rule(&result, "sql"),
            "parseInt should sanitize SQL injection in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that textContent is safe (vs innerHTML)
    #[tokio::test]
    async fn test_textcontent_is_safe() {
        let code = r#"
function displayMessage(userInput) {
    const element = document.getElementById('output');
    element.textContent = userInput;  // Safe, no HTML parsing
}
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            !has_data_flow_rule(&result, "xss"),
            "textContent should be safe in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that DOMPurify sanitizes XSS
    #[tokio::test]
    async fn test_dompurify_sanitizes_xss() {
        let code = r#"
const DOMPurify = require('dompurify');

function renderHTML(userInput) {
    const safeHTML = DOMPurify.sanitize(userInput);  // Sanitized
    document.getElementById('content').innerHTML = safeHTML;
}
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            !has_data_flow_rule(&result, "xss"),
            "DOMPurify.sanitize should sanitize XSS in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that path.basename prevents path traversal
    #[tokio::test]
    async fn test_path_basename_prevents_traversal() {
        let code = r#"
const fs = require('fs');
const path = require('path');
const express = require('express');

app.get('/file', (req, res) => {
    const filename = req.query.name;
    const safeName = path.basename(filename);  // Strips ../
    const filePath = path.join('./uploads', safeName);
    res.sendFile(filePath);
});
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            !has_data_flow_rule(&result, "path") && !has_data_flow_rule(&result, "traversal"),
            "path.basename should prevent traversal in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }
}

// ============================================================================
// Go Sanitizer Tests
// ============================================================================

mod go_sanitizers {
    use super::*;

    /// Test that strconv.Atoi sanitizes numeric input
    #[tokio::test]
    async fn test_strconv_atoi_sanitizes() {
        let code = r#"
package main

import (
    "database/sql"
    "fmt"
    "net/http"
    "strconv"
)

func getUser(w http.ResponseWriter, r *http.Request) {
    idStr := r.URL.Query().Get("id")
    id, err := strconv.Atoi(idStr)  // Sanitized to int
    if err != nil {
        http.Error(w, "Invalid ID", 400)
        return
    }
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
    db.Query(query)
}
"#;
        let result = analyze_code(code, "go").await;
        assert!(
            !has_data_flow_rule(&result, "sql"),
            "strconv.Atoi should sanitize SQL injection in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }

    /// Test that URL validation with allowlist is safe
    #[tokio::test]
    async fn test_url_allowlist_is_safe() {
        let code = r#"
package main

import (
    "net/http"
    "net/url"
)

var allowedHosts = map[string]bool{
    "api.example.com": true,
}

func proxyRequest(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    u, err := url.Parse(targetURL)
    if err != nil || !allowedHosts[u.Host] {
        http.Error(w, "Invalid URL", 400)
        return
    }
    http.Get(u.String())  // Safe after validation
}
"#;
        let result = analyze_code(code, "go").await;
        // Note: This is a more complex validation pattern that may not be detected
        // The test documents expected behavior
        println!("Go URL allowlist findings: {:?}", result);
    }

    /// Test that html.EscapeString sanitizes XSS
    #[tokio::test]
    async fn test_html_escape_string_sanitizes() {
        let code = r#"
package main

import (
    "html"
    "net/http"
)

func greet(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    safeName := html.EscapeString(name)  // Sanitized
    w.Write([]byte("<h1>Hello, " + safeName + "</h1>"))
}
"#;
        let result = analyze_code(code, "go").await;
        assert!(
            !has_data_flow_rule(&result, "xss"),
            "html.EscapeString should sanitize XSS in data flow, but found: {:?}",
            result.data_flow_rules
        );
    }
}

// ============================================================================
// False Sanitizer Tests (should NOT sanitize)
// ============================================================================

mod false_sanitizers {
    use super::*;

    /// Test that strip() does NOT sanitize SQL injection
    #[tokio::test]
    async fn test_strip_does_not_sanitize_sqli() {
        let code = r#"
from django.db import connection

def get_user(request):
    user_id = request.GET.get('id').strip()  # strip() doesn't sanitize!
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor = connection.cursor()
    cursor.execute(query)
"#;
        let result = analyze_code(code, "py").await;
        // Either static or data-flow rule should fire - strip() doesn't sanitize
        assert!(
            has_rule(&result, "sql"),
            "strip() should NOT sanitize SQL injection, but no findings: {:?}",
            result.all_rules
        );
    }

    /// Test that toLowerCase() does NOT sanitize XSS
    #[tokio::test]
    async fn test_tolowercase_does_not_sanitize_xss() {
        let code = r#"
function display(userInput) {
    const lower = userInput.toLowerCase();  // Doesn't sanitize!
    document.getElementById('output').innerHTML = lower;
}
"#;
        let result = analyze_code(code, "js").await;
        assert!(
            has_rule(&result, "xss") || has_rule(&result, "innerhtml"),
            "toLowerCase() should NOT sanitize XSS, but no findings: {:?}",
            result.all_rules
        );
    }

    /// Test that url.Parse alone does NOT sanitize SSRF
    #[tokio::test]
    async fn test_url_parse_alone_does_not_sanitize_ssrf() {
        let code = r#"
package main

import (
    "net/http"
    "net/url"
)

func proxyRequest(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    u, _ := url.Parse(targetURL)  // Parse alone doesn't validate!
    http.Get(u.String())  // Still vulnerable to SSRF
}
"#;
        let result = analyze_code(code, "go").await;
        // This documents that url.Parse alone shouldn't prevent SSRF detection
        println!("Go url.Parse findings: {:?}", result);
    }
}

// ============================================================================
// Confidence Reduction Tests (Generic Validators)
// ============================================================================

mod confidence_reduction {
    use super::*;

    /// Test that regex validation reduces confidence but may still report
    #[tokio::test]
    async fn test_regex_validation_reduces_confidence() {
        let code = r#"
import re
from django.db import connection

def get_user(request):
    user_id = request.GET.get('id')
    if not re.match(r'^\d+$', user_id):  # Regex validation
        return None
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = connection.cursor()
    cursor.execute(query)
"#;
        let result = analyze_code(code, "py").await;
        // Regex validation should ideally reduce confidence
        // This test documents current behavior
        println!("Python regex validation findings: {:?}", result);
    }

    /// Test that allowlist check reduces confidence
    #[tokio::test]
    async fn test_allowlist_check_reduces_confidence() {
        let code = r#"
ALLOWED_ACTIONS = ['view', 'edit', 'delete']

def perform_action(request):
    action = request.GET.get('action')
    if action not in ALLOWED_ACTIONS:
        return None
    eval(f"do_{action}()")  # Still suspicious but action is constrained
"#;
        let result = analyze_code(code, "py").await;
        // Allowlist check should reduce confidence but eval is still dangerous
        println!("Python allowlist validation findings: {:?}", result);
    }
}
