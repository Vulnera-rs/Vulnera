//! Unit tests for GenerateCodeFixUseCase

use rstest::rstest;
use std::sync::Arc;
use vulnera_llm::application::use_cases::GenerateCodeFixUseCase;

mod common {
    include!("../common/mod.rs");
}

use common::{create_test_config, MockLlmProvider};

/// Test successful code fix generation with valid JSON response
#[tokio::test]
async fn test_generate_code_fix_success() {
    let json_response = r#"{
        "explanation": "The code was vulnerable to SQL injection. Using parameterized queries prevents this.",
        "fixed_code": "db.query(\"SELECT * FROM users WHERE id = $1\", [user_id])",
        "diff": "- db.query(\"SELECT * FROM users WHERE id = \" + user_id)\n+ db.query(\"SELECT * FROM users WHERE id = $1\", [user_id])"
    }"#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider.clone(), config);

    let result = use_case
        .execute(
            "CVE-2023-1234",
            "db.query(\"SELECT * FROM users WHERE id = \" + user_id)",
            "SQL Injection vulnerability in user query",
        )
        .await;

    assert!(result.is_ok());
    let code_fix = result.unwrap();
    assert_eq!(code_fix.finding_id, "CVE-2023-1234");
    assert!(code_fix.explanation.contains("SQL injection"));
    assert!(code_fix.suggested_code.contains("$1"));
    assert!(code_fix.diff.contains("-"));
    assert!(code_fix.diff.contains("+"));
}

/// Test code fix with JSON wrapped in markdown code block
#[tokio::test]
async fn test_generate_code_fix_with_markdown_wrapper() {
    let json_response = r#"Here's the fix:

```json
{
    "explanation": "Fixed XSS vulnerability by escaping user input.",
    "fixed_code": "element.textContent = userInput;",
    "diff": "- element.innerHTML = userInput;\n+ element.textContent = userInput;"
}
```

This ensures safe HTML handling."#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute(
            "XSS-001",
            "element.innerHTML = userInput;",
            "Cross-site scripting via innerHTML",
        )
        .await;

    assert!(result.is_ok());
    let code_fix = result.unwrap();
    assert_eq!(code_fix.finding_id, "XSS-001");
    assert!(code_fix.explanation.contains("XSS"));
}

/// Test error handling when provider returns an error
#[tokio::test]
async fn test_generate_code_fix_provider_error() {
    let provider = Arc::new(MockLlmProvider::new().with_error("API rate limit exceeded"));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute("CVE-2023-1234", "vulnerable_code()", "Some vulnerability")
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("rate limit"));
}

/// Test error handling when LLM returns invalid JSON
#[tokio::test]
async fn test_generate_code_fix_invalid_json() {
    let provider = Arc::new(MockLlmProvider::with_json_response(
        "This is not valid JSON at all",
    ));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute("CVE-2023-1234", "code()", "Description")
        .await;

    assert!(result.is_err());
}

/// Test error handling when LLM returns JSON missing required fields
#[tokio::test]
async fn test_generate_code_fix_incomplete_json() {
    let json_response = r#"{"explanation": "Only explanation, missing other fields"}"#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute("CVE-2023-1234", "code()", "Description")
        .await;

    assert!(result.is_err());
}

/// Test that the correct model is used from config
#[tokio::test]
async fn test_generate_code_fix_uses_configured_model() {
    let json_response = r#"{
        "explanation": "Fixed",
        "fixed_code": "safe_code()",
        "diff": "- bad\n+ good"
    }"#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider.clone(), config);

    let _ = use_case.execute("CVE-001", "code", "desc").await;

    let requests = provider.captured_requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, "code-fix-model");
}

/// Test that default model is used when code_fix_model is not set
#[tokio::test]
async fn test_generate_code_fix_uses_default_model() {
    let json_response = r#"{
        "explanation": "Fixed",
        "fixed_code": "safe_code()",
        "diff": "- bad\n+ good"
    }"#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let mut config = create_test_config();
    config.code_fix_model = None;
    let use_case = GenerateCodeFixUseCase::new(provider.clone(), config);

    let _ = use_case.execute("CVE-001", "code", "desc").await;

    let requests = provider.captured_requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, "test-model");
}

/// Parameterized test for various vulnerability types
#[rstest]
#[case("SQL Injection", "user_input in query", "parameterized query")]
#[case("XSS", "innerHTML assignment", "textContent or sanitization")]
#[case("Path Traversal", "../../../etc/passwd", "path validation")]
#[case("Command Injection", "shell execution", "input sanitization")]
#[tokio::test]
async fn test_generate_code_fix_various_vulnerabilities(
    #[case] vuln_type: &str,
    #[case] _vulnerable_pattern: &str,
    #[case] fix_hint: &str,
) {
    let json_response = format!(
        r#"{{
        "explanation": "Fixed {} vulnerability using {}.",
        "fixed_code": "secure_code()",
        "diff": "- vulnerable\n+ secure"
    }}"#,
        vuln_type, fix_hint
    );

    let provider = Arc::new(MockLlmProvider::with_json_response(&json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute(
            &format!("{}-001", vuln_type.replace(' ', "-")),
            "vulnerable_code()",
            &format!("{} vulnerability detected", vuln_type),
        )
        .await;

    assert!(result.is_ok());
}

/// Test that original code is preserved in result
#[tokio::test]
async fn test_generate_code_fix_preserves_original_code() {
    let original_code = "const dangerous = eval(userInput);";
    let json_response = r#"{
        "explanation": "Removed eval usage",
        "fixed_code": "const safe = JSON.parse(userInput);",
        "diff": "- eval\n+ JSON.parse"
    }"#;

    let provider = Arc::new(MockLlmProvider::with_json_response(json_response));
    let config = create_test_config();
    let use_case = GenerateCodeFixUseCase::new(provider, config);

    let result = use_case
        .execute("EVAL-001", original_code, "Dangerous eval usage")
        .await;

    assert!(result.is_ok());
    let code_fix = result.unwrap();
    assert_eq!(code_fix.original_code, original_code);
}
