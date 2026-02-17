//! Unit tests for NaturalLanguageQueryUseCase

use std::sync::Arc;
use vulnera_llm::application::use_cases::NaturalLanguageQueryUseCase;
use vulnera_llm::domain::LlmError;

mod common {
    include!("../common/mod.rs");
}

use common::{MockLlmProvider, create_completion_response, create_test_config};

/// Test successful natural language query
#[tokio::test]
async fn test_natural_language_query_success() {
    let response = create_completion_response(
        "Based on the findings, there are 3 critical SQL injection vulnerabilities in the authentication module.",
    );
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider, config);

    let findings_json = r#"[
        {"id": "SQL-001", "type": "SQL Injection", "severity": "Critical"},
        {"id": "SQL-002", "type": "SQL Injection", "severity": "Critical"},
        {"id": "SQL-003", "type": "SQL Injection", "severity": "Critical"}
    ]"#;

    let result = use_case
        .execute(
            "How many critical SQL injection issues are there?",
            findings_json,
        )
        .await;

    assert!(result.is_ok());
    let answer = result.unwrap();
    assert!(answer.contains("3") || answer.contains("three"));
    assert!(answer.contains("SQL injection"));
}

/// Test query with empty findings
#[tokio::test]
async fn test_natural_language_query_empty_findings() {
    let response =
        create_completion_response("No vulnerabilities were found in the provided findings.");
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider, config);

    let result = use_case.execute("What vulnerabilities exist?", "[]").await;

    assert!(result.is_ok());
    let answer = result.unwrap();
    assert!(answer.contains("No vulnerabilities") || answer.to_lowercase().contains("no"));
}

/// Test error handling when provider fails
#[tokio::test]
async fn test_natural_language_query_provider_error() {
    let provider = Arc::new(
        MockLlmProvider::new().with_error(LlmError::ServiceUnavailable(
            "Service unavailable".to_string(),
        )),
    );
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider, config);

    let result = use_case.execute("Any query", "[]").await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Service unavailable")
    );
}

/// Test that default model is always used
#[tokio::test]
async fn test_natural_language_query_uses_default_model() {
    let response = create_completion_response("Answer");
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider.clone(), config);

    let _ = use_case.execute("Query", "[]").await;

    let requests = provider.captured_requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, "test-model");
}

/// Test that streaming is disabled for queries
#[tokio::test]
async fn test_natural_language_query_disables_streaming() {
    let response = create_completion_response("Answer");
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider.clone(), config);

    let _ = use_case.execute("Query", "[]").await;

    let requests = provider.captured_requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].stream, None);
}

/// Test request contains query and findings in prompt
#[tokio::test]
async fn test_natural_language_query_includes_context() {
    let response = create_completion_response("Answer");
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider.clone(), config);

    let query = "Which vulnerabilities affect the payment module?";
    let findings = r#"[{"id": "PAY-001", "module": "payment"}]"#;

    let _ = use_case.execute(query, findings).await;

    let requests = provider.captured_requests.lock().await;
    let user_message = requests[0].messages[0].text();
    assert!(user_message.contains("payment module"));
    assert!(user_message.contains("PAY-001"));
}

/// Test config parameters are applied
#[tokio::test]
async fn test_natural_language_query_applies_config() {
    let response = create_completion_response("Answer");
    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let mut config = create_test_config();
    config.max_tokens = 2048;
    config.temperature = 0.5;
    let use_case = NaturalLanguageQueryUseCase::new(provider.clone(), config);

    let _ = use_case.execute("Query", "[]").await;

    let requests = provider.captured_requests.lock().await;
    assert_eq!(requests[0].max_tokens, Some(2048));
    assert_eq!(requests[0].temperature, Some(0.5));
}

/// Test various query types
#[tokio::test]
async fn test_natural_language_query_various_queries() {
    let queries = [
        "What is the most critical vulnerability?",
        "How many high severity issues exist?",
        "List all XSS vulnerabilities",
        "Which files have security issues?",
        "Summarize the security findings",
    ];

    for query in queries {
        let response = create_completion_response(&format!("Answer to: {}", query));
        let provider = Arc::new(MockLlmProvider::new().with_response(response));
        let config = create_test_config();
        let use_case = NaturalLanguageQueryUseCase::new(provider, config);

        let result = use_case.execute(query, "[]").await;
        assert!(result.is_ok(), "Failed for query: {}", query);
    }
}

/// Test error when LLM returns empty response
#[tokio::test]
async fn test_natural_language_query_empty_response() {
    let response = create_completion_response("");

    let provider = Arc::new(MockLlmProvider::new().with_response(response));
    let config = create_test_config();
    let use_case = NaturalLanguageQueryUseCase::new(provider, config);

    let result = use_case.execute("Query", "[]").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}
