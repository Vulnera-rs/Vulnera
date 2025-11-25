//! Unit tests for prompt templates and PromptBuilder

use vulnera_llm::infrastructure::prompts::{
    PromptBuilder, CODE_FIX_SYSTEM_PROMPT, EXPLAIN_VULNERABILITY_PROMPT, NL_QUERY_PROMPT,
};

/// Test that CODE_FIX_SYSTEM_PROMPT contains expected structure
#[test]
fn test_code_fix_system_prompt_structure() {
    assert!(CODE_FIX_SYSTEM_PROMPT.contains("secure coding"));
    assert!(CODE_FIX_SYSTEM_PROMPT.contains("JSON"));
    assert!(CODE_FIX_SYSTEM_PROMPT.contains("explanation"));
    assert!(CODE_FIX_SYSTEM_PROMPT.contains("fixed_code"));
    assert!(CODE_FIX_SYSTEM_PROMPT.contains("diff"));
}

/// Test that EXPLAIN_VULNERABILITY_PROMPT has placeholders
#[test]
fn test_explain_vulnerability_prompt_has_placeholders() {
    assert!(EXPLAIN_VULNERABILITY_PROMPT.contains("{finding_id}"));
    assert!(EXPLAIN_VULNERABILITY_PROMPT.contains("{severity}"));
    assert!(EXPLAIN_VULNERABILITY_PROMPT.contains("{description}"));
}

/// Test that NL_QUERY_PROMPT has placeholders
#[test]
fn test_nl_query_prompt_has_placeholders() {
    assert!(NL_QUERY_PROMPT.contains("{query}"));
    assert!(NL_QUERY_PROMPT.contains("{findings_json}"));
}

/// Test PromptBuilder builds explanation prompt correctly
#[test]
fn test_prompt_builder_explanation() {
    let prompt = PromptBuilder::build_explanation_prompt(
        "CVE-2021-44228",
        "Critical",
        "Log4j remote code execution vulnerability",
    );

    assert!(prompt.contains("CVE-2021-44228"));
    assert!(prompt.contains("Critical"));
    assert!(prompt.contains("Log4j remote code execution"));
    assert!(!prompt.contains("{finding_id}"));
    assert!(!prompt.contains("{severity}"));
    assert!(!prompt.contains("{description}"));
}

/// Test PromptBuilder builds NL query prompt correctly
#[test]
fn test_prompt_builder_nl_query() {
    let query = "How many critical vulnerabilities exist?";
    let findings = r#"[{"id": "SQL-001", "severity": "Critical"}]"#;

    let prompt = PromptBuilder::build_nl_query_prompt(query, findings);

    assert!(prompt.contains(query));
    assert!(prompt.contains(findings));
    assert!(!prompt.contains("{query}"));
    assert!(!prompt.contains("{findings_json}"));
}

/// Test explanation prompt with special characters
#[test]
fn test_prompt_builder_explanation_special_chars() {
    let prompt = PromptBuilder::build_explanation_prompt(
        "CVE-2021-44228",
        "Critical",
        "Vulnerability with <special> & \"characters\"",
    );

    assert!(prompt.contains("<special>"));
    assert!(prompt.contains("&"));
    assert!(prompt.contains("\"characters\""));
}

/// Test NL query prompt with complex JSON
#[test]
fn test_prompt_builder_nl_query_complex_json() {
    let complex_findings = r#"{
        "findings": [
            {"id": "SQL-001", "severity": "Critical", "location": {"file": "app.py", "line": 42}},
            {"id": "XSS-002", "severity": "High", "location": {"file": "index.html", "line": 15}}
        ],
        "metadata": {"total": 2, "critical": 1}
    }"#;

    let prompt =
        PromptBuilder::build_nl_query_prompt("Summarize the critical findings", complex_findings);

    assert!(prompt.contains("SQL-001"));
    assert!(prompt.contains("XSS-002"));
    assert!(prompt.contains("app.py"));
}

/// Test CODE_FIX_SYSTEM_PROMPT mentions security best practices
#[test]
fn test_code_fix_prompt_security_focus() {
    let prompt = CODE_FIX_SYSTEM_PROMPT.to_lowercase();
    assert!(prompt.contains("security") || prompt.contains("secure"));
    assert!(prompt.contains("vulnerab"));
}

/// Test prompts don't have unterminated placeholders
#[test]
fn test_prompts_no_broken_placeholders() {
    // Check for unmatched braces which could indicate broken placeholders
    let prompts = [
        CODE_FIX_SYSTEM_PROMPT,
        EXPLAIN_VULNERABILITY_PROMPT,
        NL_QUERY_PROMPT,
    ];

    for prompt in prompts {
        let open_count = prompt.matches('{').count();
        let close_count = prompt.matches('}').count();
        assert_eq!(
            open_count, close_count,
            "Unmatched braces in prompt: {}",
            &prompt[..50.min(prompt.len())]
        );
    }
}
