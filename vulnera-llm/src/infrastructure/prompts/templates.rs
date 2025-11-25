pub const CODE_FIX_SYSTEM_PROMPT: &str = r#"You are an expert secure coding assistant. Your task is to analyze a security vulnerability finding and provide a secure code fix.
You will be provided with:
1. The vulnerability details (type, severity, description).
2. The vulnerable code snippet with context.

Your response must be a JSON object with the following structure:
{
    "explanation": "Brief explanation of why the code is vulnerable and how the fix addresses it.",
    "fixed_code": "The complete fixed code snippet.",
    "diff": "A unified diff showing the changes."
}

Ensure the fixed code follows best security practices and maintains the original functionality.
"#;

pub const EXPLAIN_VULNERABILITY_PROMPT: &str = r#"You are an expert security analyst. Explain the following vulnerability in simple terms.
Finding ID: {finding_id}
Severity: {severity}
Description: {description}

Provide a clear explanation of the risk, potential impact, and general remediation steps. Use Markdown formatting.
"#;

pub const NL_QUERY_PROMPT: &str = r#"You are a security assistant. Analyze the following list of vulnerability findings and answer the user's query.
User Query: {query}

Findings:
{findings_json}

Provide a concise and accurate answer based ONLY on the provided findings.
"#;

pub struct PromptBuilder;

impl PromptBuilder {
    pub fn build_explanation_prompt(finding_id: &str, severity: &str, description: &str) -> String {
        EXPLAIN_VULNERABILITY_PROMPT
            .replace("{finding_id}", finding_id)
            .replace("{severity}", severity)
            .replace("{description}", description)
    }

    pub fn build_nl_query_prompt(query: &str, findings_json: &str) -> String {
        NL_QUERY_PROMPT
            .replace("{query}", query)
            .replace("{findings_json}", findings_json)
    }
}
