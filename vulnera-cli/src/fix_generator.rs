//! Fix Generator - LLM-powered code fix generation for SARIF enrichment
//!
//! This module provides code fix generation using the Vulnera server's LLM endpoint.
//! When used with `--fix` flag and `--format sarif`, findings include suggested fixes.
//!
//! ## Usage
//!
//! The fix generator is only available when online and authenticated.
//! Use `--fix` flag to enable LLM-powered fix suggestions.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::api_client::VulneraClient;

/// Generated code fix for a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFix {
    /// ID of the finding this fix applies to
    pub finding_id: String,
    /// Original vulnerable code
    pub original_code: String,
    /// Suggested fixed code
    pub suggested_code: String,
    /// Explanation of the fix
    pub explanation: String,
    /// Unified diff format
    pub diff: String,
}

/// SARIF-compatible fix object
#[derive(Debug, Clone, Serialize)]
pub struct SarifFix {
    /// Description of the fix
    pub description: SarifMessage,
    /// Artifact changes to apply
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// SARIF message structure
#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// SARIF artifact change
#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactChange {
    /// Artifact location
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    /// Replacements to apply
    pub replacements: Vec<SarifReplacement>,
}

/// SARIF artifact location
#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// SARIF replacement
#[derive(Debug, Clone, Serialize)]
pub struct SarifReplacement {
    /// Region to delete
    #[serde(rename = "deletedRegion")]
    pub deleted_region: SarifRegion,
    /// Content to insert
    #[serde(rename = "insertedContent")]
    pub inserted_content: SarifContent,
}

/// SARIF region
#[derive(Debug, Clone, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

/// SARIF content
#[derive(Debug, Clone, Serialize)]
pub struct SarifContent {
    pub text: String,
}

/// Fix generator using Vulnera server's LLM endpoint
pub struct FixGenerator {
    client: VulneraClient,
}

/// Request for generating a code fix
#[derive(Debug, Serialize)]
pub struct CodeFixRequest {
    pub finding_id: String,
    pub vulnerability_description: String,
    pub code_context: String,
    pub file_path: String,
    pub line_number: u32,
}

/// Response from the code fix endpoint
#[derive(Debug, Deserialize)]
pub struct CodeFixResponse {
    pub success: bool,
    pub fix: Option<CodeFix>,
    pub error: Option<String>,
}

impl FixGenerator {
    /// Create a new fix generator with an API client
    pub fn new(client: VulneraClient) -> Self {
        Self { client }
    }

    /// Generate a fix for a single finding
    pub async fn generate_fix(
        &self,
        finding_id: &str,
        description: &str,
        file_path: &Path,
        line: u32,
    ) -> Result<Option<CodeFix>> {
        // Read file content around the finding
        let code_context = self.read_code_context(file_path, line)?;

        let request = CodeFixRequest {
            finding_id: finding_id.to_string(),
            vulnerability_description: description.to_string(),
            code_context,
            file_path: file_path.to_string_lossy().to_string(),
            line_number: line,
        };

        match self.call_fix_endpoint(request).await {
            Ok(response) => {
                if response.success {
                    Ok(response.fix)
                } else {
                    tracing::warn!(
                        "Fix generation failed for {}: {}",
                        finding_id,
                        response.error.unwrap_or_default()
                    );
                    Ok(None)
                }
            }
            Err(e) => {
                tracing::warn!("Failed to generate fix for {}: {}", finding_id, e);
                Ok(None) // Graceful fallback - return no fix instead of error
            }
        }
    }

    /// Read code context around a specific line
    fn read_code_context(&self, file_path: &Path, line: u32) -> Result<String> {
        let content = std::fs::read_to_string(file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        // Get 5 lines before and 5 lines after
        let start = line.saturating_sub(6) as usize;
        let end = std::cmp::min(line as usize + 5, lines.len());

        Ok(lines[start..end].join("\n"))
    }

    /// Call the server's code fix endpoint
    async fn call_fix_endpoint(&self, request: CodeFixRequest) -> Result<CodeFixResponse> {
        use crate::api_client::LlmFixRequest;

        let llm_request = LlmFixRequest {
            vulnerability_id: request.finding_id.clone(),
            vulnerable_code: request.code_context.clone(),
            language: detect_language_from_path(&request.file_path),
            context: Some(format!(
                "{}:{} — {}",
                request.file_path, request.line_number, request.vulnerability_description
            )),
        };

        let response = self.client.generate_code_fix(&llm_request).await?;

        Ok(CodeFixResponse {
            success: true,
            fix: Some(CodeFix {
                finding_id: request.finding_id,
                original_code: request.code_context,
                suggested_code: response.fixed_code,
                explanation: response.explanation,
                diff: String::new(),
            }),
            error: None,
        })
    }

    /// Convert a CodeFix to SARIF fix format
    pub fn to_sarif_fix(fix: &CodeFix, file_path: &str, line: u32) -> SarifFix {
        SarifFix {
            description: SarifMessage {
                text: fix.explanation.clone(),
            },
            artifact_changes: vec![SarifArtifactChange {
                artifact_location: SarifArtifactLocation {
                    uri: file_path.to_string(),
                },
                replacements: vec![SarifReplacement {
                    deleted_region: SarifRegion {
                        start_line: line,
                        end_line: Some(line),
                        start_column: None,
                        end_column: None,
                    },
                    inserted_content: SarifContent {
                        text: fix.suggested_code.clone(),
                    },
                }],
            }],
        }
    }
}

/// Infer programming language from a file path extension.
fn detect_language_from_path(path: &str) -> String {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext {
        "rs" => "rust",
        "py" | "pyi" => "python",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" | "mts" | "cts" => "typescript",
        "jsx" => "jsx",
        "tsx" => "tsx",
        "go" => "go",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp",
        "java" => "java",
        "rb" => "ruby",
        "php" => "php",
        "cs" => "csharp",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        "scala" => "scala",
        "sh" | "bash" | "zsh" => "shell",
        "yml" | "yaml" => "yaml",
        "toml" => "toml",
        "json" => "json",
        "tf" | "hcl" => "terraform",
        "dockerfile" => "dockerfile",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_fix_structure() {
        let fix = CodeFix {
            finding_id: "test-1".to_string(),
            original_code: "eval(input)".to_string(),
            suggested_code: "# Use safe parsing instead".to_string(),
            explanation: "Avoid eval() as it can execute arbitrary code".to_string(),
            diff: "- eval(input)\n+ # Use safe parsing instead".to_string(),
        };

        let sarif_fix = FixGenerator::to_sarif_fix(&fix, "src/main.py", 42);

        assert_eq!(sarif_fix.description.text, fix.explanation);
        assert_eq!(sarif_fix.artifact_changes.len(), 1);
        assert_eq!(
            sarif_fix.artifact_changes[0].artifact_location.uri,
            "src/main.py"
        );
    }
}
