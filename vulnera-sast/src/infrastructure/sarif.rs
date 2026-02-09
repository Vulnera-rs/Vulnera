//! SARIF v2.1.0 exporter for SAST findings
//!
//! This module provides conversion of SAST findings to SARIF format for:
//! - GitHub Code Scanning integration
//! - IDE integration
//! - CI/CD pipeline integration
//! - Interoperability with other security tools

use crate::domain::{
    Finding, Rule, SarifArtifactChange, SarifArtifactLocation, SarifCodeFlow,
    SarifDefaultConfiguration, SarifFix, SarifInsertedContent, SarifInvocation, SarifLevel,
    SarifLocation, SarifMessage, SarifPhysicalLocation, SarifRegion, SarifReplacement,
    SarifReport, SarifResult, SarifRule, SarifRuleProperties, SarifRun, SarifSnippet,
    SarifThreadFlow, SarifThreadFlowLocation, SarifTool, SarifToolDriver, Severity,
};
use std::collections::HashMap;
use tracing::{debug, instrument};

/// SARIF exporter configuration
#[derive(Debug, Clone)]
pub struct SarifExporterConfig {
    /// Tool name (default: "vulnera-sast")
    pub tool_name: String,
    /// Tool version
    pub tool_version: Option<String>,
    /// Include code snippets in results
    pub include_snippets: bool,
    /// Include fix suggestions
    pub include_fixes: bool,
    /// Base URI for relative file paths
    pub uri_base_id: Option<String>,
    /// Information URI for the tool
    pub information_uri: Option<String>,
}

impl Default for SarifExporterConfig {
    fn default() -> Self {
        Self {
            tool_name: "vulnera-sast".to_string(),
            tool_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            include_snippets: true,
            include_fixes: true,
            uri_base_id: Some("%SRCROOT%".to_string()),
            information_uri: Some("https://github.com/k5602/vulnera".to_string()),
        }
    }
}

/// SARIF exporter for converting findings to SARIF format
pub struct SarifExporter {
    config: SarifExporterConfig,
}

impl SarifExporter {
    /// Create a new SARIF exporter with default config
    pub fn new() -> Self {
        Self {
            config: SarifExporterConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: SarifExporterConfig) -> Self {
        Self { config }
    }

    /// Export findings to SARIF report
    #[instrument(skip(self, findings, rules), fields(finding_count = findings.len()))]
    pub fn export(&self, findings: &[Finding], rules: &[Rule]) -> SarifReport {
        let rule_map: HashMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();

        // Build SARIF rules from our rules
        let sarif_rules: Vec<SarifRule> = rules.iter().map(|r| self.rule_to_sarif(r)).collect();

        // Build SARIF results from findings
        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| self.finding_to_sarif_result(f, rule_map.get(f.rule_id.as_str()).copied()))
            .collect();

        let run = SarifRun {
            tool: SarifTool {
                driver: SarifToolDriver {
                    name: self.config.tool_name.clone(),
                    semantic_version: self.config.tool_version.clone(),
                    rules: sarif_rules,
                },
            },
            results,
            invocations: vec![SarifInvocation {
                execution_successful: true,
                tool_execution_notifications: vec![],
            }],
        };

        debug!(
            rule_count = rules.len(),
            result_count = findings.len(),
            "Generated SARIF report"
        );

        SarifReport {
            runs: vec![run],
            ..Default::default()
        }
    }

    /// Convert a Rule to SarifRule
    fn rule_to_sarif(&self, rule: &Rule) -> SarifRule {
        let mut tags = rule.tags.clone();
        tags.extend(rule.cwe_ids.iter().cloned());
        tags.extend(rule.owasp_categories.iter().cloned());

        SarifRule {
            id: rule.id.clone(),
            name: Some(rule.name.clone()),
            short_description: Some(SarifMessage {
                text: rule.name.clone(),
                markdown: None,
            }),
            full_description: Some(SarifMessage {
                text: rule.description.clone(),
                markdown: None,
            }),
            help: Some(SarifMessage {
                text: rule.description.clone(),
                markdown: Some(format!(
                    "## {}\n\n{}\n\n### CWE\n{}\n\n### OWASP\n{}",
                    rule.name,
                    rule.description,
                    rule.cwe_ids.join(", "),
                    rule.owasp_categories.join(", ")
                )),
            }),
            help_uri: self.config.information_uri.clone(),
            default_configuration: Some(SarifDefaultConfiguration {
                level: SarifLevel::from(&rule.severity),
            }),
            properties: Some(SarifRuleProperties {
                tags,
                precision: Some(self.severity_to_precision(&rule.severity)),
            }),
        }
    }

    /// Convert a Finding to SarifResult
    fn finding_to_sarif_result(&self, finding: &Finding, rule: Option<&Rule>) -> SarifResult {
        let snippet = if self.config.include_snippets {
            // Use the snippet from finding if available, otherwise extract from description
            finding
                .snippet
                .clone()
                .or_else(|| self.extract_snippet_from_description(&finding.description))
        } else {
            None
        };

        let fix = if self.config.include_fixes {
            // Use rule fix if available, otherwise use recommendation
            rule.and_then(|r| r.fix.as_ref())
                .map(|f| {
                    vec![SarifFix {
                        description: SarifMessage {
                            text: "Apply suggested fix".to_string(),
                            markdown: None,
                        },
                        artifact_changes: vec![SarifArtifactChange {
                            artifact_location: SarifArtifactLocation {
                                uri: finding.location.file_path.clone(),
                                uri_base_id: self.config.uri_base_id.clone(),
                            },
                            replacements: vec![SarifReplacement {
                                deleted_region: SarifRegion {
                                    start_line: finding.location.line,
                                    start_column: finding.location.column,
                                    end_line: finding.location.end_line,
                                    end_column: finding.location.end_column,
                                    snippet: None,
                                },
                                inserted_content: SarifInsertedContent { text: f.clone() },
                            }],
                        }],
                    }]
                })
                .or_else(|| {
                    finding.recommendation.as_ref().map(|rec| {
                        vec![SarifFix {
                            description: SarifMessage {
                                text: rec.clone(),
                                markdown: None,
                            },
                            artifact_changes: vec![],
                        }]
                    })
                })
        } else {
            None
        };

        let level = rule
            .map(|r| SarifLevel::from(&r.severity))
            .unwrap_or(SarifLevel::from(&finding.severity));

        // Build code flows from data flow path if available
        let code_flows = finding.data_flow_path.as_ref().map(|path| {
            vec![SarifCodeFlow {
                thread_flows: vec![SarifThreadFlow {
                    locations: path
                        .steps
                        .iter()
                        .map(|step| SarifThreadFlowLocation {
                            location: SarifLocation {
                                physical_location: SarifPhysicalLocation {
                                    artifact_location: SarifArtifactLocation {
                                        uri: step.location.file_path.clone(),
                                        uri_base_id: self.config.uri_base_id.clone(),
                                    },
                                    region: Some(SarifRegion {
                                        start_line: step.location.line,
                                        start_column: step.location.column,
                                        end_line: step.location.end_line,
                                        end_column: step.location.end_column,
                                        snippet: Some(SarifSnippet {
                                            text: step.expression.clone(),
                                        }),
                                    }),
                                },
                            },
                        })
                        .collect(),
                }],
            }]
        });

        SarifResult {
            rule_id: finding.rule_id.clone(),
            level,
            message: SarifMessage {
                text: finding.description.clone(),
                markdown: None,
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding.location.file_path.clone(),
                        uri_base_id: self.config.uri_base_id.clone(),
                    },
                    region: Some(SarifRegion {
                        start_line: finding.location.line,
                        start_column: finding.location.column,
                        end_line: finding.location.end_line,
                        end_column: finding.location.end_column,
                        snippet: snippet.map(|s| SarifSnippet { text: s }),
                    }),
                },
            }],
            fingerprints: Some(HashMap::from([(
                "primaryLocationLineHash".to_string(),
                finding.id.clone(),
            )])),
            fixes: fix,
            code_flows,
        }
    }

    /// Extract code snippet from finding description
    fn extract_snippet_from_description(&self, description: &str) -> Option<String> {
        // Look for code blocks in the description
        if let Some(start) = description.find("```") {
            if let Some(end) = description[start + 3..].find("```") {
                let code = &description[start + 3..start + 3 + end];
                // Remove language identifier if present
                let code = code
                    .lines()
                    .skip_while(|l| l.chars().all(|c| c.is_alphanumeric()))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !code.trim().is_empty() {
                    return Some(code.trim().to_string());
                }
            }
        }

        // Look for "Matched code:" section
        if let Some(idx) = description.find("Matched code:") {
            let rest = &description[idx + 13..];
            let lines: Vec<&str> = rest.lines().take(5).collect();
            if !lines.is_empty() {
                return Some(lines.join("\n").trim().to_string());
            }
        }

        None
    }

    /// Convert severity to SARIF precision string
    fn severity_to_precision(&self, severity: &Severity) -> String {
        match severity {
            Severity::Critical | Severity::High => "high".to_string(),
            Severity::Medium => "medium".to_string(),
            Severity::Low | Severity::Info => "low".to_string(),
        }
    }

    /// Serialize report to JSON string
    pub fn to_json(&self, report: &SarifReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }

    /// Serialize report to compact JSON string
    pub fn to_json_compact(&self, report: &SarifReport) -> Result<String, serde_json::Error> {
        serde_json::to_string(report)
    }
}

impl Default for SarifExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Location;
    use crate::domain::value_objects::Confidence;

    fn sample_finding() -> Finding {
        Finding {
            id: "test-finding-1".to_string(),
            rule_id: "sql-injection".to_string(),
            location: Location {
                file_path: "src/app.py".to_string(),
                line: 10,
                column: Some(5),
                end_line: Some(10),
                end_column: Some(40),
            },
            severity: Severity::Critical,
            confidence: Confidence::High,
            description: "SQL injection vulnerability.\n\nMatched code:\ncursor.execute(query)"
                .to_string(),
            recommendation: Some("Use parameterized queries".to_string()),
            data_flow_path: None,
            snippet: None,
        }
    }

    fn sample_rule() -> Rule {
        Rule {
            id: "sql-injection".to_string(),
            name: "SQL Injection".to_string(),
            description: "Detects potential SQL injection vulnerabilities".to_string(),
            severity: Severity::Critical,
            languages: vec![crate::domain::value_objects::Language::Python],
            pattern: crate::domain::Pattern::TreeSitterQuery("(call) @call".to_string()),
            options: Default::default(),
            cwe_ids: vec!["CWE-89".to_string()],
            owasp_categories: vec!["A03:2021 - Injection".to_string()],
            tags: vec!["security".to_string()],
            message: None,
            fix: None,
        }
    }

    #[test]
    fn test_export_basic() {
        let exporter = SarifExporter::new();
        let findings = vec![sample_finding()];
        let rules = vec![sample_rule()];

        let report = exporter.export(&findings, &rules);

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);

        let run = &report.runs[0];
        assert_eq!(run.tool.driver.name, "vulnera-sast");
        assert_eq!(run.results.len(), 1);
        assert_eq!(run.tool.driver.rules.len(), 1);

        let result = &run.results[0];
        assert_eq!(result.rule_id, "sql-injection");
        assert_eq!(result.level, SarifLevel::Error);
        assert_eq!(result.locations.len(), 1);
        assert_eq!(
            result.locations[0]
                .physical_location
                .region
                .as_ref()
                .unwrap()
                .start_line,
            10
        );
    }

    #[test]
    fn test_sarif_level_from_severity() {
        assert_eq!(SarifLevel::from(&Severity::Critical), SarifLevel::Error);
        assert_eq!(SarifLevel::from(&Severity::High), SarifLevel::Error);
        assert_eq!(SarifLevel::from(&Severity::Medium), SarifLevel::Warning);
        assert_eq!(SarifLevel::from(&Severity::Low), SarifLevel::Note);
        assert_eq!(SarifLevel::from(&Severity::Info), SarifLevel::Note);
    }

    #[test]
    fn test_extract_snippet() {
        let exporter = SarifExporter::new();

        let desc_with_code = "Error found.\n\n```python\neval(user_input)\n```";
        let snippet = exporter.extract_snippet_from_description(desc_with_code);
        assert!(snippet.is_some());
        assert!(snippet.unwrap().contains("eval"));

        let desc_with_matched = "Error.\n\nMatched code:\ncursor.execute(query)";
        let snippet = exporter.extract_snippet_from_description(desc_with_matched);
        assert!(snippet.is_some());
        assert!(snippet.unwrap().contains("cursor.execute"));
    }

    #[test]
    fn test_to_json() {
        let exporter = SarifExporter::new();
        let findings = vec![sample_finding()];
        let rules = vec![sample_rule()];

        let report = exporter.export(&findings, &rules);
        let json = exporter.to_json(&report).unwrap();

        assert!(json.contains("\"$schema\""));
        assert!(json.contains("sarif-schema-2.1.0.json"));
        assert!(json.contains("sql-injection"));
    }

    #[test]
    fn test_rule_properties() {
        let exporter = SarifExporter::new();
        let rules = vec![sample_rule()];

        let sarif_rule = exporter.rule_to_sarif(&rules[0]);

        assert_eq!(sarif_rule.id, "sql-injection");
        assert!(sarif_rule.properties.is_some());

        let props = sarif_rule.properties.unwrap();
        assert!(props.tags.contains(&"CWE-89".to_string()));
        assert!(props.tags.contains(&"security".to_string()));
        assert_eq!(props.precision, Some("high".to_string()));
    }
}
