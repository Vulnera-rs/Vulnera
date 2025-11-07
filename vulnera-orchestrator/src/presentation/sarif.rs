//! SARIF report format implementation

use crate::domain::entities::{AggregatedReport, Finding, FindingSeverity};
use serde_json::{Value, json};

/// Generate SARIF report from aggregated analysis results
pub fn generate_sarif_report(report: &AggregatedReport) -> Result<String, serde_json::Error> {
    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vulnera",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/k5602/vulnera"
                }
            },
            "results": report.findings.iter().map(convert_finding_to_sarif_result).collect::<Vec<_>>(),
            "properties": {
                "job_id": report.job_id.to_string(),
                "project_id": report.project_id,
                "total_findings": report.summary.total_findings
            }
        }]
    });

    serde_json::to_string_pretty(&sarif)
}

/// Convert a finding to SARIF result
fn convert_finding_to_sarif_result(finding: &Finding) -> Value {
    let mut result = json!({
        "message": {
            "text": finding.description
        },
        "level": match finding.severity {
            FindingSeverity::Critical => "error",
            FindingSeverity::High => "error",
            FindingSeverity::Medium => "warning",
            FindingSeverity::Low => "note",
            FindingSeverity::Info => "note",
        }
    });

    // Add rule ID if available
    if let Some(rule_id) = &finding.rule_id {
        result["ruleId"] = json!(rule_id);
    }

    // Add location
    let mut location = json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.location.path
            }
        }
    });

    // Add region if line information is available
    if let Some(line) = finding.location.line {
        let mut region = json!({
            "startLine": line
        });

        if let Some(column) = finding.location.column {
            region["startColumn"] = json!(column);
        }

        if let Some(end_line) = finding.location.end_line {
            region["endLine"] = json!(end_line);
        }

        if let Some(end_column) = finding.location.end_column {
            region["endColumn"] = json!(end_column);
        }

        location["physicalLocation"]["region"] = region;
    }

    result["locations"] = json!([location]);

    result
}
