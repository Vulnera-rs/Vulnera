//! Optional intelligence utilities: ranking and cross-module correlation.
//!
//! This module intentionally uses deterministic heuristics as a safe baseline
//! until ML-assisted ranking is introduced.

use std::collections::{BTreeMap, HashSet};

use vulnera_core::domain::module::{
    Finding, FindingConfidence, FindingSeverity, ModuleResult, ModuleType,
};

/// Stable correlation key for findings that likely refer to the same issue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CorrelationKey {
    pub path: String,
    pub line: Option<u32>,
    pub rule_id: Option<String>,
}

/// Correlation cluster across modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedFinding {
    pub key: CorrelationKey,
    pub modules: Vec<ModuleType>,
    pub finding_ids: Vec<String>,
}

/// Ranked finding with deterministic priority score.
#[derive(Debug, Clone)]
pub struct RankedFinding {
    pub score: u32,
    pub finding: Finding,
}

/// Build correlation clusters from module results.
pub fn correlate_findings(module_results: &[ModuleResult]) -> Vec<CorrelatedFinding> {
    let mut grouped: BTreeMap<CorrelationKey, (HashSet<ModuleType>, Vec<String>)> = BTreeMap::new();

    for result in module_results {
        for finding in &result.findings {
            let key = CorrelationKey {
                path: finding.location.path.clone(),
                line: finding.location.line,
                rule_id: finding.rule_id.clone(),
            };

            let entry = grouped
                .entry(key)
                .or_insert_with(|| (HashSet::new(), Vec::new()));
            entry.0.insert(result.module_type.clone());
            entry.1.push(finding.id.clone());
        }
    }

    grouped
        .into_iter()
        .map(|(key, (modules, finding_ids))| {
            let mut modules: Vec<ModuleType> = modules.into_iter().collect();
            modules.sort_by_key(|m| format!("{:?}", m));

            CorrelatedFinding {
                key,
                modules,
                finding_ids,
            }
        })
        .collect()
}

/// Deterministic heuristic ranking (safe baseline for future ML ranking).
///
/// Score model:
/// - Severity: critical=100, high=80, medium=50, low=20, info=5
/// - Confidence: high=15, medium=8, low=3
/// - Correlation boost: +10 per additional corroborating module (capped +30)
pub fn rank_findings(
    findings: Vec<Finding>,
    correlation_index: &BTreeMap<String, usize>,
) -> Vec<RankedFinding> {
    let mut ranked: Vec<RankedFinding> = findings
        .into_iter()
        .map(|finding| {
            let base = severity_score(&finding.severity) + confidence_score(&finding.confidence);
            let corroboration = correlation_index.get(&finding.id).copied().unwrap_or(1);
            let boost = ((corroboration.saturating_sub(1) as u32) * 10).min(30);

            RankedFinding {
                score: base + boost,
                finding,
            }
        })
        .collect();

    ranked.sort_by(|lhs, rhs| {
        rhs.score
            .cmp(&lhs.score)
            .then_with(|| lhs.finding.id.cmp(&rhs.finding.id))
    });

    ranked
}

/// Build an index: finding_id -> number of corroborating modules.
pub fn build_correlation_index(clusters: &[CorrelatedFinding]) -> BTreeMap<String, usize> {
    let mut index = BTreeMap::new();
    for cluster in clusters {
        let corroborating_modules = cluster.modules.len();
        for finding_id in &cluster.finding_ids {
            index.insert(finding_id.clone(), corroborating_modules);
        }
    }
    index
}

fn severity_score(severity: &FindingSeverity) -> u32 {
    match severity {
        FindingSeverity::Critical => 100,
        FindingSeverity::High => 80,
        FindingSeverity::Medium => 50,
        FindingSeverity::Low => 20,
        FindingSeverity::Info => 5,
    }
}

fn confidence_score(confidence: &FindingConfidence) -> u32 {
    match confidence {
        FindingConfidence::High => 15,
        FindingConfidence::Medium => 8,
        FindingConfidence::Low => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vulnera_core::domain::module::{
        FindingType, Location, ModuleResultMetadata, VulnerabilityFindingMetadata,
    };

    fn mk_finding(
        id: &str,
        path: &str,
        line: u32,
        rule_id: Option<&str>,
        severity: FindingSeverity,
        confidence: FindingConfidence,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            r#type: FindingType::Vulnerability,
            rule_id: rule_id.map(ToString::to_string),
            location: Location {
                path: path.to_string(),
                line: Some(line),
                column: None,
                end_line: Some(line),
                end_column: None,
            },
            severity,
            confidence,
            description: "desc".to_string(),
            recommendation: None,
            secret_metadata: None,
            vulnerability_metadata: VulnerabilityFindingMetadata::default(),
            enrichment: None,
        }
    }

    fn mk_result(module_type: ModuleType, findings: Vec<Finding>) -> ModuleResult {
        ModuleResult {
            job_id: Uuid::new_v4(),
            module_type,
            findings,
            metadata: ModuleResultMetadata::default(),
            error: None,
        }
    }

    #[test]
    fn correlation_groups_by_location_and_rule() {
        let shared_a = mk_finding(
            "sast-1",
            "src/app.py",
            12,
            Some("rule-a"),
            FindingSeverity::High,
            FindingConfidence::High,
        );
        let shared_b = mk_finding(
            "sec-1",
            "src/app.py",
            12,
            Some("rule-a"),
            FindingSeverity::Medium,
            FindingConfidence::Medium,
        );

        let module_results = vec![
            mk_result(ModuleType::SAST, vec![shared_a]),
            mk_result(ModuleType::SecretDetection, vec![shared_b]),
        ];

        let clusters = correlate_findings(&module_results);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].modules.len(), 2);
        assert_eq!(clusters[0].finding_ids.len(), 2);
    }

    #[test]
    fn ranking_prefers_higher_severity_and_corroboration() {
        let critical = mk_finding(
            "f-critical",
            "src/a.py",
            10,
            Some("r1"),
            FindingSeverity::Critical,
            FindingConfidence::Medium,
        );
        let high = mk_finding(
            "f-high",
            "src/b.py",
            11,
            Some("r2"),
            FindingSeverity::High,
            FindingConfidence::High,
        );

        let index = BTreeMap::from([
            ("f-critical".to_string(), 1usize),
            ("f-high".to_string(), 4usize),
        ]);

        let ranked = rank_findings(vec![high.clone(), critical.clone()], &index);

        // high: 80 + 15 + 30(max boost) = 125
        // critical: 100 + 8 + 0 = 108
        assert_eq!(ranked[0].finding.id, "f-high");
        assert_eq!(ranked[1].finding.id, "f-critical");
    }
}
