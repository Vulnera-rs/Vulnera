//! Analysis engine selector
//!
//! This module provides intelligent selection of analysis engines based on:
//! - Rule type (tree-sitter query vs Semgrep pattern)
//! - Analysis requirements (taint tracking needs Semgrep)
//! - File patterns and language support
//! - Performance considerations

use crate::domain::entities::{Rule, SemgrepRule, SemgrepRuleMode};
use crate::domain::value_objects::{AnalysisEngine, Language};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, instrument};

/// Selection result for a single file
#[derive(Debug, Clone)]
pub struct EngineSelection {
    /// Primary engine to use
    pub engine: AnalysisEngine,
    /// Tree-sitter rules to execute (if any)
    pub tree_sitter_rules: Vec<Rule>,
    /// Semgrep rules to execute (if any)
    pub semgrep_rules: Vec<SemgrepRule>,
    /// Whether taint analysis is required
    pub requires_taint: bool,
}

/// Configuration for the analysis selector
#[derive(Debug, Clone)]
pub struct AnalysisSelectorConfig {
    /// Prefer tree-sitter for simple pattern matching (faster)
    pub prefer_tree_sitter: bool,
    /// Use Semgrep for taint tracking
    pub use_semgrep_for_taint: bool,
    /// File patterns to always use Semgrep (e.g., "**/*.py" for Python taint rules)
    pub semgrep_file_patterns: Vec<String>,
    /// File patterns to skip entirely
    pub skip_patterns: Vec<String>,
    /// Maximum file size to analyze (bytes)
    pub max_file_size: usize,
}

impl Default for AnalysisSelectorConfig {
    fn default() -> Self {
        Self {
            prefer_tree_sitter: true,
            use_semgrep_for_taint: true,
            semgrep_file_patterns: vec![],
            skip_patterns: vec![
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
                "**/vendor/**".to_string(),
                "**/__pycache__/**".to_string(),
            ],
            max_file_size: 1024 * 1024, // 1MB
        }
    }
}

/// Smart analysis engine selector
pub struct AnalysisSelector {
    config: AnalysisSelectorConfig,
    /// Compiled glob patterns for Semgrep preference
    semgrep_globs: GlobSet,
    /// Compiled glob patterns for skipping
    skip_globs: GlobSet,
}

impl AnalysisSelector {
    /// Create a new selector with default configuration
    pub fn new() -> Self {
        Self::with_config(AnalysisSelectorConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: AnalysisSelectorConfig) -> Self {
        let semgrep_globs = Self::build_glob_set(&config.semgrep_file_patterns);
        let skip_globs = Self::build_glob_set(&config.skip_patterns);

        Self {
            config,
            semgrep_globs,
            skip_globs,
        }
    }

    /// Build a GlobSet from patterns
    fn build_glob_set(patterns: &[String]) -> GlobSet {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            if let Ok(glob) = Glob::new(pattern) {
                builder.add(glob);
            }
        }
        builder
            .build()
            .unwrap_or_else(|_| GlobSetBuilder::new().build().unwrap())
    }

    /// Check if a file should be skipped
    pub fn should_skip(&self, file_path: &Path) -> bool {
        self.skip_globs.is_match(file_path)
    }

    /// Check if Semgrep is preferred for a file
    pub fn prefers_semgrep(&self, file_path: &Path) -> bool {
        self.semgrep_globs.is_match(file_path)
    }

    /// Select the appropriate engine and rules for a file
    #[instrument(skip(self, ts_rules, sg_rules), fields(file = %file_path.display()))]
    pub fn select_for_file(
        &self,
        file_path: &Path,
        language: &Language,
        ts_rules: &[Rule],
        sg_rules: &[SemgrepRule],
    ) -> EngineSelection {
        // Filter rules by language
        let applicable_ts_rules: Vec<Rule> = ts_rules
            .iter()
            .filter(|r| r.languages.contains(language))
            .cloned()
            .collect();

        let applicable_sg_rules: Vec<SemgrepRule> = sg_rules
            .iter()
            .filter(|r| r.languages.contains(language))
            .cloned()
            .collect();

        // Check if taint analysis is required
        let requires_taint = applicable_sg_rules
            .iter()
            .any(|r| r.mode == SemgrepRuleMode::Taint);

        // Determine engine based on rules and configuration
        let engine = self.determine_engine(
            file_path,
            &applicable_ts_rules,
            &applicable_sg_rules,
            requires_taint,
        );

        debug!(
            engine = ?engine,
            ts_rules = applicable_ts_rules.len(),
            sg_rules = applicable_sg_rules.len(),
            requires_taint = requires_taint,
            "Selected analysis engine"
        );

        EngineSelection {
            engine,
            tree_sitter_rules: applicable_ts_rules,
            semgrep_rules: applicable_sg_rules,
            requires_taint,
        }
    }

    /// Determine which engine to use
    fn determine_engine(
        &self,
        file_path: &Path,
        ts_rules: &[Rule],
        sg_rules: &[SemgrepRule],
        requires_taint: bool,
    ) -> AnalysisEngine {
        // If taint analysis is required and configured to use Semgrep for it
        if requires_taint && self.config.use_semgrep_for_taint {
            if ts_rules.is_empty() {
                return AnalysisEngine::Semgrep;
            }
            return AnalysisEngine::Hybrid;
        }

        // If file matches Semgrep preference patterns
        if self.prefers_semgrep(file_path) {
            if ts_rules.is_empty() {
                return AnalysisEngine::Semgrep;
            }
            return AnalysisEngine::Hybrid;
        }

        // If only tree-sitter rules available
        if sg_rules.is_empty() {
            return AnalysisEngine::TreeSitter;
        }

        // If only Semgrep rules available
        if ts_rules.is_empty() {
            return AnalysisEngine::Semgrep;
        }

        // Both types of rules - use hybrid if configured to prefer tree-sitter
        if self.config.prefer_tree_sitter {
            AnalysisEngine::Hybrid
        } else {
            AnalysisEngine::Semgrep
        }
    }

    /// Select engines for multiple files (batch optimization)
    #[instrument(skip(self, files, ts_rules, sg_rules), fields(file_count))]
    pub fn select_for_files<P: AsRef<Path>>(
        &self,
        files: &[(P, Language)],
        ts_rules: &[Rule],
        sg_rules: &[SemgrepRule],
    ) -> Vec<(String, EngineSelection)> {
        tracing::Span::current().record("file_count", files.len());
        files
            .iter()
            .filter(|(path, _)| !self.should_skip(path.as_ref()))
            .map(|(path, lang)| {
                let selection = self.select_for_file(path.as_ref(), lang, ts_rules, sg_rules);
                (path.as_ref().to_string_lossy().to_string(), selection)
            })
            .collect()
    }

    /// Group files by selected engine for batch processing
    pub fn group_by_engine(
        selections: &[(String, EngineSelection)],
    ) -> HashMap<AnalysisEngine, Vec<&str>> {
        let mut groups: HashMap<AnalysisEngine, Vec<&str>> = HashMap::new();

        for (path, selection) in selections {
            groups
                .entry(selection.engine.clone())
                .or_default()
                .push(path.as_str());
        }

        groups
    }

    /// Analyze rule coverage for a language
    pub fn analyze_coverage(
        &self,
        language: &Language,
        ts_rules: &[Rule],
        sg_rules: &[SemgrepRule],
    ) -> RuleCoverageReport {
        let ts_count = ts_rules
            .iter()
            .filter(|r| r.languages.contains(language))
            .count();
        let sg_count = sg_rules
            .iter()
            .filter(|r| r.languages.contains(language))
            .count();
        let taint_count = sg_rules
            .iter()
            .filter(|r| r.languages.contains(language) && r.mode == SemgrepRuleMode::Taint)
            .count();

        // Collect unique CWEs covered
        let mut cwes: HashSet<String> = HashSet::new();
        for rule in ts_rules.iter().filter(|r| r.languages.contains(language)) {
            cwes.extend(rule.cwe_ids.iter().cloned());
        }
        for rule in sg_rules.iter().filter(|r| r.languages.contains(language)) {
            cwes.extend(rule.cwe_ids.iter().cloned());
        }

        RuleCoverageReport {
            language: language.clone(),
            tree_sitter_rules: ts_count,
            semgrep_rules: sg_count,
            taint_rules: taint_count,
            total_rules: ts_count + sg_count,
            cwes_covered: cwes.into_iter().collect(),
        }
    }
}

impl Default for AnalysisSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Report on rule coverage for a language
#[derive(Debug, Clone)]
pub struct RuleCoverageReport {
    pub language: Language,
    pub tree_sitter_rules: usize,
    pub semgrep_rules: usize,
    pub taint_rules: usize,
    pub total_rules: usize,
    pub cwes_covered: Vec<String>,
}

/// Categorize rules by their detection capabilities
#[derive(Debug, Clone, Default)]
pub struct RuleCategories {
    /// Simple pattern matching rules (tree-sitter)
    pub pattern_rules: Vec<String>,
    /// Dataflow/taint tracking rules (Semgrep)
    pub taint_rules: Vec<String>,
    /// Injection detection rules
    pub injection_rules: Vec<String>,
    /// Authentication/authorization rules
    pub auth_rules: Vec<String>,
    /// Cryptography rules
    pub crypto_rules: Vec<String>,
    /// Other security rules
    pub other_rules: Vec<String>,
}

impl RuleCategories {
    /// Categorize a set of rules
    pub fn from_rules(ts_rules: &[Rule], sg_rules: &[SemgrepRule]) -> Self {
        let mut categories = Self::default();

        for rule in ts_rules {
            let id = rule.id.clone();
            if Self::is_injection_rule(&rule.cwe_ids, &rule.tags) {
                categories.injection_rules.push(id.clone());
            }
            if Self::is_auth_rule(&rule.cwe_ids, &rule.tags) {
                categories.auth_rules.push(id.clone());
            }
            if Self::is_crypto_rule(&rule.cwe_ids, &rule.tags) {
                categories.crypto_rules.push(id.clone());
            }
            categories.pattern_rules.push(id);
        }

        for rule in sg_rules {
            let id = rule.id.clone();
            if rule.mode == SemgrepRuleMode::Taint {
                categories.taint_rules.push(id.clone());
            }
            if Self::is_injection_rule(&rule.cwe_ids, &rule.tags) {
                categories.injection_rules.push(id.clone());
            }
            if Self::is_auth_rule(&rule.cwe_ids, &rule.tags) {
                categories.auth_rules.push(id.clone());
            }
            if Self::is_crypto_rule(&rule.cwe_ids, &rule.tags) {
                categories.crypto_rules.push(id.clone());
            }
        }

        categories
    }

    fn is_injection_rule(cwes: &[String], tags: &[String]) -> bool {
        let injection_cwes = ["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-77"];
        cwes.iter()
            .any(|c| injection_cwes.iter().any(|ic| c.contains(ic)))
            || tags.iter().any(|t| t.to_lowercase().contains("injection"))
    }

    fn is_auth_rule(cwes: &[String], tags: &[String]) -> bool {
        let auth_cwes = ["CWE-287", "CWE-306", "CWE-862", "CWE-863"];
        cwes.iter()
            .any(|c| auth_cwes.iter().any(|ac| c.contains(ac)))
            || tags.iter().any(|t| {
                let lower = t.to_lowercase();
                lower.contains("auth") || lower.contains("permission") || lower.contains("access")
            })
    }

    fn is_crypto_rule(cwes: &[String], tags: &[String]) -> bool {
        let crypto_cwes = ["CWE-327", "CWE-328", "CWE-330", "CWE-338"];
        cwes.iter()
            .any(|c| crypto_cwes.iter().any(|cc| c.contains(cc)))
            || tags.iter().any(|t| {
                let lower = t.to_lowercase();
                lower.contains("crypto") || lower.contains("cipher") || lower.contains("hash")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{RulePattern, entities::RuleOptions};

    fn sample_ts_rule(id: &str, lang: Language) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("{} Rule", id),
            description: "Test rule".to_string(),
            severity: crate::domain::entities::Severity::Medium,
            languages: vec![lang],
            pattern: RulePattern::TreeSitterQuery("(call) @call".to_string()),
            options: RuleOptions::default(),
            cwe_ids: vec!["CWE-89".to_string()],
            owasp_categories: vec![],
            tags: vec!["security".to_string()],
        }
    }

    fn sample_sg_rule(id: &str, lang: Language, taint: bool) -> SemgrepRule {
        use crate::domain::entities::{TaintConfig, TaintPattern};

        SemgrepRule {
            id: id.to_string(),
            name: format!("{} Rule", id),
            message: "Test message".to_string(),
            languages: vec![lang],
            severity: crate::domain::entities::Severity::High,
            mode: if taint {
                SemgrepRuleMode::Taint
            } else {
                SemgrepRuleMode::Search
            },
            pattern: if taint {
                None
            } else {
                Some("$X(...)".to_string())
            },
            patterns: None,
            taint_config: if taint {
                Some(TaintConfig {
                    sources: vec![TaintPattern {
                        pattern: "request.args".to_string(),
                        label: None,
                        requires: None,
                    }],
                    sinks: vec![TaintPattern {
                        pattern: "db.execute($X)".to_string(),
                        label: None,
                        requires: None,
                    }],
                    sanitizers: vec![],
                    propagators: vec![],
                })
            } else {
                None
            },
            cwe_ids: vec!["CWE-89".to_string()],
            owasp_categories: vec![],
            tags: vec![],
            fix: None,
            metadata: Default::default(),
        }
    }

    #[test]
    fn test_select_tree_sitter_only() {
        let selector = AnalysisSelector::new();
        let ts_rules = vec![sample_ts_rule("ts-1", Language::Python)];
        let sg_rules: Vec<SemgrepRule> = vec![];

        let selection = selector.select_for_file(
            Path::new("test.py"),
            &Language::Python,
            &ts_rules,
            &sg_rules,
        );

        assert_eq!(selection.engine, AnalysisEngine::TreeSitter);
        assert_eq!(selection.tree_sitter_rules.len(), 1);
        assert!(selection.semgrep_rules.is_empty());
        assert!(!selection.requires_taint);
    }

    #[test]
    fn test_select_semgrep_only() {
        let selector = AnalysisSelector::new();
        let ts_rules: Vec<Rule> = vec![];
        let sg_rules = vec![sample_sg_rule("sg-1", Language::Python, false)];

        let selection = selector.select_for_file(
            Path::new("test.py"),
            &Language::Python,
            &ts_rules,
            &sg_rules,
        );

        assert_eq!(selection.engine, AnalysisEngine::Semgrep);
        assert!(selection.tree_sitter_rules.is_empty());
        assert_eq!(selection.semgrep_rules.len(), 1);
    }

    #[test]
    fn test_select_hybrid_with_taint() {
        let selector = AnalysisSelector::new();
        let ts_rules = vec![sample_ts_rule("ts-1", Language::Python)];
        let sg_rules = vec![sample_sg_rule("sg-1", Language::Python, true)];

        let selection = selector.select_for_file(
            Path::new("test.py"),
            &Language::Python,
            &ts_rules,
            &sg_rules,
        );

        assert_eq!(selection.engine, AnalysisEngine::Hybrid);
        assert!(!selection.tree_sitter_rules.is_empty());
        assert!(!selection.semgrep_rules.is_empty());
        assert!(selection.requires_taint);
    }

    #[test]
    fn test_should_skip() {
        let selector = AnalysisSelector::new();

        assert!(selector.should_skip(Path::new("node_modules/test.js")));
        assert!(selector.should_skip(Path::new("target/debug/main.rs")));
        assert!(selector.should_skip(Path::new(".git/config")));
        assert!(!selector.should_skip(Path::new("src/main.py")));
    }

    #[test]
    fn test_language_filtering() {
        let selector = AnalysisSelector::new();
        let ts_rules = vec![
            sample_ts_rule("ts-py", Language::Python),
            sample_ts_rule("ts-js", Language::JavaScript),
        ];
        let sg_rules: Vec<SemgrepRule> = vec![];

        let selection = selector.select_for_file(
            Path::new("test.py"),
            &Language::Python,
            &ts_rules,
            &sg_rules,
        );

        assert_eq!(selection.tree_sitter_rules.len(), 1);
        assert_eq!(selection.tree_sitter_rules[0].id, "ts-py");
    }

    #[test]
    fn test_coverage_report() {
        let selector = AnalysisSelector::new();
        let ts_rules = vec![
            sample_ts_rule("ts-1", Language::Python),
            sample_ts_rule("ts-2", Language::Python),
        ];
        let sg_rules = vec![
            sample_sg_rule("sg-1", Language::Python, true),
            sample_sg_rule("sg-2", Language::JavaScript, false),
        ];

        let report = selector.analyze_coverage(&Language::Python, &ts_rules, &sg_rules);

        assert_eq!(report.tree_sitter_rules, 2);
        assert_eq!(report.semgrep_rules, 1);
        assert_eq!(report.taint_rules, 1);
        assert_eq!(report.total_rules, 3);
    }

    #[test]
    fn test_rule_categories() {
        let ts_rules = vec![sample_ts_rule("injection-1", Language::Python)];
        let sg_rules = vec![sample_sg_rule("taint-1", Language::Python, true)];

        let categories = RuleCategories::from_rules(&ts_rules, &sg_rules);

        assert!(!categories.injection_rules.is_empty());
        assert!(!categories.taint_rules.is_empty());
    }
}
