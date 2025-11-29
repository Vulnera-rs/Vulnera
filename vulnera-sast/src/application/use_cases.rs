//! SAST use cases

use std::path::Path;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::SastConfig;

use crate::domain::entities::{Finding as SastFinding, RulePattern, FileSuppressions};
use crate::domain::value_objects::Confidence;
use crate::infrastructure::parsers::{ParserFactory, find_call_node, node_has_literal_argument};
use crate::infrastructure::rules::{RuleEngine, RuleRepository};
use crate::infrastructure::scanner::DirectoryScanner;

/// Result of a SAST scan
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<SastFinding>,
    pub files_scanned: usize,
}

/// Use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    parser_factory: ParserFactory,
    rule_repository: RuleRepository,
    rule_engine: RuleEngine,
}

impl ScanProjectUseCase {
    pub fn new() -> Self {
        Self::with_config(&SastConfig::default())
    }

    pub fn with_config(config: &SastConfig) -> Self {
        let scanner = DirectoryScanner::new(config.max_scan_depth)
            .with_exclude_patterns(config.exclude_patterns.clone());

        let rule_repository = if let Some(ref rule_file_path) = config.rule_file_path {
            RuleRepository::with_file_and_defaults(rule_file_path)
        } else {
            RuleRepository::new()
        };

        Self {
            scanner,
            parser_factory: ParserFactory,
            rule_repository,
            rule_engine: RuleEngine::new(),
        }
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        info!("Starting SAST scan");
        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::Io(e)
        })?;

        let file_count = files.len();
        info!(file_count, "Found files to scan");

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        for file in files {
            debug!(file = %file.path.display(), language = ?file.language, "Scanning file");

            let content = match std::fs::read_to_string(&file.path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(file = %file.path.display(), error = %e, "Failed to read file");
                    continue;
                }
            };

            // Parse suppression comments from the file
            let suppressions = FileSuppressions::parse(&content);

            // Detect test context for the file
            let is_test_context = Self::is_test_file(&file.path, &content);

            let mut parser = match self.parser_factory.create_parser(&file.language) {
                Ok(parser) => parser,
                Err(e) => {
                    error!(file = %file.path.display(), language = ?file.language, error = %e, "Failed to create parser");
                    continue;
                }
            };

            let ast = match parser.parse(&content) {
                Ok(ast) => ast,
                Err(e) => {
                    warn!(file = %file.path.display(), error = %e, "Failed to parse file");
                    continue;
                }
            };

            files_scanned += 1;
            let rules = self.rule_repository.get_rules_for_language(&file.language);
            debug!(rule_count = rules.len(), "Applying rules to file");

            // Traverse AST and match rules with suppression and test context
            self.traverse_and_match(&ast, &rules, &file.path, &suppressions, is_test_context, &mut all_findings);
        }

        info!(
            finding_count = all_findings.len(),
            files_scanned, "SAST scan completed"
        );
        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
        })
    }

    /// Check if a file is in a test context
    fn is_test_file(path: &Path, content: &str) -> bool {
        // Check path-based test indicators
        let path_str = path.display().to_string();
        if path_str.contains("/tests/")
            || path_str.contains("/test/")
            || path_str.ends_with("_test.rs")
            || path_str.ends_with("_test.py")
            || path_str.ends_with(".test.js")
            || path_str.ends_with(".test.ts")
            || path_str.ends_with("_test.go")
            || path_str.contains("/benches/")
            || path_str.contains("/examples/")
        {
            return true;
        }

        // Check content-based test indicators (for Rust inline tests)
        if content.contains("#[cfg(test)]") || content.contains("#[test]") {
            return true;
        }

        false
    }

    fn traverse_and_match(
        &self,
        node: &crate::infrastructure::parsers::AstNode,
        rules: &[&crate::domain::entities::Rule],
        file_path: &Path,
        suppressions: &FileSuppressions,
        is_test_context: bool,
        findings: &mut Vec<SastFinding>,
    ) {
        // Check each rule against this node
        for rule in rules {
            if self.rule_engine.match_rule(rule, node) {
                let line = node.start_point.0 + 1; // 1-based line number

                // Check if this finding should be suppressed
                if suppressions.is_suppressed(line, &rule.id) {
                    debug!(
                        rule_id = %rule.id,
                        line,
                        "Finding suppressed by comment directive"
                    );
                    continue;
                }

                // Check if this finding should be suppressed due to test context
                if is_test_context && rule.options.suppress_in_tests {
                    debug!(
                        rule_id = %rule.id,
                        line,
                        "Finding suppressed in test context"
                    );
                    continue;
                }

                debug!(
                    rule_id = %rule.id,
                    node_type = %node.node_type,
                    line,
                    "Rule matched"
                );

                // Calculate confidence based on pattern specificity and context
                let confidence = calculate_confidence(&rule.pattern, node);

                let finding = SastFinding {
                    id: format!("{}-{}-{}", rule.id, file_path.display(), node.start_point.0),
                    rule_id: rule.id.clone(),
                    location: crate::domain::entities::Location {
                        file_path: file_path.display().to_string(),
                        line,
                        column: Some(node.start_point.1),
                        end_line: Some(node.end_point.0 + 1),
                        end_column: Some(node.end_point.1),
                    },
                    severity: rule.severity.clone(),
                    confidence,
                    description: rule.description.clone(),
                    recommendation: Some(format!("Review and fix: {}", rule.name)),
                };
                findings.push(finding);
            }
        }

        // Recursively check children
        for child in &node.children {
            self.traverse_and_match(child, rules, file_path, suppressions, is_test_context, findings);
        }
    }
}

/// Calculate confidence level based on pattern specificity and context
fn calculate_confidence(
    pattern: &RulePattern,
    node: &crate::infrastructure::parsers::AstNode,
) -> Confidence {
    match pattern {
        // Regex patterns are most specific - high confidence
        RulePattern::Regex(_) => Confidence::High,
        // Function call patterns are specific - use AST context (call node + argument heuristics)
        RulePattern::FunctionCall(_) => {
            // Determine the call node (either the node itself, or a nested child call node)
            let call_node_opt = find_call_node(node);

            // If we found a call node, inspect its arguments to see if the first argument is a literal.
            // If the argument is a literal (e.g., setTimeout("literal", ...)), decrease confidence to reduce false positives.
            // Otherwise, if the call exists and arguments are non-literal, treat as high confidence.
            if let Some(call_node) = call_node_opt {
                if node_has_literal_argument(call_node) {
                    Confidence::Low
                } else {
                    // Call node found and arguments are not purely literal → likely dynamic/unsafe
                    Confidence::High
                }
            } else {
                // No call node found — fallback heuristics based on the node source to detect literals
                // Basic heuristic: if there's an opening '(' followed by a quote, treat as literal.
                if let Some(idx) = node.source.find('(') {
                    let after = node.source[idx + 1..].trim_start();
                    if after.starts_with('"') || after.starts_with('\'') {
                        Confidence::Low
                    } else {
                        Confidence::Medium
                    }
                } else {
                    Confidence::Medium
                }
            }
        }
        // AST node type patterns are less specific - medium confidence
        RulePattern::AstNodeType(_) => {
            // Check context: if node has specific children or structure, increase confidence
            if !node.children.is_empty() {
                Confidence::Medium
            } else {
                Confidence::Low
            }
        }
        // MethodCall patterns are AST-aware and precise - high confidence
        RulePattern::MethodCall(_) => Confidence::High,
        // Custom patterns - default to medium
        RulePattern::Custom(_) => Confidence::Medium,
    }
}

impl Default for ScanProjectUseCase {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan error
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseFailed(String),
}
