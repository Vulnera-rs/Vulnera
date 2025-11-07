//! SAST use cases

use std::path::Path;
use std::sync::Arc;

use crate::domain::entities::Finding as SastFinding;
use crate::infrastructure::parsers::ParserFactory;
use crate::infrastructure::rules::{RuleEngine, RuleRepository, SimpleRuleEngine};
use crate::infrastructure::scanner::DirectoryScanner;

/// Use case for scanning a project
pub struct ScanProjectUseCase {
    scanner: DirectoryScanner,
    parser_factory: ParserFactory,
    rule_repository: RuleRepository,
    rule_engine: Arc<dyn RuleEngine>,
}

impl ScanProjectUseCase {
    pub fn new() -> Self {
        Self {
            scanner: DirectoryScanner::new(10),
            parser_factory: ParserFactory,
            rule_repository: RuleRepository::new(),
            rule_engine: Arc::new(SimpleRuleEngine),
        }
    }

    pub async fn execute(&self, root: &Path) -> Result<Vec<SastFinding>, ScanError> {
        let files = self.scanner.scan(root)?;
        let mut all_findings = Vec::new();

        for file in files {
            let content = std::fs::read_to_string(&file.path)?;
            let mut parser = self
                .parser_factory
                .create_parser(&file.language)
                .map_err(|e| ScanError::ParseFailed(e.to_string()))?;

            let ast = parser
                .parse(&content)
                .map_err(|e| ScanError::ParseFailed(e.to_string()))?;

            let rules = self.rule_repository.get_rules_for_language(&file.language);

            // Traverse AST and match rules
            self.traverse_and_match(&ast, &rules, &file.path, &mut all_findings);
        }

        Ok(all_findings)
    }

    fn traverse_and_match(
        &self,
        node: &crate::infrastructure::parsers::AstNode,
        rules: &[&crate::domain::entities::Rule],
        file_path: &Path,
        findings: &mut Vec<SastFinding>,
    ) {
        // Check each rule against this node
        for rule in rules {
            if self.rule_engine.match_rule(rule, node) {
                let finding = SastFinding {
                    id: format!("{}-{}-{}", rule.id, file_path.display(), node.start_point.0),
                    rule_id: rule.id.clone(),
                    location: crate::domain::entities::Location {
                        file_path: file_path.display().to_string(),
                        line: node.start_point.0 + 1, // Convert to 1-based
                        column: Some(node.start_point.1),
                        end_line: Some(node.end_point.0 + 1),
                        end_column: Some(node.end_point.1),
                    },
                    severity: rule.severity.clone(),
                    confidence: crate::domain::value_objects::Confidence::Medium,
                    description: rule.description.clone(),
                    recommendation: Some(format!("Review and fix: {}", rule.name)),
                };
                findings.push(finding);
            }
        }

        // Recursively check children
        for child in &node.children {
            self.traverse_and_match(child, rules, file_path, findings);
        }
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
