//! Security detection rules

use crate::domain::entities::{Rule, RulePattern, Severity};
use crate::domain::value_objects::Language;
use crate::infrastructure::parsers::AstNode;

/// Rule engine for matching security patterns
pub trait RuleEngine: Send + Sync {
    fn match_rule(&self, rule: &Rule, node: &AstNode) -> bool;
}

/// Simple rule engine implementation
pub struct SimpleRuleEngine;

impl RuleEngine for SimpleRuleEngine {
    fn match_rule(&self, rule: &Rule, node: &AstNode) -> bool {
        match &rule.pattern {
            RulePattern::AstNodeType(pattern) => node.node_type == *pattern,
            RulePattern::FunctionCall(func_name) => {
                // Check if node is a function call with matching name
                node.node_type == "call" && node.source.contains(func_name)
            }
            RulePattern::Regex(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&node.source)
                } else {
                    false
                }
            }
            RulePattern::Custom(_) => false, // Custom patterns not implemented yet
        }
    }
}

/// SQL injection rule
pub fn sql_injection_rule() -> Rule {
    Rule {
        id: "sql-injection".to_string(),
        name: "SQL Injection".to_string(),
        description: "Potential SQL injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("execute".to_string()),
    }
}

/// Command injection rule
pub fn command_injection_rule() -> Rule {
    Rule {
        id: "command-injection".to_string(),
        name: "Command Injection".to_string(),
        description: "Potential command injection vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("exec".to_string()),
    }
}

/// Unsafe deserialization rule
pub fn unsafe_deserialization_rule() -> Rule {
    Rule {
        id: "unsafe-deserialization".to_string(),
        name: "Unsafe Deserialization".to_string(),
        description: "Potential unsafe deserialization vulnerability".to_string(),
        severity: Severity::High,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("pickle.loads".to_string()),
    }
}

/// Unsafe function call rule
pub fn unsafe_function_call_rule() -> Rule {
    Rule {
        id: "unsafe-function-call".to_string(),
        name: "Unsafe Function Call".to_string(),
        description: "Potentially unsafe function call".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Python, Language::JavaScript, Language::Rust],
        pattern: RulePattern::FunctionCall("eval".to_string()),
    }
}

/// Null pointer rule
pub fn null_pointer_rule() -> Rule {
    Rule {
        id: "null-pointer".to_string(),
        name: "Potential Null Pointer".to_string(),
        description: "Potential null pointer dereference".to_string(),
        severity: Severity::Medium,
        languages: vec![Language::Rust], // More relevant for Rust
        pattern: RulePattern::AstNodeType("unwrap".to_string()),
    }
}

/// Rule repository
pub struct RuleRepository {
    rules: Vec<Rule>,
}

impl RuleRepository {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        rules.push(sql_injection_rule());
        rules.push(command_injection_rule());
        rules.push(unsafe_deserialization_rule());
        rules.push(unsafe_function_call_rule());
        rules.push(null_pointer_rule());

        Self { rules }
    }

    pub fn get_rules_for_language(&self, language: &Language) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.languages.contains(language))
            .collect()
    }

    pub fn get_all_rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}
