//! Secret detection value objects

use crate::domain::entities::SecretType;
use serde::{Deserialize, Serialize};

/// Confidence level of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Result of semantic validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationResult {
    Verified,      // High confidence, verified via API
    Confirmed,     // High confidence, semantic match
    Potential,     // Medium confidence, regex match
    FalsePositive, // Discarded
}

/// Contextual metadata about where a secret was found
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticContext {
    pub node_type: String,            // tree-sitter node type (e.g. "comment")
    pub lhs_variable: Option<String>, // Variable name secret is assigned to
    pub rhs_value: Option<String>,    // Actual value assigned (from AST)
    pub is_test_context: bool,        // Found in a test file or mock
    pub entropy: Option<f64>,
}

/// Entropy calculation utilities
pub struct Entropy;

impl Entropy {
    /// Calculate Shannon entropy for a string
    ///
    /// Returns entropy value between 0.0 and 8.0 (for bytes)
    pub fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        let len = data.len() as f64;

        for byte in data.bytes() {
            frequency[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        for &count in frequency.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Check if a string has high entropy (likely a secret)
    pub fn is_high_entropy(data: &str, threshold: f64) -> bool {
        Self::shannon_entropy(data) >= threshold
    }

    /// Check if a string looks like Base64
    pub fn is_base64_like(data: &str) -> bool {
        // Base64 characters: A-Z, a-z, 0-9, +, /, = (padding)
        // Also support URL-safe Base64: -, _
        data.len() >= 20
            && data.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == '+'
                    || c == '/'
                    || c == '='
                    || c == '-'
                    || c == '_'
            })
            && data.len() % 4 == 0
    }

    /// Check if a string looks like hex
    pub fn is_hex_like(data: &str) -> bool {
        // Hex characters: 0-9, a-f, A-F
        data.len() >= 20 && data.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// Secret detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub secret_type: SecretType,
    pub pattern: RulePattern,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
    pub path_patterns: Vec<String>,
}

/// Rule pattern for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    /// Regex pattern
    Regex(String),
    /// Entropy-based detection
    Entropy {
        encoding: EntropyEncoding,
        threshold: f64,
    },
    /// Combined regex and entropy
    Combined {
        regex: String,
        entropy_threshold: f64,
    },
}

/// Entropy encoding type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropyEncoding {
    Base64,
    Hex,
    Generic,
}
