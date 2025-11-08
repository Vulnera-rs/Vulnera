//! Entropy-based secret detector

use crate::domain::value_objects::{Entropy, EntropyEncoding};
use tracing::debug;

/// Entropy detector for high-entropy strings
pub struct EntropyDetector {
    base64_threshold: f64,
    hex_threshold: f64,
}

impl EntropyDetector {
    pub fn new(base64_threshold: f64, hex_threshold: f64) -> Self {
        Self {
            base64_threshold,
            hex_threshold,
        }
    }

    /// Detect high-entropy strings in content
    pub fn detect(&self, content: &str, line_number: u32) -> Vec<EntropyMatch> {
        let mut matches = Vec::new();

        // Split content into potential secret candidates
        // Look for Base64-like and hex-like strings
        let words: Vec<&str> = content
            .split_whitespace()
            .flat_map(|s| s.split(|c: char| !c.is_alphanumeric() && c != '+' && c != '/' && c != '='))
            .filter(|s| s.len() >= 20) // Minimum length for secrets
            .collect();

        for word in words {
            // Check Base64-like strings
            if Entropy::is_base64_like(word) {
                let entropy = Entropy::shannon_entropy(word);
                if entropy >= self.base64_threshold {
                    debug!(
                        line = line_number,
                        entropy = entropy,
                        "Found high-entropy Base64 string"
                    );
                    matches.push(EntropyMatch {
                        encoding: EntropyEncoding::Base64,
                        entropy,
                        matched_text: word.to_string(),
                        start_pos: content.find(word).unwrap_or(0),
                        end_pos: content.find(word).unwrap_or(0) + word.len(),
                    });
                }
            }

            // Check hex-like strings
            if Entropy::is_hex_like(word) {
                let entropy = Entropy::shannon_entropy(word);
                if entropy >= self.hex_threshold {
                    debug!(
                        line = line_number,
                        entropy = entropy,
                        "Found high-entropy hex string"
                    );
                    matches.push(EntropyMatch {
                        encoding: EntropyEncoding::Hex,
                        entropy,
                        matched_text: word.to_string(),
                        start_pos: content.find(word).unwrap_or(0),
                        end_pos: content.find(word).unwrap_or(0) + word.len(),
                    });
                }
            }
        }

        matches
    }

    /// Detect high-entropy strings in a line-by-line manner (more efficient)
    pub fn detect_line(&self, line: &str, line_number: u32) -> Vec<EntropyMatch> {
        self.detect(line, line_number)
    }
}

/// Result of entropy detection
#[derive(Debug, Clone)]
pub struct EntropyMatch {
    pub encoding: EntropyEncoding,
    pub entropy: f64,
    pub matched_text: String,
    pub start_pos: usize,
    pub end_pos: usize,
}

