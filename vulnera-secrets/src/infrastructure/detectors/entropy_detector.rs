//! Entropy-based secret detector

use crate::domain::value_objects::{Entropy, EntropyEncoding};
use regex::Regex;
use tracing::debug;

/// Entropy detector for high-entropy strings
#[derive(Clone)]
pub struct EntropyDetector {
    base64_threshold: f64,
    hex_threshold: f64,
    candidate_regex: Regex,
}

impl EntropyDetector {
    pub fn new(base64_threshold: f64, hex_threshold: f64) -> Self {
        Self {
            base64_threshold,
            hex_threshold,
            // Match sequences of potential secret characters (Base64/Hex/URL-safe)
            // Minimum length 20 to avoid noise
            candidate_regex: Regex::new(r"[A-Za-z0-9+/=_-]{20,}").expect("Failed to compile entropy candidate regex"),
        }
    }

    /// Detect high-entropy strings in content
    pub fn detect(&self, content: &str, line_number: u32) -> Vec<EntropyMatch> {
        let mut matches = Vec::new();

        for mat in self.candidate_regex.find_iter(content) {
            let word = mat.as_str();
            
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
                        start_pos: mat.start(),
                        end_pos: mat.end(),
                    });
                    // If matched as Base64, don't check Hex (Hex is a subset of Base64 chars)
                    // unless we want to be very specific, but usually high entropy Base64 covers it.
                    // However, existing logic checked both. Let's keep checking both but maybe prioritize?
                    // Actually, if it's hex-like, it's also base64-like.
                    // If we add it as Base64, we might duplicate if we also add as Hex.
                    // Let's check Hex ONLY if it wasn't high enough entropy for Base64 OR if we want to classify it specifically.
                    // But wait, the thresholds might differ.
                    continue; 
                }
            }

            // Check hex-like strings (only if not already added as Base64)
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
                        start_pos: mat.start(),
                        end_pos: mat.end(),
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
