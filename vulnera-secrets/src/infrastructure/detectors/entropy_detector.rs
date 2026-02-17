//! Entropy-based secret detector

use crate::domain::value_objects::{Entropy, EntropyEncoding};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

static CANDIDATE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9+/=_-]{20,}").expect("Failed to compile entropy candidate regex")
});

/// Entropy detector for high-entropy strings
#[derive(Clone)]
pub struct EntropyDetector {
    base64_threshold: f64,
    hex_threshold: f64,
}

const GENERIC_THRESHOLD: f64 = 4.3;
const MIN_TOKEN_LENGTH: usize = 20;
const MIN_UNIQUE_BASE64: usize = 10;
const MIN_UNIQUE_HEX: usize = 8;
const MIN_UNIQUE_GENERIC: usize = 12;
const MAX_DOMINANT_CHAR_RATIO: f64 = 0.35;

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

        for mat in CANDIDATE_REGEX.find_iter(content) {
            let word = mat.as_str();
            if !Self::is_reasonable_candidate(word) {
                continue;
            }

            let entropy = Entropy::shannon_entropy(word);
            let unique_chars = Self::unique_char_count(word);
            let dominant_ratio = Self::dominant_char_ratio(word);

            // Check Base64-like strings
            if Entropy::is_base64_like(word) {
                let normalized = entropy / 6.0; // max entropy for base64 alphabet ~= log2(64)=6
                if entropy >= self.base64_threshold
                    && normalized >= 0.70
                    && unique_chars >= MIN_UNIQUE_BASE64
                    && dominant_ratio <= MAX_DOMINANT_CHAR_RATIO
                {
                    debug!(
                        line = line_number,
                        entropy = entropy,
                        normalized_entropy = normalized,
                        unique_chars = unique_chars,
                        "Found high-entropy Base64 string"
                    );
                    matches.push(EntropyMatch {
                        encoding: EntropyEncoding::Base64,
                        entropy,
                        matched_text: word.to_string(),
                        start_pos: mat.start(),
                        end_pos: mat.end(),
                    });
                    // Skip hex checking if Base64 threshold is met, to avoid duplicate matches (hex is a subset of Base64).
                    continue;
                }
            }

            // Check hex-like strings (only if not already added as Base64)
            if Entropy::is_hex_like(word) {
                let normalized = entropy / 4.0; // max entropy for hex alphabet = log2(16)=4
                if entropy >= self.hex_threshold
                    && normalized >= 0.72
                    && unique_chars >= MIN_UNIQUE_HEX
                    && dominant_ratio <= MAX_DOMINANT_CHAR_RATIO
                {
                    debug!(
                        line = line_number,
                        entropy = entropy,
                        normalized_entropy = normalized,
                        unique_chars = unique_chars,
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
                continue;
            }

            // Generic high-entropy token detection for non-base64/non-hex strings
            let normalized_generic = entropy / (word.len().min(94) as f64).log2();
            if entropy >= GENERIC_THRESHOLD
                && normalized_generic >= 0.70
                && unique_chars >= MIN_UNIQUE_GENERIC
                && dominant_ratio <= MAX_DOMINANT_CHAR_RATIO
            {
                debug!(
                    line = line_number,
                    entropy = entropy,
                    normalized_entropy = normalized_generic,
                    unique_chars = unique_chars,
                    "Found high-entropy generic string"
                );
                matches.push(EntropyMatch {
                    encoding: EntropyEncoding::Generic,
                    entropy,
                    matched_text: word.to_string(),
                    start_pos: mat.start(),
                    end_pos: mat.end(),
                });
            }
        }

        matches
    }

    /// Detect high-entropy strings in a line-by-line manner (more efficient)
    pub fn detect_line(&self, line: &str, line_number: u32) -> Vec<EntropyMatch> {
        self.detect(line, line_number)
    }

    fn is_reasonable_candidate(word: &str) -> bool {
        if word.len() < MIN_TOKEN_LENGTH {
            return false;
        }

        // Skip obvious separators-only patterns often found in formatting or dummy values
        let starts_or_ends_with_separator = word.starts_with('_')
            || word.ends_with('_')
            || word.starts_with('-')
            || word.ends_with('-')
            || word.starts_with('=');

        !starts_or_ends_with_separator
    }

    fn unique_char_count(word: &str) -> usize {
        let mut freq = HashMap::new();
        for ch in word.chars() {
            *freq.entry(ch).or_insert(0usize) += 1;
        }
        freq.len()
    }

    fn dominant_char_ratio(word: &str) -> f64 {
        if word.is_empty() {
            return 1.0;
        }

        let mut freq = HashMap::new();
        for ch in word.chars() {
            *freq.entry(ch).or_insert(0usize) += 1;
        }

        let max_count = freq.values().copied().max().unwrap_or(0);
        max_count as f64 / word.len() as f64
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_detector_rejects_repeated_char_sequences() {
        let detector = EntropyDetector::new(4.5, 3.0);
        let findings = detector.detect_line("token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_detector_detects_random_base64_like_string() {
        let detector = EntropyDetector::new(4.5, 3.0);
        let findings =
            detector.detect_line("token=Q29tcGxleFJhbmRvbVN0cmluZ1dpdGhIaWdoRW50cm9weQ==", 1);
        assert!(!findings.is_empty());
    }
}
