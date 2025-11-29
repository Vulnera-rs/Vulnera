//! Detector engine that orchestrates multiple detectors

use crate::domain::entities::{Location, SecretFinding, SecretType, Severity};
use crate::domain::value_objects::{Confidence, SecretRule};
use crate::infrastructure::detectors::{EntropyDetector, RegexDetector, RegexMatch};
use crate::infrastructure::rules::RuleRepository;
use crate::infrastructure::verification::{VerificationResult, VerificationService};
use globset::{Glob, GlobMatcher};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// Detector engine that combines regex and entropy detection
#[derive(Clone)]
pub struct DetectorEngine {
    regex_detector: RegexDetector,
    entropy_detector: Option<EntropyDetector>,
    #[allow(dead_code)]
    rule_repository: RuleRepository,
    verification_service: Option<Arc<VerificationService>>,
    /// Precompiled path matchers per rule for efficient path matching
    path_matchers: HashMap<String, Vec<GlobMatcher>>,
}

impl DetectorEngine {
    pub fn new(
        rule_repository: RuleRepository,
        base64_threshold: f64,
        hex_threshold: f64,
        enable_entropy: bool,
    ) -> Self {
        Self::new_with_verification(
            rule_repository,
            base64_threshold,
            hex_threshold,
            enable_entropy,
            None,
        )
    }

    pub fn new_with_verification(
        rule_repository: RuleRepository,
        base64_threshold: f64,
        hex_threshold: f64,
        enable_entropy: bool,
        verification_service: Option<Arc<VerificationService>>,
    ) -> Self {
        let rules = rule_repository.get_all_rules().to_vec();
        // Clone rules for detector initialization; we keep a copy to build path matchers
        let regex_detector = RegexDetector::new(rules.clone());

        let entropy_detector = if enable_entropy {
            Some(EntropyDetector::new(base64_threshold, hex_threshold))
        } else {
            None
        };

        // Pre-compile glob matchers for rule.path_patterns into a HashMap keyed by rule id
        let mut path_matchers: HashMap<String, Vec<GlobMatcher>> = HashMap::new();
        for rule in &rules {
            if rule.path_patterns.is_empty() {
                continue;
            }
            let mut matchers: Vec<GlobMatcher> = Vec::new();
            for pattern in &rule.path_patterns {
                match Glob::new(pattern) {
                    Ok(g) => matchers.push(g.compile_matcher()),
                    Err(e) => {
                        tracing::warn!(rule_id = %rule.id, pattern = %pattern, error = %e, "Failed to compile glob pattern");
                    }
                }
            }
            if !matchers.is_empty() {
                path_matchers.insert(rule.id.clone(), matchers);
            }
        }

        Self {
            regex_detector,
            entropy_detector,
            rule_repository,
            verification_service,
            path_matchers,
        }
    }

    /// Detect secrets in a file's content (async version with verification support)
    pub async fn detect_in_file_async(
        &self,
        file_path: &Path,
        content: &str,
    ) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        let file_path_str = file_path.display().to_string();

        // Process line by line for better location tracking
        for (line_idx, line) in content.lines().enumerate() {
            let line_number = (line_idx + 1) as u32;

            // Run regex detection
            let regex_matches = self.regex_detector.detect_line(line, line_number);
            for regex_match in regex_matches {
                // Skip matches when this rule defines specific path_patterns and they do not match this file path
                if !self.rule_applies_to_file(&regex_match.rule, &file_path_str) {
                    debug!(file = %file_path_str, rule_id = %regex_match.rule_id, "Skipping finding - rule path_patterns do not match this file path");
                    continue;
                }

                let mut confidence = self.calculate_confidence_for_regex_match(&regex_match);
                let severity = self.determine_severity(&regex_match.rule.secret_type);

                // Verify secret if verification is enabled
                let mut is_verified = false;
                if let Some(ref verification_service) = self.verification_service {
                    let verification_result = verification_service
                        .verify_secret(&regex_match.matched_text, &regex_match.rule.secret_type)
                        .await;

                    match verification_result {
                        VerificationResult::Verified => {
                            is_verified = true;
                            confidence = Confidence::High; // Verified secrets get high confidence
                        }
                        VerificationResult::Invalid => {
                            // Invalid secrets might be false positives, lower confidence
                            if confidence == Confidence::High {
                                confidence = Confidence::Medium;
                            }
                        }
                        _ => {
                            // Failed or not supported - keep original confidence
                        }
                    }
                }

                findings.push(SecretFinding {
                    id: format!("{}-{}-{}", regex_match.rule_id, file_path_str, line_number),
                    rule_id: regex_match.rule_id.clone(),
                    secret_type: regex_match.rule.secret_type.clone(),
                    location: Location {
                        file_path: file_path_str.clone(),
                        line: line_number,
                        column: Some(regex_match.start_pos as u32 + 1),
                        end_line: Some(line_number),
                        end_column: Some(regex_match.end_pos as u32 + 1),
                    },
                    severity,
                    confidence,
                    description: {
                        let mut desc = regex_match.rule.description.clone();
                        if is_verified {
                            desc.push_str(" (VERIFIED - Secret is active)");
                        }
                        desc
                    },
                    recommendation: Some(format!(
                        "Remove or rotate the exposed {}",
                        regex_match.rule.name
                    )),
                    matched_secret: Self::redact_secret(&regex_match.matched_text),
                    entropy: None,
                });
            }

            // Run entropy detection if enabled
            if let Some(ref entropy_detector) = self.entropy_detector {
                let entropy_matches = entropy_detector.detect_line(line, line_number);
                for entropy_match in entropy_matches {
                    // Check if this entropy match overlaps with any regex match
                    let overlaps = findings.iter().any(|f| {
                        f.location.line == line_number
                            && f.location.column.unwrap_or(0) <= entropy_match.start_pos as u32
                            && f.location.end_column.unwrap_or(0) >= entropy_match.end_pos as u32
                    });

                    if !overlaps {
                        let secret_type = match entropy_match.encoding {
                            crate::domain::value_objects::EntropyEncoding::Base64 => {
                                SecretType::HighEntropyBase64
                            }
                            crate::domain::value_objects::EntropyEncoding::Hex => {
                                SecretType::HighEntropyHex
                            }
                            crate::domain::value_objects::EntropyEncoding::Generic => {
                                SecretType::Other
                            }
                        };

                        findings.push(SecretFinding {
                            id: format!(
                                "entropy-{}-{}-{}",
                                file_path_str, line_number, entropy_match.start_pos
                            ),
                            rule_id: format!("entropy-{:?}", entropy_match.encoding),
                            secret_type,
                            location: Location {
                                file_path: file_path_str.clone(),
                                line: line_number,
                                column: Some(entropy_match.start_pos as u32 + 1),
                                end_line: Some(line_number),
                                end_column: Some(entropy_match.end_pos as u32 + 1),
                            },
                            severity: Severity::High,
                            confidence: if entropy_match.entropy >= 5.0 {
                                Confidence::High
                            } else if entropy_match.entropy >= 4.0 {
                                Confidence::Medium
                            } else {
                                Confidence::Low
                            },
                            description: format!(
                                "High-entropy {:?} string detected (entropy: {:.2})",
                                entropy_match.encoding, entropy_match.entropy
                            ),
                            recommendation: Some(
                                "Review this high-entropy string - it may be a secret or token"
                                    .to_string(),
                            ),
                            matched_secret: Self::redact_secret(&entropy_match.matched_text),
                            entropy: Some(entropy_match.entropy),
                        });
                    }
                }
            }
        }

        debug!(
            file = %file_path.display(),
            finding_count = findings.len(),
            "Detection completed"
        );

        findings
    }

    /// Detect secrets in a file's content (synchronous version for compatibility)
    pub fn detect_in_file(&self, file_path: &Path, content: &str) -> Vec<SecretFinding> {
        // For synchronous version, we can't do async verification
        // This is used by git scanner which needs sync
        let mut findings = Vec::new();
        let file_path_str = file_path.display().to_string();

        for (line_idx, line) in content.lines().enumerate() {
            let line_number = (line_idx + 1) as u32;

            // Run regex detection
            let regex_matches = self.regex_detector.detect_line(line, line_number);
            for regex_match in regex_matches {
                // Skip matches when this rule defines specific path_patterns and they do not match this file path
                if !self.rule_applies_to_file(&regex_match.rule, &file_path_str) {
                    debug!(file = %file_path_str, rule_id = %regex_match.rule_id, "Skipping finding - rule path_patterns do not match this file path");
                    continue;
                }

                let confidence = self.calculate_confidence_for_regex_match(&regex_match);
                let severity = self.determine_severity(&regex_match.rule.secret_type);

                findings.push(SecretFinding {
                    id: format!("{}-{}-{}", regex_match.rule_id, file_path_str, line_number),
                    rule_id: regex_match.rule_id.clone(),
                    secret_type: regex_match.rule.secret_type.clone(),
                    location: Location {
                        file_path: file_path_str.clone(),
                        line: line_number,
                        column: Some(regex_match.start_pos as u32 + 1),
                        end_line: Some(line_number),
                        end_column: Some(regex_match.end_pos as u32 + 1),
                    },
                    severity,
                    confidence,
                    description: regex_match.rule.description.clone(),
                    recommendation: Some(format!(
                        "Remove or rotate the exposed {}",
                        regex_match.rule.name
                    )),
                    matched_secret: Self::redact_secret(&regex_match.matched_text),
                    entropy: None,
                });
            }

            // Run entropy detection if enabled
            if let Some(ref entropy_detector) = self.entropy_detector {
                let entropy_matches = entropy_detector.detect_line(line, line_number);
                for entropy_match in entropy_matches {
                    // Check if this entropy match overlaps with any regex match
                    let overlaps = findings.iter().any(|f| {
                        f.location.line == line_number
                            && f.location.column.unwrap_or(0) <= entropy_match.start_pos as u32
                            && f.location.end_column.unwrap_or(0) >= entropy_match.end_pos as u32
                    });

                    if !overlaps {
                        let secret_type = match entropy_match.encoding {
                            crate::domain::value_objects::EntropyEncoding::Base64 => {
                                SecretType::HighEntropyBase64
                            }
                            crate::domain::value_objects::EntropyEncoding::Hex => {
                                SecretType::HighEntropyHex
                            }
                            crate::domain::value_objects::EntropyEncoding::Generic => {
                                SecretType::Other
                            }
                        };

                        findings.push(SecretFinding {
                            id: format!(
                                "entropy-{}-{}-{}",
                                file_path_str, line_number, entropy_match.start_pos
                            ),
                            rule_id: format!("entropy-{:?}", entropy_match.encoding),
                            secret_type,
                            location: Location {
                                file_path: file_path_str.clone(),
                                line: line_number,
                                column: Some(entropy_match.start_pos as u32 + 1),
                                end_line: Some(line_number),
                                end_column: Some(entropy_match.end_pos as u32 + 1),
                            },
                            severity: Severity::High,
                            confidence: if entropy_match.entropy >= 5.0 {
                                Confidence::High
                            } else if entropy_match.entropy >= 4.0 {
                                Confidence::Medium
                            } else {
                                Confidence::Low
                            },
                            description: format!(
                                "High-entropy {:?} string detected (entropy: {:.2})",
                                entropy_match.encoding, entropy_match.entropy
                            ),
                            recommendation: Some(
                                "Review this high-entropy string - it may be a secret or token"
                                    .to_string(),
                            ),
                            matched_secret: Self::redact_secret(&entropy_match.matched_text),
                            entropy: Some(entropy_match.entropy),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Calculate confidence for a regex match
    fn calculate_confidence_for_regex_match(&self, regex_match: &RegexMatch) -> Confidence {
        // High confidence for specific patterns (AWS keys, tokens with known formats)
        match regex_match.rule.secret_type {
            SecretType::AwsAccessKey
            | SecretType::AwsSecretKey
            | SecretType::StripeApiKey
            | SecretType::GitHubToken
            | SecretType::JwtToken => Confidence::High,
            SecretType::GenericApiKey | SecretType::OAuthToken | SecretType::BearerToken => {
                Confidence::Medium
            }
            _ => Confidence::Medium,
        }
    }

    /// Determine severity based on secret type
    fn determine_severity(&self, secret_type: &SecretType) -> Severity {
        match secret_type {
            SecretType::AwsAccessKey
            | SecretType::AwsSecretKey
            | SecretType::AwsSessionToken
            | SecretType::DatabasePassword
            | SecretType::SshPrivateKey
            | SecretType::RsaPrivateKey
            | SecretType::EcPrivateKey => Severity::Critical,
            SecretType::ApiKey
            | SecretType::StripeApiKey
            | SecretType::TwilioApiKey
            | SecretType::GitHubToken
            | SecretType::GitLabToken
            | SecretType::AzureKey
            | SecretType::GcpKey => Severity::High,
            SecretType::OAuthToken | SecretType::BearerToken | SecretType::JwtToken => {
                Severity::High
            }
            SecretType::HighEntropyBase64 | SecretType::HighEntropyHex => Severity::High,
            _ => Severity::Medium,
        }
    }

    /// Redact secret for safe logging/display
    fn redact_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            return "***".to_string();
        }
        format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
    }

    /// Check whether a rule applies to the supplied file path.
    /// Precompiled matchers (from `path_matchers`) are used for efficient matching.
    /// If a rule defines `path_patterns`, the rule only applies when at least one compiled pattern matches the file path.
    fn rule_applies_to_file(&self, rule: &SecretRule, file_path: &str) -> bool {
        if rule.path_patterns.is_empty() {
            return true;
        }

        // Normalize path separators for matching (Windows -> '/')
        let path_norm = file_path.replace('\\', "/");

        if let Some(matchers) = self.path_matchers.get(&rule.id) {
            for matcher in matchers {
                if matcher.is_match(&path_norm) {
                    return true;
                }
            }
        }

        false
    }
}
