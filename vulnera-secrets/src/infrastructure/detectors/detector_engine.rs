//! Detector engine that orchestrates multiple detectors

use crate::domain::entities::{Location, SecretFinding, SecretType, Severity};
use crate::domain::value_objects::Confidence;
use crate::infrastructure::detectors::{EntropyDetector, RegexDetector, RegexMatch};
use crate::infrastructure::rules::RuleRepository;
use std::path::Path;
use tracing::debug;

/// Detector engine that combines regex and entropy detection
pub struct DetectorEngine {
    regex_detector: RegexDetector,
    entropy_detector: Option<EntropyDetector>,
    #[allow(dead_code)]
    rule_repository: RuleRepository,
}

impl DetectorEngine {
    pub fn new(
        rule_repository: RuleRepository,
        base64_threshold: f64,
        hex_threshold: f64,
        enable_entropy: bool,
    ) -> Self {
        let rules = rule_repository.get_all_rules().to_vec();
        let regex_detector = RegexDetector::new(rules);

        let entropy_detector = if enable_entropy {
            Some(EntropyDetector::new(base64_threshold, hex_threshold))
        } else {
            None
        };

        Self {
            regex_detector,
            entropy_detector,
            rule_repository,
        }
    }

    /// Detect secrets in a file's content
    pub fn detect_in_file(
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
                let confidence = self.calculate_confidence_for_regex_match(&regex_match);
                let severity = self.determine_severity(&regex_match.rule.secret_type);

                findings.push(SecretFinding {
                    id: format!(
                        "{}-{}-{}",
                        regex_match.rule_id, file_path_str, line_number
                    ),
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
                            crate::domain::value_objects::EntropyEncoding::Generic => SecretType::Other,
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
}

