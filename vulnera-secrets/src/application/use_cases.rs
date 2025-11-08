//! Secret detection use cases

use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::SecretDetectionConfig;

use crate::domain::entities::SecretFinding;
use crate::infrastructure::detectors::DetectorEngine;
use crate::infrastructure::rules::RuleRepository;
use crate::infrastructure::scanner::{DirectoryScanner, ScanFile};

/// Result of a secret detection scan
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
}

/// Use case for scanning a project for secrets
pub struct ScanForSecretsUseCase {
    scanner: DirectoryScanner,
    detector_engine: Arc<DetectorEngine>,
}

impl ScanForSecretsUseCase {
    pub fn new() -> Self {
        Self::with_config(&SecretDetectionConfig::default())
    }

    pub fn with_config(config: &SecretDetectionConfig) -> Self {
        let scanner = DirectoryScanner::new(config.max_scan_depth, config.max_file_size_bytes)
            .with_exclude_patterns(config.exclude_patterns.clone());

        let rule_repository = if let Some(ref rule_file_path) = config.rule_file_path {
            RuleRepository::with_file_and_defaults(rule_file_path)
        } else {
            RuleRepository::new()
        };

        let detector_engine = Arc::new(DetectorEngine::new(
            rule_repository,
            config.base64_entropy_threshold,
            config.hex_entropy_threshold,
            config.enable_entropy_detection,
        ));

        Self {
            scanner,
            detector_engine,
        }
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        info!("Starting secret detection scan");
        let files = self.scanner.scan(root).map_err(|e| {
            error!(error = %e, "Failed to scan directory");
            ScanError::Io(e)
        })?;

        let file_count = files.len();
        info!(file_count, "Found files to scan");

        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        // Process files in parallel using tokio
        let mut handles = Vec::new();

        for file in files {
            let detector_engine = self.detector_engine.clone();
            let handle = tokio::spawn(async move {
                Self::scan_file(&detector_engine, &file).await
            });
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(Ok(findings)) => {
                    files_scanned += 1;
                    all_findings.extend(findings);
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "Failed to scan file");
                }
                Err(e) => {
                    warn!(error = %e, "Task join error");
                }
            }
        }

        info!(
            finding_count = all_findings.len(),
            files_scanned, "Secret detection scan completed"
        );
        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
        })
    }

    async fn scan_file(
        detector_engine: &DetectorEngine,
        file: &ScanFile,
    ) -> Result<Vec<SecretFinding>, ScanError> {
        debug!(file = %file.path.display(), "Scanning file");

        let content = match tokio::fs::read_to_string(&file.path).await {
            Ok(content) => content,
            Err(e) => {
                warn!(file = %file.path.display(), error = %e, "Failed to read file");
                return Err(ScanError::Io(e));
            }
        };

        let findings = detector_engine.detect_in_file(&file.path, &content);
        Ok(findings)
    }
}

impl Default for ScanForSecretsUseCase {
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

