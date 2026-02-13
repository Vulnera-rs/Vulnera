//! Baseline repository for tracking known secrets

use crate::domain::entities::SecretFinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// Baseline entry for a secret finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Stable finding fingerprint (v2 format)
    pub fingerprint: String,
    /// File path where secret was found
    pub file_path: String,
    /// Line number
    pub line: u32,
    /// Rule ID that detected the secret
    pub rule_id: String,
    /// Whether this is actually a secret (false = false positive)
    pub is_secret: bool,
    /// Whether the secret was verified
    pub is_verified: bool,
    /// Optional suppression reason
    #[serde(default)]
    pub suppression_reason: Option<String>,
    /// Timestamp when this entry was created
    #[serde(default = "default_suppressed_at")]
    pub suppressed_at: DateTime<Utc>,
    /// Optional detector id used for this finding
    #[serde(default)]
    pub detector_id: Option<String>,
}

fn default_suppressed_at() -> DateTime<Utc> {
    Utc::now()
}

/// Baseline structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Baseline version
    pub version: String,
    /// Entries in the baseline
    pub entries: Vec<BaselineEntry>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: "2.0".to_string(),
            entries: Vec::new(),
        }
    }
}

/// Repository trait for baseline operations
pub trait BaselineRepository: Send + Sync {
    /// Load baseline from storage
    fn load(&self) -> Result<Baseline, BaselineError>;

    /// Save baseline to storage
    fn save(&self, baseline: &Baseline) -> Result<(), BaselineError>;

    /// Check if a finding exists in baseline
    fn contains(&self, finding: &SecretFinding) -> Result<bool, BaselineError>;

    /// Add entry to baseline
    fn add_entry(&mut self, entry: BaselineEntry) -> Result<(), BaselineError>;
}

/// File-based baseline repository with caching
pub struct FileBaselineRepository {
    file_path: std::path::PathBuf,
    /// Cached baseline to avoid repeated file I/O
    baseline: Arc<RwLock<Option<Baseline>>>,
    /// File modification time when baseline was last loaded (for cache invalidation)
    last_modified: Arc<RwLock<Option<std::time::SystemTime>>>,
}

impl FileBaselineRepository {
    pub fn new(file_path: impl AsRef<Path>) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
            baseline: Arc::new(RwLock::new(None)),
            last_modified: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if cached baseline is still valid
    fn is_cache_valid(&self) -> bool {
        if !self.file_path.exists() {
            return false;
        }

        let metadata = match std::fs::metadata(&self.file_path) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(_) => return false,
        };

        let last_modified = self.last_modified.read().unwrap();
        match *last_modified {
            Some(last) => modified == last,
            None => false,
        }
    }

    /// Load baseline with caching
    fn load_cached(&self) -> Result<Baseline, BaselineError> {
        // Check if cache is valid
        if self.is_cache_valid() {
            let baseline = self.baseline.read().unwrap();
            if let Some(ref cached) = *baseline {
                debug!("Using cached baseline");
                return Ok(cached.clone());
            }
        }

        // Load from file
        let baseline = if !self.file_path.exists() {
            debug!(
                path = %self.file_path.display(),
                "Baseline file does not exist, returning empty baseline"
            );
            Baseline::default()
        } else {
            let content = std::fs::read_to_string(&self.file_path)?;
            let baseline: Baseline = serde_json::from_str(&content)
                .map_err(|e| BaselineError::ParseError(e.to_string()))?;

            info!(
                path = %self.file_path.display(),
                entry_count = baseline.entries.len(),
                "Loaded baseline from file"
            );

            baseline
        };

        // Update cache
        {
            let mut cached = self.baseline.write().unwrap();
            *cached = Some(baseline.clone());
        }

        // Update modification time
        if self.file_path.exists() {
            if let Ok(metadata) = std::fs::metadata(&self.file_path) {
                if let Ok(modified) = metadata.modified() {
                    let mut last_mod = self.last_modified.write().unwrap();
                    *last_mod = Some(modified);
                }
            }
        }

        Ok(baseline)
    }

    /// Normalize path separators for stable cross-platform fingerprints
    fn normalize_path(path: &str) -> String {
        path.replace('\\', "/")
    }

    fn token_shape(secret: &str) -> String {
        if secret.is_empty() {
            return "empty".to_string();
        }

        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_symbol = false;

        for ch in secret.chars() {
            if ch.is_ascii_lowercase() {
                has_lower = true;
            } else if ch.is_ascii_uppercase() {
                has_upper = true;
            } else if ch.is_ascii_digit() {
                has_digit = true;
            } else {
                has_symbol = true;
            }
        }

        format!(
            "len:{}|l:{}|u:{}|d:{}|s:{}",
            secret.len(),
            has_lower,
            has_upper,
            has_digit,
            has_symbol
        )
    }

    /// Create a stable fingerprint for a finding (v2)
    pub fn finding_fingerprint(finding: &SecretFinding) -> String {
        use sha2::{Digest, Sha256};

        let normalized_path = Self::normalize_path(&finding.location.file_path);
        let detector_id = if finding.detector_id.is_empty() {
            finding.rule_id.as_str()
        } else {
            finding.detector_id.as_str()
        };
        let token_shape = Self::token_shape(&finding.matched_secret);
        let context = finding.evidence.join("|");

        let canonical = format!(
            "v2|detector:{}|rule:{}|path:{}|line:{}|col:{:?}|end_line:{:?}|end_col:{:?}|stype:{:?}|shape:{}|ctx:{}",
            detector_id,
            finding.rule_id,
            normalized_path,
            finding.location.line,
            finding.location.column,
            finding.location.end_line,
            finding.location.end_column,
            finding.secret_type,
            token_shape,
            context
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl BaselineRepository for FileBaselineRepository {
    fn load(&self) -> Result<Baseline, BaselineError> {
        self.load_cached()
    }

    fn save(&self, baseline: &Baseline) -> Result<(), BaselineError> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(baseline)
            .map_err(|e| BaselineError::SerializeError(e.to_string()))?;

        std::fs::write(&self.file_path, content)?;

        // Update cache after saving
        {
            let mut cached = self.baseline.write().unwrap();
            *cached = Some(baseline.clone());
        }

        // Update modification time
        if let Ok(metadata) = std::fs::metadata(&self.file_path) {
            if let Ok(modified) = metadata.modified() {
                let mut last_mod = self.last_modified.write().unwrap();
                *last_mod = Some(modified);
            }
        }

        info!(
            path = %self.file_path.display(),
            entry_count = baseline.entries.len(),
            "Saved baseline"
        );

        Ok(())
    }

    fn contains(&self, finding: &SecretFinding) -> Result<bool, BaselineError> {
        // Use cached baseline to avoid file I/O
        let baseline = self.load_cached()?;
        let fingerprint = Self::finding_fingerprint(finding);

        // Check if finding exists in baseline
        let exists = baseline
            .entries
            .iter()
            .any(|entry| entry.fingerprint == fingerprint);

        Ok(exists)
    }

    fn add_entry(&mut self, entry: BaselineEntry) -> Result<(), BaselineError> {
        let mut baseline = self.load_cached()?;
        baseline.entries.push(entry);
        self.save(&baseline)?;
        Ok(())
    }
}

impl FileBaselineRepository {
    /// Add multiple entries to baseline (more efficient than calling add_entry multiple times)
    pub fn add_entries(&self, entries: Vec<BaselineEntry>) -> Result<(), BaselineError> {
        let mut baseline = self.load_cached()?;
        baseline.entries.extend(entries);
        self.save(&baseline)?;
        Ok(())
    }

    /// Convert a SecretFinding to a BaselineEntry
    pub fn finding_to_entry(
        finding: &SecretFinding,
        is_secret: bool,
        is_verified: bool,
    ) -> BaselineEntry {
        BaselineEntry {
            fingerprint: Self::finding_fingerprint(finding),
            file_path: finding.location.file_path.clone(),
            line: finding.location.line,
            rule_id: finding.rule_id.clone(),
            is_secret,
            is_verified,
            suppression_reason: Some("baseline_suppression".to_string()),
            suppressed_at: Utc::now(),
            detector_id: Some(finding.detector_id.clone()),
        }
    }
}

/// Error type for baseline operations
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Serialize error: {0}")]
    SerializeError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::{
        Location, SecretFinding, SecretType, SecretVerificationState, Severity,
    };
    use crate::domain::value_objects::Confidence;

    fn sample_finding() -> SecretFinding {
        SecretFinding {
            id: "f-1".to_string(),
            rule_id: "github-token".to_string(),
            detector_id: "github-token".to_string(),
            secret_type: SecretType::GitHubToken,
            location: Location {
                file_path: "src/main.rs".to_string(),
                line: 42,
                column: Some(5),
                end_line: Some(42),
                end_column: Some(48),
            },
            severity: Severity::High,
            confidence: Confidence::High,
            verification_state: SecretVerificationState::Verified,
            description: "GitHub token detected".to_string(),
            recommendation: Some("Rotate token".to_string()),
            matched_secret: "ghp_123456789012345678901234567890123456".to_string(),
            entropy: None,
            evidence: vec!["detection:regex".to_string()],
        }
    }

    #[test]
    fn baseline_contains_v2_fingerprint_entry() {
        let temp = tempfile::tempdir().unwrap();
        let baseline_path = temp.path().join("baseline.json");
        let repo = FileBaselineRepository::new(&baseline_path);
        let finding = sample_finding();

        let entry = FileBaselineRepository::finding_to_entry(&finding, true, true);
        repo.add_entries(vec![entry]).unwrap();

        assert!(repo.contains(&finding).unwrap());
    }

    #[test]
    fn baseline_does_not_match_non_fingerprint_entry() {
        let temp = tempfile::tempdir().unwrap();
        let baseline_path = temp.path().join("baseline.json");
        let repo = FileBaselineRepository::new(&baseline_path);
        let finding = sample_finding();

        let baseline = Baseline {
            version: "2.0".to_string(),
            entries: vec![BaselineEntry {
                fingerprint: String::new(),
                file_path: finding.location.file_path.clone(),
                line: finding.location.line,
                rule_id: finding.rule_id.clone(),
                is_secret: true,
                is_verified: true,
                suppression_reason: None,
                suppressed_at: Utc::now(),
                detector_id: None,
            }],
        };

        repo.save(&baseline).unwrap();
        assert!(!repo.contains(&finding).unwrap());
    }
}
