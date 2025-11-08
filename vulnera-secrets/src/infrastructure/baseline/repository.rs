//! Baseline repository for tracking known secrets

use crate::domain::entities::SecretFinding;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// Baseline entry for a secret finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Hash of the secret (for identification)
    pub secret_hash: String,
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
            version: "1.0".to_string(),
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


    /// Hash a secret for baseline tracking
    pub fn hash_secret(secret: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
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
        let secret_hash = Self::hash_secret(&finding.matched_secret);

        // Check if finding exists in baseline
        let exists = baseline.entries.iter().any(|entry| {
            entry.secret_hash == secret_hash
                && entry.file_path == finding.location.file_path
                && entry.line == finding.location.line
                && entry.rule_id == finding.rule_id
        });

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
    pub fn finding_to_entry(finding: &SecretFinding, is_secret: bool, is_verified: bool) -> BaselineEntry {
        BaselineEntry {
            secret_hash: Self::hash_secret(&finding.matched_secret),
            file_path: finding.location.file_path.clone(),
            line: finding.location.line,
            rule_id: finding.rule_id.clone(),
            is_secret,
            is_verified,
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

