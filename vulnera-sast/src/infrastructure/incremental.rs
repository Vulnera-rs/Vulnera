//! Incremental Analysis Support
//!
//! Tracks file content hashes to enable incremental analysis.
//! Files with unchanged content can be skipped to improve scan performance.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, info};

/// Tracks file changes for incremental analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncrementalTracker {
    /// Previous scan state: file_path -> content_hash
    previous_state: HashMap<String, FileState>,
    /// Current state being built
    #[serde(skip)]
    current_state: HashMap<String, FileState>,
    /// Cross-file dependencies: file_path -> set of files it depends on.
    /// If any dependency changes, the dependent file needs re-analysis.
    #[serde(default)]
    file_dependencies: HashMap<String, HashSet<String>>,
    /// Metadata about the last scan
    #[serde(default)]
    pub metadata: ScanMetadata,
}

/// State of a single file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileState {
    /// SHA-256 hash of file content
    pub content_hash: String,
    /// File size in bytes
    pub size: u64,
    /// Number of findings in this file (from last scan)
    #[serde(default)]
    pub finding_count: usize,
}

/// Metadata about the scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanMetadata {
    /// Timestamp of last scan
    #[serde(default)]
    pub last_scan_timestamp: Option<u64>,
    /// Total files scanned
    #[serde(default)]
    pub total_files: usize,
    /// Files skipped (unchanged)
    #[serde(default)]
    pub files_skipped: usize,
    /// SAST version used
    #[serde(default)]
    pub sast_version: Option<String>,
}

impl IncrementalTracker {
    /// Create a new empty tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Load previous state from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let path = path.as_ref();
        if !path.exists() {
            debug!(
                "No incremental state file found at {:?}, starting fresh",
                path
            );
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(path)?;
        let tracker: IncrementalTracker = serde_json::from_str(&content).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse incremental state: {}", e),
            )
        })?;

        info!(
            files = tracker.previous_state.len(),
            "Loaded incremental state from {:?}", path
        );

        Ok(tracker)
    }

    /// Save current state to a JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let path = path.as_ref();

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Build the saveable state (current becomes previous for next run)
        let saveable = IncrementalTracker {
            previous_state: self.current_state.clone(),
            current_state: HashMap::new(),
            file_dependencies: self.file_dependencies.clone(),
            metadata: self.metadata.clone(),
        };

        let content = serde_json::to_string_pretty(&saveable)?;
        std::fs::write(path, content)?;

        info!(
            files = self.current_state.len(),
            "Saved incremental state to {:?}", path
        );

        Ok(())
    }

    /// Compute SHA-256 hash of content
    pub fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Check if a file needs re-analysis based on content hash and dependencies
    pub fn needs_analysis(&self, file_path: &str, content: &str) -> (bool, String) {
        let content_hash = Self::hash_content(content);
        let size = content.len() as u64;

        let self_changed = match self.previous_state.get(file_path) {
            Some(prev_state) => prev_state.content_hash != content_hash || prev_state.size != size,
            None => true, // New file
        };

        if self_changed {
            return (true, content_hash);
        }

        // Check if any dependency has changed (content differs from previous state).
        // A dependency is "changed" if its current_state hash differs from previous_state hash,
        // or if it exists in current_state but not previous_state (new file).
        let dep_changed = self
            .file_dependencies
            .get(file_path)
            .map(|deps| {
                deps.iter().any(|dep| {
                    match (self.previous_state.get(dep), self.current_state.get(dep)) {
                        (Some(prev), Some(curr)) => prev.content_hash != curr.content_hash,
                        (None, Some(_)) => true,  // New dependency file
                        (Some(_), None) => false, // Not yet processed — can't tell, skip
                        (None, None) => false,
                    }
                })
            })
            .unwrap_or(false);

        if dep_changed {
            debug!(
                file = file_path,
                "File needs re-analysis: dependency changed"
            );
        }

        (dep_changed, content_hash)
    }

    /// Record a file that was analyzed
    pub fn record_file(
        &mut self,
        file_path: &str,
        content_hash: String,
        size: u64,
        finding_count: usize,
    ) {
        self.current_state.insert(
            file_path.to_string(),
            FileState {
                content_hash,
                size,
                finding_count,
            },
        );
    }

    /// Get previous finding count for a file (if available)
    pub fn get_previous_findings(&self, file_path: &str) -> Option<usize> {
        self.previous_state.get(file_path).map(|s| s.finding_count)
    }

    /// Set cross-file dependency map extracted from call graph edges.
    ///
    /// `deps` maps each file to the set of files it depends on (i.e., files
    /// containing functions it calls). When any dependency changes, the
    /// dependent file is re-analyzed even if its own content is unchanged.
    pub fn set_file_dependencies(&mut self, deps: HashMap<String, HashSet<String>>) {
        self.file_dependencies = deps;
    }

    /// Get statistics about the current analysis
    pub fn stats(&self) -> IncrementalStats {
        let total_previous = self.previous_state.len();
        let total_current = self.current_state.len();

        // Count how many files were skipped (in previous but hash matches)
        let skipped = self
            .previous_state
            .iter()
            .filter(|(path, _)| !self.current_state.contains_key(path.as_str()))
            .count();

        IncrementalStats {
            previous_files: total_previous,
            current_files: total_current,
            files_skipped: skipped,
            files_analyzed: total_current,
        }
    }

    /// Update metadata with scan completion info
    pub fn finalize(&mut self, total_files: usize, files_skipped: usize) {
        self.metadata.last_scan_timestamp = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        self.metadata.total_files = total_files;
        self.metadata.files_skipped = files_skipped;
        self.metadata.sast_version = Some(env!("CARGO_PKG_VERSION").to_string());
    }
}

/// Statistics about incremental analysis
#[derive(Debug, Clone)]
pub struct IncrementalStats {
    pub previous_files: usize,
    pub current_files: usize,
    pub files_skipped: usize,
    pub files_analyzed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash1 = IncrementalTracker::hash_content("hello");
        let hash2 = IncrementalTracker::hash_content("hello");
        let hash3 = IncrementalTracker::hash_content("world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_needs_analysis_new_file() {
        let tracker = IncrementalTracker::new();
        let (needs, _hash) = tracker.needs_analysis("new_file.py", "print('hello')");
        assert!(needs);
    }

    #[test]
    fn test_needs_analysis_unchanged_file() {
        let mut tracker = IncrementalTracker::new();
        let content = "print('hello')";
        let hash = IncrementalTracker::hash_content(content);

        // Simulate previous scan
        tracker.previous_state.insert(
            "test.py".to_string(),
            FileState {
                content_hash: hash,
                size: content.len() as u64,
                finding_count: 0,
            },
        );

        let (needs, _) = tracker.needs_analysis("test.py", content);
        assert!(!needs);
    }

    #[test]
    fn test_needs_analysis_changed_file() {
        let mut tracker = IncrementalTracker::new();
        let old_content = "print('hello')";
        let new_content = "print('world')";

        tracker.previous_state.insert(
            "test.py".to_string(),
            FileState {
                content_hash: IncrementalTracker::hash_content(old_content),
                size: old_content.len() as u64,
                finding_count: 1,
            },
        );

        let (needs, _) = tracker.needs_analysis("test.py", new_content);
        assert!(needs);
    }

    #[test]
    fn test_record_and_get_findings() {
        let mut tracker = IncrementalTracker::new();
        tracker.record_file("test.py", "hash123".to_string(), 100, 5);

        // Move current to previous (simulating save/load)
        tracker.previous_state = tracker.current_state.clone();

        assert_eq!(tracker.get_previous_findings("test.py"), Some(5));
        assert_eq!(tracker.get_previous_findings("unknown.py"), None);
    }
}
