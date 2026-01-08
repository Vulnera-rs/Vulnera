//! File Cache - Incremental file hashing for SAST and Secrets scanning
//!
//! This module caches file hashes to enable incremental scanning.
//! Only files that have changed since the last scan are re-analyzed.
//!
//! ## Cache location
//!
//! Cache is stored in `.vulnera_cache/` in the project directory.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cache directory name (hidden folder in project root)
const CACHE_DIR_NAME: &str = ".vulnera_cache";
/// Cache filename for file hashes
const CACHE_FILE_NAME: &str = "file_hashes.json";

/// Manages file hash caching for incremental scanning
pub struct FileCache {
    cache_dir: PathBuf,
    entries: HashMap<PathBuf, FileHashEntry>,
    modified: bool,
}

/// Cached entry for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashEntry {
    /// SHA-256 hash of the file content
    pub content_hash: String,
    /// Last modification time (Unix timestamp)
    pub last_modified: u64,
    /// Size of the file in bytes
    pub size: u64,
    /// Cached findings for this file
    #[serde(default)]
    pub findings: Vec<CachedFinding>,
}

/// Cached finding from a previous scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFinding {
    pub id: String,
    pub rule_id: Option<String>,
    pub severity: String,
    pub description: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub module: String,
}

/// Statistics about cache usage
#[derive(Debug, Default)]
pub struct CacheStats {
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub files_unchanged: usize,
    pub files_changed: usize,
    pub files_new: usize,
}

impl FileCache {
    /// Create a new file cache for a project directory
    pub fn new(project_path: &Path) -> Result<Self> {
        let cache_dir = project_path.join(CACHE_DIR_NAME);
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

        let mut cache = Self {
            cache_dir,
            entries: HashMap::new(),
            modified: false,
        };

        cache.load()?;
        Ok(cache)
    }

    /// Load cache from disk
    fn load(&mut self) -> Result<()> {
        let cache_file = self.cache_dir.join(CACHE_FILE_NAME);

        if !cache_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&cache_file).context("Failed to read cache file")?;

        self.entries = match serde_json::from_str(&content) {
            Ok(entries) => entries,
            Err(_) => {
                // Invalid cache, start fresh
                HashMap::new()
            }
        };

        Ok(())
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<()> {
        if !self.modified {
            return Ok(());
        }

        let cache_file = self.cache_dir.join(CACHE_FILE_NAME);
        let json = serde_json::to_string_pretty(&self.entries)?;
        fs::write(&cache_file, json).context("Failed to write cache file")?;

        Ok(())
    }

    /// Compute SHA-256 hash of file content
    pub fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Check if a file has changed and needs re-scanning
    pub fn is_changed(&self, file_path: &Path) -> bool {
        let entry = match self.entries.get(file_path) {
            Some(e) => e,
            None => return true, // New file
        };

        // Quick check: file metadata
        let metadata = match fs::metadata(file_path) {
            Ok(m) => m,
            Err(_) => return true, // Can't read, consider changed
        };

        let size = metadata.len();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // If size or modification time differs, likely changed
        if size != entry.size || modified != entry.last_modified {
            // Verify with content hash
            let content = match fs::read(file_path) {
                Ok(c) => c,
                Err(_) => return true,
            };
            let current_hash = Self::compute_hash(&content);
            return current_hash != entry.content_hash;
        }

        false
    }

    /// Filter files to only those that have changed
    pub fn get_changed_files(&self, files: &[PathBuf]) -> (Vec<PathBuf>, CacheStats) {
        let mut changed = Vec::new();
        let mut stats = CacheStats::default();

        for file in files {
            if self.entries.contains_key(file) {
                if self.is_changed(file) {
                    changed.push(file.clone());
                    stats.files_changed += 1;
                    stats.cache_misses += 1;
                } else {
                    stats.files_unchanged += 1;
                    stats.cache_hits += 1;
                }
            } else {
                changed.push(file.clone());
                stats.files_new += 1;
                stats.cache_misses += 1;
            }
        }

        (changed, stats)
    }

    /// Update cache entry for a file with new findings
    pub fn update_file(&mut self, file_path: &Path, findings: Vec<CachedFinding>) -> Result<()> {
        let metadata = fs::metadata(file_path)?;
        let content = fs::read(file_path)?;

        let entry = FileHashEntry {
            content_hash: Self::compute_hash(&content),
            last_modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            size: metadata.len(),
            findings,
        };

        self.entries.insert(file_path.to_path_buf(), entry);
        self.modified = true;

        Ok(())
    }

    /// Get cached findings for a file (if unchanged)
    pub fn get_cached_findings(&self, file_path: &Path) -> Option<Vec<CachedFinding>> {
        if self.is_changed(file_path) {
            return None;
        }
        self.entries.get(file_path).map(|e| e.findings.clone())
    }

    /// Get all cached findings for unchanged files
    pub fn get_all_cached_findings(&self, files: &[PathBuf]) -> Vec<(PathBuf, Vec<CachedFinding>)> {
        files
            .iter()
            .filter_map(|f| {
                if !self.is_changed(f) {
                    self.entries.get(f).map(|e| (f.clone(), e.findings.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Clear all cache entries
    pub fn clear(&mut self) -> Result<()> {
        self.entries.clear();
        self.modified = true;

        let cache_file = self.cache_dir.join(CACHE_FILE_NAME);
        if cache_file.exists() {
            fs::remove_file(&cache_file)?;
        }

        Ok(())
    }

    /// Get number of cached entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Drop for FileCache {
    fn drop(&mut self) {
        // Auto-save on drop
        let _ = self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_cache() -> (FileCache, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let cache = FileCache::new(temp_dir.path()).unwrap();
        (cache, temp_dir)
    }

    #[test]
    fn test_compute_hash() {
        let hash1 = FileCache::compute_hash(b"test content");
        let hash2 = FileCache::compute_hash(b"test content");
        let hash3 = FileCache::compute_hash(b"different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_new_file_is_changed() {
        let (cache, _temp) = create_test_cache();
        let fake_path = PathBuf::from("/nonexistent/file.rs");

        assert!(cache.is_changed(&fake_path));
    }

    #[test]
    fn test_update_and_check() {
        let (mut cache, temp) = create_test_cache();

        // Create a test file
        let test_file = temp.path().join("test.rs");
        fs::write(&test_file, "fn main() {}").unwrap();

        // Initially the file is "changed" (not in cache)
        assert!(cache.is_changed(&test_file));

        // Update cache
        cache.update_file(&test_file, Vec::new()).unwrap();

        // Now it should not be changed
        assert!(!cache.is_changed(&test_file));
    }

    #[test]
    fn test_file_modification_detected() {
        let (mut cache, temp) = create_test_cache();

        let test_file = temp.path().join("test.rs");
        fs::write(&test_file, "fn main() {}").unwrap();

        cache.update_file(&test_file, Vec::new()).unwrap();
        assert!(!cache.is_changed(&test_file));

        // Modify the file
        fs::write(&test_file, "fn main() { println!(\"hello\"); }").unwrap();

        // Should now be detected as changed
        assert!(cache.is_changed(&test_file));
    }

    #[test]
    fn test_get_changed_files() {
        let (mut cache, temp) = create_test_cache();

        let file1 = temp.path().join("file1.rs");
        let file2 = temp.path().join("file2.rs");
        let file3 = temp.path().join("file3.rs");

        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();
        fs::write(&file3, "content3").unwrap();

        // Cache file1 and file2
        cache.update_file(&file1, Vec::new()).unwrap();
        cache.update_file(&file2, Vec::new()).unwrap();

        let files = vec![file1.clone(), file2.clone(), file3.clone()];
        let (changed, stats) = cache.get_changed_files(&files);

        // Only file3 should be in changed (new file)
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0], file3);
        assert_eq!(stats.files_unchanged, 2);
        assert_eq!(stats.files_new, 1);
    }

    #[test]
    fn test_cached_findings() {
        let (mut cache, temp) = create_test_cache();

        let test_file = temp.path().join("test.rs");
        fs::write(&test_file, "fn main() {}").unwrap();

        let findings = vec![CachedFinding {
            id: "test-1".to_string(),
            rule_id: Some("test-rule".to_string()),
            severity: "high".to_string(),
            description: "Test finding".to_string(),
            line: Some(1),
            column: None,
            module: "sast".to_string(),
        }];

        cache.update_file(&test_file, findings.clone()).unwrap();

        let cached = cache.get_cached_findings(&test_file);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);
    }
}
