//! Manifest Cache - SHA-256 hash caching for dependency manifests
//!
//! This module caches dependency manifest hashes to avoid redundant server
//! requests when the manifest hasn't changed since the last scan.
//!
//! ## How it works
//!
//! 1. Before sending a manifest to the server, we compute its SHA-256 hash
//! 2. If the hash matches the cached hash, we return the cached result
//! 3. If the hash differs (or no cache), we proceed with the server call
//! 4. After a successful server call, we cache the result
//!
//! ## Cache location
//!
//! Cache files are stored in `~/.vulnera/cache/manifests/`

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default cache directory name
const CACHE_DIR_NAME: &str = "manifests";

/// Manages caching of dependency manifest analysis results
pub struct ManifestCache {
    cache_dir: PathBuf,
}

/// Cached manifest entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedManifestEntry {
    /// SHA-256 hash of the manifest content
    pub content_hash: String,
    /// Timestamp when the cache was created
    pub cached_at: i64,
    /// Cached analysis result
    pub result: CachedDepsResult,
}

/// Cached dependency analysis result (serializable subset of DependencyAnalysisResponse)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDepsResult {
    pub total_dependencies: usize,
    pub vulnerable_dependencies: usize,
    pub vulnerabilities: Vec<CachedVulnerability>,
}

/// Cached vulnerability info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVulnerability {
    pub id: String,
    pub severity: String,
    pub package_name: String,
    pub package_version: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub fixed_version: Option<String>,
}

impl ManifestCache {
    /// Create a new manifest cache
    pub fn new() -> Result<Self> {
        let cache_dir = Self::get_cache_dir()?;
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

        Ok(Self { cache_dir })
    }

    /// Get the cache directory path
    fn get_cache_dir() -> Result<PathBuf> {
        let data_dir = dirs::data_dir()
            .or_else(dirs::home_dir)
            .context("Could not determine data directory")?;

        Ok(data_dir.join(".vulnera").join("cache").join(CACHE_DIR_NAME))
    }

    /// Compute SHA-256 hash of content
    pub fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Generate cache file path for a manifest file
    fn cache_file_path(&self, manifest_path: &Path) -> PathBuf {
        // Hash the manifest path to create a unique filename
        let path_hash = Self::compute_hash(&manifest_path.to_string_lossy());
        self.cache_dir.join(format!("{}.json", &path_hash[..16]))
    }

    /// Check if manifest content is unchanged and return cached result if available
    pub fn get_if_unchanged(
        &self,
        manifest_path: &Path,
        current_content: &str,
    ) -> Result<Option<CachedManifestEntry>> {
        let cache_file = self.cache_file_path(manifest_path);

        if !cache_file.exists() {
            return Ok(None);
        }

        let cached_data = match fs::read_to_string(&cache_file) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("Failed to read cache file"),
        };

        let entry: CachedManifestEntry = match serde_json::from_str(&cached_data) {
            Ok(e) => e,
            Err(_) => {
                // Invalid cache, remove it
                let _ = fs::remove_file(&cache_file);
                return Ok(None);
            }
        };

        let current_hash = Self::compute_hash(current_content);

        if entry.content_hash == current_hash {
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Check if manifest is unchanged (simpler version, just returns bool)
    pub fn is_unchanged(&self, manifest_path: &Path, current_content: &str) -> bool {
        self.get_if_unchanged(manifest_path, current_content)
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    /// Clear all cached manifests
    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                if entry.path().extension().map_or(false, |e| e == "json") {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> Result<CacheStats> {
        let mut count = 0;
        let mut total_size = 0u64;

        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                if entry.path().extension().map_or(false, |e| e == "json") {
                    count += 1;
                    total_size += entry.metadata()?.len();
                }
            }
        }

        Ok(CacheStats { count, total_size })
    }

    /// Store analysis result from DepsResult (used by deps.rs command)
    pub fn store_from_deps_result(
        &self,
        manifest_path: &Path,
        content: &str,
        result: &crate::commands::deps::DepsResult,
    ) -> Result<()> {
        let cache_file = self.cache_file_path(manifest_path);

        // Convert DepsResult vulnerabilities to cached format
        let vulnerabilities: Vec<CachedVulnerability> = result
            .vulnerabilities
            .iter()
            .map(|v| CachedVulnerability {
                id: v.id.clone(),
                severity: v.severity.clone(),
                package_name: v.package.clone(),
                package_version: v.version.clone(),
                title: Some(v.description.clone()),
                description: Some(v.description.clone()),
                fixed_version: v.fixed_version.clone(),
            })
            .collect();

        let entry = CachedManifestEntry {
            content_hash: Self::compute_hash(content),
            cached_at: chrono::Utc::now().timestamp(),
            result: CachedDepsResult {
                total_dependencies: result.summary.total_dependencies,
                vulnerable_dependencies: result.summary.vulnerable_dependencies,
                vulnerabilities,
            },
        };

        let json = serde_json::to_string_pretty(&entry)?;
        fs::write(&cache_file, json).context("Failed to write cache file")?;

        Ok(())
    }
}

/// Cache statistics
#[derive(Debug)]
pub struct CacheStats {
    pub count: usize,
    pub total_size: u64,
}

impl Default for ManifestCache {
    fn default() -> Self {
        Self::new().expect("Failed to create manifest cache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cache() -> (ManifestCache, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let cache = ManifestCache {
            cache_dir: temp_dir.path().to_path_buf(),
        };
        (cache, temp_dir)
    }

    #[test]
    fn test_compute_hash() {
        let hash1 = ManifestCache::compute_hash("test content");
        let hash2 = ManifestCache::compute_hash("test content");
        let hash3 = ManifestCache::compute_hash("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_is_unchanged_no_cache() {
        let (cache, _temp) = test_cache();
        let manifest_path = Path::new("/fake/package.json");

        assert!(!cache.is_unchanged(manifest_path, "{}"));
    }

    #[test]
    fn test_cache_file_path_consistency() {
        let (cache, _temp) = test_cache();
        let manifest_path = Path::new("/project/package.json");

        let path1 = cache.cache_file_path(manifest_path);
        let path2 = cache.cache_file_path(manifest_path);

        assert_eq!(path1, path2);
    }

    #[test]
    fn test_clear_cache() {
        let (cache, _temp) = test_cache();

        // Create some fake cache files
        fs::write(cache.cache_dir.join("test1.json"), "{}").unwrap();
        fs::write(cache.cache_dir.join("test2.json"), "{}").unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.count, 2);

        cache.clear().unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.count, 0);
    }
}
