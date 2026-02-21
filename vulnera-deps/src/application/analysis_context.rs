//! Analysis context for project-wide dependency analysis
//!
//! This module provides context management for analyzing dependencies across
//! entire projects, including workspace detection and configuration management.

use globset::{Glob, GlobSetBuilder};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use vulnera_core::domain::vulnerability::value_objects::Ecosystem;

/// Configuration for dependency analysis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisConfig {
    /// Patterns to ignore (e.g., ["node_modules/**", "target/**"])
    pub ignore_patterns: Vec<String>,
    /// Severity filters (only report vulnerabilities of these severities)
    pub severity_filters: Option<HashSet<String>>,
    /// Maximum depth for dependency resolution
    pub max_depth: Option<usize>,
    /// Whether to include dev dependencies
    pub include_dev: bool,
    /// Whether to include optional dependencies
    pub include_optional: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            ignore_patterns: vec![
                "node_modules/**".to_string(),
                "target/**".to_string(),
                ".git/**".to_string(),
                "vendor/**".to_string(),
            ],
            severity_filters: None,
            max_depth: None,
            include_dev: true,
            include_optional: true,
        }
    }
}

/// Workspace information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceInfo {
    /// Root directory of the workspace
    pub root: PathBuf,
    /// Detected ecosystems in the workspace
    pub ecosystems: HashSet<Ecosystem>,
    /// Dependency files found
    pub dependency_files: Vec<PathBuf>,
    /// Whether this is a monorepo
    pub is_monorepo: bool,
}

/// Analysis context for a project
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Project root directory
    pub project_root: PathBuf,
    /// Workspace information
    pub workspace: Option<WorkspaceInfo>,
    /// Analysis configuration
    pub config: AnalysisConfig,
    /// Cached analysis results (file path -> last analysis time)
    pub cache: HashMap<PathBuf, std::time::SystemTime>,
}

impl AnalysisContext {
    /// Create a new analysis context
    pub fn new(project_root: impl AsRef<Path>) -> Self {
        Self {
            project_root: project_root.as_ref().to_path_buf(),
            workspace: None,
            config: AnalysisConfig::default(),
            cache: HashMap::new(),
        }
    }

    /// Create a new analysis context with configuration
    pub fn with_config(project_root: impl AsRef<Path>, config: AnalysisConfig) -> Self {
        Self {
            project_root: project_root.as_ref().to_path_buf(),
            workspace: None,
            config,
            cache: HashMap::new(),
        }
    }

    /// Check if a path should be ignored based on ignore patterns
    pub fn should_ignore(&self, path: &Path) -> bool {
        let normalized = normalize_path(path);
        let suffix = normalized
            .split_once('/')
            .map(|(_, rest)| rest)
            .unwrap_or(normalized.as_str());

        for pattern in &self.config.ignore_patterns {
            if self.matches_pattern(&normalized, suffix, pattern) {
                return true;
            }
        }
        false
    }

    fn matches_pattern(&self, path: &str, suffix: &str, pattern: &str) -> bool {
        let mut builder = GlobSetBuilder::new();
        let normalized_pattern = pattern.replace('\\', "/");

        let glob = match Glob::new(&normalized_pattern) {
            Ok(glob) => glob,
            Err(_) => return false,
        };

        builder.add(glob);

        let prefixed_pattern = format!("**/{normalized_pattern}");
        if let Ok(prefixed_glob) = Glob::new(&prefixed_pattern) {
            builder.add(prefixed_glob);
        }

        let set = match builder.build() {
            Ok(set) => set,
            Err(_) => return false,
        };

        set.is_match(path) || set.is_match(suffix)
    }

    /// Update cache entry for a file
    pub fn update_cache(&mut self, file_path: &Path) {
        self.cache
            .insert(file_path.to_path_buf(), std::time::SystemTime::now());
    }

    /// Check if a file needs re-analysis (not in cache or modified)
    pub fn needs_analysis(&self, file_path: &Path) -> bool {
        // Check if file is in cache
        if let Some(cached_time) = self.cache.get(file_path) {
            // Check if file has been modified since last analysis
            if let Ok(metadata) = std::fs::metadata(file_path)
                && let Ok(modified) = metadata.modified()
            {
                // File needs re-analysis if it was modified after cache time
                return modified > *cached_time;
            }
            // If we can't get modification time, assume it needs analysis
            return true;
        }
        // Not in cache, needs analysis
        true
    }
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| {
            let value = component.as_os_str().to_string_lossy();
            if value == "/" || value == "." {
                None
            } else {
                Some(value.to_string())
            }
        })
        .collect::<Vec<String>>()
        .join("/")
}

/// Detect workspace information from a directory
pub fn detect_workspace(root: impl AsRef<Path>) -> Option<WorkspaceInfo> {
    let root = root.as_ref();
    let mut ecosystems = HashSet::new();
    let mut dependency_files = Vec::new();

    // Common workspace indicators
    let workspace_files = vec![
        ("package.json", Ecosystem::Npm),
        ("Cargo.toml", Ecosystem::Cargo),
        ("go.mod", Ecosystem::Go),
        ("pyproject.toml", Ecosystem::PyPI),
        ("composer.json", Ecosystem::Packagist),
        ("pom.xml", Ecosystem::Maven),
    ];

    for (filename, ecosystem) in workspace_files {
        let file_path = root.join(filename);
        if file_path.exists() {
            ecosystems.insert(ecosystem);
            dependency_files.push(file_path);
        }
    }

    if ecosystems.is_empty() {
        return None;
    }

    // Check if this is a monorepo (has multiple package directories)
    let is_monorepo = ecosystems.len() > 1
        || root.join("packages").exists()
        || root.join("workspaces").exists()
        || root.join("apps").exists();

    Some(WorkspaceInfo {
        root: root.to_path_buf(),
        ecosystems,
        dependency_files,
        is_monorepo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_context_new() {
        let ctx = AnalysisContext::new("/tmp/test");
        assert_eq!(ctx.project_root, PathBuf::from("/tmp/test"));
        assert!(ctx.workspace.is_none());
    }

    #[test]
    fn test_should_ignore() {
        let ctx = AnalysisContext::new("/tmp/test");
        assert!(ctx.should_ignore(Path::new("/tmp/test/node_modules/express")));
        assert!(!ctx.should_ignore(Path::new("/tmp/test/src/main.rs")));
    }

    #[test]
    fn test_should_ignore_glob_patterns() {
        let config = AnalysisConfig {
            ignore_patterns: vec!["**/*.lock".to_string(), "src/generated/**".to_string()],
            ..AnalysisConfig::default()
        };
        let ctx = AnalysisContext::with_config("/tmp/test", config);

        assert!(ctx.should_ignore(Path::new("/tmp/test/Cargo.lock")));
        assert!(ctx.should_ignore(Path::new("/tmp/test/src/generated/types.rs")));
        assert!(!ctx.should_ignore(Path::new("/tmp/test/src/domain/mod.rs")));
    }

    #[test]
    fn test_update_cache() {
        let mut ctx = AnalysisContext::new("/tmp/test");
        let file_path = Path::new("/tmp/test/package.json");
        ctx.update_cache(file_path);
        assert!(ctx.cache.contains_key(file_path));
    }
}
