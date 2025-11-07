//! Directory scanner for SAST analysis

use std::path::{Path, PathBuf};
use tracing::{debug, instrument, trace};
use walkdir::WalkDir;

use crate::domain::value_objects::Language;

/// File to scan
#[derive(Debug, Clone)]
pub struct ScanFile {
    pub path: PathBuf,
    pub language: Language,
}

/// Directory scanner for finding source files
pub struct DirectoryScanner {
    max_depth: usize,
    exclude_patterns: Vec<String>,
}

impl DirectoryScanner {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
            ],
        }
    }

    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Scan directory for source files
    #[instrument(skip(self), fields(root = %root.display(), max_depth = self.max_depth))]
    pub fn scan(&self, root: &Path) -> Result<Vec<ScanFile>, std::io::Error> {
        let mut files = Vec::new();
        let mut excluded_count = 0;

        for entry in WalkDir::new(root).max_depth(self.max_depth) {
            let entry = entry?;
            let path = entry.path();

            // Skip excluded directories
            if entry.file_type().is_dir() {
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.exclude_patterns.iter().any(|p| dir_name.contains(p)) {
                        trace!(directory = %dir_name, "Excluding directory");
                        excluded_count += 1;
                        continue;
                    }
                }
            }

            if entry.file_type().is_file() {
                if let Some(language) = Language::from_filename(path.to_string_lossy().as_ref()) {
                    trace!(file = %path.display(), language = ?language, "Found scannable file");
                    files.push(ScanFile {
                        path: path.to_path_buf(),
                        language,
                    });
                }
            }
        }

        debug!(
            file_count = files.len(),
            excluded_dirs = excluded_count,
            "Directory scan completed"
        );
        Ok(files)
    }
}

