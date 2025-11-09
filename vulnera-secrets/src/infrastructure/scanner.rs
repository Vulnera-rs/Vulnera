//! File scanner for secret detection

use std::path::{Path, PathBuf};
use tracing::{debug, instrument, trace, warn};

/// File to scan
#[derive(Debug, Clone)]
pub struct ScanFile {
    pub path: PathBuf,
    pub size: u64,
}

/// Directory scanner for finding files to scan
pub struct DirectoryScanner {
    max_depth: usize,
    exclude_patterns: Vec<String>,
    max_file_size: u64,
}

impl DirectoryScanner {
    pub fn new(max_depth: usize, max_file_size: u64) -> Self {
        Self {
            max_depth,
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "__pycache__".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
                ".pytest_cache".to_string(),
                "dist".to_string(),
                "build".to_string(),
            ],
            max_file_size,
        }
    }

    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Scan directory for files
    #[instrument(skip(self), fields(root = %root.display(), max_depth = self.max_depth))]
    pub fn scan(&self, root: &Path) -> Result<Vec<ScanFile>, std::io::Error> {
        let mut files = Vec::new();
        let mut excluded_count = 0;
        let mut skipped_size_count = 0;

        for entry in walkdir::WalkDir::new(root).max_depth(self.max_depth) {
            let entry = entry?;
            let path = entry.path();

            // Skip excluded directories
            if entry.file_type().is_dir() {
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.exclude_patterns.iter().any(|p| {
                        dir_name.contains(p)
                            || p.contains('*') && dir_name.matches(&p.replace('*', "")).count() > 0
                    }) {
                        trace!(directory = %dir_name, "Excluding directory");
                        excluded_count += 1;
                        continue;
                    }
                }
            }

            if entry.file_type().is_file() {
                // Check file size
                let metadata = entry.metadata()?;
                let file_size = metadata.len();

                if file_size > self.max_file_size {
                    trace!(
                        file = %path.display(),
                        size = file_size,
                        "Skipping file - exceeds size limit"
                    );
                    skipped_size_count += 1;
                    continue;
                }

                // Check if file is text-based (basic check)
                if Self::is_likely_text_file(path) {
                    trace!(file = %path.display(), "Found scannable file");
                    files.push(ScanFile {
                        path: path.to_path_buf(),
                        size: file_size,
                    });
                } else {
                    trace!(file = %path.display(), "Skipping binary file");
                }
            }
        }

        debug!(
            file_count = files.len(),
            excluded_dirs = excluded_count,
            skipped_size = skipped_size_count,
            "Directory scan completed"
        );
        Ok(files)
    }

    /// Check if a file is likely a text file
    fn is_likely_text_file(path: &Path) -> bool {
        // Check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            // Common binary extensions to exclude
            let binary_extensions = [
                "exe", "dll", "so", "dylib", "bin", "o", "obj", "a", "lib", "jar", "war", "ear",
                "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "pdf", "doc", "docx", "xls", "xlsx",
                "ppt", "pptx", "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "mp3",
                "mp4", "avi", "mov", "wmv", "flv", "mkv", "woff", "woff2", "ttf", "otf", "eot",
            ];
            if binary_extensions.contains(&ext_lower.as_str()) {
                return false;
            }
        }

        // Check filename patterns
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            let filename_lower = filename.to_lowercase();
            // Exclude common binary/lock files
            if filename_lower.ends_with(".min.js")
                || filename_lower.ends_with(".min.css")
                || filename_lower.ends_with(".lock")
                || filename_lower.ends_with(".pack")
            {
                return false;
            }
        }

        true
    }
}


