//! File scanner for secret detection

use std::fs::File;
use std::io::Read;
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
    exclude_extensions: Vec<String>,
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
            exclude_extensions: vec![
                "md".to_string(),
                "markdown".to_string(),
                "rst".to_string(),
                "html".to_string(),
            ],
            max_file_size,
        }
    }

    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    pub fn with_exclude_extensions(mut self, extensions: Vec<String>) -> Self {
        self.exclude_extensions = extensions;
        self
    }

    /// Scan directory for files
    #[instrument(skip(self), fields(root = %root.display(), max_depth = self.max_depth))]
    pub fn scan(&self, root: &Path) -> Result<Vec<ScanFile>, std::io::Error> {
        let mut files = Vec::new();
        let mut skipped_size_count = 0;

        let walker = walkdir::WalkDir::new(root).max_depth(self.max_depth);

        // Use filter_entry to skip excluded directories efficiently
        let it = walker.into_iter().filter_entry(|e| {
            if e.file_type().is_dir()
                && let Some(dir_name) = e.file_name().to_str()
                && self.exclude_patterns.iter().any(|p| {
                    dir_name.contains(p)
                        || p.contains('*') && dir_name.matches(&p.replace('*', "")).count() > 0
                })
            {
                return false;
            }
            true
        });

        for entry in it {
            // Handle errors (e.g. permission denied) by skipping
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "Error accessing file entry");
                    continue;
                }
            };

            let path = entry.path();

            if entry.file_type().is_file() {
                // Check file size
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(file = %path.display(), error = %e, "Failed to get metadata");
                        continue;
                    }
                };

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
                if self.is_likely_text_file(path) {
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
            skipped_size = skipped_size_count,
            "Directory scan completed"
        );
        Ok(files)
    }

    /// Check if a file is likely a text file
    fn is_likely_text_file(&self, path: &Path) -> bool {
        // Check extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();

            // Exclude file extensions matched by configuration to avoid docs/non-target files
            if self
                .exclude_extensions
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&ext_lower))
            {
                return false;
            }

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

        // Final heuristic: check content for null bytes if it passed extension/name filters
        !self.is_binary_content(path)
    }

    /// Check if file content appears to be binary by looking for null bytes in the first 1024 bytes
    fn is_binary_content(&self, path: &Path) -> bool {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut buffer = [0u8; 1024];
        match file.read(&mut buffer) {
            Ok(n) if n > 0 => {
                // A common heuristic: if a file contains null bytes, it's likely binary
                buffer[..n].contains(&0)
            }
            _ => false,
        }
    }
}
