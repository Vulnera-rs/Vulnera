//! File Watcher - Live security linting with file system watching
//!
//! This module provides file system watching with debouncing for
//! live security scanning during development.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let watcher = FileWatcher::new(&path, 500)?;
//! watcher.watch(|changed_files| async {
//!     // Re-run analysis on changed files
//! }).await?;
//! ```

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{DebouncedEvent, Debouncer, new_debouncer};

/// File watcher for live security scanning
pub struct FileWatcher {
    /// Directory being watched
    watch_path: PathBuf,
    /// Debounce time in milliseconds
    debounce_ms: u64,
}

/// Events received from the file watcher
#[derive(Debug)]
pub struct WatchEvent {
    /// Paths that changed
    pub paths: Vec<PathBuf>,
    /// Whether a rescan is needed
    pub needs_rescan: bool,
}

impl FileWatcher {
    /// Create a new file watcher for a directory
    pub fn new(watch_path: &Path, debounce_ms: u64) -> Result<Self> {
        Ok(Self {
            watch_path: watch_path.to_path_buf(),
            debounce_ms,
        })
    }

    /// Start watching and call handler on each change
    ///
    /// This function blocks and runs the watch loop until an error occurs
    /// or the watcher is stopped.
    pub fn start<F>(&self, on_change: F) -> Result<()>
    where
        F: Fn(WatchEvent) -> bool,
    {
        let (tx, rx) = mpsc::channel();

        let mut debouncer: Debouncer<RecommendedWatcher> =
            new_debouncer(Duration::from_millis(self.debounce_ms), tx)
                .context("Failed to create file watcher")?;

        debouncer
            .watcher()
            .watch(&self.watch_path, RecursiveMode::Recursive)
            .context("Failed to watch directory")?;

        println!(
            "👁 Watching for changes in {:?} (press Ctrl+C to stop)",
            self.watch_path
        );

        loop {
            match rx.recv() {
                Ok(Ok(events)) => {
                    let paths: Vec<PathBuf> = events
                        .into_iter()
                        .filter_map(|e| self.should_process_event(&e))
                        .collect();

                    if !paths.is_empty() {
                        let event = WatchEvent {
                            paths,
                            needs_rescan: true,
                        };

                        // If handler returns false, stop watching
                        if !on_change(event) {
                            break;
                        }
                    }
                }
                Ok(Err(error)) => {
                    eprintln!("Watch error: {:?}", error);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Channel receive error: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Check if an event should be processed
    fn should_process_event(&self, event: &DebouncedEvent) -> Option<PathBuf> {
        let path = &event.path;

        // Skip hidden files and directories
        if path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false)
        {
            return None;
        }

        // Skip cache directories
        if path.to_string_lossy().contains(".vulnera_cache")
            || path.to_string_lossy().contains("node_modules")
            || path.to_string_lossy().contains("target")
            || path.to_string_lossy().contains("__pycache__")
        {
            return None;
        }

        // Only process source files
        let extension = path.extension()?.to_string_lossy().to_lowercase();
        let source_extensions = [
            "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "c", "cpp", "h", "hpp", "cs", "rb",
            "php", "swift", "kt", "scala", "yaml", "yml", "json", "toml", "env", "sh", "bash",
            "sql",
        ];

        if source_extensions.contains(&extension.as_str()) {
            Some(path.clone())
        } else {
            None
        }
    }

    /// Get the watch path
    pub fn watch_path(&self) -> &Path {
        &self.watch_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify_debouncer_mini::DebouncedEventKind;
    use tempfile::TempDir;

    #[test]
    fn test_watcher_creation() {
        let temp_dir = TempDir::new().unwrap();
        let watcher = FileWatcher::new(temp_dir.path(), 500);
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_should_skip_hidden() {
        let temp_dir = TempDir::new().unwrap();
        let watcher = FileWatcher::new(temp_dir.path(), 500).unwrap();

        let hidden_event = DebouncedEvent {
            path: PathBuf::from("/project/.hidden_file.rs"),
            kind: DebouncedEventKind::Any,
        };

        assert!(watcher.should_process_event(&hidden_event).is_none());
    }

    #[test]
    fn test_should_process_source_file() {
        let temp_dir = TempDir::new().unwrap();
        let watcher = FileWatcher::new(temp_dir.path(), 500).unwrap();

        let source_event = DebouncedEvent {
            path: PathBuf::from("/project/src/main.rs"),
            kind: DebouncedEventKind::Any,
        };

        assert!(watcher.should_process_event(&source_event).is_some());
    }

    #[test]
    fn test_should_skip_cache_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let watcher = FileWatcher::new(temp_dir.path(), 500).unwrap();

        let cache_event = DebouncedEvent {
            path: PathBuf::from("/project/.vulnera_cache/file.json"),
            kind: DebouncedEventKind::Any,
        };

        assert!(watcher.should_process_event(&cache_event).is_none());
    }
}
