//! Test helper functions for vulnera-sast

use std::path::PathBuf;
use tempfile::TempDir;

/// Create a temporary source file
pub async fn create_source_file(
    dir: &TempDir,
    filename: &str,
    content: &str,
) -> PathBuf {
    let path = dir.path().join(filename);
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write source file");
    path
}

