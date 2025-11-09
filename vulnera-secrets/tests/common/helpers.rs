//! Test helper functions for vulnera-secrets

use std::path::PathBuf;
use tempfile::TempDir;

/// Create a temporary file with content
pub async fn create_test_file(
    dir: &TempDir,
    filename: &str,
    content: &str,
) -> PathBuf {
    let path = dir.path().join(filename);
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write test file");
    path
}

