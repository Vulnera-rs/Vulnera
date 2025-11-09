//! Test helper functions for vulnera-core

use std::path::PathBuf;
use tempfile::TempDir;

/// Create a temporary directory for testing
pub fn create_temp_dir() -> TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Create a temporary file with content
pub async fn create_temp_file(
    dir: &TempDir,
    filename: &str,
    content: &str,
) -> PathBuf {
    let path = dir.path().join(filename);
    tokio::fs::write(&path, content)
        .await
        .expect("Failed to write temp file");
    path
}

/// Assert two packages are equal (ignoring metadata)
pub fn assert_packages_equal(p1: &vulnera_core::domain::vulnerability::entities::Package, p2: &vulnera_core::domain::vulnerability::entities::Package) {
    assert_eq!(p1.name(), p2.name());
    assert_eq!(p1.version(), p2.version());
    assert_eq!(p1.ecosystem(), p2.ecosystem());
}

/// Wait for async operations to complete
pub async fn wait_for_async() {
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
}

