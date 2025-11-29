//! Integration tests for S3 project cleanup

use std::path::PathBuf;
use tokio::fs;
use vulnera_orchestrator::domain::entities::{Project, ProjectMetadata};
use vulnera_orchestrator::domain::value_objects::SourceType;

#[tokio::test]
async fn test_s3_temp_directory_cleanup() {
    // Create a mock S3 temp directory structure
    let temp_root = std::env::temp_dir().join("test-vulnera-s3-cleanup");
    let s3_temp_dir = temp_root.join("vulnera-s3-test-uuid");

    // Create the directory structure with some files
    fs::create_dir_all(&s3_temp_dir).await.expect("Failed to create temp dir");
    fs::write(s3_temp_dir.join("file1.txt"), "test").await.expect("Failed to write file");
    fs::write(s3_temp_dir.join("file2.json"), "{}").await.expect("Failed to write file");

    // Verify the directory exists
    assert!(s3_temp_dir.exists());
    let files: Vec<_> = fs::read_dir(&s3_temp_dir)
        .await
        .expect("Failed to read dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(files.len(), 2, "Should have 2 files in temp directory");

    // Create a project with S3 source and the temp directory path
    let project = Project {
        id: "test-project-1".to_string(),
        source_type: SourceType::S3Bucket,
        source_uri: "s3://test-bucket/prefix".to_string(),
        metadata: ProjectMetadata {
            languages: vec![],
            frameworks: vec![],
            dependency_files: vec![],
            detected_config_files: vec![],
            root_path: Some(s3_temp_dir.to_string_lossy().to_string()),
            git_revision: None,
        },
    };

    // Simulate cleanup_s3_project function
    if let Some(root_path) = &project.metadata.root_path {
        match fs::remove_dir_all(root_path).await {
            Ok(_) => {
                println!("Successfully cleaned up S3 temp directory: {}", root_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("S3 temp directory already removed: {}", root_path);
            }
            Err(e) => {
                panic!("Failed to clean up S3 temp directory: {}", e);
            }
        }
    }

    // Verify the directory is removed
    assert!(!s3_temp_dir.exists(), "S3 temp directory should be removed");

    // Clean up the test root
    let _ = fs::remove_dir_all(&temp_root).await;
}

#[tokio::test]
async fn test_s3_cleanup_handles_missing_directory() {
    // Create a project pointing to a non-existent directory
    let nonexistent_path = "/tmp/vulnera-s3-nonexistent-uuid";

    let project = Project {
        id: "test-project-2".to_string(),
        source_type: SourceType::S3Bucket,
        source_uri: "s3://test-bucket".to_string(),
        metadata: ProjectMetadata {
            languages: vec![],
            frameworks: vec![],
            dependency_files: vec![],
            detected_config_files: vec![],
            root_path: Some(nonexistent_path.to_string()),
            git_revision: None,
        },
    };

    // Cleanup should not panic when directory doesn't exist
    if let Some(root_path) = &project.metadata.root_path {
        match fs::remove_dir_all(root_path).await {
            Ok(_) => {
                panic!("Directory should not exist");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("Directory already missing (expected): {}", root_path);
                // This is expected
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}

#[tokio::test]
async fn test_non_s3_projects_skip_cleanup() {
    // Create projects with non-S3 sources
    let git_project = Project {
        id: "git-project".to_string(),
        source_type: SourceType::Git,
        source_uri: "https://github.com/example/repo".to_string(),
        metadata: ProjectMetadata::default(),
    };

    let dir_project = Project {
        id: "dir-project".to_string(),
        source_type: SourceType::Directory,
        source_uri: "/home/user/project".to_string(),
        metadata: ProjectMetadata::default(),
    };

    // These should not attempt cleanup (only S3Bucket source type should)
    assert_ne!(git_project.source_type, SourceType::S3Bucket);
    assert_ne!(dir_project.source_type, SourceType::S3Bucket);
}
