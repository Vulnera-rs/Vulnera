//! Project detection implementations

use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::domain::entities::{Project, ProjectMetadata};
use crate::domain::services::{ProjectDetectionError, ProjectDetector};
use crate::domain::value_objects::SourceType;
use crate::infrastructure::git::GitService;

/// File system-based project detector
pub struct FileSystemProjectDetector {
    git_service: Arc<GitService>,
}

impl FileSystemProjectDetector {
    pub fn new(git_service: Arc<GitService>) -> Self {
        Self { git_service }
    }

    fn collect_metadata(&self, root: &Path) -> Result<ProjectMetadata, ProjectDetectionError> {
        if !root.exists() {
            return Err(ProjectDetectionError::NotFound(
                root.to_string_lossy().to_string(),
            ));
        }

        let mut metadata = ProjectMetadata::default();
        metadata.root_path = Some(root.to_string_lossy().to_string());

        let mut languages = HashSet::new();
        let mut dependency_files = Vec::new();

        for entry in WalkDir::new(root).max_depth(3) {
            let entry = entry.map_err(|e| {
                ProjectDetectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                let file_path = entry.path().to_string_lossy().to_string();

                match file_name.as_ref() {
                    "package.json" | "package-lock.json" | "yarn.lock" => {
                        languages.insert("javascript".to_string());
                        dependency_files.push(file_path);
                    }
                    "requirements.txt" | "Pipfile" | "pyproject.toml" | "poetry.lock"
                    | "uv.lock" => {
                        languages.insert("python".to_string());
                        dependency_files.push(file_path);
                    }
                    "Cargo.toml" | "Cargo.lock" => {
                        languages.insert("rust".to_string());
                        dependency_files.push(file_path);
                    }
                    "go.mod" | "go.sum" => {
                        languages.insert("go".to_string());
                        dependency_files.push(file_path);
                    }
                    "pom.xml" | "build.gradle" => {
                        languages.insert("java".to_string());
                        dependency_files.push(file_path);
                    }
                    "composer.json" | "composer.lock" => {
                        languages.insert("php".to_string());
                        dependency_files.push(file_path);
                    }
                    _ => {
                        if let Some(ext) = entry.path().extension() {
                            match ext.to_string_lossy().as_ref() {
                                "py" => {
                                    languages.insert("python".to_string());
                                }
                                "js" | "jsx" | "ts" | "tsx" => {
                                    languages.insert("javascript".to_string());
                                }
                                "rs" => {
                                    languages.insert("rust".to_string());
                                }
                                "go" => {
                                    languages.insert("go".to_string());
                                }
                                "java" => {
                                    languages.insert("java".to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        metadata.languages = languages.into_iter().collect();
        metadata.dependency_files = dependency_files;
        Ok(metadata)
    }

    async fn detect_git_project(&self, source_uri: &str) -> Result<Project, ProjectDetectionError> {
        let project_id = format!("project_{}", uuid::Uuid::new_v4());
        let checkout = self
            .git_service
            .clone_repository(&project_id, source_uri)
            .await
            .map_err(|e| ProjectDetectionError::DetectionFailed(e.to_string()))?;

        let path = PathBuf::from(&checkout.checkout_path);
        let mut metadata = self.collect_metadata(&path)?;
        metadata.git_revision = checkout.head_commit;

        Ok(Project {
            id: project_id,
            source_type: SourceType::Git,
            source_uri: source_uri.to_string(),
            metadata,
        })
    }
}

#[async_trait]
impl ProjectDetector for FileSystemProjectDetector {
    async fn detect_project(
        &self,
        source_type: &SourceType,
        source_uri: &str,
    ) -> Result<Project, ProjectDetectionError> {
        match source_type {
            SourceType::Directory => {
                let metadata = self.collect_metadata(Path::new(source_uri))?;
                let project_id = format!("project_{}", uuid::Uuid::new_v4());

                Ok(Project {
                    id: project_id,
                    source_type: source_type.clone(),
                    source_uri: source_uri.to_string(),
                    metadata,
                })
            }
            SourceType::Git => self.detect_git_project(source_uri).await,
            _ => Err(ProjectDetectionError::InvalidUri(
                "Unsupported source type for file system detector".to_string(),
            )),
        }
    }
}
