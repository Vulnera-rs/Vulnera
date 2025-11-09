//! Project detection implementations

use async_trait::async_trait;
use std::path::Path;
use walkdir::WalkDir;

use crate::domain::entities::{Project, ProjectMetadata};
use crate::domain::services::{ProjectDetectionError, ProjectDetector};
use crate::domain::value_objects::SourceType;

/// File system-based project detector
pub struct FileSystemProjectDetector;

#[async_trait]
impl ProjectDetector for FileSystemProjectDetector {
    async fn detect_project(
        &self,
        source_type: &SourceType,
        source_uri: &str,
    ) -> Result<Project, ProjectDetectionError> {
        match source_type {
            SourceType::Directory => {
                let path = Path::new(source_uri);
                if !path.exists() {
                    return Err(ProjectDetectionError::NotFound(source_uri.to_string()));
                }

                let mut metadata = ProjectMetadata::default();
                metadata.root_path = Some(source_uri.to_string());

                // Detect languages and dependency files
                let mut languages = std::collections::HashSet::new();
                let mut dependency_files = Vec::new();

                for entry in WalkDir::new(path).max_depth(3) {
                    let entry = entry.map_err(|e| {
                        ProjectDetectionError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))
                    })?;

                    if entry.file_type().is_file() {
                        let file_name = entry.file_name().to_string_lossy();
                        let file_path = entry.path().to_string_lossy().to_string();

                        // Detect dependency files
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
                                // Detect by extension
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

                let project_id = format!("project_{}", uuid::Uuid::new_v4());

                Ok(Project {
                    id: project_id,
                    source_type: source_type.clone(),
                    source_uri: source_uri.to_string(),
                    metadata,
                })
            }
            SourceType::Git => {
                // For Git, we'd need to clone the repo first
                // For now, return a basic project
                let project_id = format!("project_{}", uuid::Uuid::new_v4());
                Ok(Project {
                    id: project_id,
                    source_type: source_type.clone(),
                    source_uri: source_uri.to_string(),
                    metadata: ProjectMetadata::default(),
                })
            }
            _ => Err(ProjectDetectionError::InvalidUri(
                "Unsupported source type for file system detector".to_string(),
            )),
        }
    }
}
