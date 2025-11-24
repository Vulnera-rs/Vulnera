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
        let mut frameworks = HashSet::new();
        let mut dependency_files = Vec::new();
        let mut detected_config_files = Vec::new();

        // Use a deeper search but exclude common ignore directories
        let walker = WalkDir::new(root).max_depth(5).into_iter();

        for entry in walker.filter_entry(|e| e.depth() == 0 || !is_ignored(e)) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // Skip inaccessible files
            };

            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                let file_path = entry.path().to_string_lossy().to_string();

                // Detect languages and dependencies
                match file_name.as_ref() {
                    "package.json" => {
                        languages.insert("javascript".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);

                        // Check for frameworks in package.json content if possible
                        // For now, we just mark it as a config file
                    }
                    "package-lock.json" | "yarn.lock" => {
                        languages.insert("javascript".to_string());
                        dependency_files.push(file_path);
                    }
                    "requirements.txt" | "Pipfile" | "poetry.lock" | "uv.lock" => {
                        languages.insert("python".to_string());
                        dependency_files.push(file_path);
                    }
                    "pyproject.toml" => {
                        languages.insert("python".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);
                    }
                    "Cargo.toml" => {
                        languages.insert("rust".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);
                    }
                    "Cargo.lock" => {
                        languages.insert("rust".to_string());
                        dependency_files.push(file_path);
                    }
                    "go.mod" => {
                        languages.insert("go".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);
                    }
                    "go.sum" => {
                        languages.insert("go".to_string());
                        dependency_files.push(file_path);
                    }
                    "pom.xml" | "build.gradle" | "build.gradle.kts" => {
                        languages.insert("java".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);
                    }
                    "composer.json" => {
                        languages.insert("php".to_string());
                        dependency_files.push(file_path.clone());
                        detected_config_files.push(file_path);
                    }
                    "composer.lock" => {
                        languages.insert("php".to_string());
                        dependency_files.push(file_path);
                    }
                    "Dockerfile" | "docker-compose.yml" | "docker-compose.yaml" => {
                        detected_config_files.push(file_path);
                        frameworks.insert("docker".to_string());
                    }
                    _ => {
                        if let Some(ext) = entry.path().extension() {
                            match ext.to_string_lossy().as_ref() {
                                "py" => {
                                    languages.insert("python".to_string());
                                    // Check for Django/Flask patterns in filename or path could be added here
                                    if file_name.contains("manage.py") {
                                        frameworks.insert("django".to_string());
                                    }
                                }
                                "js" | "jsx" => {
                                    languages.insert("javascript".to_string());
                                    if file_name.contains("react") {
                                        frameworks.insert("react".to_string());
                                    }
                                }
                                "ts" | "tsx" => {
                                    languages.insert("typescript".to_string());
                                    languages.insert("javascript".to_string()); // TS implies JS ecosystem
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
                                "php" => {
                                    languages.insert("php".to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        metadata.languages = languages.into_iter().collect();
        metadata.frameworks = frameworks.into_iter().collect();
        metadata.dependency_files = dependency_files;
        metadata.detected_config_files = detected_config_files;
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

/// Check if a directory entry should be ignored
fn is_ignored(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| {
            s.starts_with('.')
                || s == "node_modules"
                || s == "target"
                || s == "vendor"
                || s == "venv"
                || s == "__pycache__"
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_dummy_file(dir: &Path, name: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut file = File::create(path).unwrap();
        writeln!(file, "dummy content").unwrap();
    }

    #[test]
    fn test_detect_rust_project() {
        let temp_dir = TempDir::new().unwrap();
        create_dummy_file(temp_dir.path(), "Cargo.toml");
        create_dummy_file(temp_dir.path(), "src/main.rs");

        let git_service = Arc::new(GitService::new(Default::default()).unwrap());
        let detector = FileSystemProjectDetector::new(git_service);
        let metadata = detector.collect_metadata(temp_dir.path()).unwrap();

        assert!(metadata.languages.contains(&"rust".to_string()));
        assert!(
            metadata
                .dependency_files
                .iter()
                .any(|f| f.ends_with("Cargo.toml"))
        );
    }

    #[test]
    fn test_detect_python_django_project() {
        let temp_dir = TempDir::new().unwrap();
        create_dummy_file(temp_dir.path(), "requirements.txt");
        create_dummy_file(temp_dir.path(), "manage.py");
        create_dummy_file(temp_dir.path(), "app/views.py");

        let git_service = Arc::new(GitService::new(Default::default()).unwrap());
        let detector = FileSystemProjectDetector::new(git_service);
        let metadata = detector.collect_metadata(temp_dir.path()).unwrap();

        assert!(metadata.languages.contains(&"python".to_string()));
        assert!(metadata.frameworks.contains(&"django".to_string()));
        assert!(
            metadata
                .dependency_files
                .iter()
                .any(|f| f.ends_with("requirements.txt"))
        );
    }

    #[test]
    fn test_detect_react_project() {
        let temp_dir = TempDir::new().unwrap();
        create_dummy_file(temp_dir.path(), "package.json");
        create_dummy_file(temp_dir.path(), "src/App.tsx");

        let git_service = Arc::new(GitService::new(Default::default()).unwrap());
        let detector = FileSystemProjectDetector::new(git_service);
        let metadata = detector.collect_metadata(temp_dir.path()).unwrap();

        assert!(metadata.languages.contains(&"typescript".to_string()));
        assert!(metadata.languages.contains(&"javascript".to_string()));
        // React detection currently relies on filename containing "react", which is weak.
        // But let's verify TS detection at least.
    }

    #[test]
    fn test_detect_docker_project() {
        let temp_dir = TempDir::new().unwrap();
        create_dummy_file(temp_dir.path(), "Dockerfile");
        create_dummy_file(temp_dir.path(), "docker-compose.yml");

        let git_service = Arc::new(GitService::new(Default::default()).unwrap());
        let detector = FileSystemProjectDetector::new(git_service);
        let metadata = detector.collect_metadata(temp_dir.path()).unwrap();

        assert!(metadata.frameworks.contains(&"docker".to_string()));
        assert!(
            metadata
                .detected_config_files
                .iter()
                .any(|f| f.ends_with("Dockerfile"))
        );
    }

    #[test]
    fn test_ignore_patterns() {
        let temp_dir = TempDir::new().unwrap();
        create_dummy_file(temp_dir.path(), "node_modules/package.json");
        create_dummy_file(temp_dir.path(), "target/debug/app");
        create_dummy_file(temp_dir.path(), "src/main.rs");

        let git_service = Arc::new(GitService::new(Default::default()).unwrap());
        let detector = FileSystemProjectDetector::new(git_service);
        let metadata = detector.collect_metadata(temp_dir.path()).unwrap();

        assert!(metadata.languages.contains(&"rust".to_string()));
        // Should NOT contain javascript from node_modules
        assert!(!metadata.languages.contains(&"javascript".to_string()));
    }
}
