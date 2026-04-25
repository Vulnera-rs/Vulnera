//! Project domain module
//!
//! This module defines the core project entities and metadata that are shared
//! across the orchestrator and analysis modules.

use serde::{Deserialize, Serialize};

/// Source type for analysis input
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SourceType {
    /// Git repository URL
    Git,
    /// File upload
    FileUpload,
    /// S3 bucket path
    S3Bucket,
    /// Local directory path
    Directory,
}

/// Project metadata shared across modules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectMetadata {
    /// Detected languages in the project
    pub languages: Vec<String>,
    /// Detected frameworks (e.g., "django", "react", "spring")
    pub frameworks: Vec<String>,
    /// Detected dependency files
    pub dependency_files: Vec<String>,
    /// All detected configuration files of interest
    pub detected_config_files: Vec<String>,
    /// Project root path (for directory-based sources)
    pub root_path: Option<String>,
    /// Git revision (HEAD commit) when the source comes from a repository clone
    pub git_revision: Option<String>,
}

/// Represents a project to analyze
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub source_type: SourceType,
    pub source_uri: String,
    pub metadata: ProjectMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_type_json_roundtrip() {
        for st in [
            SourceType::Git,
            SourceType::FileUpload,
            SourceType::S3Bucket,
            SourceType::Directory,
        ] {
            let json = serde_json::to_string(&st).unwrap();
            let parsed: SourceType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, st);
        }
    }

    #[test]
    fn project_metadata_default() {
        let m = ProjectMetadata::default();
        assert!(m.languages.is_empty());
        assert!(m.frameworks.is_empty());
        assert!(m.dependency_files.is_empty());
        assert!(m.detected_config_files.is_empty());
        assert!(m.root_path.is_none());
        assert!(m.git_revision.is_none());
    }

    #[test]
    fn project_metadata_json_roundtrip() {
        let meta = ProjectMetadata {
            languages: vec!["rust".into(), "python".into()],
            frameworks: vec!["axum".into()],
            dependency_files: vec!["Cargo.toml".into()],
            detected_config_files: vec![".env".into()],
            root_path: Some("/tmp/project".into()),
            git_revision: Some("abc123def".into()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ProjectMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.languages, meta.languages);
        assert_eq!(parsed.frameworks, meta.frameworks);
        assert_eq!(parsed.root_path.as_deref(), Some("/tmp/project"));
        assert_eq!(parsed.git_revision.as_deref(), Some("abc123def"));
    }

    #[test]
    fn project_json_roundtrip() {
        let project = Project {
            id: "proj-01".into(),
            source_type: SourceType::Git,
            source_uri: "https://github.com/org/repo.git".into(),
            metadata: ProjectMetadata {
                languages: vec!["rust".into()],
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&project).unwrap();
        let parsed: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "proj-01");
        assert_eq!(parsed.source_type, SourceType::Git);
        assert_eq!(parsed.source_uri, "https://github.com/org/repo.git");
        assert_eq!(parsed.metadata.languages, vec!["rust"]);
    }
}
