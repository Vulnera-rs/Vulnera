//! Project domain module
//!
//! This module defines the core project entities and metadata that are shared
//! across the orchestrator and analysis modules.

use serde::{Deserialize, Serialize};

/// Source type for analysis input
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
