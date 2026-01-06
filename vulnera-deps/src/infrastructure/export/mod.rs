//! Dependency graph export infrastructure
//!
//! This module provides functionality to export dependency graphs to various formats
//! for visualization, reporting, or further analysis.

use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

use crate::domain::DependencyGraph;
use vulnera_core::application::errors::ApplicationError;

/// Exporter for dependency graphs supporting multiple formats
pub struct GraphExporter;

impl GraphExporter {
    /// Export the dependency graph to a JSON file
    pub async fn export_as_json(
        graph: &DependencyGraph,
        output_path: impl AsRef<Path>,
    ) -> Result<(), ApplicationError> {
        let path = output_path.as_ref();
        debug!("Exporting dependency graph as JSON to {:?}", path);

        let json_data = graph.to_json();
        let json_string = serde_json::to_string_pretty(&json_data).map_err(|e| {
            ApplicationError::Internal(format!("Failed to serialize graph to JSON: {}", e))
        })?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ApplicationError::Internal(format!("Failed to create directories: {}", e))
            })?;
        }

        fs::write(path, json_string).await.map_err(|e| {
            ApplicationError::Internal(format!("Failed to write graph to {:?}: {}", path, e))
        })?;

        info!("Successfully exported dependency graph to {:?}", path);
        Ok(())
    }

    /// Export the dependency graph to a DOT file for Graphviz visualization
    pub async fn export_as_dot(
        graph: &DependencyGraph,
        output_path: impl AsRef<Path>,
    ) -> Result<(), ApplicationError> {
        let path = output_path.as_ref();
        debug!("Exporting dependency graph as DOT to {:?}", path);

        let dot_string = graph.to_dot();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ApplicationError::Internal(format!("Failed to create directories: {}", e))
            })?;
        }

        fs::write(path, dot_string).await.map_err(|e| {
            ApplicationError::Internal(format!("Failed to write graph to {:?}: {}", path, e))
        })?;

        info!(
            "Successfully exported dependency graph as DOT to {:?}",
            path
        );
        Ok(())
    }

    /// Generate the JSON representation as a string
    pub fn to_json_string(graph: &DependencyGraph) -> Result<String, ApplicationError> {
        let json_data = graph.to_json();
        serde_json::to_string(&json_data).map_err(|e| {
            ApplicationError::Internal(format!("Failed to serialize graph to JSON: {}", e))
        })
    }

    /// Generate the DOT representation as a string
    pub fn to_dot_string(graph: &DependencyGraph) -> String {
        graph.to_dot()
    }
}
