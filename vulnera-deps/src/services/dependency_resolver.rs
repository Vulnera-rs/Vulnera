//! Dependency resolver service
//!
//! This module provides services for resolving transitive dependencies
//! and building complete dependency graphs from manifest and lockfiles.

use async_trait::async_trait;
use std::sync::Arc;
use vulnera_core::application::errors::ApplicationError;
use vulnera_core::domain::vulnerability::entities::Package;
use vulnera_core::domain::vulnerability::value_objects::Ecosystem;
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_core::infrastructure::registries::PackageRegistryClient;

use crate::domain::{DependencyGraph, PackageId, PackageMetadata, PackageNode};

/// Service for resolving dependencies and building dependency graphs
#[async_trait]
pub trait DependencyResolverService: Send + Sync {
    /// Build a dependency graph from parsed packages
    async fn build_graph(
        &self,
        packages: Vec<Package>,
        ecosystem: Ecosystem,
    ) -> Result<DependencyGraph, ApplicationError>;

    /// Resolve transitive dependencies for a package
    async fn resolve_transitive(
        &self,
        package: &Package,
        registry: Arc<dyn PackageRegistryClient>,
    ) -> Result<Vec<Package>, ApplicationError>;
}

/// Implementation of dependency resolver service
pub struct DependencyResolverServiceImpl {
    _parser_factory: Arc<ParserFactory>,
}

impl DependencyResolverServiceImpl {
    pub fn new(parser_factory: Arc<ParserFactory>) -> Self {
        Self {
            _parser_factory: parser_factory,
        }
    }
}

#[async_trait]
impl DependencyResolverService for DependencyResolverServiceImpl {
    async fn build_graph(
        &self,
        packages: Vec<Package>,
        _ecosystem: Ecosystem,
    ) -> Result<DependencyGraph, ApplicationError> {
        let mut graph = DependencyGraph::new();

        // Add all packages as nodes
        for package in packages {
            let node = PackageNode::new(package);
            graph.add_node(node);
        }

        // For now, we don't have dependency relationships from the parsers
        // This would need to be enhanced to extract dependencies from lockfiles
        // or resolve them from registries

        Ok(graph)
    }

    async fn resolve_transitive(
        &self,
        _package: &Package,
        _registry: Arc<dyn PackageRegistryClient>,
    ) -> Result<Vec<Package>, ApplicationError> {
        // TODO: Implement transitive dependency resolution
        // This would query the registry for the package's dependencies
        // and recursively resolve them
        Ok(Vec::new())
    }
}

/// Build a dependency graph from a lockfile
/// Lockfiles contain the complete resolved dependency tree
pub async fn build_graph_from_lockfile(
    lockfile_content: &str,
    filename: &str,
    parser_factory: &ParserFactory,
) -> Result<DependencyGraph, ApplicationError> {
    let parser = parser_factory.create_parser(filename).ok_or_else(|| {
        ApplicationError::InvalidEcosystem {
            ecosystem: format!("No parser for {}", filename),
        }
    })?;

    let packages = parser
        .parse_file(lockfile_content)
        .await
        .map_err(ApplicationError::Parse)?;

    let mut graph = DependencyGraph::new();
    let mut package_map: std::collections::HashMap<PackageId, PackageNode> =
        std::collections::HashMap::new();

    // Create nodes for all packages
    for package in packages {
        let id = PackageId::from_package(&package);
        let mut metadata = PackageMetadata::default();
        metadata.resolved_version = Some(package.version.clone());
        metadata.is_direct = true; // In lockfiles, we can determine this from structure

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        package_map.insert(id.clone(), node);
    }

    // Add nodes to graph
    for (_, node) in &package_map {
        graph.add_node(node.clone());
    }

    // TODO: Extract dependency relationships from lockfile structure
    // This requires parser-specific logic to understand the lockfile format

    Ok(graph)
}

/// Build a dependency graph from a manifest file
/// Manifest files only contain direct dependencies, so we need to resolve transitive deps
pub async fn build_graph_from_manifest(
    manifest_content: &str,
    filename: &str,
    parser_factory: &ParserFactory,
    registry: Option<Arc<dyn PackageRegistryClient>>,
) -> Result<DependencyGraph, ApplicationError> {
    let parser = parser_factory.create_parser(filename).ok_or_else(|| {
        ApplicationError::InvalidEcosystem {
            ecosystem: format!("No parser for {}", filename),
        }
    })?;

    let packages = parser
        .parse_file(manifest_content)
        .await
        .map_err(ApplicationError::Parse)?;

    let mut graph = DependencyGraph::new();

    // Add direct dependencies as nodes
    for package in packages {
        let mut metadata = PackageMetadata::default();
        metadata.is_direct = true;

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        graph.add_node(node);

        // If registry is available, resolve transitive dependencies
        if registry.is_some() {
            // TODO: Resolve transitive dependencies
            // This would query the registry for each package's dependencies
        }
    }

    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_graph_from_manifest() {
        let parser_factory = Arc::new(ParserFactory::new());
        let resolver = DependencyResolverServiceImpl::new(parser_factory.clone());

        let packages = vec![
            Package::new(
                "express".to_string(),
                vulnera_core::domain::vulnerability::value_objects::Version::parse("4.17.1")
                    .unwrap(),
                Ecosystem::Npm,
            )
            .unwrap(),
        ];

        let graph = resolver
            .build_graph(packages, Ecosystem::Npm)
            .await
            .unwrap();

        assert_eq!(graph.package_count(), 1);
        assert_eq!(graph.root_packages.len(), 1);
    }
}
