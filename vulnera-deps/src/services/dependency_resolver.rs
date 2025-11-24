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

use crate::domain::{
    DependencyEdge, DependencyGraph, PackageId, PackageMetadata, PackageNode,
    version_constraint::VersionConstraint,
};

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
        package: &Package,
        registry: Arc<dyn PackageRegistryClient>,
    ) -> Result<Vec<Package>, ApplicationError> {
        // Note: Most package registries don't expose dependency information directly
        // through their APIs. To properly resolve transitive dependencies, we would need to:
        // 1. Fetch the package manifest/metadata for the specific version
        // 2. Parse dependencies from the manifest (package.json, Cargo.toml, etc.)
        // 3. Recursively resolve those dependencies
        //
        // This is ecosystem-specific and complex. For now, we return an empty vector.
        // In practice, transitive dependencies are best resolved from lockfiles
        // (package-lock.json, Cargo.lock, etc.) which contain the complete resolved tree.
        //
        // Future enhancement: Implement ecosystem-specific manifest fetching and parsing
        // for registries that support it (e.g., npm registry API, crates.io API)

        tracing::debug!(
            "Transitive dependency resolution requested for {}:{} (not yet implemented - use lockfiles for complete dependency trees)",
            package.name,
            package.version
        );

        // Attempt to verify the package exists in the registry
        // This at least validates that the package is available
        match registry
            .list_versions(package.ecosystem.clone(), &package.name)
            .await
        {
            Ok(_versions) => {
                // Package exists, but we can't get dependencies without fetching manifests
                Ok(Vec::new())
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to verify package {} in registry: {}",
                    package.name,
                    e
                );
                // Return empty rather than error, as this is a best-effort operation
                Ok(Vec::new())
            }
        }
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
    for package in packages.packages {
        let id = PackageId::from_package(&package);
        let mut metadata = PackageMetadata::default();
        metadata.resolved_version = Some(package.version.clone());
        metadata.is_direct = true;

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        package_map.insert(id.clone(), node);
    }

    // Add nodes to graph
    for (_, node) in &package_map {
        graph.add_node(node.clone());
    }

    // TODO: Extract dependency relationships from lockfile structure
    // This requires parser-specific logic to understand the lockfile format.
    // Different lockfile formats have different structures:
    // - package-lock.json: dependencies are nested under each package
    // - yarn.lock: dependencies are listed with "^" references
    // - Cargo.lock: dependencies are listed in [[package]] sections with dependencies array
    // - go.sum: doesn't contain dependency relationships, only checksums
    //
    // To implement this properly, we would need to:
    // 1. Enhance parsers to return dependency relationships along with packages
    // 2. Or parse the lockfile structure directly here (ecosystem-specific)
    // 3. Create DependencyEdge objects for each relationship
    // 4. Add edges to the graph using graph.add_edge()
    //
    // For now, the graph contains all packages as nodes but no edges.
    // This is still useful for package enumeration, but doesn't show the dependency tree.

    Ok(graph)
}

/// Build a dependency graph from a manifest file
/// Manifest files only contain direct dependencies, so we need to resolve transitive deps
pub async fn build_graph_from_manifest(
    manifest_content: &str,
    filename: &str,
    parser_factory: Arc<ParserFactory>,
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
    let packages_clone = packages.packages.clone();

    // Add direct dependencies as nodes
    for package in packages.packages {
        let mut metadata = PackageMetadata::default();
        metadata.is_direct = true;

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        graph.add_node(node);
    }

    // If registry is available, resolve transitive dependencies
    if let Some(registry) = &registry {
        // Resolve transitive dependencies for each direct dependency
        // Note: This is a best-effort operation as most registries don't expose
        // dependency information directly. Lockfiles are preferred for complete trees.
        let resolver = DependencyResolverServiceImpl::new(parser_factory.clone());
        for package in &packages_clone {
            match resolver.resolve_transitive(package, registry.clone()).await {
                Ok(transitive_deps) => {
                    for dep in transitive_deps {
                        let mut metadata = PackageMetadata::default();
                        metadata.is_direct = false; // These are transitive

                        let dep_node = PackageNode::new(dep).with_metadata(metadata);
                        graph.add_node(dep_node.clone());

                        // Create edge from the direct dependency to its transitive dependency
                        let from_id = PackageId::from_package(package);
                        let to_id = dep_node.id.clone();
                        let edge = DependencyEdge::new(
                            from_id,
                            to_id,
                            VersionConstraint::Any, // We don't know the exact constraint
                            true,                   // This is a transitive dependency
                        );
                        graph.add_edge(edge);
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to resolve transitive dependencies for {}: {}",
                        package.name,
                        e
                    );
                    // Continue with other packages
                }
            }
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
