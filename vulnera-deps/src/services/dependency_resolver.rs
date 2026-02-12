//! Dependency resolver service
//!
//! This module provides services for resolving transitive dependencies
//! and building complete dependency graphs from manifest and lockfiles.

use async_trait::async_trait;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, warn};
use vulnera_core::application::errors::ApplicationError;
use vulnera_core::domain::vulnerability::entities::Package;
use vulnera_core::domain::vulnerability::value_objects::Ecosystem;
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_core::infrastructure::registries::{PackageRegistryClient, RegistryError, VersionInfo};

use crate::domain::{
    DependencyEdge, DependencyGraph, PackageId, PackageMetadata, PackageNode,
    version_constraint::VersionConstraint,
};

/// Service for resolving dependencies and building dependency graphs
#[async_trait]
pub trait DependencyResolverService: Send + Sync {
    /// Build a dependency graph from parsed packages and dependencies
    async fn build_graph(
        &self,
        packages: Vec<Package>,
        dependencies: Vec<vulnera_core::domain::vulnerability::entities::Dependency>,
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

    fn package_key(package: &Package) -> String {
        format!(
            "{}:{}@{}",
            package.ecosystem.canonical_name(),
            package.name,
            package.version
        )
    }

    fn map_registry_error(error: RegistryError, resource: &str) -> ApplicationError {
        match error {
            RegistryError::RateLimited => ApplicationError::RateLimited {
                message: format!("Registry rate-limited request for {resource}"),
            },
            RegistryError::NotFound => ApplicationError::NotFound {
                resource: "package".to_string(),
                id: resource.to_string(),
            },
            RegistryError::UnsupportedEcosystem(ecosystem) => ApplicationError::InvalidEcosystem {
                ecosystem: ecosystem.to_string(),
            },
            RegistryError::Parse(message) => ApplicationError::Configuration { message },
            RegistryError::Http { message, .. } | RegistryError::Other(message) => {
                ApplicationError::Configuration {
                    message: format!("Registry request failed for {resource}: {message}"),
                }
            }
        }
    }

    fn select_best_version(
        versions: Vec<VersionInfo>,
        requirement: &str,
    ) -> Option<vulnera_core::domain::vulnerability::value_objects::Version> {
        let constraint = VersionConstraint::parse(requirement).unwrap_or(VersionConstraint::Any);

        versions
            .into_iter()
            .map(|v| v.version)
            .filter(|version| constraint.satisfies(version))
            .max()
    }
}

#[async_trait]
impl DependencyResolverService for DependencyResolverServiceImpl {
    async fn build_graph(
        &self,
        packages: Vec<Package>,
        dependencies: Vec<vulnera_core::domain::vulnerability::entities::Dependency>,
        _ecosystem: Ecosystem,
    ) -> Result<DependencyGraph, ApplicationError> {
        let mut graph = DependencyGraph::new();

        // Add all packages as nodes
        for package in packages {
            let node = PackageNode::new(package);
            graph.add_node(node);
        }

        // Add dependency edges from the provided dependencies
        for dep in dependencies {
            let from_id = PackageId::from_package(&dep.from);
            let to_id = PackageId::from_package(&dep.to);

            // Ensure nodes exist in graph (they should be in packages, but safety first)
            if graph.get_node(&from_id).is_none() {
                graph.add_node(PackageNode::new(dep.from.clone()));
            }
            if graph.get_node(&to_id).is_none() {
                graph.add_node(PackageNode::new(dep.to.clone()));
            }

            // Create constraint from requirement string
            let constraint = match VersionConstraint::parse(&dep.requirement) {
                Ok(constraint) => constraint,
                Err(error) => {
                    warn!(
                        requirement = %dep.requirement,
                        from = %dep.from.identifier(),
                        to = %dep.to.identifier(),
                        error = %error,
                        "Invalid dependency constraint; defaulting to wildcard"
                    );
                    VersionConstraint::Any
                }
            };

            let edge = DependencyEdge::new(from_id, to_id, constraint, dep.is_transitive);
            graph.add_edge(edge);
        }

        Ok(graph)
    }

    async fn resolve_transitive(
        &self,
        package: &Package,
        registry: Arc<dyn PackageRegistryClient>,
    ) -> Result<Vec<Package>, ApplicationError> {
        debug!(
            "Resolving transitive dependencies for {}:{}",
            package.name, package.version
        );

        let mut queue = VecDeque::new();
        queue.push_back(package.clone());

        let mut visited = HashSet::new();
        let mut discovered: HashMap<String, Package> = HashMap::new();

        while let Some(current) = queue.pop_front() {
            let current_key = Self::package_key(&current);
            if !visited.insert(current_key) {
                continue;
            }

            let metadata = match registry
                .fetch_metadata(current.ecosystem.clone(), &current.name, &current.version)
                .await
            {
                Ok(metadata) => metadata,
                Err(error) => {
                    if current.name == package.name && current.version == package.version {
                        return Err(Self::map_registry_error(
                            error,
                            &format!("{}@{}", current.name, current.version),
                        ));
                    }

                    warn!(
                        package = %current.identifier(),
                        "Failed to fetch metadata for transitive package: {}",
                        error
                    );
                    continue;
                }
            };

            for dependency in metadata.dependencies {
                if dependency.is_dev || dependency.is_optional {
                    continue;
                }

                let versions = match registry
                    .list_versions(current.ecosystem.clone(), &dependency.name)
                    .await
                {
                    Ok(versions) => versions,
                    Err(error) => {
                        warn!(
                            dependency = %dependency.name,
                            requirement = %dependency.requirement,
                            "Failed to list versions for dependency: {}",
                            error
                        );
                        continue;
                    }
                };

                let Some(version) = Self::select_best_version(versions, &dependency.requirement)
                else {
                    warn!(
                        dependency = %dependency.name,
                        requirement = %dependency.requirement,
                        "No compatible version found for dependency requirement"
                    );
                    continue;
                };

                let transitive_package =
                    match Package::new(dependency.name.clone(), version, current.ecosystem.clone())
                    {
                        Ok(package) => package,
                        Err(error) => {
                            warn!(
                                dependency = %dependency.name,
                                "Failed to build transitive package model: {}",
                                error
                            );
                            continue;
                        }
                    };

                let key = Self::package_key(&transitive_package);
                if discovered.contains_key(&key) {
                    continue;
                }

                discovered.insert(key, transitive_package.clone());
                queue.push_back(transitive_package);
            }
        }

        Ok(discovered.into_values().collect())
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
        let metadata = PackageMetadata {
            resolved_version: Some(package.version.clone()),
            is_direct: true,
            ..Default::default()
        };

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        package_map.insert(id.clone(), node);
    }

    // Add nodes to graph
    for node in package_map.values() {
        graph.add_node(node.clone());
    }

    // Extract dependency relationships from lockfile structure
    for dep in packages.dependencies {
        let from_id = PackageId::from_package(&dep.from);
        let to_id = PackageId::from_package(&dep.to);

        let constraint = match VersionConstraint::parse(&dep.requirement) {
            Ok(constraint) => constraint,
            Err(error) => {
                warn!(
                    requirement = %dep.requirement,
                    from = %dep.from.identifier(),
                    to = %dep.to.identifier(),
                    error = %error,
                    "Invalid lockfile dependency constraint; defaulting to wildcard"
                );
                VersionConstraint::Any
            }
        };

        let edge = DependencyEdge::new(from_id, to_id, constraint, dep.is_transitive);
        graph.add_edge(edge);
    }

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
        let metadata = PackageMetadata {
            is_direct: true,
            ..Default::default()
        };

        let node = PackageNode::new(package.clone()).with_metadata(metadata);
        graph.add_node(node);
    }

    // Add edges from manifest (direct dependencies)
    for dep in packages.dependencies {
        let from_id = PackageId::from_package(&dep.from);
        let to_id = PackageId::from_package(&dep.to);

        let constraint = match VersionConstraint::parse(&dep.requirement) {
            Ok(constraint) => constraint,
            Err(error) => {
                warn!(
                    requirement = %dep.requirement,
                    from = %dep.from.identifier(),
                    to = %dep.to.identifier(),
                    error = %error,
                    "Invalid manifest dependency constraint; defaulting to wildcard"
                );
                VersionConstraint::Any
            }
        };

        let edge = DependencyEdge::new(from_id, to_id, constraint, dep.is_transitive);
        graph.add_edge(edge);
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
                        let metadata = PackageMetadata {
                            is_direct: false, // These are transitive
                            ..Default::default()
                        };

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
    use std::sync::Mutex;
    use vulnera_core::domain::vulnerability::value_objects::Version;
    use vulnera_core::infrastructure::registries::{
        RegistryDependency, RegistryPackageMetadata, VersionInfo,
    };

    #[derive(Default)]
    struct MockRegistryClient {
        versions: Mutex<HashMap<String, Vec<VersionInfo>>>,
        metadata: Mutex<HashMap<String, RegistryPackageMetadata>>,
    }

    impl MockRegistryClient {
        fn key(ecosystem: Ecosystem, name: &str) -> String {
            format!("{}:{}", ecosystem.canonical_name(), name)
        }

        fn metadata_key(ecosystem: Ecosystem, name: &str, version: &str) -> String {
            format!("{}:{}@{}", ecosystem.canonical_name(), name, version)
        }

        fn add_versions(&self, ecosystem: Ecosystem, name: &str, versions: Vec<&str>) {
            let infos = versions
                .into_iter()
                .map(|v| VersionInfo::new(Version::parse(v).unwrap(), false, None))
                .collect();
            self.versions
                .lock()
                .unwrap()
                .insert(Self::key(ecosystem, name), infos);
        }

        fn add_metadata(
            &self,
            ecosystem: Ecosystem,
            name: &str,
            version: &str,
            dependencies: Vec<RegistryDependency>,
        ) {
            let metadata = RegistryPackageMetadata {
                name: name.to_string(),
                version: Version::parse(version).unwrap(),
                dependencies,
                project_url: None,
                license: None,
            };
            self.metadata
                .lock()
                .unwrap()
                .insert(Self::metadata_key(ecosystem, name, version), metadata);
        }
    }

    #[async_trait]
    impl PackageRegistryClient for MockRegistryClient {
        async fn list_versions(
            &self,
            ecosystem: Ecosystem,
            name: &str,
        ) -> Result<Vec<VersionInfo>, RegistryError> {
            Ok(self
                .versions
                .lock()
                .unwrap()
                .get(&Self::key(ecosystem, name))
                .cloned()
                .unwrap_or_default())
        }

        async fn fetch_metadata(
            &self,
            ecosystem: Ecosystem,
            name: &str,
            version: &Version,
        ) -> Result<RegistryPackageMetadata, RegistryError> {
            self.metadata
                .lock()
                .unwrap()
                .get(&Self::metadata_key(ecosystem, name, &version.to_string()))
                .cloned()
                .ok_or(RegistryError::NotFound)
        }
    }

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
            .build_graph(packages, vec![], Ecosystem::Npm)
            .await
            .unwrap();

        assert_eq!(graph.package_count(), 1);
        assert_eq!(graph.root_packages.len(), 1);
    }

    #[tokio::test]
    async fn test_resolve_transitive_resolves_nested_dependencies() {
        let parser_factory = Arc::new(ParserFactory::new());
        let resolver = DependencyResolverServiceImpl::new(parser_factory);

        let root = Package::new(
            "root".to_string(),
            Version::parse("1.0.0").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        let registry = Arc::new(MockRegistryClient::default());

        registry.add_versions(Ecosystem::Npm, "dep-a", vec!["1.0.0", "1.2.0"]);
        registry.add_versions(Ecosystem::Npm, "dep-b", vec!["2.0.0"]);

        registry.add_metadata(
            Ecosystem::Npm,
            "root",
            "1.0.0",
            vec![RegistryDependency {
                name: "dep-a".to_string(),
                requirement: ">=1.1.0".to_string(),
                is_dev: false,
                is_optional: false,
            }],
        );

        registry.add_metadata(
            Ecosystem::Npm,
            "dep-a",
            "1.2.0",
            vec![RegistryDependency {
                name: "dep-b".to_string(),
                requirement: "^2.0.0".to_string(),
                is_dev: false,
                is_optional: false,
            }],
        );

        registry.add_metadata(Ecosystem::Npm, "dep-b", "2.0.0", vec![]);

        let resolved = resolver
            .resolve_transitive(&root, registry)
            .await
            .expect("transitive resolution should succeed");

        assert!(
            resolved
                .iter()
                .any(|pkg| pkg.name == "dep-a" && pkg.version == Version::parse("1.2.0").unwrap())
        );
        assert!(
            resolved
                .iter()
                .any(|pkg| pkg.name == "dep-b" && pkg.version == Version::parse("2.0.0").unwrap())
        );
    }

    #[tokio::test]
    async fn test_resolve_transitive_skips_dev_and_optional_dependencies() {
        let parser_factory = Arc::new(ParserFactory::new());
        let resolver = DependencyResolverServiceImpl::new(parser_factory);

        let root = Package::new(
            "root".to_string(),
            Version::parse("1.0.0").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();

        let registry = Arc::new(MockRegistryClient::default());
        registry.add_versions(Ecosystem::Npm, "prod-dep", vec!["1.0.0"]);
        registry.add_versions(Ecosystem::Npm, "dev-dep", vec!["1.0.0"]);

        registry.add_metadata(
            Ecosystem::Npm,
            "root",
            "1.0.0",
            vec![
                RegistryDependency {
                    name: "prod-dep".to_string(),
                    requirement: "*".to_string(),
                    is_dev: false,
                    is_optional: false,
                },
                RegistryDependency {
                    name: "dev-dep".to_string(),
                    requirement: "*".to_string(),
                    is_dev: true,
                    is_optional: false,
                },
            ],
        );

        registry.add_metadata(Ecosystem::Npm, "prod-dep", "1.0.0", vec![]);

        let resolved = resolver
            .resolve_transitive(&root, registry)
            .await
            .expect("transitive resolution should succeed");

        assert!(resolved.iter().any(|pkg| pkg.name == "prod-dep"));
        assert!(!resolved.iter().any(|pkg| pkg.name == "dev-dep"));
    }
}
