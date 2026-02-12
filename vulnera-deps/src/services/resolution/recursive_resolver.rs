//! Recursive dependency resolver service using a queue-based BFS approach.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, warn};

use vulnera_core::application::errors::{ApplicationError, VulnerabilityError};
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::domain::vulnerability::entities::Package;
use vulnera_core::domain::vulnerability::value_objects::{Ecosystem, Version};
use vulnera_core::infrastructure::registries::{PackageRegistryClient, RegistryPackageMetadata};

use crate::domain::version_constraint::VersionConstraint;
use crate::domain::{DependencyEdge, DependencyGraph, PackageId, PackageMetadata, PackageNode};

/// Result of a recursive resolution operation
pub struct RecursiveResolutionResult {
    /// The resulting dependency graph
    pub graph: DependencyGraph,
    /// List of packages that could not be resolved (Name, Requirement)
    pub unresolved: Vec<(String, String)>,
}

/// Service for deep dependency subtree analysis using a queue-based BFS approach
pub struct RecursiveResolver<C: CacheService> {
    registry_client: Arc<dyn PackageRegistryClient>,
    cache_service: Arc<C>,
    max_depth: usize,
}

impl<C: CacheService> RecursiveResolver<C> {
    /// Create a new recursive resolver
    pub fn new(
        registry_client: Arc<dyn PackageRegistryClient>,
        cache_service: Arc<C>,
        max_depth: usize,
    ) -> Self {
        Self {
            registry_client,
            cache_service,
            max_depth,
        }
    }

    /// Resolve dependencies for a list of root packages using BFS
    pub async fn resolve(
        &self,
        roots: Vec<Package>,
        ecosystem: Ecosystem,
    ) -> Result<RecursiveResolutionResult, ApplicationError> {
        let mut graph = DependencyGraph::new();
        let mut visited = HashSet::new();
        let mut unresolved = Vec::new();
        let mut queue = VecDeque::new();

        // Initialize queue with root packages
        for root in roots {
            let pkg_id = PackageId::from_package(&root);

            // Add root nodes to graph if not already present
            if graph.get_node(&pkg_id).is_none() {
                let metadata = PackageMetadata {
                    is_direct: true,
                    resolved_version: Some(root.version.clone()),
                    ..Default::default()
                };

                let node = PackageNode::new(root.clone()).with_metadata(metadata);
                graph.add_node(node);
            }

            queue.push_back((root, 0));
        }

        while let Some((current_pkg, depth)) = queue.pop_front() {
            let current_id = PackageId::from_package(&current_pkg);

            // Skip if already visited subtree or max depth reached
            if visited.contains(&current_id) || depth >= self.max_depth {
                continue;
            }

            visited.insert(current_id.clone());

            debug!(
                "Resolving dependencies for {}@{} (depth: {})",
                current_pkg.name, current_pkg.version, depth
            );

            // Fetch metadata for the current package
            let metadata = match self
                .fetch_metadata_with_cache(&ecosystem, &current_pkg.name, &current_pkg.version)
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "Failed to fetch metadata for {}@{}: {}",
                        current_pkg.name, current_pkg.version, e
                    );
                    continue;
                }
            };

            for reg_dep in metadata.dependencies {
                // Skip dev dependencies for transitive resolution
                if reg_dep.is_dev {
                    continue;
                }

                // Resolve the requirement to a specific version
                let resolved_version = match self
                    .resolve_requirement(&ecosystem, &reg_dep.name, &reg_dep.requirement)
                    .await
                {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        unresolved.push((reg_dep.name.clone(), reg_dep.requirement.clone()));
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to resolve version for {} ({}): {}",
                            reg_dep.name, reg_dep.requirement, e
                        );
                        unresolved.push((reg_dep.name.clone(), reg_dep.requirement.clone()));
                        continue;
                    }
                };

                let dep_pkg =
                    Package::new(reg_dep.name.clone(), resolved_version, ecosystem.clone())
                        .map_err(|e| {
                            ApplicationError::Vulnerability(VulnerabilityError::DomainCreation {
                                message: format!("Invalid package construction: {}", e),
                            })
                        })?;

                let dep_id = PackageId::from_package(&dep_pkg);

                // Add node to graph if not present
                if graph.get_node(&dep_id).is_none() {
                    let metadata = PackageMetadata {
                        is_direct: false,
                        resolved_version: Some(dep_pkg.version.clone()),
                        ..Default::default()
                    };

                    let node = PackageNode::new(dep_pkg.clone()).with_metadata(metadata);
                    graph.add_node(node);
                }

                // Add edge from current to dependency
                let constraint = VersionConstraint::parse(&reg_dep.requirement)
                    .unwrap_or(VersionConstraint::Any);
                let edge = DependencyEdge::new(
                    current_id.clone(),
                    dep_id.clone(),
                    constraint,
                    true, // This is a transitive edge discovered during BFS
                );
                graph.add_edge(edge);

                // Add to queue for further processing if not visited and within depth limits
                if !visited.contains(&dep_id) && depth + 1 < self.max_depth {
                    queue.push_back((dep_pkg, depth + 1));
                }
            }
        }

        Ok(RecursiveResolutionResult { graph, unresolved })
    }

    /// Fetch metadata with caching support
    async fn fetch_metadata_with_cache(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        version: &Version,
    ) -> Result<RegistryPackageMetadata, ApplicationError> {
        let cache_key = format!(
            "reg_meta:{}:{}:{}",
            ecosystem.canonical_name(),
            name,
            version
        );

        // Try cache
        if let Ok(Some(cached)) = self
            .cache_service
            .get::<RegistryPackageMetadata>(&cache_key)
            .await
        {
            return Ok(cached);
        }

        // Fetch from registry
        let meta = self
            .registry_client
            .fetch_metadata(ecosystem.clone(), name, version)
            .await
            .map_err(|e| {
                ApplicationError::Vulnerability(VulnerabilityError::Repository {
                    message: format!("Registry error: {}", e),
                })
            })?;

        // Store in cache (TTL 24h)
        let _ = self
            .cache_service
            .set(&cache_key, &meta, std::time::Duration::from_secs(86400))
            .await;

        Ok(meta)
    }

    /// Resolve a version requirement to the best matching version
    async fn resolve_requirement(
        &self,
        ecosystem: &Ecosystem,
        name: &str,
        requirement: &str,
    ) -> Result<Option<Version>, ApplicationError> {
        let constraint = VersionConstraint::parse(requirement).unwrap_or(VersionConstraint::Any);

        // Fetch all available versions
        let versions = self
            .registry_client
            .list_versions(ecosystem.clone(), name)
            .await
            .map_err(|e| {
                ApplicationError::Vulnerability(VulnerabilityError::Repository {
                    message: format!("Registry error: {}", e),
                })
            })?;

        // Find the best matching version (latest that satisfies the constraint)
        let mut compatible_versions: Vec<Version> = versions
            .into_iter()
            .map(|vi| vi.version)
            .filter(|v| constraint.satisfies(v))
            .collect();

        compatible_versions.sort();

        Ok(compatible_versions.last().cloned())
    }
}
