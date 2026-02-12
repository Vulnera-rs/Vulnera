//! Advanced dependency resolution algorithms
//!
//! This module provides advanced algorithms for dependency resolution,
//! including constraint satisfaction and conflict resolution.

use std::collections::HashMap;
use vulnera_core::domain::vulnerability::value_objects::Version;

use crate::domain::{DependencyGraph, PackageId, VersionConstraint};

/// Result of dependency resolution
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// Resolved package versions
    pub resolved: HashMap<PackageId, Version>,
    /// Conflicts that couldn't be resolved
    pub conflicts: Vec<ResolutionConflict>,
}

/// A dependency conflict that couldn't be resolved
#[derive(Debug, Clone)]
pub struct ResolutionConflict {
    pub package: PackageId,
    pub conflicting_constraints: Vec<VersionConstraint>,
    pub message: String,
}

/// Simple backtracking resolver for dependency constraints
pub struct BacktrackingResolver;

impl BacktrackingResolver {
    /// Resolve dependencies using backtracking algorithm
    pub fn resolve(
        graph: &DependencyGraph,
        available_versions: &HashMap<PackageId, Vec<Version>>,
    ) -> ResolutionResult {
        let mut resolved = HashMap::new();
        let mut conflicts = Vec::new();

        let constraints_by_package = Self::constraints_by_package(graph);

        let mut resolvable_packages = Vec::new();
        for package_id in graph.nodes.keys() {
            let constraints = constraints_by_package
                .get(package_id)
                .cloned()
                .unwrap_or_default();

            let Some(versions) = available_versions.get(package_id) else {
                conflicts.push(ResolutionConflict {
                    package: package_id.clone(),
                    conflicting_constraints: constraints,
                    message: format!("No versions available for {}", package_id),
                });
                continue;
            };

            let candidates = Self::compatible_versions(versions, &constraints);
            if candidates.is_empty() {
                conflicts.push(ResolutionConflict {
                    package: package_id.clone(),
                    conflicting_constraints: constraints,
                    message: format!("No compatible version found for {}", package_id),
                });
                continue;
            }

            resolvable_packages.push(package_id.clone());
        }

        let search_order = Self::ordered_packages(
            &resolvable_packages,
            available_versions,
            &constraints_by_package,
            graph,
        );

        let solved = Self::backtrack(
            &search_order,
            0,
            available_versions,
            &constraints_by_package,
            &mut resolved,
            &mut conflicts,
        );

        if !solved {
            // Keep any partial assignments found, and return collected conflicts.
            // Conflicts are already captured during the search.
        }

        ResolutionResult { resolved, conflicts }
    }

    fn constraints_by_package(graph: &DependencyGraph) -> HashMap<PackageId, Vec<VersionConstraint>> {
        let mut constraints: HashMap<PackageId, Vec<VersionConstraint>> = HashMap::new();
        for edge in &graph.edges {
            constraints
                .entry(edge.to.clone())
                .or_default()
                .push(edge.constraint.clone());
        }
        constraints
    }

    fn ordered_packages(
        packages: &[PackageId],
        available_versions: &HashMap<PackageId, Vec<Version>>,
        constraints_by_package: &HashMap<PackageId, Vec<VersionConstraint>>,
        graph: &DependencyGraph,
    ) -> Vec<PackageId> {
        let mut ordered = packages.to_vec();
        ordered.sort_by(|left, right| {
            let left_constraints = constraints_by_package
                .get(left)
                .cloned()
                .unwrap_or_default();
            let right_constraints = constraints_by_package
                .get(right)
                .cloned()
                .unwrap_or_default();

            let left_candidates = available_versions
                .get(left)
                .map(|v| Self::compatible_versions(v, &left_constraints).len())
                .unwrap_or(0);
            let right_candidates = available_versions
                .get(right)
                .map(|v| Self::compatible_versions(v, &right_constraints).len())
                .unwrap_or(0);

            left_candidates
                .cmp(&right_candidates)
                .then_with(|| {
                    let left_degree = graph
                        .nodes
                        .get(left)
                        .map(|node| node.dependents.len() + node.direct_dependencies.len())
                        .unwrap_or(0);
                    let right_degree = graph
                        .nodes
                        .get(right)
                        .map(|node| node.dependents.len() + node.direct_dependencies.len())
                        .unwrap_or(0);

                    right_degree.cmp(&left_degree)
                })
                .then_with(|| left.to_string().cmp(&right.to_string()))
        });
        ordered
    }

    fn backtrack(
        order: &[PackageId],
        index: usize,
        available_versions: &HashMap<PackageId, Vec<Version>>,
        constraints_by_package: &HashMap<PackageId, Vec<VersionConstraint>>,
        assignments: &mut HashMap<PackageId, Version>,
        conflicts: &mut Vec<ResolutionConflict>,
    ) -> bool {
        if index >= order.len() {
            return true;
        }

        let package_id = &order[index];
        let constraints = constraints_by_package
            .get(package_id)
            .cloned()
            .unwrap_or_default();

        let Some(versions) = available_versions.get(package_id) else {
            conflicts.push(ResolutionConflict {
                package: package_id.clone(),
                conflicting_constraints: constraints,
                message: format!("No versions available for {}", package_id),
            });
            return false;
        };

        let candidates = Self::compatible_versions(versions, &constraints);
        if candidates.is_empty() {
            conflicts.push(ResolutionConflict {
                package: package_id.clone(),
                conflicting_constraints: constraints,
                message: format!("No compatible version found for {}", package_id),
            });
            return false;
        }

        for candidate in candidates {
            assignments.insert(package_id.clone(), candidate.clone());

            if Self::forward_check(order, index + 1, available_versions, constraints_by_package)
                && Self::backtrack(
                    order,
                    index + 1,
                    available_versions,
                    constraints_by_package,
                    assignments,
                    conflicts,
                ) {
                    return true;
                }

            assignments.remove(package_id);
        }

        conflicts.push(ResolutionConflict {
            package: package_id.clone(),
            conflicting_constraints: constraints,
            message: format!(
                "Backtracking exhausted all candidate versions for {}",
                package_id
            ),
        });
        false
    }

    fn forward_check(
        order: &[PackageId],
        next_index: usize,
        available_versions: &HashMap<PackageId, Vec<Version>>,
        constraints_by_package: &HashMap<PackageId, Vec<VersionConstraint>>,
    ) -> bool {
        for package_id in &order[next_index..] {
            let constraints = constraints_by_package
                .get(package_id)
                .cloned()
                .unwrap_or_default();

            let Some(versions) = available_versions.get(package_id) else {
                return false;
            };

            if Self::compatible_versions(versions, &constraints).is_empty() {
                return false;
            }
        }

        true
    }

    fn compatible_versions(
        versions: &[Version],
        constraints: &[VersionConstraint],
    ) -> Vec<Version> {
        let combined_constraint = constraints
            .iter()
            .cloned()
            .try_fold(VersionConstraint::Any, |acc, current| {
                acc.intersect(&current)
            });

        let Some(combined_constraint) = combined_constraint else {
            return Vec::new();
        };

        let mut candidates: Vec<Version> = versions
            .iter()
            .filter(|version| combined_constraint.satisfies(version))
            .cloned()
            .collect();
        candidates.sort();
        candidates.reverse();
        candidates
    }
}

/// Lexicographic optimization for version selection
/// Prioritizes patch > minor > major upgrades
pub struct LexicographicOptimizer;

impl LexicographicOptimizer {
    /// Select the best version using lexicographic optimization
    pub fn select_version(current: Option<&Version>, candidates: &[Version]) -> Option<Version> {
        if candidates.is_empty() {
            return None;
        }

        if let Some(current_version) = current {
            // Find the minimum upgrade (patch > minor > major)
            // Prefer patch upgrades, then minor, then major
            let mut best: Option<&Version> = None;

            for candidate in candidates {
                if candidate <= current_version {
                    continue; // Skip downgrades
                }

                if let Some(current_best) = best {
                    if Self::is_better_upgrade(current_version, candidate, current_best) {
                        best = Some(candidate);
                    }
                } else {
                    best = Some(candidate);
                }
            }

            best.cloned()
        } else {
            // No current version, return latest
            candidates.last().cloned()
        }
    }

    /// Check if candidate1 is a better upgrade than candidate2
    fn is_better_upgrade(current: &Version, candidate1: &Version, candidate2: &Version) -> bool {
        // Prefer patch upgrades
        if candidate1.0.major == current.0.major
            && candidate1.0.minor == current.0.minor
            && (candidate2.0.major != current.0.major || candidate2.0.minor != current.0.minor)
        {
            return true; // candidate1 is patch, candidate2 is not
        }

        // Prefer minor upgrades over major
        if candidate1.0.major == current.0.major && candidate2.0.major != current.0.major {
            return true; // candidate1 is minor, candidate2 is major
        }

        // If both are same type, prefer lower version (minimal upgrade)
        candidate1 < candidate2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DependencyEdge, DependencyGraph, PackageNode};
    use vulnera_core::domain::vulnerability::entities::Package;
    use vulnera_core::domain::vulnerability::value_objects::Ecosystem;

    fn test_package(name: &str, version: &str) -> Package {
        Package::new(
            name.to_string(),
            Version::parse(version).unwrap(),
            Ecosystem::Npm,
        )
        .unwrap()
    }

    #[test]
    fn test_lexicographic_optimizer() {
        let current = Version::parse("1.2.3").unwrap();
        let candidates = vec![
            Version::parse("1.2.4").unwrap(), // patch
            Version::parse("1.3.0").unwrap(), // minor
            Version::parse("2.0.0").unwrap(), // major
        ];

        let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
        assert_eq!(selected, Some(Version::parse("1.2.4").unwrap())); // Should prefer patch
    }

    #[test]
    fn test_lexicographic_optimizer_minor_over_major() {
        let current = Version::parse("1.2.3").unwrap();
        let candidates = vec![
            Version::parse("1.3.0").unwrap(), // minor
            Version::parse("2.0.0").unwrap(), // major
        ];

        let selected = LexicographicOptimizer::select_version(Some(&current), &candidates);
        assert_eq!(selected, Some(Version::parse("1.3.0").unwrap())); // Should prefer minor
    }

    #[test]
    fn test_backtracking_resolver_respects_intersection() {
        let mut graph = DependencyGraph::new();

        let root = test_package("root", "1.0.0");
        let dep = test_package("dep", "1.0.0");

        let root_id = crate::domain::PackageId::from_package(&root);
        let dep_id = crate::domain::PackageId::from_package(&dep);

        graph.add_node(PackageNode::new(root));
        graph.add_node(PackageNode::new(dep));

        graph.add_edge(DependencyEdge::new(
            root_id.clone(),
            dep_id.clone(),
            VersionConstraint::parse(">=1.2.0").unwrap(),
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            root_id.clone(),
            dep_id.clone(),
            VersionConstraint::parse("<2.0.0").unwrap(),
            false,
        ));

        let mut available_versions = HashMap::new();
        available_versions.insert(root_id.clone(), vec![Version::parse("1.0.0").unwrap()]);
        available_versions.insert(
            dep_id.clone(),
            vec![
                Version::parse("1.1.0").unwrap(),
                Version::parse("1.5.0").unwrap(),
                Version::parse("2.0.0").unwrap(),
            ],
        );

        let result = BacktrackingResolver::resolve(&graph, &available_versions);
        assert!(result.conflicts.is_empty());
        assert_eq!(
            result.resolved.get(&dep_id),
            Some(&Version::parse("1.5.0").unwrap())
        );
    }

    #[test]
    fn test_backtracking_resolver_reports_conflicts() {
        let mut graph = DependencyGraph::new();

        let root = test_package("root", "1.0.0");
        let dep = test_package("dep", "1.0.0");

        let root_id = crate::domain::PackageId::from_package(&root);
        let dep_id = crate::domain::PackageId::from_package(&dep);

        graph.add_node(PackageNode::new(root));
        graph.add_node(PackageNode::new(dep));

        graph.add_edge(DependencyEdge::new(
            root_id.clone(),
            dep_id.clone(),
            VersionConstraint::parse(">=2.0.0").unwrap(),
            false,
        ));
        graph.add_edge(DependencyEdge::new(
            root_id.clone(),
            dep_id.clone(),
            VersionConstraint::parse("<2.0.0").unwrap(),
            false,
        ));

        let mut available_versions = HashMap::new();
        available_versions.insert(root_id.clone(), vec![Version::parse("1.0.0").unwrap()]);
        available_versions.insert(
            dep_id.clone(),
            vec![Version::parse("1.5.0").unwrap(), Version::parse("2.1.0").unwrap()],
        );

        let result = BacktrackingResolver::resolve(&graph, &available_versions);
        let conflict = result
            .conflicts
            .iter()
            .find(|conflict| conflict.package == dep_id)
            .expect("expected conflict for dep package");

        assert_eq!(conflict.conflicting_constraints.len(), 2);
    }
}
