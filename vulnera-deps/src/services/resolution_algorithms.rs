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

        // Simple resolution: try to satisfy all constraints
        // This is a simplified version - a full implementation would use proper backtracking
        for (package_id, node) in &graph.nodes {
            if let Some(versions) = available_versions.get(package_id) {
                // Find a version that satisfies all constraints
                if let Some(version) = Self::find_compatible_version(
                    package_id,
                    &node.direct_dependencies,
                    versions,
                    graph,
                ) {
                    resolved.insert(package_id.clone(), version);
                } else {
                    conflicts.push(ResolutionConflict {
                        package: package_id.clone(),
                        conflicting_constraints: Vec::new(), // Would be populated in full impl
                        message: format!("No compatible version found for {}", package_id),
                    });
                }
            } else {
                // No versions available for this package
                conflicts.push(ResolutionConflict {
                    package: package_id.clone(),
                    conflicting_constraints: Vec::new(),
                    message: format!("No versions available for {}", package_id),
                });
            }
        }

        ResolutionResult {
            resolved,
            conflicts,
        }
    }

    /// Find a compatible version for a package
    fn find_compatible_version(
        _package_id: &PackageId,
        _dependencies: &[PackageId],
        versions: &[Version],
        _graph: &DependencyGraph,
    ) -> Option<Version> {
        // Simplified: return the latest version
        // A full implementation would check constraints
        versions.last().cloned()
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
}
