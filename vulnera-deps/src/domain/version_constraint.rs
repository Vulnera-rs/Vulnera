//! Version constraint parsing and validation
//!
//! This module provides parsing and manipulation of version constraints
//! (^1.2.3, ~1.2.3, >=1.0.0, etc.) used across different package ecosystems.

use vulnera_core::domain::vulnerability::value_objects::Version;

/// Version constraint for dependency specifications
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VersionConstraint {
    /// Exact version match
    Exact(Version),
    /// Caret range: ^1.2.3 means >=1.2.3 <2.0.0
    Caret(Version),
    /// Tilde range: ~1.2.3 means >=1.2.3 <1.3.0
    Tilde(Version),
    /// Greater than or equal
    GreaterOrEqual(Version),
    /// Less than or equal
    LessOrEqual(Version),
    /// Strictly greater than
    GreaterThan(Version),
    /// Strictly less than
    LessThan(Version),
    /// Range: >=1.0.0,<2.0.0
    Range {
        min: Version,
        max: Version,
        min_inclusive: bool,
        max_inclusive: bool,
    },
    /// Any version (wildcard, *)
    Any,
}

impl VersionConstraint {
    /// Parse a version constraint string
    /// Supports: ^, ~, >=, <=, >, <, ==, ranges, and wildcards
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();

        if s.is_empty() || s == "*" || s == "latest" {
            return Ok(VersionConstraint::Any);
        }

        // Range: >=1.0.0,<2.0.0 or 1.0.0 - 2.0.0
        if s.contains(',') || s.contains(" - ") {
            return Self::parse_range(s);
        }

        // Exact version (== prefix or no prefix)
        if let Some(version_str) = s.strip_prefix("==") {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::Exact(version));
        }

        // Caret range: ^1.2.3
        if let Some(version_str) = s.strip_prefix('^') {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::Caret(version));
        }

        // Tilde range: ~1.2.3
        if let Some(version_str) = s.strip_prefix('~') {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::Tilde(version));
        }

        // Greater or equal: >=1.0.0
        if let Some(version_str) = s.strip_prefix(">=") {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::GreaterOrEqual(version));
        }

        // Less or equal: <=1.0.0
        if let Some(version_str) = s.strip_prefix("<=") {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::LessOrEqual(version));
        }

        // Greater than: >1.0.0
        if let Some(version_str) = s.strip_prefix('>') {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::GreaterThan(version));
        }

        // Less than: <1.0.0
        if let Some(version_str) = s.strip_prefix('<') {
            let version = Version::parse(version_str.trim())
                .map_err(|e| format!("Invalid version in constraint: {}", e))?;
            return Ok(VersionConstraint::LessThan(version));
        }

        // Try parsing as exact version (no prefix)
        if let Ok(version) = Version::parse(s) {
            return Ok(VersionConstraint::Exact(version));
        }

        Err(format!("Unable to parse version constraint: {}", s))
    }

    /// Parse a range constraint
    fn parse_range(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = if s.contains(',') {
            s.split(',').collect()
        } else {
            s.split(" - ").collect()
        };

        if parts.len() != 2 {
            return Err(format!("Invalid range format: {}", s));
        }

        let min_str = parts[0].trim();
        let max_str = parts[1].trim();

        let (min, min_inclusive) = if let Some(v) = min_str.strip_prefix(">=") {
            (
                Version::parse(v.trim()).map_err(|e| format!("Invalid min version: {}", e))?,
                true,
            )
        } else if let Some(v) = min_str.strip_prefix('>') {
            (
                Version::parse(v.trim()).map_err(|e| format!("Invalid min version: {}", e))?,
                false,
            )
        } else {
            // Assume >= if no prefix
            (
                Version::parse(min_str).map_err(|e| format!("Invalid min version: {}", e))?,
                true,
            )
        };

        let (max, max_inclusive) = if let Some(v) = max_str.strip_prefix("<=") {
            (
                Version::parse(v.trim()).map_err(|e| format!("Invalid max version: {}", e))?,
                true,
            )
        } else if let Some(v) = max_str.strip_prefix('<') {
            (
                Version::parse(v.trim()).map_err(|e| format!("Invalid max version: {}", e))?,
                false,
            )
        } else {
            // Assume < if no prefix
            (
                Version::parse(max_str).map_err(|e| format!("Invalid max version: {}", e))?,
                false,
            )
        };

        Ok(VersionConstraint::Range {
            min,
            max,
            min_inclusive,
            max_inclusive,
        })
    }

    /// Check if a version satisfies this constraint
    pub fn satisfies(&self, version: &Version) -> bool {
        match self {
            VersionConstraint::Exact(v) => version == v,
            VersionConstraint::Caret(v) => {
                // ^1.2.3 means >=1.2.3 <2.0.0
                version >= v && version < &Version::new(v.0.major + 1, 0, 0)
            }
            VersionConstraint::Tilde(v) => {
                // ~1.2.3 means >=1.2.3 <1.3.0
                version >= v && version < &Version::new(v.0.major, v.0.minor + 1, 0)
            }
            VersionConstraint::GreaterOrEqual(v) => version >= v,
            VersionConstraint::LessOrEqual(v) => version <= v,
            VersionConstraint::GreaterThan(v) => version > v,
            VersionConstraint::LessThan(v) => version < v,
            VersionConstraint::Range {
                min,
                max,
                min_inclusive,
                max_inclusive,
            } => {
                let min_ok = if *min_inclusive {
                    version >= min
                } else {
                    version > min
                };
                let max_ok = if *max_inclusive {
                    version <= max
                } else {
                    version < max
                };
                min_ok && max_ok
            }
            VersionConstraint::Any => true,
        }
    }

    /// Get the minimum version that satisfies this constraint (if applicable)
    pub fn min_version(&self) -> Option<Version> {
        match self {
            VersionConstraint::Exact(v) => Some(v.clone()),
            VersionConstraint::Caret(v) => Some(v.clone()),
            VersionConstraint::Tilde(v) => Some(v.clone()),
            VersionConstraint::GreaterOrEqual(v) => Some(v.clone()),
            VersionConstraint::GreaterThan(v) => {
                // Next patch version
                Some(Version::new(v.0.major, v.0.minor, v.0.patch + 1))
            }
            VersionConstraint::Range { min, .. } => Some(min.clone()),
            _ => None,
        }
    }

    /// Intersect two constraints (find versions that satisfy both)
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let lower = match (self.lower_bound(), other.lower_bound()) {
            (None, None) => None,
            (Some(bound), None) | (None, Some(bound)) => Some(bound),
            (Some(left), Some(right)) => Some(max_lower_bound(left, right)),
        };

        let upper = match (self.upper_bound(), other.upper_bound()) {
            (None, None) => None,
            (Some(bound), None) | (None, Some(bound)) => Some(bound),
            (Some(left), Some(right)) => Some(min_upper_bound(left, right)),
        };

        match (lower, upper) {
            (Some(low), Some(high)) => {
                if low.version > high.version {
                    return None;
                }

                if low.version == high.version {
                    if low.inclusive && high.inclusive {
                        return Some(VersionConstraint::Exact(low.version));
                    }
                    return None;
                }

                Some(VersionConstraint::Range {
                    min: low.version,
                    max: high.version,
                    min_inclusive: low.inclusive,
                    max_inclusive: high.inclusive,
                })
            }
            (Some(low), None) => {
                if low.inclusive {
                    Some(VersionConstraint::GreaterOrEqual(low.version))
                } else {
                    Some(VersionConstraint::GreaterThan(low.version))
                }
            }
            (None, Some(high)) => {
                if high.inclusive {
                    Some(VersionConstraint::LessOrEqual(high.version))
                } else {
                    Some(VersionConstraint::LessThan(high.version))
                }
            }
            (None, None) => Some(VersionConstraint::Any),
        }
    }

    fn lower_bound(&self) -> Option<VersionBound> {
        match self {
            VersionConstraint::Any => None,
            VersionConstraint::Exact(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::Caret(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::Tilde(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::GreaterOrEqual(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::GreaterThan(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: false,
            }),
            VersionConstraint::LessOrEqual(_) | VersionConstraint::LessThan(_) => None,
            VersionConstraint::Range {
                min, min_inclusive, ..
            } => Some(VersionBound {
                version: min.clone(),
                inclusive: *min_inclusive,
            }),
        }
    }

    fn upper_bound(&self) -> Option<VersionBound> {
        match self {
            VersionConstraint::Any => None,
            VersionConstraint::Exact(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::Caret(v) => Some(VersionBound {
                version: caret_upper_bound(v),
                inclusive: false,
            }),
            VersionConstraint::Tilde(v) => Some(VersionBound {
                version: Version::new(v.0.major, v.0.minor + 1, 0),
                inclusive: false,
            }),
            VersionConstraint::GreaterOrEqual(_) | VersionConstraint::GreaterThan(_) => None,
            VersionConstraint::LessOrEqual(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: true,
            }),
            VersionConstraint::LessThan(v) => Some(VersionBound {
                version: v.clone(),
                inclusive: false,
            }),
            VersionConstraint::Range {
                max, max_inclusive, ..
            } => Some(VersionBound {
                version: max.clone(),
                inclusive: *max_inclusive,
            }),
        }
    }
}

#[derive(Clone)]
struct VersionBound {
    version: Version,
    inclusive: bool,
}

fn max_lower_bound(left: VersionBound, right: VersionBound) -> VersionBound {
    if left.version > right.version {
        left
    } else if right.version > left.version {
        right
    } else {
        VersionBound {
            version: left.version,
            inclusive: left.inclusive && right.inclusive,
        }
    }
}

fn min_upper_bound(left: VersionBound, right: VersionBound) -> VersionBound {
    if left.version < right.version {
        left
    } else if right.version < left.version {
        right
    } else {
        VersionBound {
            version: left.version,
            inclusive: left.inclusive && right.inclusive,
        }
    }
}

fn caret_upper_bound(version: &Version) -> Version {
    if version.0.major > 0 {
        Version::new(version.0.major + 1, 0, 0)
    } else if version.0.minor > 0 {
        Version::new(0, version.0.minor + 1, 0)
    } else {
        Version::new(0, 0, version.0.patch + 1)
    }
}

impl std::fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionConstraint::Exact(v) => write!(f, "=={}", v),
            VersionConstraint::Caret(v) => write!(f, "^{}", v),
            VersionConstraint::Tilde(v) => write!(f, "~{}", v),
            VersionConstraint::GreaterOrEqual(v) => write!(f, ">={}", v),
            VersionConstraint::LessOrEqual(v) => write!(f, "<={}", v),
            VersionConstraint::GreaterThan(v) => write!(f, ">{}", v),
            VersionConstraint::LessThan(v) => write!(f, "<{}", v),
            VersionConstraint::Range {
                min,
                max,
                min_inclusive,
                max_inclusive,
            } => {
                let min_op = if *min_inclusive { ">=" } else { ">" };
                let max_op = if *max_inclusive { "<=" } else { "<" };
                write!(f, "{}{}, {}{}", min_op, min, max_op, max)
            }
            VersionConstraint::Any => write!(f, "*"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exact() {
        let c = VersionConstraint::parse("1.2.3").unwrap();
        assert!(matches!(c, VersionConstraint::Exact(_)));
        assert!(c.satisfies(&Version::parse("1.2.3").unwrap()));
        assert!(!c.satisfies(&Version::parse("1.2.4").unwrap()));
    }

    #[test]
    fn test_parse_caret() {
        let c = VersionConstraint::parse("^1.2.3").unwrap();
        assert!(matches!(c, VersionConstraint::Caret(_)));
        assert!(c.satisfies(&Version::parse("1.2.3").unwrap()));
        assert!(c.satisfies(&Version::parse("1.9.9").unwrap()));
        assert!(!c.satisfies(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn test_parse_tilde() {
        let c = VersionConstraint::parse("~1.2.3").unwrap();
        assert!(matches!(c, VersionConstraint::Tilde(_)));
        assert!(c.satisfies(&Version::parse("1.2.3").unwrap()));
        assert!(c.satisfies(&Version::parse("1.2.9").unwrap()));
        assert!(!c.satisfies(&Version::parse("1.3.0").unwrap()));
    }

    #[test]
    fn test_parse_range() {
        let c = VersionConstraint::parse(">=1.0.0,<2.0.0").unwrap();
        assert!(matches!(c, VersionConstraint::Range { .. }));
        assert!(c.satisfies(&Version::parse("1.5.0").unwrap()));
        assert!(!c.satisfies(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn test_parse_any() {
        let c = VersionConstraint::parse("*").unwrap();
        assert!(matches!(c, VersionConstraint::Any));
        assert!(c.satisfies(&Version::parse("1.0.0").unwrap()));
        assert!(c.satisfies(&Version::parse("999.999.999").unwrap()));
    }

    #[test]
    fn test_intersect_lower_and_upper_bounds() {
        let ge = VersionConstraint::parse(">=1.2.0").unwrap();
        let lt = VersionConstraint::parse("<2.0.0").unwrap();

        let intersection = ge.intersect(&lt).unwrap();
        assert!(intersection.satisfies(&Version::parse("1.5.0").unwrap()));
        assert!(!intersection.satisfies(&Version::parse("2.0.0").unwrap()));
        assert!(!intersection.satisfies(&Version::parse("1.1.9").unwrap()));
    }

    #[test]
    fn test_intersect_exact_conflict() {
        let first = VersionConstraint::parse("==1.2.3").unwrap();
        let second = VersionConstraint::parse("==1.2.4").unwrap();
        assert!(first.intersect(&second).is_none());
    }

    #[test]
    fn test_intersect_exact_in_range() {
        let exact = VersionConstraint::parse("==1.2.3").unwrap();
        let range = VersionConstraint::parse(">=1.0.0,<2.0.0").unwrap();

        let intersection = exact.intersect(&range).unwrap();
        assert_eq!(
            intersection,
            VersionConstraint::Exact(Version::parse("1.2.3").unwrap())
        );
    }
}
