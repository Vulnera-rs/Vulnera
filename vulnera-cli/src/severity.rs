//! Severity Utilities - Shared severity parsing and comparison
//!
//! This module provides unified severity handling used across all CLI commands
//! to eliminate code duplication and ensure consistent behavior.

use vulnera_core::domain::module::FindingSeverity;

/// Parse a severity string to FindingSeverity enum
///
/// Supports case-insensitive matching. Unknown values default to `Low`.
///
/// # Examples
/// ```
/// use vulnera_cli::severity::parse_severity;
/// use vulnera_core::domain::module::FindingSeverity;
///
/// assert_eq!(parse_severity("critical"), FindingSeverity::Critical);
/// assert_eq!(parse_severity("HIGH"), FindingSeverity::High);
/// assert_eq!(parse_severity("unknown"), FindingSeverity::Low);
/// ```
pub fn parse_severity(s: &str) -> FindingSeverity {
    match s.to_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        "info" => FindingSeverity::Info,
        _ => FindingSeverity::Low,
    }
}

/// Convert FindingSeverity to a numeric level for comparison
///
/// Higher values indicate more severe findings:
/// - Critical: 4
/// - High: 3
/// - Medium: 2
/// - Low: 1
/// - Info: 0
pub fn severity_to_level(severity: &FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 1,
        FindingSeverity::Info => 0,
    }
}

/// Convert a severity string to a numeric level for comparison
pub fn severity_str_to_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0,
    }
}

/// Check if a finding severity meets the minimum threshold
///
/// Returns `true` if `severity` is at least as severe as `minimum`.
///
/// # Examples
/// ```
/// use vulnera_cli::severity::severity_meets_minimum;
/// use vulnera_core::domain::module::FindingSeverity;
///
/// // Critical meets any minimum
/// assert!(severity_meets_minimum(&FindingSeverity::Critical, &FindingSeverity::High));
///
/// // Low doesn't meet High minimum
/// assert!(!severity_meets_minimum(&FindingSeverity::Low, &FindingSeverity::High));
/// ```
pub fn severity_meets_minimum(severity: &FindingSeverity, minimum: &FindingSeverity) -> bool {
    severity_to_level(severity) >= severity_to_level(minimum)
}

/// Check if a severity string meets the minimum threshold string
///
/// Case-insensitive comparison. Returns `true` if `severity` is at least as severe as `minimum`.
pub fn severity_meets_minimum_str(severity: &str, minimum: &str) -> bool {
    severity_str_to_level(severity) >= severity_str_to_level(minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), FindingSeverity::Critical);
        assert_eq!(parse_severity("high"), FindingSeverity::High);
        assert_eq!(parse_severity("medium"), FindingSeverity::Medium);
        assert_eq!(parse_severity("low"), FindingSeverity::Low);
        assert_eq!(parse_severity("info"), FindingSeverity::Info);
        assert_eq!(parse_severity("unknown"), FindingSeverity::Low); // Default fallback
        assert_eq!(parse_severity("CRITICAL"), FindingSeverity::Critical); // Case insensitive
        assert_eq!(parse_severity("High"), FindingSeverity::High); // Mixed case
    }

    #[test]
    fn test_severity_to_level() {
        assert_eq!(severity_to_level(&FindingSeverity::Critical), 4);
        assert_eq!(severity_to_level(&FindingSeverity::High), 3);
        assert_eq!(severity_to_level(&FindingSeverity::Medium), 2);
        assert_eq!(severity_to_level(&FindingSeverity::Low), 1);
        assert_eq!(severity_to_level(&FindingSeverity::Info), 0);
    }

    #[test]
    fn test_severity_str_to_level() {
        assert_eq!(severity_str_to_level("critical"), 4);
        assert_eq!(severity_str_to_level("CRITICAL"), 4);
        assert_eq!(severity_str_to_level("high"), 3);
        assert_eq!(severity_str_to_level("medium"), 2);
        assert_eq!(severity_str_to_level("low"), 1);
        assert_eq!(severity_str_to_level("info"), 0);
        assert_eq!(severity_str_to_level("unknown"), 0);
    }

    #[test]
    fn test_severity_meets_minimum() {
        // Critical meets everything
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Medium
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Low
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Info
        ));

        // High meets High and below, but not Critical
        assert!(!severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Low
        ));

        // Low only meets Low and Info
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Critical
        ));
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::High
        ));
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Medium
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Low
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Info
        ));
    }

    #[test]
    fn test_severity_meets_minimum_str() {
        assert!(severity_meets_minimum_str("critical", "high"));
        assert!(severity_meets_minimum_str("high", "high"));
        assert!(!severity_meets_minimum_str("medium", "high"));
        assert!(!severity_meets_minimum_str("low", "high"));

        // Case insensitive
        assert!(severity_meets_minimum_str("CRITICAL", "high"));
        assert!(severity_meets_minimum_str("critical", "HIGH"));
    }
}
