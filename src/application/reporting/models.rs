//! Report data models
//!
//! This module defines the data structures used for report generation.

use crate::domain::vulnerability::entities::Vulnerability;
use crate::domain::vulnerability::value_objects::{Severity, VulnerabilityId};

/// Structured report data for API consumption
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructuredReport {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub summary: ReportSummary,
    pub severity_breakdown: crate::domain::vulnerability::entities::SeverityBreakdown,
    pub package_summaries: Vec<PackageSummary>,
    pub prioritized_vulnerabilities: Vec<Vulnerability>,
}

/// Summary statistics for the report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub clean_packages: usize,
    pub total_vulnerabilities: usize,
    pub vulnerability_percentage: f64,
    pub analysis_duration: std::time::Duration,
    pub sources_queried: Vec<String>,
}

/// Package summary with vulnerability information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageSummary {
    pub name: String,
    pub version: crate::domain::vulnerability::value_objects::Version,
    pub ecosystem: crate::domain::vulnerability::value_objects::Ecosystem,
    pub vulnerability_count: usize,
    pub highest_severity: Severity,
    pub vulnerabilities: Vec<VulnerabilityId>,
}


