//! Report service for generating vulnerability analysis reports

use async_trait::async_trait;

use tracing::info;

use crate::application::errors::ApplicationError;
use crate::application::reporting::formats::html;
use crate::application::reporting::{PackageSummary, ReportSummary, StructuredReport};
use crate::domain::vulnerability::entities::{AnalysisMetadata, AnalysisReport, Vulnerability};
use crate::domain::vulnerability::value_objects::Severity;

/// Service for generating and formatting reports
#[async_trait]
pub trait ReportService: Send + Sync {
    async fn generate_report(&self, analysis: &AnalysisReport) -> Result<String, ApplicationError>;
    async fn generate_html_report(
        &self,
        analysis: &AnalysisReport,
    ) -> Result<String, ApplicationError>;
}

/// Report service implementation with advanced features
pub struct ReportServiceImpl {
    deduplication_enabled: bool,
    include_metadata: bool,
}

impl ReportServiceImpl {
    /// Create a new report service implementation
    pub fn new() -> Self {
        Self {
            deduplication_enabled: true,
            include_metadata: true,
        }
    }

    /// Create a new report service with custom configuration
    pub fn with_config(deduplication_enabled: bool, include_metadata: bool) -> Self {
        Self {
            deduplication_enabled,
            include_metadata,
        }
    }

    /// Deduplicate vulnerabilities across multiple sources
    pub fn deduplicate_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        if !self.deduplication_enabled {
            return vulnerabilities;
        }

        let mut deduplicated: Vec<Vulnerability> = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        let original_count = vulnerabilities.len();

        for vulnerability in vulnerabilities {
            let id_str = vulnerability.id.as_str();

            if seen_ids.contains(id_str) {
                // Find existing vulnerability and merge sources
                if let Some(existing) = deduplicated.iter_mut().find(|v| v.id.as_str() == id_str) {
                    // Merge sources from duplicate vulnerability
                    for source in vulnerability.sources {
                        if !existing.sources.contains(&source) {
                            existing.sources.push(source);
                        }
                    }

                    // Merge references
                    for reference in vulnerability.references {
                        if !existing.references.contains(&reference) {
                            existing.references.push(reference);
                        }
                    }

                    // Use the higher severity if different
                    if vulnerability.severity > existing.severity {
                        existing.severity = vulnerability.severity.clone();
                    }
                }
            } else {
                seen_ids.insert(id_str.to_string());
                deduplicated.push(vulnerability);
            }
        }

        info!(
            "Deduplicated {} vulnerabilities down to {}",
            original_count,
            deduplicated.len()
        );

        deduplicated
    }

    /// Calculate severity score for prioritization
    pub fn calculate_severity_score(&self, vulnerability: &Vulnerability) -> f64 {
        let base_score = match vulnerability.severity {
            Severity::Critical => 10.0,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 2.5,
        };

        // Adjust score based on number of affected packages
        let package_multiplier = 1.0 + (vulnerability.affected_packages.len() as f64 * 0.1);

        // Adjust score based on number of sources (more sources = higher confidence)
        let source_multiplier = 1.0 + (vulnerability.sources.len() as f64 * 0.05);

        // Adjust score based on age (newer vulnerabilities might be more critical)
        let age_days = chrono::Utc::now()
            .signed_duration_since(vulnerability.published_at)
            .num_days();
        let age_multiplier = if age_days < 30 {
            1.2 // Recent vulnerabilities get higher priority
        } else if age_days < 365 {
            1.0
        } else {
            0.9 // Older vulnerabilities get slightly lower priority
        };

        base_score * package_multiplier * source_multiplier * age_multiplier
    }

    /// Sort vulnerabilities by priority (severity score)
    pub fn prioritize_vulnerabilities(
        &self,
        mut vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        vulnerabilities.sort_by(|a, b| {
            let score_a = self.calculate_severity_score(a);
            let score_b = self.calculate_severity_score(b);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        vulnerabilities
    }

    /// Generate comprehensive analysis metadata
    pub fn generate_analysis_metadata(&self, report: &AnalysisReport) -> AnalysisMetadata {
        let mut metadata = report.metadata.clone();

        if self.include_metadata {
            // Add additional metadata calculations
            let vulnerability_sources: std::collections::HashSet<_> = report
                .vulnerabilities
                .iter()
                .flat_map(|v| &v.sources)
                .collect();

            let unique_sources: Vec<String> = vulnerability_sources
                .iter()
                .map(|source| format!("{:?}", source))
                .collect();

            // Update sources queried with actual sources found
            metadata.sources_queried = unique_sources;
        }

        metadata
    }

    /// Generate text report format
    pub fn generate_text_report(&self, analysis: &AnalysisReport) -> String {
        let mut report = String::new();

        // Header
        report.push_str("# Vulnerability Analysis Report\n\n");
        report.push_str(&format!(
            "Generated: {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str(&format!("Analysis ID: {}\n\n", analysis.id));

        // Summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- Total packages analyzed: {}\n",
            analysis.metadata.total_packages
        ));
        report.push_str(&format!(
            "- Vulnerable packages: {}\n",
            analysis.metadata.vulnerable_packages
        ));
        report.push_str(&format!(
            "- Total vulnerabilities: {}\n",
            analysis.metadata.total_vulnerabilities
        ));
        report.push_str(&format!(
            "- Analysis duration: {:?}\n\n",
            analysis.metadata.analysis_duration
        ));

        // Severity breakdown
        report.push_str("## Severity Breakdown\n\n");
        let breakdown = &analysis.metadata.severity_breakdown;
        report.push_str(&format!("- Critical: {}\n", breakdown.critical));
        report.push_str(&format!("- High: {}\n", breakdown.high));
        report.push_str(&format!("- Medium: {}\n", breakdown.medium));
        report.push_str(&format!("- Low: {}\n\n", breakdown.low));

        // Vulnerable packages
        if !analysis.vulnerabilities.is_empty() {
            report.push_str("## Vulnerable Packages\n\n");

            let vulnerable_packages = analysis.vulnerable_packages();
            for package in vulnerable_packages {
                report.push_str(&format!("### {}\n\n", package.identifier()));

                let package_vulns = analysis.vulnerabilities_for_package(package);
                for vuln in package_vulns {
                    report.push_str(&format!("- **{}** ({})\n", vuln.id.as_str(), vuln.severity));
                    report.push_str(&format!("  {}\n", vuln.summary));
                    if !vuln.references.is_empty() {
                        report.push_str(&format!("  References: {}\n", vuln.references.join(", ")));
                    }
                    report.push('\n');
                }
            }
        }

        // Clean packages
        let clean_packages = analysis.clean_packages();
        if !clean_packages.is_empty() {
            report.push_str("## Clean Packages\n\n");
            for package in clean_packages {
                report.push_str(&format!("- {}\n", package.identifier()));
            }
            report.push('\n');
        }

        report
    }

    /// Generate structured report data for frontend consumption
    pub fn generate_structured_report(&self, analysis: &AnalysisReport) -> StructuredReport {
        let vulnerable_packages = analysis.vulnerable_packages();
        let clean_packages = analysis.clean_packages();

        let vulnerability_percentage = if analysis.metadata.total_packages > 0 {
            (analysis.metadata.vulnerable_packages as f64 / analysis.metadata.total_packages as f64)
                * 100.0
        } else {
            0.0
        };

        let package_summaries: Vec<PackageSummary> = vulnerable_packages
            .iter()
            .map(|package| {
                let package_vulns = analysis.vulnerabilities_for_package(package);
                let highest_severity = package_vulns
                    .iter()
                    .map(|v| &v.severity)
                    .max()
                    .cloned()
                    .unwrap_or(Severity::Low);

                PackageSummary {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    ecosystem: package.ecosystem.clone(),
                    vulnerability_count: package_vulns.len(),
                    highest_severity,
                    vulnerabilities: package_vulns.iter().map(|v| v.id.clone()).collect(),
                }
            })
            .collect();

        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(analysis.vulnerabilities.clone());

        StructuredReport {
            id: analysis.id,
            created_at: analysis.created_at,
            summary: ReportSummary {
                total_packages: analysis.metadata.total_packages,
                vulnerable_packages: analysis.metadata.vulnerable_packages,
                clean_packages: clean_packages.len(),
                total_vulnerabilities: analysis.metadata.total_vulnerabilities,
                vulnerability_percentage,
                analysis_duration: analysis.metadata.analysis_duration,
                sources_queried: analysis.metadata.sources_queried.clone(),
            },
            severity_breakdown: analysis.metadata.severity_breakdown.clone(),
            package_summaries,
            prioritized_vulnerabilities,
        }
    }
}

impl Default for ReportServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReportService for ReportServiceImpl {
    async fn generate_report(&self, analysis: &AnalysisReport) -> Result<String, ApplicationError> {
        info!("Generating text report for analysis: {}", analysis.id);

        // Create a copy of the analysis with deduplicated vulnerabilities
        let deduplicated_vulnerabilities =
            self.deduplicate_vulnerabilities(analysis.vulnerabilities.clone());
        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(deduplicated_vulnerabilities);

        // Create a new analysis report with processed vulnerabilities
        let processed_analysis = AnalysisReport {
            id: analysis.id,
            packages: analysis.packages.clone(),
            vulnerabilities: prioritized_vulnerabilities,
            metadata: self.generate_analysis_metadata(analysis),
            created_at: analysis.created_at,
        };

        let report = self.generate_text_report(&processed_analysis);

        info!("Generated text report ({} characters)", report.len());
        Ok(report)
    }

    async fn generate_html_report(
        &self,
        analysis: &AnalysisReport,
    ) -> Result<String, ApplicationError> {
        info!("Generating HTML report for analysis: {}", analysis.id);

        // Create a copy of the analysis with deduplicated vulnerabilities
        let deduplicated_vulnerabilities =
            self.deduplicate_vulnerabilities(analysis.vulnerabilities.clone());
        let prioritized_vulnerabilities =
            self.prioritize_vulnerabilities(deduplicated_vulnerabilities);

        // Create a new analysis report with processed vulnerabilities
        let processed_analysis = AnalysisReport {
            id: analysis.id,
            packages: analysis.packages.clone(),
            vulnerabilities: prioritized_vulnerabilities,
            metadata: analysis.metadata.clone(),
            created_at: analysis.created_at,
        };

        let report = html::generate_html_report(&processed_analysis)?;

        info!("Generated HTML report ({} characters)", report.len());
        Ok(report)
    }
}
