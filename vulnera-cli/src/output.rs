//! Output Formatting - Table, JSON, and plain text output
//!
//! This module provides consistent output formatting across all CLI commands
//! with support for tables, JSON, plain text, and SARIF formats.

use std::io;

use comfy_table::{Cell, Color, ContentArrangement, Table, presets};
use console::{Style, style};
use serde::Serialize;

/// Vulnera ASCII Art Banner
const VULNERA_BANNER: &str = r#"
  ╔═══════════════════════════════════════╗
  ║   ██╗   ██╗██╗   ██╗██╗     ███████╗  ║
  ║   ██║   ██║██║   ██║██║     ██╔════╝  ║
  ║   ██║   ██║██║   ██║██║     ███████╗  ║
  ║   ██║   ██║██║   ██║██║     ╚════██║  ║
  ║   ╚██████╔╝╚██████╔╝███████╗███████║  ║
  ║    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝  ║
  ║                                       ║
  ║  Comprehensive Vulnerability Scanner  ║
  ╚═══════════════════════════════════════╝
"#;

/// Output format options
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed table format (default for interactive use)
    #[default]
    Table,
    /// JSON output for machine processing
    Json,
    /// Plain text output (minimal formatting)
    Plain,
    /// SARIF format for IDE/CI integration
    Sarif,
}

/// Output writer that handles formatting based on configuration
pub struct OutputWriter {
    format: OutputFormat,
    quiet: bool,
    verbose: bool,
}

impl OutputWriter {
    /// Create a new output writer
    pub fn new(format: OutputFormat, quiet: bool, verbose: bool) -> Self {
        Self {
            format,
            quiet,
            verbose,
        }
    }

    /// Get the output format
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Check if quiet mode is enabled
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Check if verbose mode is enabled
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Print a success message
    pub fn success(&self, message: &str) {
        if self.quiet {
            return;
        }
        println!("{} {}", style("✓").green().bold(), message);
    }

    /// Print a warning message
    pub fn warn(&self, message: &str) {
        if self.quiet {
            return;
        }
        eprintln!("{} {}", style("⚠").yellow().bold(), message);
    }

    /// Print an error message
    pub fn error(&self, message: &str) {
        eprintln!("{} {}", style("✗").red().bold(), message);
    }

    /// Print the Vulnera banner (only in non-quiet, non-JSON modes)
    pub fn banner(&self) {
        if self.quiet || self.format == OutputFormat::Json || self.format == OutputFormat::Sarif {
            return;
        }
        println!("{}", style(VULNERA_BANNER).cyan());
    }

    /// Print a section divider
    pub fn divider(&self) {
        if self.quiet || self.format == OutputFormat::Json || self.format == OutputFormat::Sarif {
            return;
        }
        println!("{}", style("─".repeat(50)).dim());
    }

    /// Print a summary section with styled heading
    pub fn summary(&self, title: &str, count: usize, severity: &str) {
        if self.quiet || self.format == OutputFormat::Json {
            return;
        }
        let icon = match severity {
            "critical" => style("●").red().bold(),
            "high" => style("●").red(),
            "medium" => style("●").yellow(),
            "low" => style("●").yellow().dim(),
            _ => style("●").white().dim(),
        };
        println!("{} {} {}", icon, style(title).bold(), count);
    }

    /// Print an info message
    pub fn info(&self, message: &str) {
        if self.quiet {
            return;
        }
        println!("{} {}", style("ℹ").cyan().bold(), message);
    }

    /// Print a debug message (only in verbose mode)
    pub fn debug(&self, message: &str) {
        if !self.verbose {
            return;
        }
        println!("{} {}", style("⋯").dim(), style(message).dim());
    }

    /// Print a header/title with styled formatting
    pub fn header(&self, title: &str) {
        if self.quiet {
            return;
        }
        match self.format {
            OutputFormat::Table | OutputFormat::Plain => {
                self.divider();
                println!("  {}", style(title).bold().cyan());
                self.divider();
            }
            OutputFormat::Json | OutputFormat::Sarif => {
                // Headers are part of JSON structure
            }
        }
    }

    /// Print raw output (respects quiet mode)
    pub fn print(&self, message: &str) {
        if self.quiet {
            return;
        }
        println!("{}", message);
    }

    /// Print raw output to stderr
    pub fn eprint(&self, message: &str) {
        eprintln!("{}", message);
    }

    /// Print JSON output (always prints, ignores quiet)
    pub fn json<T: Serialize + ?Sized>(&self, data: &T) -> io::Result<()> {
        let json = serde_json::to_string_pretty(data)?;
        println!("{}", json);
        Ok(())
    }

    /// Print a table
    pub fn table(&self, table: &Table) {
        if self.quiet {
            return;
        }
        println!("{}", table);
    }

    /// Create a new styled table
    pub fn create_table(&self) -> Table {
        let mut table = Table::new();
        table
            .load_preset(presets::UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic);
        table
    }

    /// Create a table with headers
    pub fn create_table_with_headers(&self, headers: &[&str]) -> Table {
        let mut table = self.create_table();
        table.set_header(
            headers
                .iter()
                .map(|h| Cell::new(h).fg(Color::Cyan))
                .collect::<Vec<_>>(),
        );
        table
    }

    /// Output vulnerabilities in the appropriate format
    pub fn vulnerabilities<T: Serialize + VulnerabilityDisplay>(
        &self,
        vulnerabilities: &[T],
    ) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => self.json(vulnerabilities),
            OutputFormat::Sarif => self.sarif_internal(vulnerabilities),
            OutputFormat::Table => {
                self.vulnerability_table(vulnerabilities);
                Ok(())
            }
            OutputFormat::Plain => {
                self.vulnerability_plain(vulnerabilities);
                Ok(())
            }
        }
    }

    /// Print vulnerabilities as a table
    fn vulnerability_table<T: VulnerabilityDisplay>(&self, vulnerabilities: &[T]) {
        if vulnerabilities.is_empty() {
            self.success("No vulnerabilities found!");
            return;
        }

        let mut table = self.create_table_with_headers(&[
            "Severity",
            "ID",
            "Package",
            "Version",
            "Description",
        ]);

        for vuln in vulnerabilities {
            let severity = vuln.severity();
            let severity_style = match severity.to_lowercase().as_str() {
                "critical" => Style::new().red().bold(),
                "high" => Style::new().red(),
                "medium" => Style::new().yellow(),
                "low" => Style::new().blue(),
                _ => Style::new().dim(),
            };

            table.add_row(vec![
                Cell::new(severity_style.apply_to(&severity)),
                Cell::new(vuln.id()),
                Cell::new(vuln.package()),
                Cell::new(vuln.version()),
                Cell::new(truncate_string(&vuln.description(), 50)),
            ]);
        }

        self.table(&table);
        println!(
            "\n{} {} vulnerabilities found",
            style("Total:").bold(),
            vulnerabilities.len()
        );
    }

    /// Print vulnerabilities as plain text
    fn vulnerability_plain<T: VulnerabilityDisplay>(&self, vulnerabilities: &[T]) {
        if vulnerabilities.is_empty() {
            println!("No vulnerabilities found");
            return;
        }

        for vuln in vulnerabilities {
            println!(
                "[{}] {} - {} {} - {}",
                vuln.severity(),
                vuln.id(),
                vuln.package(),
                vuln.version(),
                vuln.description()
            );
        }

        println!("\nTotal: {} vulnerabilities", vulnerabilities.len());
    }

    /// Print findings as a table (public method for commands)
    pub fn print_findings_table<T: VulnerabilityDisplay>(&self, findings: &[T]) {
        self.vulnerability_table(findings);
    }

    /// Print findings in SARIF format (public method for commands)
    pub fn sarif<T: VulnerabilityDisplay + Serialize>(
        &self,
        findings: &[T],
        tool_name: &str,
        tool_version: &str,
    ) -> io::Result<()> {
        // Convert findings to SARIF results
        let results: Vec<serde_json::Value> = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                serde_json::json!({
                    "ruleId": f.id(),
                    "level": match f.severity().to_lowercase().as_str() {
                        "critical" | "high" => "error",
                        "medium" => "warning",
                        _ => "note"
                    },
                    "message": {
                        "text": f.description()
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.package()
                            },
                            "region": {
                                "startLine": f.version().trim_start_matches('L').parse::<u32>().unwrap_or(1)
                            }
                        }
                    }],
                    "partialFingerprints": {
                        "primaryLocationLineHash": format!("{}_{}", f.id(), i)
                    }
                })
            })
            .collect();

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/k5602/vulnera"
                    }
                },
                "results": results
            }]
        });

        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }

    /// Print vulnerabilities in SARIF format (internal method)
    fn sarif_internal<T: Serialize>(&self, vulnerabilities: &[T]) -> io::Result<()> {
        // Basic SARIF structure
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "vulnera",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/k5602/vulnera"
                    }
                },
                "results": vulnerabilities
            }]
        });

        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }
}

/// Trait for displaying vulnerability information
pub trait VulnerabilityDisplay {
    fn severity(&self) -> String;
    fn id(&self) -> String;
    fn package(&self) -> String;
    fn version(&self) -> String;
    fn description(&self) -> String;
}

/// Progress indicator for long-running operations
pub struct ProgressIndicator {
    bar: indicatif::ProgressBar,
}

#[allow(dead_code)]
impl ProgressIndicator {
    /// Create a new spinner progress indicator
    pub fn spinner(message: &str) -> Self {
        let bar = indicatif::ProgressBar::new_spinner();
        bar.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .expect("Valid template"),
        );
        bar.set_message(message.to_string());
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        Self { bar }
    }

    /// Create a progress bar with known length
    pub fn bar(len: u64, message: &str) -> Self {
        let bar = indicatif::ProgressBar::new(len);
        bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .expect("Valid template")
                .progress_chars("█▓░"),
        );
        bar.set_message(message.to_string());
        Self { bar }
    }

    /// Update the message
    pub fn set_message(&self, message: &str) {
        self.bar.set_message(message.to_string());
    }

    /// Increment the progress
    pub fn inc(&self, delta: u64) {
        self.bar.inc(delta);
    }

    /// Set the progress position
    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }

    /// Finish with a success message
    pub fn finish_with_message(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Finish and clear
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }
}

/// Truncate a string to a maximum length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Ask for confirmation (respects CI mode)
pub fn confirm(message: &str, default: bool, ci_mode: bool) -> io::Result<bool> {
    if ci_mode {
        return Ok(default);
    }

    let result = dialoguer::Confirm::new()
        .with_prompt(message)
        .default(default)
        .interact()?;

    Ok(result)
}

/// Ask for text input
#[allow(dead_code)]
pub fn input(prompt: &str, default: Option<&str>, ci_mode: bool) -> io::Result<String> {
    if ci_mode {
        return Ok(default.unwrap_or("").to_string());
    }

    let mut input = dialoguer::Input::<String>::new().with_prompt(prompt);

    if let Some(d) = default {
        input = input.default(d.to_string());
    }

    let result = input.interact_text()?;
    Ok(result)
}

/// Ask for password input (hidden)
pub fn password(prompt: &str, ci_mode: bool) -> io::Result<String> {
    if ci_mode {
        // In CI mode, require env var
        return std::env::var("VULNERA_API_KEY")
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "VULNERA_API_KEY not set"));
    }

    let result = dialoguer::Password::new().with_prompt(prompt).interact()?;

    Ok(result)
}

/// Ask for selection from a list
#[allow(dead_code)]
pub fn select(prompt: &str, items: &[&str], default: usize, ci_mode: bool) -> io::Result<usize> {
    if ci_mode {
        return Ok(default);
    }

    let result = dialoguer::Select::new()
        .with_prompt(prompt)
        .items(items)
        .default(default)
        .interact()?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
    }

    #[test]
    fn test_output_writer_creation() {
        let writer = OutputWriter::new(OutputFormat::Json, false, true);
        assert_eq!(writer.format(), OutputFormat::Json);
        assert!(!writer.is_quiet());
        assert!(writer.is_verbose());
    }
}
