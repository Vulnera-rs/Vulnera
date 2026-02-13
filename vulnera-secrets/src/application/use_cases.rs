//! Secret detection use cases

use regex::Regex;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant, timeout};
use tracing::{debug, error, info, instrument, warn};

use vulnera_core::config::SecretDetectionConfig;

use crate::domain::entities::SecretFinding;
use crate::infrastructure::baseline::{BaselineRepository, FileBaselineRepository};
use crate::infrastructure::detectors::DetectorEngine;
use crate::infrastructure::git::GitScanner;
use crate::infrastructure::rules::RuleRepository;
use crate::infrastructure::scanner::{DirectoryScanner, ScanFile};
use crate::infrastructure::verification::VerificationService;

/// Result of a secret detection scan
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
    pub baseline_suppressed: usize,
    pub allowlist_suppressed: usize,
    pub suppression_breakdown: std::collections::HashMap<String, usize>,
}

/// Use case for scanning a project for secrets
pub struct ScanForSecretsUseCase {
    scanner: DirectoryScanner,
    detector_engine: Arc<DetectorEngine>,
    baseline_repository: Option<Arc<FileBaselineRepository>>,
    /// Whether to update baseline with new findings
    update_baseline: bool,
    scan_git_history: bool,
    max_commits: Option<usize>,
    since_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Semaphore to limit concurrent file scanning operations
    scan_semaphore: Arc<Semaphore>,
    /// Timeout for file read operations
    file_read_timeout: Duration,
    /// Whether to scan code blocks inside Markdown files (when Markdown files are processed)
    scan_markdown_codeblocks: bool,
    /// Overall scan timeout
    scan_timeout: Option<Duration>,
    /// Compiled global allowlist regex patterns
    global_allowlist_patterns: Vec<Regex>,
    /// Compiled rule-scoped allowlist regex patterns
    rule_allowlist_patterns: std::collections::HashMap<String, Vec<Regex>>,
}

impl ScanForSecretsUseCase {
    pub fn new() -> Self {
        Self::with_config(&SecretDetectionConfig::default())
    }

    pub fn with_config(config: &SecretDetectionConfig) -> Self {
        let mut exclude_extensions = config.exclude_extensions.clone();

        // If markdown scanning is enabled, ensure we don't exclude markdown files
        if config.scan_markdown_codeblocks {
            exclude_extensions.retain(|ext| {
                let ext_lower = ext.to_lowercase();
                ext_lower != "md" && ext_lower != "markdown"
            });
        }

        let scanner = DirectoryScanner::new(config.max_scan_depth, config.max_file_size_bytes)
            .with_exclude_patterns(config.exclude_patterns.clone())
            .with_exclude_extensions(exclude_extensions);

        let rule_repository = if let Some(ref rule_file_path) = config.rule_file_path {
            RuleRepository::with_file_and_defaults(rule_file_path)
        } else {
            RuleRepository::new()
        };

        let verification_service = if config.enable_verification {
            Some(Arc::new(VerificationService::new(Duration::from_secs(
                config.verification_timeout_seconds,
            ))))
        } else {
            None
        };

        let detector_engine = if let Some(ref verification_service) = verification_service {
            Arc::new(DetectorEngine::new_with_verification(
                rule_repository,
                config.base64_entropy_threshold,
                config.hex_entropy_threshold,
                config.enable_entropy_detection,
                Some(verification_service.clone()),
            ))
        } else {
            Arc::new(DetectorEngine::new(
                rule_repository,
                config.base64_entropy_threshold,
                config.hex_entropy_threshold,
                config.enable_entropy_detection,
            ))
        };

        let baseline_repository = config
            .baseline_file_path
            .as_ref()
            .map(|path| Arc::new(FileBaselineRepository::new(path)));

        // Use verification_concurrent_limit for file scanning concurrency, with a reasonable default
        let max_concurrent_scans = config.verification_concurrent_limit.clamp(10, 100);
        let scan_semaphore = Arc::new(Semaphore::new(max_concurrent_scans));

        let file_read_timeout = Duration::from_secs(config.file_read_timeout_seconds);
        let scan_timeout = config.scan_timeout_seconds.map(Duration::from_secs);

        let global_allowlist_patterns = config
            .global_allowlist_patterns
            .iter()
            .filter_map(|pattern| match Regex::new(pattern) {
                Ok(regex) => Some(regex),
                Err(err) => {
                    warn!(pattern = %pattern, error = %err, "Invalid global allowlist regex; skipping pattern");
                    None
                }
            })
            .collect();

        let mut rule_allowlist_patterns: std::collections::HashMap<String, Vec<Regex>> =
            std::collections::HashMap::new();
        for (rule_id, patterns) in &config.rule_allowlist_patterns {
            let mut compiled_patterns = Vec::new();
            for pattern in patterns {
                match Regex::new(pattern) {
                    Ok(regex) => compiled_patterns.push(regex),
                    Err(err) => {
                        warn!(rule_id = %rule_id, pattern = %pattern, error = %err, "Invalid rule allowlist regex; skipping pattern");
                    }
                }
            }

            if !compiled_patterns.is_empty() {
                rule_allowlist_patterns.insert(rule_id.clone(), compiled_patterns);
            }
        }

        Self {
            scanner,
            detector_engine: detector_engine.clone(),
            baseline_repository,
            update_baseline: config.update_baseline,
            scan_git_history: config.scan_git_history,
            max_commits: config.max_commits_to_scan,
            since_date: config.since_date,
            scan_semaphore,
            file_read_timeout,
            scan_markdown_codeblocks: config.scan_markdown_codeblocks,
            scan_timeout,
            global_allowlist_patterns,
            rule_allowlist_patterns,
        }
    }

    #[instrument(skip(self), fields(root = %root.display()))]
    pub async fn execute(&self, root: &Path) -> Result<ScanResult, ScanError> {
        info!("Starting secret detection scan");

        // Track start time for overall timeout
        let start_time = Instant::now();

        // Create cancellation token using tokio's watch channel
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let cancel_tx = Arc::new(cancel_tx);

        // Set up overall scan timeout if configured
        let scan_future = async {
            // Check for cancellation before starting
            if *cancel_rx.borrow() {
                return Err(ScanError::Configuration("Scan was cancelled".to_string()));
            }

            let files = self.scanner.scan(root).map_err(|e| {
                error!(
                    error = %e,
                    root = %root.display(),
                    "Failed to scan directory"
                );
                ScanError::Io {
                    message: e.to_string(),
                    path: root.display().to_string(),
                    source: e,
                }
            })?;

            let file_count = files.len();
            info!(file_count, "Found files to scan");

            let mut all_findings = Vec::new();
            let mut files_scanned = 0;

            // Process files in parallel using tokio with bounded concurrency
            let mut handles = Vec::new();
            let semaphore = self.scan_semaphore.clone();
            let file_read_timeout = self.file_read_timeout;
            let cancel_tx_clone = cancel_tx.clone();
            let scan_markdown_codeblocks = self.scan_markdown_codeblocks;

            for file in files {
                // Check for cancellation before spawning new tasks
                if *cancel_rx.borrow() {
                    warn!("Scan cancelled, stopping file processing");
                    break;
                }

                let detector_engine = self.detector_engine.clone();
                let semaphore = semaphore.clone();
                let cancel_tx_task = cancel_tx_clone.clone();
                let handle = tokio::spawn(async move {
                    // Check cancellation before acquiring permit
                    if *cancel_tx_task.subscribe().borrow() {
                        return Err(ScanError::Configuration("Task cancelled".to_string()));
                    }

                    // Acquire permit before scanning (will wait if limit reached)
                    let _permit =
                        semaphore
                            .acquire()
                            .await
                            .map_err(|e| ScanError::ParseFailed {
                                message: format!("Failed to acquire scan permit: {}", e),
                                file: file.path.display().to_string(),
                            })?;

                    // Check cancellation again after acquiring permit
                    if *cancel_tx_task.subscribe().borrow() {
                        return Err(ScanError::Configuration("Task cancelled".to_string()));
                    }

                    Self::scan_file_async_with_timeout(
                        &detector_engine,
                        &file,
                        file_read_timeout,
                        scan_markdown_codeblocks,
                    )
                    .await
                });
                handles.push(handle);
            }

            // Collect results with progress reporting and cancellation checks
            let progress_interval = (file_count / 10).max(1); // Report every 10% or every file if < 10 files
            for (idx, handle) in handles.into_iter().enumerate() {
                // Check for cancellation periodically
                if *cancel_rx.borrow() {
                    warn!("Scan cancelled, stopping result collection");
                    break;
                }

                match handle.await {
                    Ok(Ok(findings)) => {
                        files_scanned += 1;
                        all_findings.extend(findings);

                        // Report progress at intervals
                        if (idx + 1) % progress_interval == 0 || (idx + 1) == file_count {
                            let progress_pct = ((idx + 1) * 100) / file_count;
                            info!(
                                files_scanned = idx + 1,
                                total_files = file_count,
                                progress_percent = progress_pct,
                                findings_so_far = all_findings.len(),
                                "Scan progress"
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "Failed to scan file");
                    }
                    Err(e) => {
                        warn!(error = %e, "Task join error");
                    }
                }
            }

            // Scan git history if enabled (with cancellation check)
            if self.scan_git_history && !*cancel_rx.borrow() {
                let git_scanner = GitScanner::new(
                    (*self.detector_engine).clone(),
                    self.max_commits,
                    self.since_date,
                );

                match git_scanner.scan_history(root).await {
                    Ok(git_findings) => {
                        info!(
                            git_finding_count = git_findings.len(),
                            "Found secrets in git history"
                        );
                        all_findings.extend(git_findings);
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to scan git history");
                    }
                }
            }

            // Filter findings using allowlists first
            let mut allowlist_suppressed = 0usize;
            let mut suppression_breakdown = std::collections::HashMap::new();
            let mut allowlist_filtered = Vec::new();

            for finding in all_findings {
                match self.allowlist_reason(&finding) {
                    Some(reason) => {
                        allowlist_suppressed += 1;
                        *suppression_breakdown.entry(reason).or_insert(0) += 1;
                    }
                    None => allowlist_filtered.push(finding),
                }
            }

            // Filter findings using baseline if available
            let mut baseline_suppressed = 0usize;
            let filtered_findings = if let Some(ref baseline_repo) = self.baseline_repository {
                let mut filtered = Vec::new();
                let mut new_findings_for_baseline = Vec::new();

                for finding in allowlist_filtered {
                    match baseline_repo.contains(&finding) {
                        Ok(true) => {
                            debug!(
                                file = %finding.location.file_path,
                                line = finding.location.line,
                                "Finding filtered by baseline"
                            );
                            // Skip findings that exist in baseline (assumed false positives)
                            baseline_suppressed += 1;
                            *suppression_breakdown
                                .entry("baseline".to_string())
                                .or_insert(0) += 1;
                        }
                        Ok(false) => {
                            filtered.push(finding.clone());
                            // Track new findings for baseline update
                            if self.update_baseline {
                                new_findings_for_baseline.push(finding);
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Error checking baseline, including finding");
                            filtered.push(finding);
                        }
                    }
                }

                // Update baseline with new findings if enabled
                if self.update_baseline && !new_findings_for_baseline.is_empty() {
                    info!(
                        new_finding_count = new_findings_for_baseline.len(),
                        "Updating baseline with new findings"
                    );

                    let entries: Vec<_> = new_findings_for_baseline
                        .iter()
                        .map(|finding| {
                            let is_verified = matches!(
                                finding.verification_state,
                                crate::domain::entities::SecretVerificationState::Verified
                            );
                            FileBaselineRepository::finding_to_entry(finding, true, is_verified)
                        })
                        .collect();

                    if let Err(e) = baseline_repo.add_entries(entries) {
                        warn!(error = %e, "Failed to update baseline");
                    } else {
                        info!("Baseline updated successfully");
                    }
                }

                filtered
            } else {
                allowlist_filtered
            };

            info!(
                finding_count = filtered_findings.len(),
                files_scanned, "Secret detection scan completed"
            );
            Ok(ScanResult {
                findings: filtered_findings,
                files_scanned,
                baseline_suppressed,
                allowlist_suppressed,
                suppression_breakdown,
            })
        };

        // Execute with timeout if configured
        match self.scan_timeout {
            Some(timeout_duration) => {
                match timeout(timeout_duration, scan_future).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Timeout occurred - signal cancellation
                        let _ = cancel_tx.send(true);
                        let _elapsed = start_time.elapsed();
                        Err(ScanError::Timeout {
                            operation: "Secret detection scan".to_string(),
                            timeout_seconds: timeout_duration.as_secs(),
                        })
                    }
                }
            }
            None => scan_future.await,
        }
    }

    /// Scan a file with timeout support
    async fn scan_file_async_with_timeout(
        detector_engine: &DetectorEngine,
        file: &ScanFile,
        timeout_duration: Duration,
        scan_markdown_codeblocks: bool,
    ) -> Result<Vec<SecretFinding>, ScanError> {
        debug!(file = %file.path.display(), "Scanning file");

        // Read file with timeout
        let read_future = tokio::fs::read_to_string(&file.path);
        let mut content = match timeout(timeout_duration, read_future).await {
            Ok(Ok(content)) => content,
            Ok(Err(e)) => {
                warn!(
                    file = %file.path.display(),
                    error = %e,
                    "Failed to read file"
                );
                return Err(ScanError::Io {
                    message: e.to_string(),
                    path: file.path.display().to_string(),
                    source: e,
                });
            }
            Err(_) => {
                warn!(
                    file = %file.path.display(),
                    timeout_seconds = timeout_duration.as_secs(),
                    "File read operation timed out"
                );
                return Err(ScanError::Timeout {
                    operation: format!("Reading file: {}", file.path.display()),
                    timeout_seconds: timeout_duration.as_secs(),
                });
            }
        };

        // Optionally strip markdown code blocks if Markdown files are being scanned
        if !scan_markdown_codeblocks {
            if let Some(ext) = file.path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                if ext_lower == "md" || ext_lower == "markdown" {
                    content = Self::strip_markdown_code_blocks(&content);
                }
            }
        }

        let findings = detector_engine
            .detect_in_file_async(&file.path, &content)
            .await;
        Ok(findings)
    }

    /// Remove code blocks from Markdown content (``` fenced blocks or ~~~ fences)
    fn strip_markdown_code_blocks(content: &str) -> String {
        let mut out = String::new();
        let mut in_block = false;

        for line in content.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
                in_block = !in_block;
                // Skip fence lines entirely
                continue;
            }

            if !in_block {
                out.push_str(line);
                out.push('\n');
            }
        }

        out
    }
}

impl ScanForSecretsUseCase {
    fn allowlist_reason(&self, finding: &SecretFinding) -> Option<String> {
        if self
            .global_allowlist_patterns
            .iter()
            .any(|pattern| pattern.is_match(&finding.matched_secret))
        {
            return Some("allowlist:global".to_string());
        }

        if let Some(patterns) = self.rule_allowlist_patterns.get(&finding.rule_id) {
            if patterns
                .iter()
                .any(|pattern| pattern.is_match(&finding.matched_secret))
            {
                return Some(format!("allowlist:rule:{}", finding.rule_id));
            }
        }

        None
    }
}

impl Default for ScanForSecretsUseCase {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan error with context
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("IO error: {message} (path: {path})")]
    Io {
        message: String,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Parse error: {message} (file: {file})")]
    ParseFailed { message: String, file: String },

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Timeout error: {operation} exceeded {timeout_seconds}s")]
    Timeout {
        operation: String,
        timeout_seconds: u64,
    },
}
