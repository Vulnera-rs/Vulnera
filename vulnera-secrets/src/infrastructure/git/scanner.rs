//! Git history scanner for detecting secrets in commit history

use crate::domain::entities::{Location, SecretFinding};
use crate::infrastructure::detectors::DetectorEngine;
use chrono::{DateTime, Utc};
use git2::{Commit, DiffDelta, DiffHunk, DiffLine, Repository};
use std::path::Path;
use tracing::{debug, error, info, instrument, warn};

/// Git commit metadata
#[derive(Debug, Clone)]
pub struct CommitMetadata {
    pub hash: String,
    pub author: String,
    pub email: String,
    pub date: DateTime<Utc>,
    pub message: String,
}

/// Git history scanner
pub struct GitScanner {
    detector_engine: DetectorEngine,
    max_commits: Option<usize>,
    since_date: Option<DateTime<Utc>>,
}

impl GitScanner {
    pub fn new(
        detector_engine: DetectorEngine,
        max_commits: Option<usize>,
        since_date: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            detector_engine,
            max_commits,
            since_date,
        }
    }

    /// Scan git repository history for secrets
    #[instrument(skip(self), fields(repo_path = %repo_path.display()))]
    pub fn scan_history(&self, repo_path: &Path) -> Result<Vec<SecretFinding>, GitScanError> {
        info!("Starting git history scan");
        let repo = Repository::open(repo_path).map_err(|e| {
            error!(error = %e, "Failed to open git repository");
            GitScanError::GitError(e)
        })?;

        let mut revwalk = repo.revwalk().map_err(GitScanError::GitError)?;
        revwalk
            .set_sorting(git2::Sort::TIME)
            .map_err(GitScanError::GitError)?;
        revwalk.push_head().map_err(GitScanError::GitError)?;

        let mut all_findings = Vec::new();
        let mut commit_count = 0;

        // Estimate total commits for progress reporting (approximate)
        let mut total_commits_estimate = 0;
        let mut revwalk_estimate = repo.revwalk().map_err(GitScanError::GitError)?;
        revwalk_estimate
            .set_sorting(git2::Sort::TIME)
            .map_err(GitScanError::GitError)?;
        revwalk_estimate
            .push_head()
            .map_err(GitScanError::GitError)?;
        for _ in revwalk_estimate {
            total_commits_estimate += 1;
            if total_commits_estimate > 10000 {
                // Cap estimate to avoid long iteration
                break;
            }
        }

        let progress_interval = (total_commits_estimate / 10).max(1); // Report every 10%

        for oid in revwalk {
            let oid = oid.map_err(GitScanError::GitError)?;

            // Check max commits limit
            if let Some(max) = self.max_commits {
                if commit_count >= max {
                    debug!("Reached max commits limit: {}", max);
                    break;
                }
            }

            let commit = repo.find_commit(oid).map_err(GitScanError::GitError)?;
            let commit_time =
                DateTime::from_timestamp(commit.time().seconds(), 0).unwrap_or_else(Utc::now);

            // Check since_date filter
            if let Some(since) = self.since_date {
                if commit_time < since {
                    debug!(
                        commit = %oid,
                        date = %commit_time,
                        "Skipping commit before since_date"
                    );
                    continue;
                }
            }

            commit_count += 1;

            // Report progress at intervals
            if commit_count % progress_interval == 0 {
                let progress_pct = if total_commits_estimate > 0 {
                    (commit_count * 100) / total_commits_estimate.min(commit_count + 1000)
                } else {
                    0
                };
                info!(
                    commits_scanned = commit_count,
                    findings_so_far = all_findings.len(),
                    progress_percent = progress_pct,
                    "Git history scan progress"
                );
            }

            // Get commit metadata
            let metadata = CommitMetadata {
                hash: oid.to_string(),
                author: commit.author().name().unwrap_or("unknown").to_string(),
                email: commit.author().email().unwrap_or("unknown").to_string(),
                date: commit_time,
                message: commit.message().unwrap_or("").to_string(),
            };

            // Scan commit diff
            let findings = self.scan_commit(&repo, &commit, &metadata)?;
            all_findings.extend(findings);
        }

        info!(
            commit_count,
            finding_count = all_findings.len(),
            "Git history scan completed"
        );

        Ok(all_findings)
    }

    /// Scan a single commit for secrets
    fn scan_commit(
        &self,
        repo: &Repository,
        commit: &Commit,
        metadata: &CommitMetadata,
    ) -> Result<Vec<SecretFinding>, GitScanError> {
        let mut findings = Vec::new();

        // Get parent commit for diff
        let parent = if commit.parent_count() > 0 {
            commit.parent(0).ok()
        } else {
            None
        };

        let tree = commit.tree().map_err(GitScanError::GitError)?;
        let parent_tree = parent
            .and_then(|p| p.tree().ok())
            .or_else(|| repo.find_tree(git2::Oid::zero()).ok());

        // Create diff
        let diff = repo
            .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None)
            .map_err(GitScanError::GitError)?;

        // Use a helper struct to avoid borrow checker issues with closures
        struct DiffScanner<'a> {
            scanner: &'a GitScanner,
            metadata: &'a CommitMetadata,
            findings: &'a mut Vec<SecretFinding>,
        }

        let diff_scanner = DiffScanner {
            scanner: self,
            metadata,
            findings: &mut findings,
        };

        // Scan each line in the diff
        let mut file_cb = |_delta: DiffDelta, _progress: f32| true;
        let mut line_cb = |delta: DiffDelta, _hunk: Option<DiffHunk>, line: DiffLine| {
            diff_scanner.scanner.scan_diff_line(
                delta,
                line,
                diff_scanner.metadata,
                diff_scanner.findings,
            );
            true
        };
        diff.foreach(&mut file_cb, None, None, Some(&mut line_cb))
            .map_err(GitScanError::GitError)?;

        Ok(findings)
    }

    /// Scan a diff line for secrets
    fn scan_diff_line(
        &self,
        delta: DiffDelta,
        line: DiffLine,
        metadata: &CommitMetadata,
        findings: &mut Vec<SecretFinding>,
    ) {
        // Only scan added lines (new secrets)
        if line.origin() != '+' {
            return;
        }

        let content = match std::str::from_utf8(line.content()) {
            Ok(s) => s,
            Err(_) => return, // Skip binary or invalid UTF-8
        };

        let file_path = delta
            .new_file()
            .path()
            .or_else(|| delta.old_file().path())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("unknown"));

        // Run detector on the line
        let line_findings = self.detector_engine.detect_in_file(&file_path, content);

        // Convert to git history findings with commit metadata
        for finding in line_findings {
            findings.push(SecretFinding {
                id: format!("{}-{}", metadata.hash, finding.id),
                rule_id: finding.rule_id,
                secret_type: finding.secret_type,
                location: Location {
                    file_path: format!("{}:{}", metadata.hash, finding.location.file_path),
                    line: finding.location.line,
                    column: finding.location.column,
                    end_line: finding.location.end_line,
                    end_column: finding.location.end_column,
                },
                severity: finding.severity,
                confidence: finding.confidence,
                description: format!(
                    "{} (Found in commit {} by {} on {})",
                    finding.description,
                    &metadata.hash[..8],
                    metadata.author,
                    metadata.date.format("%Y-%m-%d")
                ),
                recommendation: finding.recommendation,
                matched_secret: finding.matched_secret,
                entropy: finding.entropy,
            });
        }
    }
}

/// Error type for git scanning
#[derive(Debug, thiserror::Error)]
pub enum GitScanError {
    #[error("Git error: {0}")]
    GitError(#[from] git2::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
