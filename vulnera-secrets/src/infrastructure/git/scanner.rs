//! Git history scanner for detecting secrets in commit history

use crate::domain::entities::{Location, SecretFinding};
use crate::infrastructure::detectors::DetectorEngine;
use chrono::{DateTime, Utc};
use git2::{Commit, DiffDelta, DiffHunk, DiffLine, Repository};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, instrument};

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
    pub async fn scan_history(&self, repo_path: &Path) -> Result<Vec<SecretFinding>, GitScanError> {
        info!("Starting git history scan");

        // Collect all OIDs first to avoid holding revwalk across await
        let oids = {
            let repo = Repository::open(repo_path).map_err(|e| {
                error!(error = %e, "Failed to open git repository");
                GitScanError::GitError(e)
            })?;
            let mut revwalk = repo.revwalk().map_err(GitScanError::GitError)?;
            revwalk
                .set_sorting(git2::Sort::TIME)
                .map_err(GitScanError::GitError)?;
            revwalk.push_head().map_err(GitScanError::GitError)?;
            revwalk
                .collect::<Result<Vec<_>, _>>()
                .map_err(GitScanError::GitError)?
        };

        let total_commits = oids.len();
        let progress_interval = (total_commits / 10).max(1);
        let mut all_findings = Vec::new();
        let mut commit_count = 0;

        for oid in oids {
            // Check max commits limit
            if let Some(max) = self.max_commits {
                if commit_count >= max {
                    debug!("Reached max commits limit: {}", max);
                    break;
                }
            }

            // Extract commit data and lines to scan synchronously
            let commit_data = {
                let repo = Repository::open(repo_path).map_err(GitScanError::GitError)?;
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
                        None
                    } else {
                        let metadata = CommitMetadata {
                            hash: oid.to_string(),
                            author: commit.author().name().unwrap_or("unknown").to_string(),
                            email: commit.author().email().unwrap_or("unknown").to_string(),
                            date: commit_time,
                            message: commit.message().unwrap_or("").to_string(),
                        };
                        let lines = self.get_commit_lines(&repo, &commit)?;
                        Some((metadata, lines))
                    }
                } else {
                    let metadata = CommitMetadata {
                        hash: oid.to_string(),
                        author: commit.author().name().unwrap_or("unknown").to_string(),
                        email: commit.author().email().unwrap_or("unknown").to_string(),
                        date: commit_time,
                        message: commit.message().unwrap_or("").to_string(),
                    };
                    let lines = self.get_commit_lines(&repo, &commit)?;
                    Some((metadata, lines))
                }
            };

            let (metadata, lines_to_scan) = match commit_data {
                Some(data) => data,
                None => continue,
            };

            commit_count += 1;

            // Report progress at intervals
            if commit_count % progress_interval == 0 {
                let progress_pct = (commit_count * 100) / total_commits;
                info!(
                    commits_scanned = commit_count,
                    total_commits,
                    findings_so_far = all_findings.len(),
                    progress_percent = progress_pct,
                    "Git history scan progress"
                );
            }

            // Process collected lines asynchronously
            for (file_path, content) in lines_to_scan {
                let line_findings = self
                    .detector_engine
                    .detect_in_file_async(&file_path, &content)
                    .await;

                // Convert to git history findings with commit metadata
                for finding in line_findings {
                    all_findings.push(SecretFinding {
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

        info!(
            commit_count,
            finding_count = all_findings.len(),
            "Git history scan completed"
        );

        Ok(all_findings)
    }

    /// Get lines added in a commit for scanning
    fn get_commit_lines(
        &self,
        repo: &Repository,
        commit: &Commit<'_>,
    ) -> Result<Vec<(PathBuf, String)>, GitScanError> {
        let mut lines_to_scan: Vec<(PathBuf, String)> = Vec::new();

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

        let mut file_cb = |_delta: DiffDelta<'_>, _progress: f32| true;
        let mut line_cb =
            |delta: DiffDelta<'_>, _hunk: Option<DiffHunk<'_>>, line: DiffLine<'_>| {
                // Only scan added lines (new secrets)
                if line.origin() == '+' {
                    if let Ok(content) = std::str::from_utf8(line.content()) {
                        let file_path = delta
                            .new_file()
                            .path()
                            .or_else(|| delta.old_file().path())
                            .map(|p| p.to_path_buf())
                            .unwrap_or_else(|| PathBuf::from("unknown"));

                        lines_to_scan.push((file_path, content.to_string()));
                    }
                }
                true
            };

        diff.foreach(&mut file_cb, None, None, Some(&mut line_cb))
            .map_err(GitScanError::GitError)?;

        Ok(lines_to_scan)
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
