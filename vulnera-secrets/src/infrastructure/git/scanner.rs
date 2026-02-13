//! Git history scanner for detecting secrets in commit history

use crate::domain::entities::{Location, SecretFinding};
use crate::infrastructure::detectors::DetectorEngine;
use chrono::{DateTime, Utc};
use git2::{Commit, DiffDelta, DiffHunk, DiffLine, Repository};
use std::cell::RefCell;
use std::collections::HashMap;
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

#[derive(Debug, Clone)]
struct GitHunkChunk {
    file_path: PathBuf,
    content: String,
    added_line_map: HashMap<u32, u32>,
}

#[derive(Debug, Default)]
struct HunkBuilder {
    file_path: PathBuf,
    content: String,
    snippet_line: u32,
    added_line_map: HashMap<u32, u32>,
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
            if let Some(max) = self.max_commits
                && commit_count >= max
            {
                debug!("Reached max commits limit: {}", max);
                break;
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

            // Process collected hunks asynchronously
            for chunk in lines_to_scan {
                let hunk_findings = self
                    .detector_engine
                    .detect_in_file_async(&chunk.file_path, &chunk.content)
                    .await;

                // Convert to git history findings with commit metadata
                for mut finding in hunk_findings {
                    // Keep only findings that originate from added lines in this hunk
                    let snippet_line = finding.location.line;
                    let Some(actual_line) = chunk.added_line_map.get(&snippet_line).copied() else {
                        continue;
                    };

                    finding.location.line = actual_line;
                    finding.location.end_line = Some(actual_line);

                    all_findings.push(SecretFinding {
                        id: format!("{}-{}", metadata.hash, finding.id),
                        rule_id: finding.rule_id,
                        detector_id: finding.detector_id,
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
                        verification_state: finding.verification_state,
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
                        evidence: finding.evidence,
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
    ) -> Result<Vec<GitHunkChunk>, GitScanError> {
        let hunk_builders: RefCell<HashMap<String, HunkBuilder>> = RefCell::new(HashMap::new());

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
        let mut hunk_cb = |delta: DiffDelta<'_>, hunk: DiffHunk<'_>| {
            let file_path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("unknown"));

            let key = format!(
                "{}:{}:{}",
                file_path.display(),
                hunk.new_start(),
                hunk.new_lines()
            );

            hunk_builders
                .borrow_mut()
                .entry(key)
                .or_insert_with(|| HunkBuilder {
                    file_path,
                    content: String::new(),
                    snippet_line: 1,
                    added_line_map: HashMap::new(),
                });

            true
        };

        let mut line_cb = |delta: DiffDelta<'_>, hunk: Option<DiffHunk<'_>>, line: DiffLine<'_>| {
            let Some(hunk) = hunk else {
                return true;
            };

            let file_path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("unknown"));

            let key = format!(
                "{}:{}:{}",
                file_path.display(),
                hunk.new_start(),
                hunk.new_lines()
            );

            let mut builders = hunk_builders.borrow_mut();
            let Some(builder) = builders.get_mut(&key) else {
                return true;
            };

            // Build a scanable hunk content stream using context and added lines.
            // Removed lines are skipped because they do not exist in the new file version.
            if (line.origin() == '+' || line.origin() == ' ')
                && let Ok(content) = std::str::from_utf8(line.content())
            {
                builder.content.push_str(content);
                if !content.ends_with('\n') {
                    builder.content.push('\n');
                }

                if line.origin() == '+'
                    && let Some(actual_line) = line.new_lineno()
                {
                    builder
                        .added_line_map
                        .insert(builder.snippet_line, actual_line);
                }

                builder.snippet_line = builder.snippet_line.saturating_add(1);
            }

            true
        };

        diff.foreach(&mut file_cb, None, Some(&mut hunk_cb), Some(&mut line_cb))
            .map_err(GitScanError::GitError)?;

        let chunks = hunk_builders
            .into_inner()
            .into_values()
            .filter(|builder| !builder.added_line_map.is_empty() && !builder.content.is_empty())
            .map(|builder| GitHunkChunk {
                file_path: builder.file_path,
                content: builder.content,
                added_line_map: builder.added_line_map,
            })
            .collect();

        Ok(chunks)
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
