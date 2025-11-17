use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use git2::{Cred, FetchOptions, RemoteCallbacks, build::RepoBuilder, opts};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::token::current_request_git_token;

/// Configuration for the Git service.
#[derive(Debug, Clone)]
pub struct GitServiceConfig {
    /// Optional parent directory for temporary checkouts. Defaults to std::env::temp_dir().
    pub checkout_parent: Option<PathBuf>,
    /// Timeout applied to network fetches (passed down to libgit2).
    pub fetch_timeout: Duration,
}

impl Default for GitServiceConfig {
    fn default() -> Self {
        Self {
            checkout_parent: None,
            fetch_timeout: Duration::from_secs(30),
        }
    }
}

/// Result data for a Git checkout.
#[derive(Debug, Clone)]
pub struct GitCheckout {
    /// Local filesystem path of the cloned repository root.
    pub checkout_path: String,
    /// HEAD commit SHA (if resolved).
    pub head_commit: Option<String>,
}

/// Errors emitted by the Git service.
#[derive(Debug, thiserror::Error)]
pub enum GitServiceError {
    #[error("Unsupported Git URL scheme for {0}. Only HTTPS is supported.")]
    UnsupportedScheme(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git operation failed: {0}")]
    Git(#[from] git2::Error),
    #[error("Blocking clone task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Service responsible for cloning Git repositories into per-job temp directories.
#[derive(Debug)]
pub struct GitService {
    checkout_parent: PathBuf,
    checkouts: Arc<Mutex<HashMap<String, TempDir>>>,
    config: GitServiceConfig,
}

impl GitService {
    /// Create a new Git service with the provided configuration.
    pub fn new(config: GitServiceConfig) -> std::io::Result<Self> {
        let checkout_parent = config
            .checkout_parent
            .clone()
            .unwrap_or_else(std::env::temp_dir);

        if !checkout_parent.exists() {
            std::fs::create_dir_all(&checkout_parent)?;
        }

        Ok(Self {
            checkout_parent,
            checkouts: Arc::new(Mutex::new(HashMap::new())),
            config,
        })
    }

    /// Clone the provided repository URL at shallow depth into a temp directory tied to `project_id`.
    pub async fn clone_repository(
        &self,
        project_id: &str,
        repository_url: &str,
    ) -> Result<GitCheckout, GitServiceError> {
        if !repository_url.starts_with("https://") {
            return Err(GitServiceError::UnsupportedScheme(
                repository_url.to_string(),
            ));
        }

        let project_key = project_id.to_string();
        let checkout_dir = tempfile::Builder::new()
            .prefix("vulnera-git-")
            .tempdir_in(&self.checkout_parent)?;
        let checkout_path = checkout_dir.path().to_path_buf();
        let checkout_path_string = checkout_path.to_string_lossy().to_string();
        let dest_for_clone = checkout_path.clone();
        let repo_url = repository_url.to_string();
        let token = current_request_git_token();
        let fetch_timeout = self.config.fetch_timeout;

        info!(project_id = %project_key, repository = %repo_url, "Starting Git clone");

        Self::configure_git_timeouts(fetch_timeout)?;

        let head_commit = tokio::task::spawn_blocking(move || {
            Self::perform_clone(dest_for_clone.as_path(), &repo_url, token.as_deref())
        })
        .await??;

        let mut checkouts = self.checkouts.lock().await;
        checkouts.insert(project_key.clone(), checkout_dir);
        drop(checkouts);

        debug!(project_id = %project_key, path = %checkout_path_string, "Git clone completed");

        Ok(GitCheckout {
            checkout_path: checkout_path_string,
            head_commit,
        })
    }

    fn perform_clone(
        destination: &Path,
        repository_url: &str,
        token: Option<&str>,
    ) -> Result<Option<String>, GitServiceError> {
        let mut callbacks = RemoteCallbacks::new();
        if let Some(token_value) = token {
            let token_string = token_value.to_string();
            callbacks.credentials(move |_url, username_from_url, allowed| {
                if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
                    let username = username_from_url.unwrap_or("x-access-token");
                    Cred::userpass_plaintext(username, &token_string)
                } else {
                    Cred::default()
                }
            });
        }

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);
        fetch_options.download_tags(git2::AutotagOption::None);
        fetch_options.update_fetchhead(true);
        fetch_options.proxy_options(git2::ProxyOptions::new());
        fetch_options.depth(1);

        let mut builder = RepoBuilder::new();
        builder.fetch_options(fetch_options);
        builder.clone(repository_url, destination)?;
        let repo = git2::Repository::open(destination)?;
        let head = repo
            .head()
            .ok()
            .and_then(|h| h.target())
            .map(|oid| oid.to_string());
        Ok(head)
    }

    fn configure_git_timeouts(fetch_timeout: Duration) -> Result<(), GitServiceError> {
        let timeout_ms = fetch_timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        unsafe {
            opts::set_server_connect_timeout_in_milliseconds(timeout_ms)?;
            opts::set_server_timeout_in_milliseconds(timeout_ms)?;
        }
        Ok(())
    }

    /// Remove the checkout for a project, allowing the temp directory to be deleted.
    pub async fn cleanup_project(&self, project_id: &str) -> bool {
        let mut checkouts = self.checkouts.lock().await;
        if checkouts.remove(project_id).is_some() {
            debug!(project_id = %project_id, "Removed Git checkout");
            true
        } else {
            warn!(project_id = %project_id, "No Git checkout found during cleanup");
            false
        }
    }

    /// Clear all tracked checkouts. Intended for graceful shutdowns/tests.
    pub async fn cleanup_all(&self) {
        let mut checkouts = self.checkouts.lock().await;
        checkouts.clear();
    }

    /// Convenience helper for generating IDs for standalone clones (non-project flows/tests).
    pub fn allocate_project_id() -> String {
        format!("project_{}", Uuid::new_v4())
    }
}
