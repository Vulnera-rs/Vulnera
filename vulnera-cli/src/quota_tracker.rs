//! Quota Tracker - Usage limit management with local persistence
//!
//! This module tracks CLI usage quotas with:
//! - Local persistence in JSON file
//! - UTC daily reset at midnight
//! - Graceful handling of corrupted/missing files

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, Utc};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// Default daily limit for unauthenticated users
pub const UNAUTHENTICATED_DAILY_LIMIT: u32 = 10;

/// Default daily limit for authenticated users
pub const AUTHENTICATED_DAILY_LIMIT: u32 = 40;

/// Local quota file name
const QUOTA_FILE_NAME: &str = "quota.json";

/// Manages usage quotas with local persistence
pub struct QuotaTracker {
    /// Path to local quota file
    quota_file: PathBuf,

    /// Current quota state
    state: QuotaState,

    /// Daily limit based on authentication status
    daily_limit: u32,

    /// Whether user is authenticated
    is_authenticated: bool,

    /// Machine ID for remote sync (hash of machine-specific data)
    machine_id: String,
}

/// Persisted quota state
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuotaState {
    /// Date of the quota period (UTC)
    pub date: NaiveDate,

    /// Number of requests used today
    pub used: u32,

    /// Last sync timestamp (if synced)
    pub last_sync: Option<DateTime<Utc>>,
}

impl Default for QuotaState {
    fn default() -> Self {
        Self {
            date: Utc::now().date_naive(),
            used: 0,
            last_sync: None,
        }
    }
}

impl QuotaTracker {
    /// Create a new quota tracker
    pub fn new(is_authenticated: bool) -> Result<Self> {
        let quota_file = Self::get_quota_file_path()?;
        let machine_id = Self::generate_machine_id();
        let daily_limit = if is_authenticated {
            AUTHENTICATED_DAILY_LIMIT
        } else {
            UNAUTHENTICATED_DAILY_LIMIT
        };

        let state = Self::load_state(&quota_file)?;

        Ok(Self {
            quota_file,
            state,
            daily_limit,
            is_authenticated,
            machine_id,
        })
    }

    /// Get the quota file path
    fn get_quota_file_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("dev", "vulnera", "vulnera-cli")
            .context("Failed to determine data directory")?;

        let data_dir = dirs.data_dir();
        fs::create_dir_all(data_dir)
            .with_context(|| format!("Failed to create data directory: {:?}", data_dir))?;

        Ok(data_dir.join(QUOTA_FILE_NAME))
    }

    /// Generate a machine-specific ID for remote sync
    fn generate_machine_id() -> String {
        use sha2::{Digest, Sha256};

        // Combine various machine-specific data
        let mut hasher = Sha256::new();

        // Add hostname
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }

        // Add user info
        if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
            hasher.update(user.as_bytes());
        }

        // Add home directory
        if let Some(home) = dirs::home_dir() {
            hasher.update(home.to_string_lossy().as_bytes());
        }

        let result = hasher.finalize();
        hex::encode(&result[..16]) // Use first 16 bytes (32 hex chars)
    }

    /// Load quota state from file, resetting if corrupted or expired
    fn load_state(path: &PathBuf) -> Result<QuotaState> {
        if !path.exists() {
            return Ok(QuotaState::default());
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read quota file, resetting: {}", e);
                return Ok(QuotaState::default());
            }
        };

        let state: QuotaState = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Quota file corrupted, resetting: {}", e);
                return Ok(QuotaState::default());
            }
        };

        // Check if the date has changed (UTC)
        let today = Utc::now().date_naive();
        if state.date != today {
            tracing::debug!("Quota date expired, resetting for new day");
            return Ok(QuotaState::default());
        }

        Ok(state)
    }

    /// Save quota state to file
    fn save_state(&self) -> Result<()> {
        let content =
            serde_json::to_string_pretty(&self.state).context("Failed to serialize quota state")?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.quota_file)
                .with_context(|| format!("Failed to create quota file: {:?}", self.quota_file))?;

            file.write_all(content.as_bytes())?;
        }

        #[cfg(not(unix))]
        fs::write(&self.quota_file, &content)
            .with_context(|| format!("Failed to write quota file: {:?}", self.quota_file))?;

        Ok(())
    }

    /// Try to consume a quota request
    ///
    /// Returns `true` if the request is allowed, `false` if quota exceeded.
    pub async fn try_consume(&mut self) -> Result<bool> {
        // Refresh state in case date changed
        self.state = Self::load_state(&self.quota_file)?;

        if self.state.used >= self.daily_limit {
            return Ok(false);
        }

        self.state.used += 1;
        self.save_state()?;

        Ok(true)
    }

    /// Get remaining quota
    pub fn remaining(&self) -> u32 {
        self.daily_limit.saturating_sub(self.state.used)
    }

    /// Get daily limit
    pub fn daily_limit(&self) -> u32 {
        self.daily_limit
    }

    /// Get used count
    pub fn used(&self) -> u32 {
        self.state.used
    }

    /// Get the current date (UTC)
    pub fn current_date(&self) -> NaiveDate {
        self.state.date
    }

    /// Get time until quota reset (next UTC midnight)
    pub fn time_until_reset(&self) -> chrono::Duration {
        let now = Utc::now();
        let tomorrow = (now.date_naive() + chrono::Days::new(1))
            .and_hms_opt(0, 0, 0)
            .expect("Valid time");
        let tomorrow_utc = DateTime::<Utc>::from_naive_utc_and_offset(tomorrow, Utc);

        tomorrow_utc.signed_duration_since(now)
    }

    /// Reset quota (for testing or admin purposes)
    pub fn reset(&mut self) -> Result<()> {
        self.state = QuotaState::default();
        self.save_state()?;
        Ok(())
    }

    /// Update authentication status (changes daily limit)
    pub fn set_authenticated(&mut self, authenticated: bool) {
        self.is_authenticated = authenticated;
        self.daily_limit = if authenticated {
            AUTHENTICATED_DAILY_LIMIT
        } else {
            UNAUTHENTICATED_DAILY_LIMIT
        };
    }

    /// Get quota status summary
    pub fn status(&self) -> QuotaStatus {
        QuotaStatus {
            used: self.state.used,
            limit: self.daily_limit,
            remaining: self.remaining(),
            reset_time: self.time_until_reset(),
            is_authenticated: self.is_authenticated,
            last_sync: self.state.last_sync,
        }
    }

    /// Get the machine ID
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }
}

/// Quota status for display
#[derive(Debug, Clone)]
pub struct QuotaStatus {
    pub used: u32,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: chrono::Duration,
    pub is_authenticated: bool,
    pub last_sync: Option<DateTime<Utc>>,
}

impl std::fmt::Display for QuotaStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hours = self.reset_time.num_hours();
        let minutes = self.reset_time.num_minutes() % 60;

        write!(
            f,
            "Quota: {}/{} ({} remaining) | Resets in {}h {}m | {}",
            self.used,
            self.limit,
            self.remaining,
            hours,
            minutes,
            if self.is_authenticated {
                "authenticated"
            } else {
                "unauthenticated"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_tracker(authenticated: bool) -> (QuotaTracker, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let quota_file = temp_dir.path().join(QUOTA_FILE_NAME);

        let tracker = QuotaTracker {
            quota_file,
            state: QuotaState::default(),
            daily_limit: if authenticated {
                AUTHENTICATED_DAILY_LIMIT
            } else {
                UNAUTHENTICATED_DAILY_LIMIT
            },
            is_authenticated: authenticated,
            machine_id: "test-machine".to_string(),
        };

        (tracker, temp_dir)
    }

    #[tokio::test]
    async fn test_consume_quota() {
        let (mut tracker, _temp) = test_tracker(false);

        // Should allow first request
        assert!(tracker.try_consume().await.unwrap());
        assert_eq!(tracker.remaining(), 9);
    }

    #[tokio::test]
    async fn test_quota_limit() {
        let (mut tracker, _temp) = test_tracker(false);

        // Consume all quota
        for _ in 0..UNAUTHENTICATED_DAILY_LIMIT {
            assert!(tracker.try_consume().await.unwrap());
        }

        // Next request should fail
        assert!(!tracker.try_consume().await.unwrap());
        assert_eq!(tracker.remaining(), 0);
    }

    #[tokio::test]
    async fn test_authenticated_limit() {
        let (tracker, _temp) = test_tracker(true);

        assert_eq!(tracker.daily_limit(), AUTHENTICATED_DAILY_LIMIT);
        assert_eq!(tracker.remaining(), AUTHENTICATED_DAILY_LIMIT);
    }

    #[test]
    fn test_time_until_reset() {
        let (tracker, _temp) = test_tracker(false);

        let time = tracker.time_until_reset();
        assert!(time.num_hours() <= 24);
        assert!(time.num_hours() >= 0);
    }

    #[test]
    fn test_status_display() {
        let (tracker, _temp) = test_tracker(false);

        let status = tracker.status();
        let display = format!("{}", status);

        assert!(display.contains("0/10"));
        assert!(display.contains("unauthenticated"));
    }
}
