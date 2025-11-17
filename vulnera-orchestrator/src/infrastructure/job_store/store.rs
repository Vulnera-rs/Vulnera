use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::infrastructure::cache::DragonflyCache;

use super::snapshot::JobSnapshot;

/// Job persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum JobStoreError {
    #[error("Job not found: {0}")]
    NotFound(Uuid),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Cache operation failed: {0}")]
    Cache(String),
}

/// Job storage interface.
#[async_trait]
pub trait JobStore: Send + Sync {
    async fn save_snapshot(&self, snapshot: JobSnapshot) -> Result<(), JobStoreError>;
    async fn get_snapshot(&self, job_id: Uuid) -> Result<Option<JobSnapshot>, JobStoreError>;
    async fn delete_snapshot(&self, job_id: Uuid) -> Result<(), JobStoreError>;
}

/// Dragonfly-backed job store with configurable TTL for replay data.
pub struct DragonflyJobStore {
    cache: Arc<DragonflyCache>,
    ttl: Duration,
}

impl DragonflyJobStore {
    pub fn new(cache: Arc<DragonflyCache>, ttl: Duration) -> Self {
        Self { cache, ttl }
    }

    fn job_key(job_id: Uuid) -> String {
        format!("job:snapshot:{}", job_id)
    }
}

#[async_trait]
impl JobStore for DragonflyJobStore {
    async fn save_snapshot(&self, snapshot: JobSnapshot) -> Result<(), JobStoreError> {
        let key = Self::job_key(snapshot.job_id);

        // Use CacheService generic set - it handles serialization internally
        self.cache.set(&key, &snapshot, self.ttl).await
            .map_err(|e| JobStoreError::Cache(e.to_string()))?;

        tracing::info!(
            job_id = %snapshot.job_id,
            "Job snapshot saved to Dragonfly with TTL {}s",
            self.ttl.as_secs()
        );

        Ok(())
    }

    async fn get_snapshot(&self, job_id: Uuid) -> Result<Option<JobSnapshot>, JobStoreError> {
        let key = Self::job_key(job_id);

        // Use CacheService generic get - it handles deserialization internally
        let snapshot: Option<JobSnapshot> = self.cache.get(&key).await
            .map_err(|e| JobStoreError::Cache(e.to_string()))?;

        if snapshot.is_some() {
            tracing::debug!(job_id = %job_id, "Job snapshot retrieved from Dragonfly");
        } else {
            tracing::debug!(job_id = %job_id, "Job snapshot not found in Dragonfly");
        }

        Ok(snapshot)
    }

    async fn delete_snapshot(&self, job_id: Uuid) -> Result<(), JobStoreError> {
        let key = Self::job_key(job_id);

        // Use CacheService invalidate method
        self.cache.invalidate(&key).await
            .map_err(|e| JobStoreError::Cache(e.to_string()))?;

        tracing::info!(job_id = %job_id, "Job snapshot deleted from Dragonfly");
        Ok(())
    }
}
