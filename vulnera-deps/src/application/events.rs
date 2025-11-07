//! Event-driven architecture for dependency analysis
//!
//! This module provides an event system for real-time updates during dependency analysis,
//! enabling IDE extensions and CLI tools to receive progress updates and results.

use async_trait::async_trait;
use std::sync::Arc;
use vulnera_core::domain::vulnerability::entities::{Package, Vulnerability};

use crate::domain::{PackageId, SourceLocation};

/// Events emitted during dependency analysis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DependencyEvent {
    /// A package was parsed from a dependency file
    PackageParsed {
        package: Package,
        location: Option<SourceLocation>,
    },
    /// A vulnerability was found for a package
    VulnerabilityFound {
        package: Package,
        vulnerability: Vulnerability,
    },
    /// Progress update during analysis
    ResolutionProgress {
        current: usize,
        total: usize,
        message: Option<String>,
    },
    /// Cache hit for a package
    CacheHit { package_id: PackageId },
    /// Cache miss for a package
    CacheMiss { package_id: PackageId },
    /// Analysis started
    AnalysisStarted {
        file_path: String,
        ecosystem: String,
    },
    /// Analysis completed
    AnalysisCompleted {
        file_path: String,
        packages_found: usize,
        vulnerabilities_found: usize,
        duration_ms: u64,
    },
    /// Error occurred during analysis
    AnalysisError { file_path: String, error: String },
}

/// Trait for event emitters
#[async_trait]
pub trait EventEmitter: Send + Sync {
    /// Emit an event
    async fn emit(&self, event: DependencyEvent);

    /// Check if there are any subscribers
    fn has_subscribers(&self) -> bool;
}

pub struct VecEventEmitter {
    events: Arc<tokio::sync::Mutex<Vec<DependencyEvent>>>,
}

impl VecEventEmitter {
    pub fn new() -> Self {
        Self {
            events: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn get_events(&self) -> Vec<DependencyEvent> {
        self.events.lock().await.clone()
    }

    pub async fn clear(&self) {
        self.events.lock().await.clear();
    }
}

impl Default for VecEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventEmitter for VecEventEmitter {
    async fn emit(&self, event: DependencyEvent) {
        self.events.lock().await.push(event);
    }

    fn has_subscribers(&self) -> bool {
        true
    }
}

/// No-op event emitter that discards all events
pub struct NoOpEventEmitter;

impl NoOpEventEmitter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoOpEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventEmitter for NoOpEventEmitter {
    async fn emit(&self, _event: DependencyEvent) {
        // Discard event
    }

    fn has_subscribers(&self) -> bool {
        false
    }
}

/// Event emitter that forwards events to multiple subscribers
pub struct MultiEventEmitter {
    emitters: Vec<Arc<dyn EventEmitter>>,
}

impl MultiEventEmitter {
    pub fn new() -> Self {
        Self {
            emitters: Vec::new(),
        }
    }

    pub fn add_emitter(&mut self, emitter: Arc<dyn EventEmitter>) {
        self.emitters.push(emitter);
    }
}

impl Default for MultiEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventEmitter for MultiEventEmitter {
    async fn emit(&self, event: DependencyEvent) {
        for emitter in &self.emitters {
            emitter.emit(event.clone()).await;
        }
    }

    fn has_subscribers(&self) -> bool {
        !self.emitters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vec_event_emitter() {
        let emitter = VecEventEmitter::new();
        let package = Package::new(
            "test".to_string(),
            vulnera_core::domain::vulnerability::value_objects::Version::parse("1.0.0").unwrap(),
            vulnera_core::domain::vulnerability::value_objects::Ecosystem::Npm,
        )
        .unwrap();

        emitter
            .emit(DependencyEvent::PackageParsed {
                package: package.clone(),
                location: None,
            })
            .await;

        let events = emitter.get_events().await;
        assert_eq!(events.len(), 1);
        match &events[0] {
            DependencyEvent::PackageParsed { package: p, .. } => {
                assert_eq!(p.name, "test");
            }
            _ => panic!("Unexpected event type"),
        }
    }

    #[tokio::test]
    async fn test_no_op_event_emitter() {
        let emitter = NoOpEventEmitter::new();
        assert!(!emitter.has_subscribers());

        // Should not panic
        emitter
            .emit(DependencyEvent::AnalysisStarted {
                file_path: "test".to_string(),
                ecosystem: "npm".to_string(),
            })
            .await;
    }
}
