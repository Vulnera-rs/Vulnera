//! No-op sandbox implementation
//!
//! This backend applies no restrictions and is used when sandboxing is disabled
//! or when a "none" backend is requested.

use async_trait::async_trait;
use tracing::info;

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxResult};

/// No-op sandbox that does nothing
#[derive(Debug, Default)]
pub struct NoOpSandbox;

impl NoOpSandbox {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SandboxBackend for NoOpSandbox {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn apply_restrictions(&self, _policy: &SandboxPolicy) -> SandboxResult<()> {
        info!("No-op sandbox: applying no restrictions");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_sandbox() {
        let sandbox = NoOpSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.name(), "noop");
    }
}
