use async_trait::async_trait;
use tracing::info;

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxResult};

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
        info!("NoOp sandbox: no restrictions applied");
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
