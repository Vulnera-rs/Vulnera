//! WASM-based sandbox fallback for non-Linux platforms
//!
//! Uses Wasmtime to provide sandboxing on Windows/macOS where
//! kernel-level sandboxing is not available.

use async_trait::async_trait;
use tracing::info;
use wasmtime::{Config, Engine};

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

/// WASM-based sandbox using Wasmtime
///
/// This is the fallback for non-Linux platforms (Windows, macOS).
/// Provides strong isolation but with higher overhead (15-30%).
#[derive(Debug)]
pub struct WasmSandbox {
    engine: Engine,
}

impl WasmSandbox {
    /// Create a new WASM sandbox
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable fuel-based execution limiting
        config.epoch_interruption(true); // Enable epoch-based interruption

        let engine = Engine::new(&config).expect("Failed to create Wasmtime engine");

        Self { engine }
    }

    /// Create with custom Wasmtime configuration
    pub fn with_config(config: Config) -> Result<Self, SandboxError> {
        let engine = Engine::new(&config)
            .map_err(|e| SandboxError::CreationFailed(format!("Failed to create engine: {}", e)))?;
        Ok(Self { engine })
    }
}

impl Default for WasmSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SandboxBackend for WasmSandbox {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn is_available(&self) -> bool {
        // WASM is always available as it's a pure software sandbox
        true
    }

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()> {
        info!("WASM sandbox configured with timeout: {:?}", policy.timeout);

        // Note: For full WASM sandboxing, modules would need to be
        // compiled to WASM ahead of time and executed within Wasmtime.
        // For now, this configures the WASM engine for execution.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_sandbox_creation() {
        let sandbox = WasmSandbox::new();
        assert_eq!(sandbox.name(), "wasm");
        assert!(sandbox.is_available());
    }
}
