use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

use crate::domain::policy::SandboxPolicy;
use crate::domain::traits::{SandboxBackend, SandboxError, SandboxResult};

#[derive(Debug)]
pub struct WasmSandbox {
    engine: Engine,
}

impl WasmSandbox {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        #[cfg(feature = "pooling-allocator")]
        config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(
            wasmtime::PoolingAllocationConfig::default().max_unused_warm_instances(5),
        ));

        let engine = Engine::new(&config).unwrap_or_else(|e| {
            warn!("Wasmtime engine creation failed (using default): {e}");
            Engine::default()
        });

        Self { engine }
    }

    pub fn with_config(config: Config) -> Result<Self, SandboxError> {
        let engine = Engine::new(&config)
            .map_err(|e| SandboxError::CreationFailed(format!("engine: {e}")))?;
        Ok(Self { engine })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn compile_module(&self, wasm: &[u8]) -> Result<Module, SandboxError> {
        Module::new(&self.engine, wasm)
            .map_err(|e| SandboxError::CreationFailed(format!("compile wasm: {e}")))
    }

    pub fn create_linker(&self) -> Linker<()> {
        Linker::new(&self.engine)
    }

    pub fn create_store(&self, policy: &SandboxPolicy) -> Store<()> {
        let mut store = Store::new(&self.engine, ());

        let fuel = (policy.timeout.as_millis() as u64) * 1000;
        store.set_fuel(fuel).ok();

        let limiter = StoreLimitsBuilder::new()
            .memory_size(policy.max_memory)
            .memories(1)
            .tables(1)
            .instances(1)
            .build();
        store.limiter(limiter);

        store
    }

    pub fn execute_within_wasm(
        &self,
        wasm: &[u8],
        policy: &SandboxPolicy,
        entry_point: &str,
        args: &[wasmtime::Val],
    ) -> SandboxResult<Vec<wasmtime::Val>> {
        let module = self.compile_module(wasm)?;
        let linker = self.create_linker();
        let mut store = self.create_store(policy);

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::ModuleExecution(format!("instantiate: {e}")))?;

        let func = instance
            .get_typed_func::<(), ()>(&mut store, entry_point)
            .map_err(|e| SandboxError::ModuleExecution(format!("get func {entry_point}: {e}")))?;

        func.call(&mut store, ())
            .map_err(|e| SandboxError::ModuleExecution(format!("call {entry_point}: {e}")))?;

        Ok(vec![])
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
        true
    }

    async fn apply_restrictions(&self, policy: &SandboxPolicy) -> SandboxResult<()> {
        info!(
            "WASM sandbox: engine configured (fuel={:?}, timeout={:?})",
            std::time::Duration::from_millis(policy.timeout.as_millis()),
            policy.timeout,
        );
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
