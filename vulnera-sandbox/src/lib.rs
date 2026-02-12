//! Vulnera Sandbox - Hybrid Kernel Sandboxing for Security Modules
//!
//! This crate provides a tiered sandboxing system for Vulnera analysis modules,
//! protecting the orchestrator from malicious repository exploitation.
//!
//! # Default Behavior
//!
//! **By default, sandboxing is enabled with Landlock on Linux**.
//! If unavailable, runtime behavior depends on configured fallback mode.
//!
//! # Architecture
//!
//! The sandbox uses platform-specific backends with automatic fallback:
//!
//! | Platform | Primary Backend | Fallback |
//! |----------|-----------------|----------|
//! | Linux 5.13+ | Landlock + seccomp | Process isolation |
//! | Older Linux | Process isolation | - |
//! | Non-Linux | WASM | NoOp |
//!
//! # Performance
//!
//! - **NoOp**: Zero overhead (no restrictions applied)
//! - **Landlock + seccomp**: <1µs overhead (kernel-native)
//! - **Process isolation**: ~1-5ms per spawn
//!
//! # Usage
//!
//! ```rust,ignore
//! use vulnera_sandbox::{SandboxPolicy, SandboxExecutor, SandboxSelector};
//!
//! // Create policy
//! let policy = SandboxPolicy::default()
//!     .with_readonly_path("/path/to/scan")
//!     .with_timeout_secs(30);
//!
//! // Auto-select best backend (Landlock on Linux)
//! let executor = SandboxExecutor::auto();
//!
//! // Execute module in sandbox
//! let result = executor.execute_module(&module, &config, &policy).await?;
//! ```

pub mod application;
pub mod domain;
pub mod infrastructure;

pub use application::executor::{SandboxExecutor, SandboxedExecutionError};
pub use application::selector::SandboxSelector;
pub use domain::limits::{ResourceLimits, calculate_limits};
pub use domain::policy::{SandboxPolicy, SandboxPolicyBuilder, SandboxPolicyProfile};
pub use domain::traits::{SandboxBackend, SandboxError, SandboxResult, SandboxStats};

// Re-export platform-specific backends
#[cfg(target_os = "linux")]
pub use infrastructure::landlock::LandlockSandbox;

#[cfg(target_os = "linux")]
pub use infrastructure::process::ProcessSandbox;

#[cfg(target_os = "linux")]
pub use infrastructure::seccomp::{SeccompConfig, create_analysis_config, is_seccomp_available};

#[cfg(not(target_os = "linux"))]
pub use infrastructure::wasm::WasmSandbox;
