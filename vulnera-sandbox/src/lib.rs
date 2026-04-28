//! Vulnera Sandbox - Hybrid Kernel Sandboxing for Security Modules

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;

pub use application::executor::{SandboxExecutor, SandboxedExecutionError};
pub use application::selector::SandboxSelector;
pub use config::{SandboxBackendPreference, SandboxConfig, SandboxFailureMode};
pub use domain::limits::{ResourceLimits, calculate_limits};
pub use domain::policy::{SandboxPolicy, SandboxPolicyProfile};
pub use domain::traits::{SandboxBackend, SandboxError, SandboxResult, SandboxStats};

#[cfg(target_os = "linux")]
pub use infrastructure::landlock::LandlockSandbox;
#[cfg(target_os = "linux")]
pub use infrastructure::process::ProcessSandbox;
#[cfg(target_os = "linux")]
pub use infrastructure::seccomp::{SeccompConfig, create_analysis_config, is_seccomp_available};
#[cfg(not(target_os = "linux"))]
pub use infrastructure::wasm::WasmSandbox;
