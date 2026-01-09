//! Sandbox backend selector
//!
//! Automatically selects the best sandbox backend based on platform capabilities.

use std::sync::Arc;
use tracing::{debug, info};

use crate::domain::traits::SandboxBackend;

#[cfg(target_os = "linux")]
use crate::infrastructure::landlock::LandlockSandbox;
#[cfg(target_os = "linux")]
use crate::infrastructure::process::ProcessSandbox;
#[cfg(not(target_os = "linux"))]
use crate::infrastructure::wasm::WasmSandbox;

/// Sandbox backend selector
///
/// Automatically chooses the best available sandbox backend:
/// 1. Landlock (Linux 5.13+) - fastest, kernel-enforced
/// 2. Process isolation (older Linux) - resource limits
pub struct SandboxSelector;

impl SandboxSelector {
    /// Select the best available sandbox backend
    ///
    /// Returns an Arc-wrapped backend for shared ownership.
    pub fn select() -> Arc<dyn SandboxBackend> {
        #[cfg(target_os = "linux")]
        {
            if LandlockSandbox::is_supported() {
                info!("Using Landlock sandbox (kernel 5.13+)");
                return Arc::new(LandlockSandbox::new());
            }

            info!("Landlock not available, using process sandbox");
            return Arc::new(ProcessSandbox::new());
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!("Non-Linux platform, using WASM sandbox");
            Arc::new(WasmSandbox::new())
        }
    }

    /// Select a specific backend by name
    ///
    /// Valid names: "landlock", "process", "wasm", "auto", "noop" (or "none"/"disabled")
    pub fn select_by_name(name: &str) -> Option<Arc<dyn SandboxBackend>> {
        match name.to_lowercase().as_str() {
            "auto" => Some(Self::select()),

            // No-op backend for when sandboxing is disabled
            "noop" => {
                debug!("Using no-op sandbox backend (sandboxing disabled)");
                Some(Arc::new(crate::infrastructure::noop::NoOpSandbox::new()))
            }

            #[cfg(target_os = "linux")]
            "landlock" => {
                if LandlockSandbox::is_supported() {
                    Some(Arc::new(LandlockSandbox::new()))
                } else {
                    debug!("Landlock requested but not available");
                    None
                }
            }

            #[cfg(target_os = "linux")]
            "process" => Some(Arc::new(ProcessSandbox::new())),

            #[cfg(not(target_os = "linux"))]
            "wasm" => Some(Arc::new(WasmSandbox::new())),

            _ => {
                debug!("Unknown sandbox backend: {}", name);
                None
            }
        }
    }

    /// Get the name of the best available backend without instantiating it
    pub fn best_available() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            if LandlockSandbox::is_supported() {
                return "landlock";
            }
            return "process";
        }

        #[cfg(not(target_os = "linux"))]
        {
            "wasm"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_selection() {
        let _backend = SandboxSelector::select();
        let name = SandboxSelector::best_available();
        assert!(!name.is_empty());
        println!("Selected backend: {}", name);
    }

    #[test]
    fn test_select_by_name_auto() {
        let backend = SandboxSelector::select_by_name("auto");
        assert!(backend.is_some());
    }

    #[test]
    fn test_select_unknown() {
        let backend = SandboxSelector::select_by_name("unknown");
        assert!(backend.is_none());
    }

    #[test]
    fn test_select_noop_backend() {
        // Test all aliases for noop backend
        for name in ["noop", "none", "disabled"] {
            let backend = SandboxSelector::select_by_name(name);
            assert!(backend.is_some(), "Backend '{}' should be available", name);
            assert_eq!(backend.unwrap().name(), "noop");
        }
    }
}
