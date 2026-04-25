use std::sync::Arc;
use tracing::{debug, info};

use crate::domain::traits::SandboxBackend;
#[cfg(target_os = "linux")]
use crate::infrastructure::landlock::LandlockSandbox;
#[cfg(target_os = "linux")]
use crate::infrastructure::process::ProcessSandbox;
#[cfg(not(target_os = "linux"))]
use crate::infrastructure::wasm::WasmSandbox;

pub struct SandboxSelector;

impl SandboxSelector {
    pub fn select() -> Arc<dyn SandboxBackend> {
        #[cfg(target_os = "linux")]
        {
            if LandlockSandbox::is_supported() {
                info!("Selecting Landlock sandbox (kernel 5.13+)");
                return Arc::new(LandlockSandbox::new());
            }
            info!(
                "Landlock unavailable, selecting process sandbox (seccomp + rlimits + namespaces)"
            );
            Arc::new(ProcessSandbox::new())
        }
        #[cfg(not(target_os = "linux"))]
        {
            info!("Non-Linux platform, selecting WASM sandbox");
            Arc::new(WasmSandbox::new())
        }
    }

    pub fn select_by_name(name: &str) -> Option<Arc<dyn SandboxBackend>> {
        match name.to_lowercase().as_str() {
            "auto" => Some(Self::select()),
            "noop" | "none" | "disabled" => {
                debug!("Using NoOp sandbox");
                Some(Arc::new(crate::infrastructure::noop::NoOpSandbox::new()))
            }
            #[cfg(target_os = "linux")]
            "landlock" => {
                if LandlockSandbox::is_supported() {
                    Some(Arc::new(LandlockSandbox::new()))
                } else {
                    debug!("Landlock requested but unavailable");
                    None
                }
            }
            #[cfg(target_os = "linux")]
            "process" => Some(Arc::new(ProcessSandbox::new())),
            #[cfg(not(target_os = "linux"))]
            "wasm" => Some(Arc::new(WasmSandbox::new())),
            _ => None,
        }
    }

    pub fn best_available() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            if LandlockSandbox::is_supported() {
                return "landlock";
            }
            "process"
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
        let backend = SandboxSelector::select();
        assert!(backend.is_available());
        let name = SandboxSelector::best_available();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_select_by_name_auto() {
        let backend = SandboxSelector::select_by_name("auto");
        assert!(backend.is_some());
    }

    #[test]
    fn test_select_unknown() {
        assert!(SandboxSelector::select_by_name("unknown").is_none());
    }

    #[test]
    fn test_select_noop() {
        let backend = SandboxSelector::select_by_name("noop");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name(), "noop");
    }
}
