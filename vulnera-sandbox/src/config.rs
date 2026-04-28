use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxBackendPreference {
    #[default]
    Landlock,
    Process,
    Wasm,
    Noop,
}

impl SandboxBackendPreference {
    pub fn platform_default() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Landlock
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::Wasm
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxBackendPreference::Landlock => "landlock",
            SandboxBackendPreference::Process => "process",
            SandboxBackendPreference::Wasm => "wasm",
            SandboxBackendPreference::Noop => "noop",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxFailureMode {
    FailClosed,
    #[default]
    BestEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub backend: SandboxBackendPreference,
    pub failure_mode: SandboxFailureMode,
    pub timeout_ms: u64,
    pub max_memory_bytes: u64,
    pub allow_network: bool,
    pub dynamic_limits: bool,
    pub timeout_per_mb_ms: u64,
    pub memory_per_mb_ratio: f64,
    pub max_memory_cap_bytes: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: SandboxBackendPreference::platform_default(),
            failure_mode: SandboxFailureMode::BestEffort,
            timeout_ms: 60_000,
            max_memory_bytes: 1024 * 1024 * 1024,
            allow_network: false,
            dynamic_limits: true,
            timeout_per_mb_ms: 200,
            memory_per_mb_ratio: 10.0,
            max_memory_cap_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}
