//! Sandbox infrastructure implementations

#[cfg(target_os = "linux")]
pub mod landlock;

#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "linux")]
pub mod process;

#[cfg(not(target_os = "linux"))]
pub mod wasm;

pub mod noop;
