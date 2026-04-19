# vulnera-sandbox

Hybrid isolation sandbox for analysis modules with multiple backend options.

## Purpose

Provide least-privilege execution environments for security analysis:

- **Landlock** (Linux 5.13+) - Kernel-enforced filesystem/network restrictions
- **Seccomp** (Older Linux) - Syscall filtering with process isolation
- **WASM** (Non-Linux) - WebAssembly-based portable sandbox (in development)
- **NoOp** (Development) - Disabled sandboxing for debugging

## Architecture

```
domain/
  policy.rs          - SandboxPolicy and profiles
  backend.rs         - SandboxBackend trait
  
application/
  executor.rs        - SandboxExecutor
  selector.rs        - Backend selection logic
  
infrastructure/
  landlock.rs        - Landlock LSM implementation
  seccomp.rs         - Seccomp syscall filtering
  process.rs         - Process-based isolation
  wasm.rs            - WASM runtime (stub)
  worker.rs          - Worker binary entry point
```

## Policy Profiles

- `ReadOnlyAnalysis` - Filesystem-only access, no network
- `DependencyResolution` - HTTP(S) + optional Redis access

## Resource Limits

Dynamic scaling by module type:
- DependencyAnalyzer: 2.5x timeout, 1.5x memory
- SAST: 2.0x timeout, 2.0x memory
- Others: 1.0x/1.0x baseline

## Usage

```rust
let policy = SandboxPolicy::for_analysis(source_path)
    .with_profile(SandboxPolicyProfile::ReadOnlyAnalysis)
    .with_timeout_secs(120)
    .with_memory_mb(2048);

let executor = SandboxExecutor::new(backend, policy);
executor.execute(module_config).await?;
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
