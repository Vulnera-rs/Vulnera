# vulnera-sandbox

Hybrid isolation sandbox for analysis modules with defense-in-depth.

## Architecture

```
domain/
  traits.rs        - SandboxBackend trait, SandboxError, SandboxStats
  policy.rs        - SandboxPolicy with builder and profiles
  limits.rs        - Dynamic resource limit calculation

application/
  executor.rs      - SandboxExecutor - runs modules within sandbox
  selector.rs      - Auto-selection of best backend by platform

infrastructure/
  landlock.rs      - Landlock LSM + seccomp (Linux 5.13+, ABI V4)
  seccomp.rs       - Standalone seccomp-bpf syscall filter
  process.rs       - Resource limits + namespaces + seccomp (older Linux)
  wasm.rs          - Wasmtime-based sandbox (non-Linux fallback)
  noop.rs          - No restrictions (development)
```

## Backend Priority

| Priority | Backend | Platform | Isolation |
|----------|---------|----------|-----------|
| 1 | Landlock | Linux 5.13+ | Landlock FS+net + seccomp BPF |
| 2 | Process | Linux (all) | rlimits + namespaces + seccomp |
| 3 | WASM | Non-Linux | Wasmtime fuel/epoch isolation |
| 4 | NoOp | Any | No restrictions (development) |

## Defense-in-Depth

- **Landlock backend**: Landlock restricts filesystem paths and network ports; seccomp restricts available syscalls
- **Process backend**: RLIMIT_AS/CPU/CORE/NOFILE/NPROC + user/mount/network/IPC namespaces + seccomp BPF allowlist
- **WASM backend**: Wasmtime with fuel metering, epoch interruption, and StoreLimits for memory

## Policy Profiles

- `ReadOnlyAnalysis` - Filesystem read-only, no network
- `DependencyResolution` - HTTP(S) + optional Redis port

## Usage

```rust
use vulnera_sandbox::{SandboxExecutor, SandboxPolicy, SandboxSelector};

let executor = SandboxExecutor::new(SandboxSelector::select());
let policy = SandboxPolicy::for_analysis("/path/to/scan")
    .with_profile(SandboxPolicyProfile::ReadOnlyAnalysis);

let result = executor.execute_module(&module, &config, &policy).await?;
```

## License

AGPL-3.0-or-later.
