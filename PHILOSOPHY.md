# The Vulnera Philosophy

**Applies to:** All Vulnera projects and contributions

---

## Our Core Belief

Security tools should be as fast, safe, and transparent as the code they protect.

We build security scanners with the same principles we advocate for application development: memory safety, minimal privileges, and auditable logic.

---

## Four Principles

### 1. Memory-Safe Security Tooling

**The Principle:** We write memory-safe Rust to analyze your code - whether your code is memory-safe or not.

**Why It Matters:**
- No sandbox escapes via memory corruption vulnerabilities
- No garbage collection pauses during analysis
- Predictable performance under load
- Zero-day resilience in the scanner itself

**In Practice:**
- Rust's ownership model prevents use-after-free, double-free, and buffer overflows
- `unsafe` blocks are rare, documented, and rigorously reviewed
- The same type system that protects applications protects our analysis engine

**Contrast:** Most security scanners (Semgrep, Snyk, TruffleHog) are built on Go or Python. They ask you to trust memory-unsafe tooling to find memory-unsafe bugs in your code. We find that circular.

---

### 2. Kernel-First Sandboxing

**The Principle:** While others sandbox with containers, we use Linux kernel Landlock LSM.

**Why It Matters:**
- Containers are bypassable via kernel exploits or misconfigurations
- Landlock is enforced by the kernel itself - not a userspace abstraction
- Near-zero overhead (<1µs startup vs seconds for container initialization)
- Fine-grained permissions: read-only paths, specific network ports, no escapes

**In Practice:**
```rust
// Sandboxing is not glue - it's a typed policy builder
SandboxPolicy::for_analysis(source_path)
    .with_profile(SandboxPolicyProfile::ReadOnlyAnalysis)
    .with_timeout_secs(120)
    .with_memory_mb(2048)
```

**Technical Details:**
- **Landlock** (Linux 5.13+): Filesystem and network restrictions via LSM hooks
- **Seccomp** (Older Linux): Syscall filtering with graceful fallback
- **WASM** (Non-Linux): Portable WebAssembly sandbox (in development)
- **NoOp** (Development): Disable sandboxing for debugging

**Philosophy:** Sandboxing is a first-class domain concept, not an afterthought. The `SandboxPolicy` is constructed at the composition root and injected via traits - just like any other dependency.

---

### 3. Transparent by Default

**The Principle:** Every detection must be explainable. No mystery scores, no black-box algorithms.

**Why It Matters:**
- Developers learn from explanations, not just alerts
- Security auditors can verify findings
- False positives can be debugged and tuned
- Rules can be customized without vendor lock-in

**In Practice:**

**SAST Rules (TOML):**
```toml
[[rules]]
id = "sql-injection"
name = "SQL Injection"
pattern = """
(call_expression
  function: (identifier) @func
  (#match? @func "^(execute|query|run)$")
  arguments: (argument_list
    (string_literal) @query
    (#match? @query "%")))
"""
severity = "high"
```

**Secrets Detection (Entropy + Patterns):**
- Shannon entropy thresholds you can tune
- Regex patterns you can read
- AST context for false-positive reduction

**Contrast:** Proprietary scanners give you opaque confidence scores. We give you the actual detection logic.

---

### 4. Offline-First Architecture

**The Principle:** Network calls are opt-in, not opt-out. Your code should never leave your machine unless you choose.

**Why It Matters:**
- No data exfiltration risk
- Works in air-gapped environments
- No latency from API calls
- No dependency on our infrastructure uptime

**What Works Offline:**
- ✅ **SAST** - Tree-sitter AST analysis requires zero network
- ✅ **Secrets** - Entropy and pattern matching are local
- ✅ **API Security** - OpenAPI spec analysis is local

**What Requires Network:**
- ⚠️ **Dependencies** - CVE database lookups (OSV, NVD, GHSA)
- ⚠️ **LLM Explanations** - Natural language vulnerability explanations (Gemini, OpenAI, Azure)

**In Practice:**
```bash
# Completely offline - no internet required
vulnera analyze . --modules sast,secrets,api

# Online features explicitly opted into
vulnera analyze . --modules sast,secrets,deps
vulnera explain --finding-id abc123  # Uses LLM
```

---

## Open Core Philosophy

We believe in **radical transparency for security infrastructure** and **fair compensation for team workflows**.

### What's Open Source (AGPL-3.0)

**The Security Engine:**
- SAST module with tree-sitter and taint analysis
- Secrets detection with entropy + patterns
- Dependency scanning with CVE lookup
- API security analysis
- Sandboxing backends (Landlock, Seccomp, WASM)
- LLM provider abstractions

**Why:** Core security capabilities should be accessible to all developers, auditable by the community, and improvable via contribution.

### What's Enterprise (Licensed)

**Team Workflow Features:**
- DAST (dynamic application security testing)
- IaC security (Terraform, Kubernetes, Docker)
- CSPM (cloud security posture management)
- Fuzz testing
- SBOM generation
- License compliance
- Malicious package detection
- Vulnera Studio SaaS platform
- Enterprise SSO (SAML/OIDC)
- Auto-PR generation

**Why:** These features require ongoing infrastructure, support, and development. Licensing funds continued open-source development.

**Our Commitment:**
- The CLI scanner is and always will be fully functional open source
- We will never gate basic security detection behind a paywall
- Enterprise features are additive - they don't remove capabilities from the open-source version

---

## Design Patterns

### Dependency Inversion at Every Boundary

Nothing instantiates its own database pool, HTTP client, or cache. Everything is wired at the composition root (`src/app.rs`) and injected via `Arc<dyn Trait>`.

**Why:** Testability, flexibility, and clear boundaries.

### Make Illegal States Unrepresentable

The type system enforces domain invariants:
- `JobStatus` state machine prevents invalid transitions at compile time
- `ModuleConfig` validated at construction
- `Finding` requires severity and location

**Why:** Bugs caught at compile time don't reach production.

### Domain-Driven Design

Four layers with strict dependency direction:
1. **Domain** - Pure types, zero side effects
2. **Application** - Use case orchestration
3. **Infrastructure** - I/O, databases, HTTP
4. **Presentation** - HTTP controllers, DTOs

Dependencies point inward. Domain knows nothing of HTTP or SQL.

---

## Anti-Patterns We Reject

❌ **Black-box scoring** - Every detection is explainable
❌ **Memory-unsafe scanners** - We eat our own dog food on Rust
❌ **Container-only sandboxing** - Kernel-level or nothing
❌ **Vendor lock-in** - Open formats (SARIF, TOML rules), open source
❌ **Security theater** - Features that look good but don't actually protect

---

## Target Audience

**Primary:** Small development teams (5-50 engineers) who:
- Value speed and CI integration
- Want security without security team bottlenecks
- Prefer self-hosted solutions
- Appreciate open-source transparency

**Secondary:** Individual developers and open-source maintainers who want free, powerful security scanning.

**Not Targeted For Now:** Large enterprises requiring dedicated support - that's what our licensed tier is for.

---

## Success Metrics

We measure success by:

1. **Adoption:** CLI installs and active daily users
2. **Performance:** Median scan time <10s for typical projects
3. **Accuracy:** False positive rate <5% for high-confidence findings
4. **Community:** Active contributors and rule pack authors
5. **Trust:** Users who read our rules and understand our detections

We do not measure:
- Total scans run (quality > quantity)
- LLM API calls (offline-first is preferred)
- Revenue from OSS users (enterprise/Pro funds development, OSS is free)

---

## Contributing to This Philosophy

This document evolves. If you believe a principle is wrong or missing:

1. Open an issue explaining the gap
2. Reference specific real-world scenarios
3. Propose concrete changes

Philosophy without practice is meaningless. Every principle here must be observable in the codebase.

---

**Related Documents:**
- [Architecture](docs/src/reference/architecture.md) - Technical implementation
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Security](SECURITY.md) - Security policy
- [License](LICENSE) - AGPL-3.0 full text
