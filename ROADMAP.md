# Vulnera Roadmap

**Version:** 0.6.0-target
**Last Updated:** April 2025
**Status:** Active Development

This roadmap reflects our open-core model: Community features are AGPL-3.0; Enterprise features require a commercial license.

---

## Now (0.6.0) - In Progress

Target: Launch readiness for small teams

### Community (AGPL-3.0)

- [ ] **SAST:** Complete 3-pass control flow graph (CFG) integration for advanced reachability analysis
- [ ] **Dependencies:** Lockfile-independent transitive resolution for npm and PyPI manifest-only projects
- [ ] **Sandbox:** Functional WASM backend for non-Linux platforms (macOS, Windows)
- [ ] **Documentation:** Comprehensive deployment guide for self-hosted installations
- [ ] **CI/CD:** Production-ready GitHub Actions integration with examples


---

## Next (0.7.0) - Planned

Target: Enhanced observability and workflow automation

### Community (AGPL-3.0)

- [ ] **Observability:** OpenTelemetry span export (Jaeger / OTLP / Prometheus)
- [ ] **SAST:** Reachability scoring - combine CVE severity with call-graph reachability analysis
- [ ] **Performance:** Parallel analysis across multiple CPU cores with work-stealing
- [ ] **Secrets:** Git history scanning for committed secrets detection


---

## Later (0.8.0–1.0.0) - Future

Target: Platform maturity and advanced capabilities

### Community (AGPL-3.0)

- [ ] **Rust Analysis:** MIR-level unsafe auditing with `unsafe` attribution across FFI boundaries
- [ ] **SAST:** Support for additional languages (Java, C# via tree-sitter)
- [ ] **ML Integration:** Machine learning for false-positive reduction (research phase)
- [ ] **Cross-Repo:** Monorepo dependency graph analysis across multiple repositories


---

## Enterprise Module Status

The following modules are defined in the codebase but have varying implementation status:

| Module | Status | Notes |
|--------|--------|-------|
| **DAST** | 🚧 Scaffolding | HTTP fuzzing via OpenAPI specs; basic structure in place |
| **IaC** | 🚧 Scaffolding | Terraform, K8s, Dockerfile analyzers stubbed |
| **CSPM** | 📋 Planned | Cloud posture management - not yet implemented |
| **Fuzz Testing** | 📋 Planned | Coverage-guided fuzzing - research phase |
| **SBOM** | 📋 Planned | SBOM generation - planned post-1.0 |
| **License Compliance** | 📋 Planned | License scanning - planned post-1.0 |
| **Malicious Package** | 📋 Planned | Heuristic detection - planned post-1.0 |

Legend:
- ✅ Production-ready
- 🚧 In development / scaffolding
- 📋 Planned / research phase
- ❌ Not planned

---

## Long-Term Vision (Post-1.0)

- **Vulnera Studio:** Full-featured SaaS platform for enterprise teams
- **Custom Rule IDE:** Web-based TOML rule editor with live AST preview
- **Vulnera Monitor:** Real-time vulnerability monitoring and dark web intelligence
- **AI-Assisted Remediation in post-production:** Context-aware vulnerabilities with confidence scoring using the power of powerful LLMs in the post-production environment, providing actionable insights and remediation steps based on the specific code context and vulnerability characteristics but currently we focus on pre-production phase.

---

## Contributing to the Roadmap

We welcome community input:

1. **Feature Requests:** Open a GitHub issue with the `enhancement` label
2. **Priority Voting:** 👍 reactions on existing issues help us prioritize
3. **Contributions:** PRs for roadmap items are always welcome

**Principles:**
- Community contributions accelerate timeline
- Enterprise features fund open-source development
- We don't accept features that compromise our core philosophy (see [PHILOSOPHY.md](PHILOSOPHY.md))

---

## Completed Milestones

### 0.5.1 (2026-02-13)
- ✅ CLI architecture overhaul with use-case orchestration
- ✅ SAST bulk fix generation with LLM integration
- ✅ Precise semver interval intersection for dependency analysis
- ✅ Granular Rust unsafe rules and improved taint analysis
- ✅ Landlock sandbox default with fail-closed mode

### 0.5.0 (2026-02-11)
- ✅ SAST V4: TOML-based rules, inter-procedural taint analysis
- ✅ JobWorkflow state machine with formal transitions
- ✅ Enterprise licensing infrastructure (ModuleTier)
- ✅ Open-core model establishment

### 0.4.x and earlier
- See [CHANGELOG.md](CHANGELOG.md) for full history

---

**Questions?** Open a discussion in GitHub Discussions or reach out to the core team.
