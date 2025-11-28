# Roadmap

This document outlines the development roadmap for Vulnera, including current capabilities, near-term enhancements, and long-term vision.

## Current Status (v0.3.2)

### ✅ Implemented Features

#### Core Infrastructure

- Unified Orchestrator Architecture with centralized module registry
- Domain-Driven Design with clean separation of concerns
- Async Runtime built on Tokio for high-performance operations
- PostgreSQL Backend for user management, API keys, and job tracking
- Dragonfly DB Caching for high-performance vulnerability data caching
- OpenAPI Documentation with auto-generated Swagger UI
- Authentication & Authorization with JWT tokens and API keys

#### Analysis Modules

- **Dependency Analysis** — npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, Ruby, .NET
- **SAST Module** — Python, JavaScript, Rust
- **Secrets Detection** — Regex-based and entropy-based detection
- **API Security** — OpenAPI 3.x specification analysis

#### Data Sources

- OSV Integration (Open Source Vulnerabilities)
- NVD Integration (National Vulnerability Database)
- GHSA Integration (GitHub Security Advisories)

#### Developer Experience

- Docker Support
- Configuration Management (TOML + environment variables)
- Comprehensive Documentation
- CI/CD Integration (GitHub Actions)

---

## Short-Term Roadmap (3-6 Months)

### Phase 1: Module Enhancements

#### Dependency Analysis

- [ ] Enhanced Version Resolution — Better handling of version ranges and pre-releases
- [ ] Additional Ecosystems — Swift, CocoaPods, Dart/Flutter, Conan (C/C++)
- [ ] Dependency Graph Analysis — Transitive vulnerability detection and visualization

#### SAST Module

- [ ] Expanded Languages — Java, C/C++, Go, TypeScript (enhanced)
- [ ] Advanced Pattern Matching — Context-aware analysis and data flow tracking

#### Secrets Detection

- [ ] Enhanced Secret Types — More cloud providers and CI/CD platforms
- [ ] Secret Verification — Integration with verification services

#### API Security

- [ ] Extended Coverage — GraphQL and gRPC security analysis
- [ ] Advanced OAuth/OIDC — Flow validation and token lifecycle analysis

### Phase 2: Platform Improvements

- [ ] OpenTelemetry Integration — Distributed tracing and metrics
- [ ] CLI Tool Enhancements — Better CI/CD integration
- [ ] SDK Development — Rust, Python, JavaScript SDKs
- [ ] IDE Integrations — VS Code extension, JetBrains plugin

---

## Medium-Term Roadmap (6-12 Months)

### Phase 3: Supply Chain Security

- [ ] **SBOM Generation** — CycloneDX and SPDX format support
- [ ] **License Compliance** — Automatic detection and policy enforcement
- [ ] **Malicious Package Detection** — Typosquatting and behavioral analysis

### Phase 4: Advanced Analysis

- [ ] **Container Image Scanning** — Docker image analysis
- [ ] **IaC Scanning** — Terraform, Kubernetes, CloudFormation
- [ ] **DAST Integration** — Dynamic Application Security Testing
- [ ] **API Fuzzing** — Automated API testing

---

## Long-Term Vision (12+ Months)

### Phase 5: Intelligence & Automation

- [ ] ML-based Module Selection
- [ ] Risk-based Finding Prioritization
- [ ] Automated Remediation Suggestions

### Phase 6: Enterprise Features

- [ ] Multi-Tenancy & Advanced RBAC
- [ ] Compliance Frameworks (SOC 2, GDPR)
- [ ] Advanced Reporting & Dashboards

### Phase 7: Scalability

- [ ] Optional Microservices Architecture
- [ ] Kubernetes Operator
- [ ] Multi-Cloud Deployment

---

## Research & Exploration

- [ ] Fuzz Testing — Coverage-guided fuzzing
- [ ] Code Quality Analysis — Technical debt metrics
- [ ] Plugin System — Community-contributed analyzers
- [ ] Rule Marketplace — Community rule sharing

---

## Contributing

We welcome community input on the roadmap!

1. **Open an Issue** — Discuss your idea
2. **Propose a Feature** — Create a detailed proposal
3. **Contribute Code** — Submit a pull request
4. **Join Discussions** — Participate in roadmap discussions

---

## Version History

| Version | Status | Key Features |
|---------|--------|--------------|
| v0.3.2 | Current | Core modules, orchestrator, authentication |
| v0.4.0 | Planned | Module enhancements, CLI improvements, SDKs |
| v0.5.0 | Planned | SBOM support, license compliance |
| v1.0.0 | Planned | Production-ready, enterprise features |

---

## Notes

- This roadmap is subject to change based on community feedback
- Items are not guaranteed in the order listed
- Timeline estimates are approximate

For updates, see [CHANGELOG.md](https://github.com/k5602/Vulnera/blob/main/CHANGELOG.md) and [GitHub Releases](https://github.com/k5602/Vulnera/releases).
